import os
import io
import csv
import time
import boto3
from datetime import datetime, timezone, timedelta
from botocore.config import Config

ssm = boto3.client('ssm', config=Config(retries={'max_attempts': 10, 'mode': 'standard'}))
ec2 = boto3.client('ec2', config=Config(retries={'max_attempts': 10, 'mode': 'standard'}))
s3  = boto3.client('s3',  config=Config(retries={'max_attempts': 10, 'mode': 'standard'}))

BUCKET             = os.environ['BUCKET']
PREFIX             = os.environ.get('PREFIX', 'patch-reports')
PLATFORM_FILTER    = os.environ.get('PLATFORM_FILTER', 'Linux')
WRITE_CONSOLIDATED = os.environ.get('WRITE_CONSOLIDATED', 'true').lower() == 'true'
WAIT_FOR_INSTALL   = int(os.environ.get('WAIT_FOR_INSTALL_SEC', '0'))

CSV_HEADER = [
    'InstanceId', 'Title', 'KBId', 'Classification', 'Severity',
    'State', 'InstalledTime', 'CVEIds', 'Vendor', 'Product'
]

def discover_instances(tag_key, tag_value):
    filters = [{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
    if tag_key and tag_value:
        filters.append({'Name': f'tag:{tag_key}', 'Values': [tag_value]})
    instance_ids = []
    paginator = ec2.get_paginator('describe_instances')
    for page in paginator.paginate(Filters=filters):
        for r in page.get('Reservations', []):
            for i in r.get('Instances', []):
                instance_ids.append(i['InstanceId'])
    return instance_ids

def filter_ssm_managed(instance_ids):
    if not instance_ids:
        return []
    managed = set()
    next_token = None
    while True:
        kwargs = {'MaxResults': 50}
        if next_token:
            kwargs['NextToken'] = next_token
        resp = ssm.describe_instance_information(**kwargs)
        for info in resp.get('InstanceInformationList', []):
            if PLATFORM_FILTER and info.get('PlatformType') != PLATFORM_FILTER:
                continue
            managed.add(info['InstanceId'])
        next_token = resp.get('NextToken')
        if not next_token:
            break
    return [i for i in instance_ids if i in managed]

def get_latest_patch_time(iid):
    resp = ssm.describe_instance_patch_states(InstanceIds=[iid])
    states = resp.get('InstancePatchStates', [])
    if not states:
        return None
    return states[0].get('OperationEndTime')

def list_recent_patches(iid, since_time):
    patches = []
    next_token = None
    buffer = timedelta(minutes=5)  # allow 5-minute skew
    while True:
        kwargs = {'InstanceId': iid, 'MaxResults': 50}
        if next_token:
            kwargs['NextToken'] = next_token
        resp = ssm.describe_instance_patches(**kwargs)
        for p in resp.get('Patches', []):
            installed = p.get('InstalledTime')
            if isinstance(installed, datetime) and since_time:
                if installed >= (since_time - buffer):
                    patches.append(p)
        next_token = resp.get('NextToken')
        if not next_token:
            break
    return patches

def to_csv_rows(iid, patches):
    rows = []
    for p in patches:
        rows.append([
            iid,
            p.get('Title', ''),
            p.get('KBId', ''),
            p.get('Classification', ''),
            p.get('Severity', ''),
            p.get('State', ''),
            p.get('InstalledTime', ''),
            p.get('CVEIds', ''),
            p.get('Vendor', ''),
            p.get('Product', ''),
        ])
    return rows

def write_csv_to_s3(key, header, rows):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    s3.put_object(
        Bucket=BUCKET, Key=key,
        Body=buf.getvalue().encode('utf-8'),
        ContentType='text/csv'
    )

def build_s3_key(instance_id, ts, consolidated=False):
    dt = datetime.now(timezone.utc)
    year = dt.strftime('%Y')
    month = dt.strftime('%m')
    day = dt.strftime('%d')
    if consolidated:
        return f"{PREFIX}/{year}/{month}/{day}/consolidated/patch-report-{ts}.csv"
    else:
        return f"{PREFIX}/{year}/{month}/{day}/{instance_id}/{instance_id}-patch-report-{ts}.csv"

def lambda_handler(event, context):
    tag_key   = event.get('tag_key')
    tag_value = event.get('tag_value')

    if WAIT_FOR_INSTALL > 0:
        time.sleep(WAIT_FOR_INSTALL)

    all_instances = discover_instances(tag_key, tag_value)
    ssm_instances = filter_ssm_managed(all_instances)

    if not ssm_instances:
        return {'message': 'No SSM-managed instances matched', 'tag_key': tag_key, 'tag_value': tag_value}

    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H-%M-%SZ')
    consolidated = []
    exported = 0

    for iid in ssm_instances:
        patch_time = get_latest_patch_time(iid)
        if not patch_time:
            print(f"{iid}: No patch operation time found")
            continue
        patches = list_recent_patches(iid, patch_time)
        rows = to_csv_rows(iid, patches)
        if not rows:
            print(f"{iid}: No recent patches found")
            continue
        key = build_s3_key(iid, ts)
        print(f"{iid}: Writing {len(rows)} patches to {key}")
        write_csv_to_s3(key, CSV_HEADER, rows)
        consolidated.extend(rows)
        exported += 1

    if WRITE_CONSOLIDATED and consolidated:
        cons_key = build_s3_key('summary', ts, consolidated=True)
        print(f"Writing consolidated report to {cons_key}")
        write_csv_to_s3(cons_key, CSV_HEADER, consolidated)

    return {
        'message': f'Exported {exported} reports',
        'total_matched': len(ssm_instances),
        'timestamp': ts
    }
