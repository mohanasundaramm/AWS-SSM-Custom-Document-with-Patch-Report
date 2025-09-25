# AWS-SSM-Custom-Document-with-Patch-Report
This repository contains code and configuration required to run a patch report using AWS SSM and generate a report using AWS Lambda and send the report to store in S3 Bucket

**Automated EC2 Patch Reporting via AWS SSM, Lambda & S3:**
**Overview:**
AWS Systems Manager (SSM) provides patching capabilities for EC2 instances, but lacks a direct method to download patch reports. Typically, generating a patch report requires integrating multiple AWS services. This project simplifies the process by using:
1. A custom AWS SSM Document to initiate patching
2. AWS Lambda to fetch patch details from SSM Inventory
3. CSV report generation
4. Export to Amazon S3
   
**Architecture Summary:**
1. SSM Document: Custom automation document to run patching.
2. Lambda Function: Triggered post-patch to collect inventory data.
3. SSM Inventory: Source of patch compliance details.
4. S3 Bucket: Stores generated CSV reports.

**Setup Instructions:**
Step 1: Create Custom SSM Document
Define a document that runs AWS-RunPatchBaseline.
Add automation steps to trigger Lambda upon success.

Step 2: Configure AWS Lambda
Lambda is triggered by the SSM automation.
It uses boto3 to:
Query EC2 patch compliance from SSM Inventory.
Format results into CSV.
Upload to S3.

Step 3: Enable SSM Inventory
Ensure EC2 instances are configured to send inventory data.
Attach appropriate IAM roles to allow inventory collection.

Step 4: Create S3 Bucket
Bucket will store:
Individual EC2 Reports: One CSV per instance.
Consolidated Report: Aggregated CSV for all patched instances.

Step 5: IAM Roles & Permissions
SSM Document: Needs permission to run patch and invoke Lambda.
Lambda: Needs permission to read SSM Inventory and write to S3.

**Output**
Report Format: CSV
Stored In: S3 Bucket

**Report Types:**
ec2-instance-id.csv – Patch details per EC2
consolidated-report.csv – Summary across all patched EC2s

**Benefits**
Eliminates need for manual report generation.
Reduces dependency on multiple AWS services.
Provides automated, auditable patch compliance data.
