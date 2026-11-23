A Python tool that checks an AWS account for common security mistakes and maps each one to the CIS AWS Foundations Benchmark.

Built a deliberately insecure AWS environment with Terraform, then wrote a scanner in Python (boto3) to find everything planted. 

Scanner output:

## How it works

The lab (Terraform): an S3 bucket with Block Public Access off, a security group open to the internet on 22 and 3389, and an IAM user with AdministratorAccess and no MFA. There's no CloudTrail on purpose. Nothing is actually exposed: the bucket is empty with no public policy, the security group isn't attached to anything, and the IAM user has no password or access keys.

The scanner (Python): each check queries one AWS service and returns Finding objects (a dataclass with severity, CIS ID, resource and issue). The scanner combines them, sorts HIGH first, and prints one aligned line per finding.



## What it checks

- **Open admin ports** (CIS 5.2): security groups allowing SSH or RDP from the whole internet
- **S3 public access** (CIS 2.1.4): buckets with Block Public Access turned off or not configured
- **Over-privileged IAM users** (CIS 1.15): AdministratorAccess attached directly to a user
- **Missing MFA** (CIS 1.10): IAM users with no MFA device
- **No audit logging** (CIS 3.1): no CloudTrail trail in the account

## Running it

# 1. deploy the lab
cd terraform/insecure
terraform init
terraform apply

# 2. run the scanner
cd ../../python
python3 -m venv .venv
source .venv/bin/activate
pip install boto3
python scanner.py

# 3. clean up when you're done
cd ../terraform/insecure
terraform destroy