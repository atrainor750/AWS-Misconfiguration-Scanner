# AWS Misconfiguration Scanner

A Python tool that audits an AWS account for common security misconfigurations, mapped to the CIS AWS Foundations Benchmark. Terraform deploys a deliberately insecure environment to test against, and a hardened version to prove the fixes.

> Work in progress — Day 1 of 7.

## Layout

```
aws-misconfig-scanner/
  terraform/
    insecure/     # Day 1: deliberately misconfigured, zero-cost resources
    hardened/     # Day 6: the fixed version
  scanner/        # Day 2+: the Python package
  tests/          # Day 5: pytest + moto
```

## Day 1 — set up AWS and deploy the insecure lab (~2 hours)

### 1. AWS account safety first (30 min)

1. Create an AWS free-tier account.
2. **Turn on MFA for the root user** (IAM → Security credentials).
3. **Create a billing alarm**: Billing → Budgets → Create budget → "Zero spend budget". You get an email if anything costs money.
4. Stop using root. Create an admin identity for yourself, ideally through IAM Identity Center (SSO); a plain IAM user with MFA is fine for a lab.

### 2. Local tools (20 min)

```bash
# AWS CLI v2 and Terraform >= 1.5 installed, then:
aws configure sso          # or: aws configure  (if using an IAM user's access key)
aws sts get-caller-identity   # should print your account ID
```

### 3. Deploy (20 min)

```bash
cd terraform/insecure
terraform init
terraform plan        # read it: 1 bucket, 1 security group, 1 IAM user + policy attachment
terraform apply
```

### 4. Check what you planted (30 min)

Find each issue by hand in the AWS console. This is what your Python scanner will automate:

| # | Misconfiguration | Where to see it | CIS control |
|---|---|---|---|
| 1 | S3 bucket with Block Public Access off | S3 → bucket → Permissions | 2.1.4 |
| 2 | Security group allowing 22 and 3389 from 0.0.0.0/0 | EC2 → Security Groups | 5.2 |
| 3 | IAM user with AdministratorAccess attached directly, no MFA | IAM → Users | 1.10, 1.15 |
| 4 | No CloudTrail trail | CloudTrail → Trails | 3.1 |

Then try the same with the CLI — these are the exact API calls your Python will make with boto3:

```bash
aws s3api get-public-access-block --bucket <bucket-name>
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0
aws iam list-attached-user-policies --user-name misconfig-lab-overprivileged-user
aws iam list-mfa-devices --user-name misconfig-lab-overprivileged-user
aws cloudtrail describe-trails
```

### 5. Commit and (optionally) tear down (10 min)

```bash
git init && git add . && git commit -m "Day 1: insecure lab environment"
terraform destroy     # safe to leave up overnight (all free), but destroy if unsure
```

## Safety notes

- Nothing here is actually exposed: the bucket is empty with no public policy, the security group is attached to nothing, and the IAM user has no password or access key.
- Never commit `.tfstate` files or credentials — `.gitignore` already excludes them.
# AWS-Misconfiguration-Scanner
