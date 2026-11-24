A Python tool that checks an AWS account for common security mistakes and maps each one to the CIS AWS Foundations Benchmark.

Built a deliberately insecure AWS environment with Terraform, then wrote a scanner in Python (boto3) to find everything planted. 

Scanner output:

<img width="739" height="94" alt="Screenshot 2026-11-23 at 17 29 17" src="https://github.com/user-attachments/assets/239656b7-6edf-4fe6-91b2-c19a623180b8" />


## How it works

The lab (Terraform): an S3 bucket with Block Public Access off, a security group open to the internet on 22 and 3389, and an IAM user with AdministratorAccess and no MFA. There's no CloudTrail on purpose. Nothing is actually exposed: the bucket is empty with no public policy, the security group isn't attached to anything, and the IAM user has no password or access keys.

The scanner (Python): each check queries one AWS service and returns Finding objects (a dataclass with severity, CIS ID, resource and issue). The scanner combines them, sorts HIGH first, and prints one aligned line per finding.



## What it checks

- **Open admin ports** (CIS 5.2): security groups allowing SSH or RDP from the whole internet
- **S3 public access** (CIS 2.1.4): buckets with Block Public Access turned off or not configured
- **Over-privileged IAM users** (CIS 1.15): AdministratorAccess attached directly to a user
- **Missing MFA** (CIS 1.10): IAM users with no MFA device

- 
## Monitoring

<img width="598" height="580" alt="Screenshot 2026-11-24 at 15 34 38" src="https://github.com/user-attachments/assets/f75bce34-2399-4ef4-b26f-c5a17722cf13" />

<img width="431" height="306" alt="Screenshot 2026-11-24 at 15 57 36" src="https://github.com/user-attachments/assets/485dac3b-b792-436a-ab7d-a0121f5f2d42" />


<img width="449" height="608" alt="Screenshot 2026-11-24 at 15 57 28" src="https://github.com/user-attachments/assets/165f93bc-c507-4be4-801c-e266e4942084" />



I wanted to see the findings change over time instead of just reading terminal output, so I turned the scanner into a Prometheus exporter. Every few minutes it reruns all four checks and publishes the number of findings for each check and severity. The first screenshot is the raw metrics page the exporter serves, with one line per check and severity, all at zero after the fix.

Prometheus scrapes those metrics and Grafana turns them into a dashboard. The "Findings over time" graph shows the insecure lab at 3 HIGH and 3 MEDIUM findings. MEDIUM drops to 2 when I added MFA to my own admin account, which the scanner had flagged. The gap is where I stopped the exporter to swap the labs over, and once the hardened Terraform was applied everything dropped to zero. The "Findings by check" chart confirms every check is now clean.

The last screenshot is the HIGH findings panel, which turns green at zero and red as soon as there's even one HIGH finding.- **No audit logging** (CIS 3.1): no CloudTrail trail in the account



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

# 3. clean up when done
cd ../terraform/insecure
terraform destroy
