
import boto3
from botocore.exceptions import ClientError
from findings import Finding, SEVERITY_ORDER





REGION = "eu-west-2"


def check_open_admin_ports():
    findings = []
    client = boto3.client("ec2", region_name="eu-west-2")
    response = client.describe_security_groups()

    for group in response["SecurityGroups"]:
        for rule in group["IpPermissions"]:
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            for ip_range in rule["IpRanges"]:
                if ip_range["CidrIp"] == '0.0.0.0/0':
                    for port in (22, 3389):
                        if from_port <= port <= to_port:
                            findings.append(Finding(
                                severity="HIGH",
                                cis_id ="5.2",
                                resource=f"{group['GroupId']} ({group['GroupName']})",
                                issue=f"allows port {port} from 0.0.0.0/0",
                                ))

                           

    return findings


def check_s3_public_access():
    
        findings = []
        s3 = boto3.client("s3", region_name=REGION)
        response = s3.list_buckets()
        for bucket in response["Buckets"]:
            flag = True
            try:
                settings = s3.get_public_access_block(Bucket=bucket["Name"])
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(Finding(
                        severity="HIGH",
                        cis_id="2.1.4",
                        resource=f"{bucket["Name"]}",
                        issue="No Block Public Access configured at all"
                    ))
                    continue
                raise
            access_block_settings = settings["PublicAccessBlockConfiguration"]
            for setting, value in access_block_settings.items():
                if not value:
                    flag = False
            if not flag:
               findings.append(Finding(
                severity="MEDIUM",
                cis_id="2.1.4",
                resource=f"{bucket["Name"]}",
                issue="Block Public Access Disabled"
               ))
        return findings

def check_iam_users():
    findings = []
    iam = boto3.client("iam")
    response = iam.list_users()
    for user in response["Users"]:
        policies = iam.list_attached_user_policies(UserName= user['UserName'])
        mfa = iam.list_mfa_devices(UserName=user['UserName'])
        for policy in policies['AttachedPolicies']:
            if policy['PolicyName'] == 'AdministratorAccess':
                findings.append(Finding(
                    severity='HIGH',
                    cis_id='1.15',
                    resource=f"{user["UserName"]}",
                    issue="Administrator Access attached directly"
                ))
        if mfa['MFADevices'] == []:
            findings.append(Finding(
                severity="MEDIUM",
                cis_id="1.10",
                resource=f"{user["UserName"]}",
                issue="User has no MFA"
            ))
    return findings

def check_cloudtrail():
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    findings = []
    cloudtrail = boto3.client("cloudtrail", region_name=REGION)
    trails = cloudtrail.describe_trails()
    if trails['trailList'] == []:
        findings.append(Finding(
            severity="HIGH",
            cis_id="3.1",
            resource=f"{account_id}",
            issue="No CloudTrail trail configured"
        ))
    return findings



all_findings = (
    check_open_admin_ports()
    + check_s3_public_access()
    + check_iam_users()
    + check_cloudtrail()
)
all_findings = sorted(all_findings, key= lambda f: SEVERITY_ORDER[f.severity])
for f in all_findings:
    print(f.to_line())


    
   




        
