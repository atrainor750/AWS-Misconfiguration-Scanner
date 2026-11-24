from scanner import check_s3_public_access, check_cloudtrail, check_iam_users, check_open_admin_ports
from prometheus_client import Gauge, start_http_server
import time


FINDINGS_GAUGE = Gauge("aws_security_findings", "Number of open security findings", labelnames=("severity", "check"))


CHECKS = {
    "open_admin_ports": check_open_admin_ports,
    "s3_public_access": check_s3_public_access,
    "iam_users": check_iam_users,
    "cloudtrail": check_cloudtrail,
}


start_http_server(8000)
while True:
    for name,function in CHECKS.items():
        high = 0
        medium = 0
        findings = function()
        for finding in findings:
            if finding.severity == "HIGH":
                high += 1
            elif finding.severity == "MEDIUM":
                medium +=1
        FINDINGS_GAUGE.labels(check=name, severity="HIGH").set(high)
        FINDINGS_GAUGE.labels(check=name, severity="MEDIUM").set(medium)
    time.sleep(300)



