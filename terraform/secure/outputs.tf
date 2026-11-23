# These are the resources your scanner should flag on Days 2-3.
# output "planted_findings" {
# description = "What the scanner is expected to find"
# value = {
#  s3_bucket_without_public_access_block = aws_s3_bucket.insecure.bucket
# security_group_open_ssh_rdp           = aws_security_group.insecure.id
# iam_user_admin_no_mfa                 = aws_iam_user.insecure.name
# cloudtrail                            = "none deployed (finding by absence)"
# }
# }
