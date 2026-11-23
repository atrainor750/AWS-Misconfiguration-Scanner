# Deliberately INSECURE lab environment 

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.92"
    }
  }

  required_version = ">= 1.2"
}



provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "Test"
      Environment = "Test"
      ManagedBy   = "TFProviders"
    }
  }
}



resource "aws_s3_bucket" "secure" {
  bucket_prefix = "${var.prefix}-secure-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true


}

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "secure" {
  name   = "secure"
  vpc_id = data.aws_vpc.default.id



}


resource "aws_vpc_security_group_egress_rule" "egress_block" {
  security_group_id = aws_security_group.secure.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}


resource "aws_iam_role" "readonly" {
  name = "${var.prefix}-readonly-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "policy" {
  role       = aws_iam_role.readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"


}

locals {
  trail_name = "${var.prefix}-trail" # fix: one place for the name, so the trail and the policy can't drift apart
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}


resource "aws_s3_bucket" "cloud_trail" {
  bucket_prefix = "${var.prefix}-cloudtrail-" # fix: no underscores, trailing hyphen
  force_destroy = true
}

# fix: lock down the log bucket so the scanner doesn't flag it
resource "aws_s3_bucket_public_access_block" "cloud_trail" {
  bucket                  = aws_s3_bucket.cloud_trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloud_trail" {
  bucket = aws_s3_bucket.cloud_trail.id
  policy = data.aws_iam_policy_document.cloud_trail.json

  depends_on = [aws_s3_bucket_public_access_block.cloud_trail] # fix: avoids S3 rejecting two changes to the bucket at once
}

data "aws_iam_policy_document" "cloud_trail" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloud_trail.arn]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"] # FIX: .name, and uses the local
    }
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloud_trail.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"] # FIX: uses the local
    }
  }
}


resource "aws_cloudtrail" "secure" {
  depends_on = [aws_s3_bucket_policy.cloud_trail]

  name                          = local.trail_name # fix: same value as in the policy
  s3_bucket_name                = aws_s3_bucket.cloud_trail.id
  s3_key_prefix                 = "prefix"
  include_global_service_events = true # fix: records IAM changes
  is_multi_region_trail         = true # fix: covers every region (CIS 3.1)
  enable_log_file_validation    = true # tamper-evident logs (CIS 3.2)
}