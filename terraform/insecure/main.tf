# Deliberately INSECURE lab environment for the AWS misconfiguration scanner.
# Written by: <you>

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



resource "aws_s3_bucket" "insecure" {
  bucket_prefix = "${var.prefix}-insecure-"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "insecure" {
  bucket                  = aws_s3_bucket.insecure.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false


}

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "insecure" {
  name   = "insecure"
  vpc_id = data.aws_vpc.default.id



}
resource "aws_vpc_security_group_ingress_rule" "ingress_block_22" {
  security_group_id = aws_security_group.insecure.id
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}
resource "aws_vpc_security_group_ingress_rule" "ingress_block_3389" {
  security_group_id = aws_security_group.insecure.id
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "egress_block" {
  security_group_id = aws_security_group.insecure.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}


resource "aws_iam_user" "insecure" {
  name          = "${var.prefix}-overprivileged-user"
  force_destroy = true
}

resource "aws_iam_user_policy_attachment" "policy" {
  user       = aws_iam_user.insecure.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"


}


