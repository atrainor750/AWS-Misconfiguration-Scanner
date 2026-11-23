variable "region" {
  description = "AWS region to deploy the lab into"
  type        = string
  default     = "eu-west-2" # London
}

variable "prefix" {
  description = "Name prefix for every lab resource, so they're easy to spot and clean up"
  type        = string
  default     = "misconfig-lab"
}
