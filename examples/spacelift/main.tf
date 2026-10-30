terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.20.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "synthetic-not-a-key"
  secret_key                  = "synthetic-not-a-secret"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation     = true
}

variable "public_ingress" {
  type    = bool
  default = true
}

resource "aws_security_group" "verification" {
  name   = "stackguard-plan-only-verification"
  vpc_id = "vpc-00000000000000000"
  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = [var.public_ingress ? "0.0.0.0/0" : "10.0.0.0/8"]
  }
  tags = { stackguard_protected = "true" }
}
