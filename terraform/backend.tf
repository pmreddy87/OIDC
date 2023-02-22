terraform {
  backend "s3" {
    bucket = "tls-cert-gitlab01"
    key    = "ssl-scm-check/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}



