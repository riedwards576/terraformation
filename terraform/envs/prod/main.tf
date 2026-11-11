terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  # Fill in after bootstrap. Key differs from dev — separate state file.
  # backend "s3" {
  #   bucket         = "tf-state-cicd-poc-xxxxxx"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "tf-lock-cicd-poc"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "terraform-cicd-poc"
      Environment = "prod"
      Owner       = var.owner
      CostCenter  = var.cost_center
      ManagedBy   = "terraform"
    }
  }
}

module "app_bucket" {
  source        = "../../modules/s3-secure"
  bucket_name   = "${var.project}-prod-app-${var.bucket_suffix}"
  force_destroy = false # prod: never auto-delete a non-empty bucket

  tags = {
    Environment = "prod"
    Owner       = var.owner
    CostCenter  = var.cost_center
  }
}
