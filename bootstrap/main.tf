# Bootstrap — run ONCE, locally, with a human admin credential.
# Creates the remote-state backend used by every env.
# After this, state lives in S3 (encrypted, versioned, locked) — never in git.
#
#   cd bootstrap
#   terraform init && terraform apply
#   # then copy outputs into terraform/envs/*/backend.tf
#
# Cost: $0 at POC scale (S3 + DynamoDB on-demand, tiny state files).

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
  # Intentionally local state here: this *creates* the remote backend.
  # Do not add an S3 backend to this directory.
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "terraform-cicd-poc"
      ManagedBy   = "terraform-bootstrap"
      Environment = "shared"
    }
  }
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "aws_s3_bucket" "state" {
  bucket = "tf-state-${var.project}-${random_string.suffix.result}"
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "lock" {
  name         = "tf-lock-${var.project}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
}
