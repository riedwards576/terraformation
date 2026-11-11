variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "cicd-poc"
}

variable "owner" {
  description = "Team / person accountable. Required by tagging policy."
  type        = string
  default     = "platform-team"
}

variable "cost_center" {
  type    = string
  default = "engineering"
}

variable "bucket_suffix" {
  description = "Unique suffix — S3 names are global. Change per account."
  type        = string
  default     = "CHANGE-ME-01"
}
