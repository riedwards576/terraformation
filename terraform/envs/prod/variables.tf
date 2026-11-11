variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project" {
  type    = string
  default = "cicd-poc"
}

variable "owner" {
  type    = string
  default = "platform-team"
}

variable "cost_center" {
  type    = string
  default = "engineering"
}

variable "bucket_suffix" {
  type    = string
  default = "CHANGE-ME-01"
}
