variable "bucket_name" {
  description = "Globally unique S3 bucket name."
  type        = string
  validation {
    condition     = length(var.bucket_name) >= 3 && length(var.bucket_name) <= 63
    error_message = "Bucket name must be 3-63 characters."
  }
}

variable "tags" {
  description = "Tags applied to all resources. Environment, Owner and CostCenter are required by policy."
  type        = map(string)
  default     = {}
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN. If null, AES256 (SSE-S3) is used."
  type        = string
  default     = null
}

variable "force_destroy" {
  description = "Allow bucket deletion even when non-empty. Keep false in prod."
  type        = bool
  default     = false
}

variable "noncurrent_days" {
  description = "Days before non-current versions expire."
  type        = number
  default     = 90
}
