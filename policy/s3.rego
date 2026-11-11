package terraform.s3

# OPA policy evaluated by Conftest against `terraform show -json tfplan`.
# Deny = PR fails. Keep rules small, named, and testable.

deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket"
	change.change.after.bucket != null
	not change.change.after.tags.Environment
	msg := sprintf("S3 bucket %s missing Environment tag", [change.address])
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket_public_access_block"
	after := change.change.after
	after.block_public_acls != true
	msg := sprintf("%s must block public ACLs", [change.address])
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket_public_access_block"
	after := change.change.after
	after.block_public_policy != true
	msg := sprintf("%s must block public policy", [change.address])
}

deny contains msg if {
	some change in input.resource_changes
	change.type == "aws_s3_bucket_versioning"
	after := change.change.after
	after.versioning_configuration[_].status != "Enabled"
	msg := sprintf("%s must have versioning Enabled", [change.address])
}
