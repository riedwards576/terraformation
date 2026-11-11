package terraform.tagging

# Every managed resource must carry Owner + CostCenter.
# This is what makes SOX / cost-allocation audits answerable later.

required_tags := {"Owner", "CostCenter", "Environment"}

deny contains msg if {
	some change in input.resource_changes
	change.change.after.tags != null
	some tag in required_tags
	not change.change.after.tags[tag]
	msg := sprintf("%s missing required tag %s", [change.address, tag])
}
