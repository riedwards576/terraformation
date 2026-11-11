#!/usr/bin/env bash
# Cheap cost guardrail for a $0 POC — no paid Infracost needed yet.
# Fails if the plan creates a resource type not on the allowlist.
# When spend grows, swap this for Infracost (free tier) and keep this as a backstop.
set -euo pipefail
PLAN_JSON="${1:-plan.json}"

# Allowlist: S3 + state plumbing only. Add types deliberately, with a cost note.
ALLOWED='aws_s3_bucket|aws_s3_bucket_versioning|aws_s3_bucket_server_side_encryption_configuration|aws_s3_bucket_public_access_block|aws_s3_bucket_lifecycle_configuration|aws_dynamodb_table|aws_iam_role|aws_iam_policy'

CREATED=$(jq -r '.resource_changes[] | select(.change.actions[] == "create") | .type' "$PLAN_JSON" | sort -u)
echo "Resource types to create:"
echo "$CREATED"

BAD=$(echo "$CREATED" | grep -vE "^($ALLOWED)$" || true)
if [ -n "$BAD" ]; then
  echo "ERROR: plan creates non-allowlisted types (cost / risk review needed):"
  echo "$BAD"
  exit 1
fi
echo "OK: all creates are on the $0 allowlist."
