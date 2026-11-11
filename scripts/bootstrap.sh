#!/usr/bin/env bash
# Bootstrap the remote-state backend once, from a human admin session.
# Usage: AWS_PROFILE=admin ./scripts/bootstrap.sh
set -euo pipefail
cd "$(dirname "$0")/../bootstrap"
terraform init -input=false
terraform apply -input=false
echo ""
echo "Copy the backend_config output into terraform/envs/dev/main.tf and prod/main.tf"
echo "(uncomment the backend block, set key = dev/terraform.tfstate / prod/terraform.tfstate)"
