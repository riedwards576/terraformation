# Terraform CI/CD POC — open-source, secure by default

A proof of concept for a startup with very little budget: **GitHub Actions + Terraform + AWS, with OIDC auth, remote state, policy-as-code, and drift detection. No paid SaaS required.**

Example workload is a secure-by-default S3 bucket — cheap enough to run at $0, real enough to prove the pipeline end to end. Swap the module for a VPC / ECS / etc. later; the pipeline doesn't change.

## Architecture

```
PR ──▶ fmt · validate · tflint · Trivy · Checkov · OPA · plan ──▶ plan posted to PR
 │        + PlanGuard attest (hash + risk score)                     (no apply)
 └─ merge to main ──▶ PlanGuard verify ──▶ apply dev (auto) ──▶ apply prod (manual + reviewer)
Nightly ──▶ plan -detailed-exitcode ──▶ drift issue if anything changed outside Terraform
```

## The novel piece: PlanGuard

Most Terraform pipelines approve Plan A in a PR, then apply a *different*
Plan B days later because code or live state moved in between. PlanGuard
closes that time-of-check / time-of-use gap — the interview talking point:

- **PR job:** `tools/planguard/planguard.py attest` hashes the canonical
  plan (SHA-256), scores its risk, and writes `attestation.json`
  (commit, PR, actor, hash, risk). The hash is posted in the PR comment
  and stored as a workflow artifact.
- **Apply job:** re-plans, runs `planguard verify`, and refuses to apply
  unless the fresh hash matches the attested hash. It then applies
  *that verified plan file*, not a second unverified apply. No
  attestation = no apply (fail closed).
- **Risk scoring:** destroys +40, replaces +30, IAM / KMS / DB types +15,
  S3 public-access disabled +50. HIGH / CRITICAL plans get a
  `needs-extra-review` label; prod already needs a human approver.

Stdlib-only Python, 9 unit tests (`cd tools/planguard && python3 -m unittest test_planguard -v`),
no paid service, no server. See `tools/planguard/README.md` for the
30-second interview story and its honest limits (attestation, not yet
Sigstore signing — that's the stated next step).

| Concern | Choice | Cost |
|---|---|---|
| CI/CD | GitHub Actions (2,000 free min/mo private, unlimited public) | $0 |
| IaC | Terraform 1.9.8 (OpenTofu is a drop-in if you prefer MPL) | $0 |
| State | S3 + DynamoDB lock, encrypted + versioned | ~$0 at POC scale |
| Auth | GitHub OIDC → AWS IAM, 3 least-privilege roles, no long-lived keys | $0 |
| Lint | terraform fmt, validate, TFLint | $0 |
| Security scan | Trivy (tfsec rules), Checkov, Gitleaks | $0 |
| Policy as code | OPA / Conftest (Rego) — deny public S3, require tags/encryption/versioning | $0 |
| Cost guardrail | `scripts/cost-check.sh` allowlist (swap for Infracost free tier later) | $0 |
| Drift | Nightly `terraform plan`, GitHub issue on drift | $0 |

**Total POC running cost: $0** — an empty S3 bucket + on-demand DynamoDB lock table. No EC2, no NAT gateway (the usual budget killer — don't add one in a POC).

## Repo layout

```
.github/workflows/
  terraform-pr.yml       PR: fmt/validate/tflint/plan + OPA, posts plan as comment
  terraform-apply.yml    main: auto-apply dev; manual dispatch + approval for prod
  security.yml           Trivy + Checkov + Gitleaks, SARIF to GitHub Security tab
  drift-detection.yml    Nightly plan, opens an issue on drift
bootstrap/               Creates the S3 state bucket + DynamoDB lock table (run once)
terraform/
  modules/s3-secure/     Reusable secure bucket (encryption, versioning, public-access block)
  envs/dev/  envs/prod/  Thin env wrappers — same module, different vars/state
policy/                  OPA Rego: S3 public-access, versioning, required tags
scripts/
  bootstrap.sh           One-command bootstrap
  oidc-setup.md          GitHub OIDC → AWS roles, step by step
  cost-check.sh          Fails a plan that creates non-allowlisted resource types
```

## Quick start (30 min)

### 1. Create the repo
```bash
gh repo create terraform-pipeline --private --clone
# Push the contents of this folder (terraform-cicd-poc/) into it.
# Also protect main: Settings > Branches > main > Require a pull request
# before merging — PlanGuard's verify step depends on PR-only merges.
```

### 2. Bootstrap state (once, human admin, local)
```bash
./scripts/bootstrap.sh
# Copy the backend_config output into terraform/envs/dev/main.tf
# and terraform/envs/prod/main.tf (uncomment backend, key = dev/... / prod/...)
```

### 3. OIDC — no AWS keys in GitHub
Follow `scripts/oidc-setup.md`. Then set 3 GitHub **Variables** (not secrets):
`AWS_ROLE_ARN_READONLY`, `AWS_ROLE_ARN_DEV`, `AWS_ROLE_ARN_PROD`

Set prod protection: Settings → Environments → `prod` → Required reviewers (1–2 people).

### 4. Open a PR
Change something in `terraform/envs/dev/` — e.g. `noncurrent_days` — and watch:
fmt → validate → TFLint → Trivy/Checkov → OPA → plan comment on the PR.
Merge → dev applies automatically. Prod: Actions → Terraform Apply → Run workflow → `prod` → wait for reviewer approval.

### 5. Local dev
```bash
pre-commit install
terraform fmt -recursive
cd terraform/envs/dev && terraform init && terraform plan
```

## Security model (for a security reviewer)

- **No long-lived credentials anywhere in CI.** OIDC short-lived tokens, scoped by repo/branch/environment in the trust policy. A leaked token can't apply prod.
- **Separation of duties:** 3 roles — read-only (PR), dev-apply, prod-apply. Dev role can't touch prod state or resources. Prod needs a human reviewer in GitHub Environments.
- **PRs never apply, and never get write credentials.** `terraform-pr.yml` only assumes the read-only role.
- **State is never in git.** `.gitignore` blocks `*.tfstate`, `*.tfvars`, `plan.json`. State bucket is encrypted, versioned, public-access-blocked, with DynamoDB locking so two applies can't race.
- **Defence in depth on S3:** module defaults (encryption, versioning, public-access block) + Trivy/Checkov + OPA deny rules. One layer failing doesn't make a public bucket.
- **Secrets:** Gitleaks scans every PR + history. No secrets in tfvars — use GitHub Variables / AWS SSM Parameter Store for real values.
- **Audit trail:** every apply is a GitHub Actions run (who, what commit, what plan) + CloudTrail on the AWS side. Drift detection catches console changes.
- **What this POC does *not* do:** no Sentinel/Terraform Cloud (paid), no auto-remediation of drift (deliberate — remediating blind is riskier than alerting), no cross-region replication or KMS CMK (add when you have real data — see `policy/` comments).

## Validation performed (2026-11-11, Terraform 1.9.8, AWS provider 5.100.0)
- `terraform fmt -check -recursive` — pass, no diff
- `terraform init -backend=false && terraform validate` — dev, prod, bootstrap — all pass, no warnings (fixed a lifecycle `filter {}` warning during validation)
- Workflows are YAML only (not run here — they need a GitHub repo + AWS account; run the first PR to prove them).
- PlanGuard: 9 unit tests pass; demo verified — unchanged plan verifies OK, tampered plan fails with exit 1.
- Note: the POC is staged locally in `~/workspace/terraform-cicd-poc/` and has **not** been pushed to GitHub yet — that waits for GitHub to show as connected. Target repo is `terraform-pipeline` (personal, private). No other repo was touched.

## Next steps when budget / scale grows
1. **Infracost** (free tier) for real $ estimates on PRs, replacing `cost-check.sh`.
2. **Atlantis or Spacelift** if you want plan/apply *inside* PR comments with locking — still open-source / free tier, but adds a server to run.
3. **Separate AWS accounts** per env (dev/prod) instead of separate roles in one account.
4. **KMS CMK + CloudTrail + GuardDuty** once you hold customer data.
5. **OpenTofu** if HashiCorp licensing matters to you — workflows change by one action name.

## Decisions to confirm with Richard
- Cloud is **AWS / us-east-1** in this POC — say the word if it's Azure/GCP instead; the pipeline shape is identical, only the provider + OIDC setup changes.
- Example workload is **S3 only** to stay at $0 — happy to add a VPC/ECS module next if you want a compute example.
- Prod is **manual dispatch + reviewer approval**; dev auto-applies on merge. Flip either if you want prod on merge-with-approval instead.
