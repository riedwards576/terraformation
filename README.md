# Terraform CI/CD POC — open-source, secure by default

A proof of concept for a startup with very little budget: **GitHub Actions + Terraform + AWS, with OIDC auth, remote state, policy-as-code, and drift detection. No paid SaaS required.**

Example workload is a secure-by-default S3 bucket — cheap enough to run at $0, real enough to prove the pipeline end to end. Swap the module for a VPC / ECS / etc. later; the pipeline doesn't change.

## Architecture

```
PR ──▶ fmt · validate · tflint · Trivy · Checkov · OPA · plan ──▶ plan posted to PR
 │        + PlanGuard attest (hash + risk score)                     (no apply)
 │        + CoverageGuard check (end-state coverage floor)
 │        + AccessGraph audit (Okta access map, report-only)
 │        + GhostChange drift check (click-ops drift, report-only)
 └─ merge to main ──▶ PlanGuard verify ──▶ apply dev (auto) ──▶ apply prod (manual + reviewer)
Nightly ──▶ plan -detailed-exitcode ──▶ drift issue if anything changed outside Terraform
```

## PlanGuard

Most Terraform pipelines approve Plan A in a PR, then apply a *different*
Plan B days later because code or live state moved in between. PlanGuard
closes that time-of-check / time-of-use gap.

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
no paid service, no server.

## CoverageGuard

While PlanGuard proves the *plan* didn't change, CoverageGuard judges the
*end state* — after this plan is applied, will fewer devices or users
be protected than the floor we established?

- **What it checks:** CrowdStrike sensor coverage, Jamf managed-device
  coverage, and Okta MFA coverage, each with a 95% floor (in
  `tools/coverageguard/coverageguard.json`), plus three hard protections
  that must stay on: CrowdStrike uninstall protection, Jamf FileVault
  enforcement, and Okta MFA-required.
- **How:** it takes a live coverage snapshot, applies the Terraform
  plan to it as deltas, and fails the PR (exit 1) if any dimension
  drops below its floor or a hard protection is turned off or deleted.
  A small drop that stays above the floor is a WARN, not a fail.
- **The principle:** it only ever blocks work that would make the end
  state worse. It does not care how the change was made, and it never
  blocks work for process reasons.

Stdlib-only Python, 15 unit tests (`cd tools/coverageguard && python3 -m unittest test_coverageguard -v`),
no paid service, no server. The POC ships a checked-in *example*
snapshot so it can be run with no accounts or credentials; in
production, a workflow step fetches a read-only snapshot from the
CrowdStrike / Jamf / Okta APIs first — see `tools/coverageguard/README.md`
for the wiring and the honest limits. With the current S3-only
Terraform, no plan touches those systems, so CoverageGuard passes
and stays out of the way until Jamf / Okta / CrowdStrike resources
are added.

## AccessGraph

AccessGraph will surface click-ops happening in Okta. This is usually the case
when multiple teams administer different parts of Okta. AccessGraph does the audit automatically:

- **What it does:** takes an Okta snapshot (users, groups, direct
  and nested membership) and a group-to-role mapping, and produces
  every user's effective access in Jamf, CrowdStrike, and Okta,
  plus findings: admins reached only via group nesting, admin
  grants to broad groups, multi-system admins, stale admin groups
  with no members, groups breaking the naming convention, and
  groups with no mapping (access unknown, never invented).
- **The principle:** it is a report, not a blocker. Admin access
  here is documented in Okta, not elusive, so a gate would just be
  a noisy version of the manual audit. The PR workflow runs it,
  uploads `access-report.json`, and posts a summary — and passes
  regardless of the findings. An opt-in `--strict` mode exists
  (exit 1 on any warning) for teams that want the gate.

Stdlib-only Python, 30 unit tests (`cd tools/accessgraph && python3 -m unittest test_accessgraph -v`),
no paid service, no server. The POC ships checked-in *example*
snapshot and mapping files so it can be run with no accounts or
credentials; in production, the snapshot comes from the Okta API
and the mapping is generated from the same Terraform code that
creates the groups and role assignments — see
`tools/accessgraph/README.md` for the wiring and the honest limits.
It also supports auditing one user at a time (`--user alice`),
the way an admin would start an audit. It also renders the audit
as a graph, two ways: `graph` produces a Mermaid flowchart for the
PR comment, and `d2` produces a D2 diagram — the artifact for
auditors, who get files from IT/Sec rather than reading PR comments.
The PR workflow compiles the `.d2` to a styled SVG with the
open-source D2 CLI (v0.9.0) and uploads both files with the report artifact.

## GhostChange

Terraform declares the SaaS config — Okta sign-on policies, Jamf
disk-encryption profiles, CrowdStrike prevention policies. But
those consoles are one click away, and when click-ops is rampant
the live config quietly stops matching what Terraform thinks it
manages. GhostChange compares a live snapshot against what
Terraform declares and lists what moved outside Terraform:

- **What it finds:** `unmanaged` (exists live, never declared —
  made in a console), `drifted` (declared, but live settings
  differ — edited in a console), `missing` (declared, but gone
  live — deleted in a console). Severity comes from a small
  critical-kinds list in `tools/ghostchange/ghostchange.json`;
  everything else is a warning, and metadata keys like
  `last_modified` are ignored so a read that changes nothing real
  never raises a finding.
- **The principle:** it is a report, not a blocker. If click-ops
  is rampant, a gate on drift would block engineering work
  constantly and hinder more than it helps. The team's response
  to drift is a decision — adopt it into Terraform or revert it —
  and a report supports that decision while a block just stops
  work. The PR workflow runs the check, uploads
  `ghost-report.json`, and posts a summary — and passes
  regardless of the findings. An opt-in `--strict` mode exists
  (exit 1 only on critical drift) for teams that want the gate.

Stdlib-only Python, 15 unit tests (`cd tools/ghostchange && python3 -m unittest test_ghostchange -v`),
no paid service, no server. The POC ships checked-in *example*
live and desired files so it can be run with no accounts or
credentials; in production, the live snapshot comes from the
Jamf / Okta / CrowdStrike APIs and the desired state is generated
from the same Terraform code that manages the config — see
`tools/ghostchange/README.md` for the wiring and the honest limits.

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
- CoverageGuard: 15 unit tests pass; demo verified — example pass plan exits 0, 10 uncovered Okta users (Okta MFA 98.0% → 91.9%) exits 1, disabling CrowdStrike uninstall protection exits 1, missing snapshot exits 2.
- AccessGraph: 30 unit tests pass (15 audit + 7 Mermaid graph + 8 D2); demo verified on the checked-in examples — 8 users, 6 admin users, 11 warnings (Alice and Bob as Okta Super Admins only via nesting, a 5-person CrowdStrike admin group, 3 naming violations, an unmapped VPN group, a stale legacy admin group); default run exits 0, `--strict` exits 1, missing snapshot exits 2; `graph` renders the audit as a Mermaid flowchart (admin roles highlighted, nested edges dotted) and the checked-in `examples/access-graph.mmd` regenerates byte-for-byte; `d2` renders the same audit as a D2 diagram (admin roles pink, nested edges dashed, each node and edge defined once), the checked-in `examples/access-graph.d2` regenerates byte-for-byte, and rendering it was verified by hand with D2 v0.9.0 (SVG and PNG).
- GhostChange: 15 unit tests pass; demo verified on the checked-in examples — 5 live, 5 desired, 3 ok, 1 drifted (uninstall protection turned off in the CrowdStrike console, critical), 1 unmanaged (Jamf profile made in the console), 1 missing (sensor policy deleted out of band); default run exits 0, `--strict` exits 1 on critical drift only, missing file exits 2.
- Note: the POC was pushed to `riedwards576/terraformation` (private) on 2026-11-11 — all 35 original files verified in place, then CoverageGuard (8 new files) and the updated `terraform-pr.yml`, verified complete at 43 files, head `a2957fd9`, plus a README correction, head `d69ca50a`. AccessGraph (5 new files) pushed 2026-11-11, verified complete at 48 files, head `edf136d6`; Richard also uploaded the updated `terraform-pr.yml` himself ("Adding in AccessGraph tooling", `4e272fbc`) just before that push, and it matches local exactly. GhostChange (6 new files) pushed 2026-11-11, verified complete at 54 files, head `133b09b7`; Richard also uploaded the updated `terraform-pr.yml` himself ("Updated with GhostChange tooling", `938c7be7`) just before that push, and it matches local exactly. The AccessGraph graph exports (Mermaid + D2: updated `accessgraph.py`, tests, README, example `.mmd` and `.d2`, workflow) are staged locally and not yet pushed.

## Next steps when budget / scale grows
1. **Infracost** (free tier) for real $ estimates on PRs, replacing `cost-check.sh`.
2. **Atlantis or Spacelift** if you want plan/apply *inside* PR comments with locking — still open-source / free tier, but adds a server to run.
3. **Separate AWS accounts** per env (dev/prod) instead of separate roles in one account.
4. **KMS CMK + CloudTrail + GuardDuty** once you hold customer data.
5. **OpenTofu** if HashiCorp licensing matters to you — workflows change by one action name.

## Items to consider in the next version of Terraform pipeline:
- Increase usability to Azure/GCP. The pipeline shape is identical, only the provider + OIDC setup changes.
- Example workload is **S3 only** to stay at $0. Add a VPC/ECS module for a compute example. Build complexity as you learn.
- Prod is **manual dispatch + reviewer approval**; dev auto-applies on merge. Flip so we update prod on merge-with-approval instead.
