# PlanGuard — attested plans, not just reviewed plans

## The interview story (30 seconds)

> "Most Terraform pipelines approve a plan in a PR, then apply a *different*
> plan days later, because code or live state moved in between. I built
> PlanGuard to close that gap: the PR job hashes the canonical plan and
> writes an attestation, and the apply job re-plans and refuses to apply
> unless the hash matches exactly. It also scores the plan — destroys,
> IAM changes, and public exposure need an extra reviewer. It's $0,
> stdlib-only Python, and it fails closed."

## How it works

```
PR job                          Apply job
  terraform plan                  terraform plan (fresh)
       │                                │
  planguard attest                     planguard verify
  → plan_sha256 + risk score           → hash == attested hash?
  → attestation.json                   → NO  → fail, apply nothing
  → uploaded as artifact               → YES → terraform apply
  → hash posted in PR comment
```

## Commands

```bash
# In the PR — after `terraform show -json tfplan > plan.json`
python3 tools/planguard/planguard.py attest \
  --plan plan.json --out attestation.json \
  --commit "$GITHUB_SHA" --pr 12 --actor "$GITHUB_ACTOR" --env dev

# Before apply — after a fresh plan in the apply job
python3 tools/planguard/planguard.py verify \
  --plan fresh-plan.json --attestation attestation.json

# Anytime — just the risk score
python3 tools/planguard/planguard.py score --plan plan.json
python3 tools/planguard/planguard.py score --plan plan.json --format json
```

## Risk scoring (transparent, arguable on purpose)

| Change | Points |
|---|---|
| Create | 2 |
| Update in place | 5 |
| Replace (delete + create) | 30 |
| Destroy | 40 |
| Sensitive type (`aws_iam_*`, `aws_kms_*`, DBs, security groups) | +15 |
| S3 public-access block disabled | +50 |

Bands: **LOW** 0–19, **MEDIUM** 20–49, **HIGH** 50–79, **CRITICAL** 80–100.
HIGH and above require an extra reviewer — enforced in the workflows,
not just suggested in a comment.

## Tests

```bash
cd tools/planguard
python3 -m unittest test_planguard -v
```

No Terraform, AWS, or network needed — the tests use hand-built plans.

## Limits (say these out loud in an interview — it builds trust)

- Attestation, not cryptographic signing (yet). Next step: sign
  `attestation.json` with Sigstore/cosign using the GitHub OIDC
  identity the pipeline already has.
- Values unknown at plan time are excluded from the hash, so a plan
  full of computed values verifies less strictly.
- It proves the *plan* didn't change. It does not prove the *live*
  infrastructure didn't change — that's what nightly drift detection is for.
