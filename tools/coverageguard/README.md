# CoverageGuard — a security coverage floor, not a process check

## The interview story (30 seconds)

> "Most pipeline checks judge the *process* — did it pass lint, did a
> scanner flag a resource. CoverageGuard judges the *end state*: after
> this plan is applied, will fewer devices or users be protected than
> the floor we promised? It takes a live snapshot of CrowdStrike,
> Jamf, and Okta coverage, applies the Terraform plan to it as deltas,
> and fails the PR if any dimension drops below its floor — 95% by
> default — or if a hard protection like uninstall protection, FileVault
> enforcement, or MFA-required gets turned off. It only ever blocks work
> that would make the end state worse."

## How it works

```
Live snapshot (CrowdStrike / Jamf / Okta)     Terraform plan
  total hosts, sensor hosts, …                     │
  total devices, managed devices, …                ▼
  total users, MFA users, …               plan deltas applied
       │                                  to the snapshot
       └──────────────┬───────────────────┘
                      ▼
              post-apply coverage
                      │
              below a floor, or a
              hard protection off?
                 YES → FAIL (exit 1, PR blocked)
                 NO  → PASS (exit 0)
```

## Commands

```bash
# From tools/coverageguard/
python3 coverageguard.py check \
  --snapshot examples/snapshot.json \
  --plan examples/plan-pass.json \
  --config coverageguard.json \
  --out coverage-report.json

# The three examples: one passes, two fail for different reasons
python3 coverageguard.py check --snapshot examples/snapshot.json --plan examples/plan-pass.json
python3 coverageguard.py check --snapshot examples/snapshot.json --plan examples/plan-fail-coverage.json
python3 coverageguard.py check --snapshot examples/snapshot.json --plan examples/plan-fail-protection.json
```

Exit codes: **0** pass, **1** fail (below floor / protection off),
**2** error (missing or invalid input — no verdict, nothing passed blind).

## What it checks

| Dimension | Floor / rule |
|---|---|
| CrowdStrike sensor coverage | ≥ 95% of hosts |
| Jamf managed-device coverage | ≥ 95% of devices |
| Okta MFA coverage | ≥ 95% of users |
| CrowdStrike uninstall protection | must stay enabled |
| Jamf FileVault enforcement | must stay enabled |
| Okta MFA required | must stay enabled |

A small drop that stays above the floor is a **WARN**, not a fail —
the reviewer sees it in the report, but it does not block the PR.
Exactly at the floor passes; below it fails.

Floors live in `coverageguard.json`. To change one, change that file
and get *that* change reviewed — do not silently lower a floor in a
PR that also drops coverage.

## The snapshot (read this before wiring it to real systems)

In production, a workflow step fetches a read-only snapshot from the
CrowdStrike, Jamf, and Okta APIs and writes `coverage-snapshot.json`,
then CoverageGuard runs against that file. This POC ships a checked-in
example snapshot (`examples/snapshot.json`: 200 hosts / 196 with
sensors, 180 devices / 176 managed, 150 users / 147 with MFA) so the
tool can be run and tested with no accounts, no credentials, and no
network. **Do not ship the example snapshot as live data** — the PR
workflow uses it only as a clearly-labelled demo, and the step that
does so says so in a comment.

The resource-type mapping in `coverageguard.py` (`COVERED_TYPES`,
`UNCOVERED_TYPES`, `PROTECTION_TYPES`) is the POC's mapping. When you
wire a real provider, change the type names to that provider's types;
the engine only cares about the effect a type is declared to have.

## Tests

```bash
cd tools/coverageguard
python3 -m unittest test_coverageguard -v
```

No Terraform, CrowdStrike, Jamf, Okta, or network needed — the tests
use hand-built snapshots and plans.

## Limits (say these out loud in an interview — it builds trust)

- It judges the coverage it can see. A plan that changes coverage
  through a resource type not in its mapping tables is ignored, not
  guessed at — so the mapping has to be kept up to date as new
  providers are added.
- It trusts the snapshot. If the snapshot is stale or wrong, the
  verdict is stale or wrong. That is why a missing or invalid
  snapshot is an error (exit 2), not a pass.
- It does not detect click-ops drift on its own. If someone changes
  a policy in the UI, CoverageGuard only sees it at the next snapshot
  fetch — that is a different tool's job (see the GhostChange idea),
  and deliberately not this one's.
