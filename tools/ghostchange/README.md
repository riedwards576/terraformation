# GhostChange — what moved outside Terraform

## The interview story (30 seconds)

> "Terraform declares the SaaS config — Okta sign-on policies, Jamf
> disk-encryption profiles, CrowdStrike prevention policies. But
> those consoles are one click away, and when click-ops is rampant
> the live config quietly stops matching what Terraform thinks it
> manages. GhostChange compares a live snapshot against what
> Terraform declares and lists what moved: things created in a
> console, things edited in a console, things deleted in a console.
> It's a report, not a blocker — if it blocked PRs on every drifted
> setting, it would block engineering work constantly. Its value is
> visibility: the team sees the drift and decides whether to adopt
> it into code or revert it. It's $0, stdlib-only Python."

## How it works

```
Live snapshot (Jamf / Okta / CrowdStrike APIs)
  vs
Desired state (what Terraform declares)
  vs
Config (critical_kinds, ignore_keys)
              │
              ▼
    ghost-report.json
    ok / drifted / unmanaged / missing
    + findings (warn / critical)
```

## Commands

```bash
# From tools/ghostchange/
python3 ghostchange.py check \
  --live examples/live.json \
  --desired examples/desired.json \
  --config ghostchange.json \
  --out ghost-report.json

# Opt-in strict mode — exit 1 only when a *critical* finding exists.
# Not used by the PR workflow; see "Why it does not block PRs" below.
python3 ghostchange.py check --live examples/live.json --desired examples/desired.json --config ghostchange.json --strict
```

Exit codes: **0** report generated (drift does not fail the run),
**1** only with `--strict` and a critical finding, **2** error
(missing or invalid input — no report, nothing passed blind).

## What it finds

| Finding | Severity | Meaning |
|---|---|---|
| `unmanaged` | warn (critical if the kind is critical) | Exists live, Terraform never declared it — made in a console |
| `drifted` | warn (critical if the kind is critical) | Declared, but live settings differ — edited in a console |
| `missing` | warn (critical if the kind is critical) | Declared, but gone live — deleted in a console |

Severity comes from the config's `critical_kinds` — a small list
of kinds where drift matters enough to be called critical
(`crowdstrike_prevention_policy`, `jamf_disk_encryption_policy`,
`okta_signon_policy` in the checked-in config). Everything else is
a warning, because click-ops is common and a warning is the honest
signal. `ignore_keys` lists setting keys that are metadata, not
config — `last_modified` and `version` — so an API read that
touches nothing real never raises a finding.

In the checked-in example (5 live, 5 desired): 3 ok, 1 drifted
(uninstall protection turned off in the CrowdStrike console —
critical), 1 unmanaged (a Jamf profile created in the console),
1 missing (the standard sensor policy deleted out of band).

## Why it does not block PRs

This was a deliberate choice, argued through with the person who
asked for it: if click-ops is rampant, a gate on drift would block
engineering work constantly and hinder more than it helps. The
team's response to drift is a decision — adopt it into Terraform
or revert it — and a report supports that decision while a block
just stops work. So the PR workflow runs the check, uploads the
report, and posts a summary, and the job passes regardless of the
findings. `--strict` is there if a team ever wants the gate, but
only on critical drift, and it is opt-in.

## The live snapshot and the desired state (read this before wiring it to real systems)

In production, a workflow step fetches a read-only live snapshot
from the Jamf / Okta / CrowdStrike APIs and writes
`live-snapshot.json`, and the desired state is generated from the
same Terraform code that manages the config — so the check and the
code cannot drift apart silently. This POC ships checked-in example
live and desired files (`examples/live.json`,
`examples/desired.json`) so the tool can be run and tested with no
accounts, no credentials, and no network. **Do not ship the example
snapshot as live data** — the PR workflow uses it only as a
clearly-labelled demo.

## Tests

```bash
cd tools/ghostchange
python3 -m unittest test_ghostchange -v
```

No Jamf, Okta, CrowdStrike, Terraform, or network needed — the
tests use hand-built live/desired snapshots, plus one end-to-end
test on the checked-in examples.

## Limits (say these out loud in an interview — it builds trust)

- It compares settings by value. It cannot tell *who* made a
  console change or *why* — only that live and desired differ.
  The audit trail lives in the SaaS consoles, not in this report.
- It trusts both inputs. If the live snapshot is stale, the
  report is stale; if the desired state does not match what
  Terraform actually manages, the comparison is wrong. A missing
  or invalid input is an error (exit 2), not a clean report.
- It does not fix anything. It will not adopt drift into
  Terraform or revert it — that decision is the team's, and this
  tool's job is to make the drift visible enough to decide on.
- It does not enforce anything. Stopping a bad change from
  landing is CoverageGuard's job (coverage floors) and PlanGuard's
  job (plan integrity). GhostChange's job is to show what already
  moved outside Terraform.
