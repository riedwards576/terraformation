# AccessGraph — an audit streamliner, not a privilege hunter

## The interview story (30 seconds)

> "Okta is the source of truth for access, and the groups that grant
> third-party access follow a naming convention — so an admin can
> already audit a user by hand, starting from their Okta group
> membership. AccessGraph just does that audit automatically: give
> it an Okta snapshot and the group-to-role mapping, and it produces
> every user's effective access — direct and nested — plus the
> findings an auditor would want, like admins reached only through
> group nesting, admin grants to broad groups, groups that break
> the naming convention, and admin groups with no members left.
> It's a report, not a blocker, because admin access here isn't
> elusive — it's documented. It's $0, stdlib-only Python."

## How it works

```
Okta snapshot                    Group-to-role mapping
  users, groups,                   which Okta group grants
  direct members,                  what role, in which system
  nested groups                           │
       │                                  │
       └──────────────┬───────────────────┘
                      ▼
              effective access per user
              + findings (info / warn)
                      │
              access-report.json
              (artifact + PR comment summary)
```

## Commands

```bash
# From tools/accessgraph/
python3 accessgraph.py audit \
  --snapshot examples/snapshot.json \
  --mapping examples/mapping.json \
  --out access-report.json

# Start an audit from one user, the way an admin would:
python3 accessgraph.py audit --snapshot examples/snapshot.json --mapping examples/mapping.json --user alice

# Opt-in strict mode — exit 1 if any warning finding exists.
# Not used by the PR workflow; see "Why it does not block PRs" below.
python3 accessgraph.py audit --snapshot examples/snapshot.json --mapping examples/mapping.json --strict
```

Exit codes: **0** report generated (warnings do not fail the run),
**1** only with `--strict` and a warning present, **2** error
(missing or invalid input — no report, nothing passed blind).

## What it finds

| Finding | Severity | Meaning |
|---|---|---|
| `admin_grant` | info | A group grants an admin role, to how many people |
| `broad_admin` | warn | An admin grant to a group with ≥ `broad_group_threshold` members (5 in the example) |
| `nested_admin` | warn | A user is an admin only via a nested group — the case a manual audit misses |
| `multi_system_admin` | warn | One user is an admin in 2+ systems |
| `stale_admin_group` | warn | A group still grants admin but has no members |
| `naming_violation` | warn | A group name does not match the naming convention |
| `unmapped_group` | warn | A group with members has no mapping — its access is unknown, not invented |
| `unknown_member`, `unknown_member_group`, `group_cycle` | warn | Data-quality problems in the snapshot; cycles are resolved safely, never looped on |

In the checked-in example (8 users): 6 admin users, 4 admin grants,
11 warnings — including Alice and Bob as Okta Super Admins only via
nesting, a 5-person CrowdStrike admin group, a badly named
`Jamf-Admins` group, an unmapped VPN group, and a legacy admin group
with nobody in it.

## Why it does not block PRs

This was a deliberate choice, argued through with the person who
asked for it: if Okta is the source of truth and the naming
convention is clean, admin access is already traceable by hand.
A tool that blocked PRs on every admin grant would just be a
noisy version of that manual audit. AccessGraph's value is
speed and completeness — the finished map, in seconds, with the
indirect cases included — not a new gate. So the PR workflow runs
it, uploads the report, and posts a summary, and the job passes
regardless of the findings. `--strict` is there if a team ever
wants the gate, but it is opt-in.

## The snapshot and the mapping (read this before wiring it to real systems)

In production, a workflow step fetches a read-only snapshot from
the Okta API and writes `access-snapshot.json`, and the mapping is
generated from the same Terraform code that creates the groups and
the role assignments — so the audit and the code cannot drift apart
silently. This POC ships a checked-in example snapshot and mapping
(`examples/snapshot.json`, `examples/mapping.json`) so the tool can
be run and tested with no accounts, no credentials, and no network.
**Do not ship the example snapshot as live data** — the PR workflow
uses it only as a clearly-labelled demo.

The mapping's naming convention (`^okta-(jamf|okta|crowdstrike)-[a-z0-9-]+$`)
requires the middle token to name the system. Groups like
`okta-legacy-admins` and `okta-vpn-users` therefore count as naming
violations under it, not just `Jamf-Admins` — that is the convention
doing its job, not a bug. Change the regex in the mapping file if
your convention is different; the tool only enforces what the
mapping declares.

## Tests

```bash
cd tools/accessgraph
python3 -m unittest test_accessgraph -v
```

No Okta, Jamf, CrowdStrike, Terraform, or network needed — the tests
use hand-built snapshots and mappings, plus one end-to-end test on
the checked-in examples.

## Limits (say these out loud in an interview — it builds trust)

- It audits what the mapping declares. A group with no mapping is
  reported as unmapped, not guessed at — so the mapping has to be
  kept up to date as groups and roles change.
- It trusts the snapshot. If the snapshot is stale, the audit is
  stale. A missing or invalid snapshot is an error (exit 2), not
  a clean report.
- It does not enforce anything. It will not stop an admin grant
  from being created — that is CoverageGuard's job for coverage,
  and PlanGuard's job for plan integrity. AccessGraph's job is to
  make the audit fast and complete.
