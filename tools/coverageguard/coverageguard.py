#!/usr/bin/env python3
"""CoverageGuard — a security coverage floor for Terraform PRs.

The problem it solves
----------------------
Most pipeline checks judge the *process*: did the plan pass lint, did
a scanner flag a resource, did someone change a file in the UI?
CoverageGuard judges the *end state* instead. It asks one question:

    After this plan is applied, will fewer devices / users be
    protected than the floor we promised?

If the answer is yes, the PR fails. If the answer is no — even if
the change was made in code, in the UI, or by hand — it passes.
That is the whole point, and it is why this tool only ever blocks
work that would make the end state worse. It never blocks work
for how it was done.

What it checks (three systems, six dimensions)
----------------------------------------------
Percentages — the share of the fleet / population that is covered.
A PR fails if the *post-apply* coverage drops below the floor:

    crowdstrike_sensor_coverage   sensor hosts / total hosts
    jamf_managed_coverage         managed devices / total devices
    okta_mfa_coverage             MFA-enrolled users / total users

Hard protections — things that must stay on, whatever the
percentage says. A PR fails if the plan turns one off, or deletes
the resource that provides it:

    crowdstrike_uninstall_protection_enabled
    jamf_filevault_enforced
    okta_mfa_required

How it knows the post-apply state
----------------------------------
Two inputs, both plain JSON:

1. A *snapshot* of live coverage right now — total hosts/devices/
   users, how many are covered, and whether each hard protection
   is on. In production this is fetched (read-only) from the
   CrowdStrike, Jamf, and Okta APIs by a workflow step before
   CoverageGuard runs. This POC ships a checked-in example
   snapshot in ``examples/snapshot.json`` so the tool can be
   run and tested with no accounts, no credentials, and no
   network. Do not ship the example snapshot as live data.

2. A Terraform plan (``terraform show -json`` output). The plan
   is applied *as deltas* to the snapshot — see ``apply_plan``
   for the exact rules — and the result is compared to the floor.

The delta rules (readable on purpose)
--------------------------------------
* Creating a covered unit (a CrowdStrike sensor, a Jamf-managed
  device, an Okta MFA factor) adds 1 to the numerator *and* the
  denominator of its dimension.
* Creating an in-scope but uncovered unit (a host with no sensor,
  a device that is not enrolled, a user with no MFA yet) adds 1
  to the denominator only — so coverage falls, which is exactly
  what a reviewer needs to see.
* Deleting a covered unit removes 1 from both; deleting an
  uncovered unit removes 1 from the denominator only.
* Replacing a unit (delete + create) is net zero for coverage.
* Updating a protection policy sets that protection to the
  planned ``after`` value. Deleting the policy resource removes
  the protection entirely.
* Any resource type not in the tables below is ignored. The tool
  only judges what it can see; it never invents a coverage
  effect for a resource it does not understand.

Resource types are the POC's mapping, not a claim about any
provider's real schema. When you wire a real Jamf / Okta /
CrowdStrike provider, change the type names in the tables below
to that provider's types — the engine only cares about the
effect a type is declared to have, not what it is called.

Exit codes
----------
0  PASS — every dimension is at or above its floor, and every
   hard protection stays on. Warnings (coverage fell but stayed
   above the floor) do not fail the run; they are reported.
1  FAIL — at least one dimension is below its floor, or a hard
   protection is turned off / deleted.
2  ERROR — bad input (missing file, invalid JSON, a snapshot
   where covered > total, a negative count). No verdict is given
   and nothing is passed blind. A missing snapshot is an error,
   not a pass: passing without measuring would be worse.

Usage
-----
    python3 coverageguard.py check \\
        --snapshot examples/snapshot.json \\
        --plan examples/plan-fail-coverage.json \\
        --config coverageguard.json \\
        --out coverage-report.json

    python3 coverageguard.py check --snapshot snap.json --plan plan.json
    # --config defaults to coverageguard.json next to this file.
    # --out is optional; without it the report is printed, not saved.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- Floors and protections -------------------------------------------
# Default floors (percent). Overridden by the config file, which is
# the place to argue about the numbers — not this code.
DEFAULT_FLOORS = {
    "crowdstrike_sensor_coverage": 95.0,
    "jamf_managed_coverage": 95.0,
    "okta_mfa_coverage": 95.0,
}

# Hard protections: these are booleans, not percentages. They must
# stay True. There is no "close enough" for uninstall protection.
HARD_PROTECTIONS = (
    "crowdstrike_uninstall_protection_enabled",
    "jamf_filevault_enforced",
    "okta_mfa_required",
)

# --- How a snapshot is organised --------------------------------------
# snapshot = {
#   "crowdstrike": {"total_hosts": 200, "sensor_hosts": 196,
#                   "uninstall_protection_enabled": True},
#   "jamf":        {"total_devices": 180, "managed_devices": 176,
#                   "filevault_enforced": True},
#   "okta":        {"total_users": 150, "mfa_users": 147,
#                   "mfa_required": True},
# }
# Each percentage dimension is (numerator field, denominator field)
# inside one system block.
DIMENSIONS = {
    "crowdstrike_sensor_coverage": ("crowdstrike", "sensor_hosts", "total_hosts"),
    "jamf_managed_coverage": ("jamf", "managed_devices", "total_devices"),
    "okta_mfa_coverage": ("okta", "mfa_users", "total_users"),
}

# Which system block a hard protection lives in.
PROTECTION_SYSTEM = {
    "crowdstrike_uninstall_protection_enabled": "crowdstrike",
    "jamf_filevault_enforced": "jamf",
    "okta_mfa_required": "okta",
}

# --- Plan -> delta mapping --------------------------------------------
# Covered units: create adds 1 to numerator + denominator,
# delete removes 1 from both. (Replace = delete + create = net 0.)
COVERED_TYPES = {
    "crowdstrike_sensor": "crowdstrike",
    "jamf_managed_device": "jamf",
    "okta_mfa_factor": "okta",
}

# In-scope but uncovered units: create adds 1 to the denominator
# only, delete removes 1 from the denominator only.
UNCOVERED_TYPES = {
    "crowdstrike_host": "crowdstrike",
    "jamf_device": "jamf",
    "okta_user": "okta",
}

# Protection policies: (system, protection name, attribute names
# to look for in the planned "after" values, first hit wins).
# Different providers spell the same setting differently, so
# several spellings are accepted rather than guessing.
PROTECTION_TYPES = {
    "crowdstrike_prevention_policy": (
        "crowdstrike",
        "crowdstrike_uninstall_protection_enabled",
        ("uninstall_protection", "uninstall_protection_enabled", "enabled"),
    ),
    "jamf_disk_encryption_policy": (
        "jamf",
        "jamf_filevault_enforced",
        ("filevault_enforced", "disk_encryption_enforced", "enabled"),
    ),
    "okta_signon_policy": (
        "okta",
        "okta_mfa_required",
        ("mfa_required", "require_mfa", "enabled"),
    ),
}


@dataclass
class DimensionResult:
    """One dimension, before and after the plan, against its floor."""

    name: str
    kind: str  # "percentage" or "protection"
    before: float | bool | None
    after: float | bool | None
    floor: float | bool | None
    status: str  # "PASS", "WARN", or "FAIL"
    detail: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "before": self.before,
            "after": self.after,
            "floor": self.floor,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass
class CoverageReport:
    """The whole verdict for one plan against one snapshot."""

    overall: str  # "PASS" or "FAIL"
    dimensions: list[DimensionResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": "coverageguard",
            "version": 1,
            "overall": self.overall,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }


def _percent(numerator: int, denominator: int) -> float | None:
    """Coverage as a percentage, or None if nothing is in scope."""
    if denominator == 0:
        return None  # No units in scope: nothing to guard, nothing to fail.
    return round(100.0 * numerator / denominator, 1)


def validate_snapshot(snapshot: dict) -> list[str]:
    """Check a snapshot is sane. Returns a list of errors (empty = OK)."""
    errors: list[str] = []
    for system, block in snapshot.items():
        if not isinstance(block, dict):
            errors.append(f"snapshot[{system!r}] is not an object")
            continue
        for key, value in block.items():
            if isinstance(value, bool):
                continue
            if not isinstance(value, int) or value < 0:
                errors.append(f"snapshot[{system}][{key!r}] must be a non-negative integer, got {value!r}")
    for _name, (system, num_field, den_field) in DIMENSIONS.items():
        block = snapshot.get(system, {})
        if num_field in block and den_field in block:
            if block[num_field] > block[den_field]:
                errors.append(
                    f"snapshot[{system}]: {num_field} ({block[num_field]}) "
                    f"cannot exceed {den_field} ({block[den_field]})"
                )
    return errors


def apply_plan(snapshot: dict, plan: dict) -> dict:
    """Return a copy of the snapshot with the plan's deltas applied.

    Only the resource types in COVERED_TYPES, UNCOVERED_TYPES, and
    PROTECTION_TYPES have an effect. Everything else is ignored —
    a plan that only touches S3 buckets, for example, leaves every
    coverage number exactly where it was, which is the correct
    answer for that plan.
    """
    # Deep-copy the counts (one level is enough: system -> fields).
    projected = {system: dict(block) for system, block in snapshot.items()}

    for change in plan.get("resource_changes", []) or []:
        resource_type = change.get("type", "")
        actions = change.get("change", {}).get("actions", [])
        after = change.get("change", {}).get("after") or {}
        address = change.get("address", "?")

        # A replace is a delete followed by a create of the same
        # thing, so for coverage it cancels out. Handle it once,
        # here, instead of double-counting it below.
        if set(actions) == {"create", "delete"}:
            continue

        if resource_type in COVERED_TYPES:
            system = COVERED_TYPES[resource_type]
            _name, num_field, den_field = next(
                (n, num, den) for n, (s, num, den) in DIMENSIONS.items() if s == system
            )
            delta = 1 if actions == ["create"] else -1 if actions == ["delete"] else 0
            if delta:
                projected[system][num_field] = projected[system].get(num_field, 0) + delta
                projected[system][den_field] = projected[system].get(den_field, 0) + delta
            continue

        if resource_type in UNCOVERED_TYPES:
            system = UNCOVERED_TYPES[resource_type]
            _name, _num, den_field = next(
                (n, num, den) for n, (s, num, den) in DIMENSIONS.items() if s == system
            )
            delta = 1 if actions == ["create"] else -1 if actions == ["delete"] else 0
            if delta:
                projected[system][den_field] = projected[system].get(den_field, 0) + delta
            continue

        if resource_type in PROTECTION_TYPES:
            system, protection, attr_names = PROTECTION_TYPES[resource_type]
            if actions == ["delete"]:
                # The policy is gone, so the protection it provided is gone.
                projected[system][protection] = False
            elif actions in (["create"], ["update"]):
                for attr in attr_names:
                    if attr in after:
                        projected[system][protection] = bool(after[attr])
                        break
                # No recognised attribute in "after": do not guess.
                # The protection keeps its snapshot value.
            continue

        # Unknown type: ignored on purpose (see module docstring).
        _ = address

    # Clamp at zero: a plan cannot delete more units than exist.
    # If it tries, the counts bottom out at 0 and the percentage
    # check still judges the result honestly.
    for block in projected.values():
        for key, value in block.items():
            if isinstance(value, int) and not isinstance(value, bool):
                block[key] = max(0, value)
    return projected


def check_coverage(snapshot: dict, plan: dict, floors: dict) -> CoverageReport:
    """Compare before/after coverage against the floors. Pure logic."""
    projected = apply_plan(snapshot, plan)
    results: list[DimensionResult] = []

    for name, (system, num_field, den_field) in DIMENSIONS.items():
        before = _percent(snapshot[system][num_field], snapshot[system][den_field])
        after = _percent(projected[system][num_field], projected[system][den_field])
        floor = float(floors[name])
        if after is None:
            status, detail = "PASS", "no units in scope after this plan"
        elif after < floor:
            status = "FAIL"
            detail = f"would drop to {after}% (floor {floor}%)"
        elif before is not None and after < before:
            status = "WARN"
            detail = f"would fall {before}% -> {after}%, still above floor {floor}%"
        else:
            status, detail = "PASS", f"{after}% (floor {floor}%)"
        results.append(DimensionResult(name, "percentage", before, after, floor, status, detail))

    for protection in HARD_PROTECTIONS:
        system = PROTECTION_SYSTEM[protection]
        before = bool(snapshot[system].get(protection, True))
        after = bool(projected[system].get(protection, True))
        if after is True:
            status, detail = "PASS", "stays enabled"
        else:
            status = "FAIL"
            detail = "would be turned off or deleted" if before else "stays off"
        results.append(DimensionResult(protection, "protection", before, after, True, status, detail))

    overall = "FAIL" if any(r.status == "FAIL" for r in results) else "PASS"
    return CoverageReport(overall=overall, dimensions=results)


def load_json(path: Path, what: str) -> dict:
    """Load a JSON file, failing with exit 2 and a clear message if bad."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"CoverageGuard: ERROR — {what} file not found: {path}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"CoverageGuard: ERROR — {what} is not valid JSON ({path}): {exc}", file=sys.stderr)
        raise SystemExit(2)


def load_config(path: Path | None) -> dict:
    """Load floors from a config file, or use the defaults."""
    if path is None:
        return dict(DEFAULT_FLOORS)
    config = load_json(path, "config")
    floors = dict(DEFAULT_FLOORS)
    floors.update({k: float(v) for k, v in (config.get("floors") or {}).items()})
    return floors


def print_report(report: CoverageReport) -> None:
    """Human-readable summary, suitable for a PR comment."""
    print(f"CoverageGuard: {report.overall}")
    for dim in report.dimensions:
        if dim.kind == "percentage":
            before = f"{dim.before}%" if dim.before is not None else "n/a"
            after = f"{dim.after}%" if dim.after is not None else "n/a"
            print(f"  [{dim.status:4}] {dim.name}: {before} -> {after} — {dim.detail}")
        else:
            print(f"  [{dim.status:4}] {dim.name}: {dim.before} -> {dim.after} — {dim.detail}")
    if report.overall == "FAIL":
        print("  Do not merge. Change the plan so the end state stays above the floor,")
        print("  or change the floor in coverageguard.json and get that change reviewed.")


def cmd_check(args: argparse.Namespace) -> int:
    """Run the check: snapshot + plan -> verdict (0 pass, 1 fail, 2 error)."""
    snapshot = load_json(args.snapshot, "snapshot")
    plan = load_json(args.plan, "plan")
    floors = load_config(args.config)

    errors = validate_snapshot(snapshot)
    if errors:
        for error in errors:
            print(f"CoverageGuard: ERROR — {error}", file=sys.stderr)
        return 2

    report = check_coverage(snapshot, plan, floors)
    print_report(report)
    if args.out:
        args.out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"CoverageGuard: report written to {args.out}")
    return 0 if report.overall == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coverageguard",
        description="Fail a PR only if its end state drops below a security coverage floor.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Check a plan against a live coverage snapshot")
    check.add_argument("--snapshot", type=Path, required=True, help="Live coverage snapshot JSON")
    check.add_argument("--plan", type=Path, required=True, help="terraform show -json output")
    check.add_argument("--config", type=Path, default=None, help="Floors config JSON (default: built-in 95%% floors)")
    check.add_argument("--out", type=Path, default=None, help="Write the report JSON here")
    check.set_defaults(func=cmd_check)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
