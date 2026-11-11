#!/usr/bin/env python3
"""GhostChange — a click-ops drift detector for Jamf / Okta / CrowdStrike.

The problem it solves (and the one it does not)
------------------------------------------------
Terraform manages a declared set of SaaS configuration: Okta sign-on
policies, Jamf disk-encryption profiles, CrowdStrike prevention
policies, and so on. But those consoles are one click away, and when
click-ops is rampant, the live config quietly stops matching what
Terraform thinks it manages. A plan then looks clean while the real
world has already moved.

GhostChange compares a live snapshot (fetched read-only from the
Jamf / Okta / CrowdStrike APIs) against the desired state Terraform
declares, and reports the differences:

* ``unmanaged`` — something exists live that Terraform does not
  declare at all. Somebody made it in a console.
* ``drifted`` — Terraform declares it, but the live settings differ.
  Somebody edited it in a console.
* ``missing`` — Terraform declares it, but it is gone live. Somebody
  deleted it in a console.

Why it is a report, not a blocker
---------------------------------
This is a deliberate choice, argued through with the person who
asked for it: if click-ops is rampant, a tool that blocks PRs on
every drifted setting would block engineering work constantly and
hinder more than it helps. GhostChange's value is visibility — a
complete, honest list of what moved outside Terraform, so the team
can decide whether to adopt it into code or revert it — not a new
gate. So the default exit code is 0 whenever a report is produced,
no matter how much drift it finds. ``--strict`` is opt-in: it exits
1 only when a *critical* finding exists (a drifted, unmanaged or
missing item whose kind is on the small critical list in the
config). The PR workflow deliberately does not use it.

Usage
-----
    python3 ghostchange.py check \
        --live examples/live.json \
        --desired examples/desired.json \
        --config ghostchange.json \
        --out ghost-report.json

    # Opt-in strict mode: fail only on critical drift.
    python3 ghostchange.py check --live ... --desired ... --strict

Exit codes: 0 report generated (drift does not fail the run),
1 only with --strict and a critical finding, 2 input error
(missing or invalid file — no report, nothing passed blind).

Standard library only. No Jamf, Okta, CrowdStrike, Terraform or
network access is needed to run it or its tests.
"""

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

TOOL = "ghostchange"
VERSION = 1


# ---------------------------------------------------------------------------
# Input loading and validation
# ---------------------------------------------------------------------------

def load_json(path: str, what: str) -> dict:
    """Load a JSON file, or exit 2 with a plain error (never a blind pass)."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"GhostChange: ERROR — {what} file not found: {path}", file=sys.stderr)
        raise SystemExit(2)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"GhostChange: ERROR — cannot read {what} file {path}: {exc}", file=sys.stderr)
        raise SystemExit(2)


@dataclass
class Item:
    """One piece of SaaS configuration, live or desired."""
    system: str          # jamf | okta | crowdstrike
    kind: str            # e.g. okta_signon_policy, jamf_disk_encryption_policy
    id: str              # stable id within its system+kind
    name: str
    settings: dict = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.system, self.kind, self.id)


def parse_items(data: dict, what: str) -> list:
    """Validate a snapshot/desired file into Items, or exit 2."""
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        print(f"GhostChange: ERROR — {what} must be an object with an 'items' list",
              file=sys.stderr)
        raise SystemExit(2)
    items = []
    seen = set()
    for raw in data["items"]:
        if not isinstance(raw, dict):
            print(f"GhostChange: ERROR — {what} item is not an object: {raw!r}",
                  file=sys.stderr)
            raise SystemExit(2)
        for field_name in ("system", "kind", "id", "name"):
            if not raw.get(field_name):
                print(f"GhostChange: ERROR — {what} item missing {field_name!r}: {raw!r}",
                      file=sys.stderr)
                raise SystemExit(2)
        if not isinstance(raw.get("settings", {}), dict):
            print(f"GhostChange: ERROR — {what} item settings must be an object: {raw!r}",
                  file=sys.stderr)
            raise SystemExit(2)
        item = Item(raw["system"], raw["kind"], raw["id"], raw["name"],
                    dict(raw.get("settings", {})))
        if item.key() in seen:
            print(f"GhostChange: ERROR — duplicate {what} item: {item.key()}",
                  file=sys.stderr)
            raise SystemExit(2)
        seen.add(item.key())
        items.append(item)
    return items


def parse_config(data: dict) -> dict:
    """Validate the config file: critical kinds and ignored setting keys."""
    if not isinstance(data, dict):
        print("GhostChange: ERROR — config must be a JSON object", file=sys.stderr)
        raise SystemExit(2)
    critical = data.get("critical_kinds", [])
    ignore = data.get("ignore_keys", [])
    if not isinstance(critical, list) or not all(isinstance(k, str) for k in critical):
        print("GhostChange: ERROR — config 'critical_kinds' must be a list of strings",
              file=sys.stderr)
        raise SystemExit(2)
    if not isinstance(ignore, list) or not all(isinstance(k, str) for k in ignore):
        print("GhostChange: ERROR — config 'ignore_keys' must be a list of strings",
              file=sys.stderr)
        raise SystemExit(2)
    return {"critical_kinds": set(critical), "ignore_keys": set(ignore)}


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str            # unmanaged | drifted | missing
    severity: str        # warn | critical
    detail: str


@dataclass
class ItemReport:
    system: str
    kind: str
    id: str
    name: str
    status: str          # ok | drifted | unmanaged | missing
    differences: list = field(default_factory=list)  # [{key, live, desired}]


@dataclass
class Report:
    tool: str = TOOL
    version: int = VERSION
    items: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "live_items": sum(1 for i in self.items if i.status != "missing"),
            "desired_items": sum(1 for i in self.items if i.status != "unmanaged"),
            "ok": sum(1 for i in self.items if i.status == "ok"),
            "drifted": sum(1 for i in self.items if i.status == "drifted"),
            "unmanaged": sum(1 for i in self.items if i.status == "unmanaged"),
            "missing": sum(1 for i in self.items if i.status == "missing"),
            "findings": len(self.findings),
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
        }

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "version": self.version,
            "summary": self.summary(),
            "items": [asdict(i) for i in self.items],
            "findings": [asdict(f) for f in self.findings],
        }


def check(live: list, desired: list, config: dict) -> Report:
    """Compare live config against desired state and report every difference."""
    critical_kinds = config["critical_kinds"]
    ignore_keys = config["ignore_keys"]
    live_by_key = {item.key(): item for item in live}
    desired_by_key = {item.key(): item for item in desired}

    report = Report()

    def severity_for(kind: str) -> str:
        # Only a drift in a kind on the small critical list is
        # critical. Everything else is a warning — including
        # unmanaged items, because click-ops is common and a
        # warning is the honest signal, not a block.
        return "critical" if kind in critical_kinds else "warn"

    # Items that exist live: ok, drifted, or unmanaged.
    for key in sorted(live_by_key):
        item = live_by_key[key]
        wanted = desired_by_key.get(key)
        if wanted is None:
            report.items.append(ItemReport(
                item.system, item.kind, item.id, item.name, "unmanaged"))
            report.findings.append(Finding(
                "unmanaged", severity_for(item.kind),
                f"{item.system} {item.kind} {item.name!r} exists live but "
                f"Terraform does not declare it — made outside Terraform",
            ))
            continue
        diffs = []
        for setting in sorted(set(item.settings) | set(wanted.settings)):
            if setting in ignore_keys:
                continue
            live_val = item.settings.get(setting)
            desired_val = wanted.settings.get(setting)
            if live_val != desired_val:
                diffs.append({"key": setting, "live": live_val, "desired": desired_val})
        if diffs:
            report.items.append(ItemReport(
                item.system, item.kind, item.id, item.name, "drifted", diffs))
            changed = ", ".join(
                f"{d['key']}: live={d['live']!r} desired={d['desired']!r}" for d in diffs)
            report.findings.append(Finding(
                "drifted", severity_for(item.kind),
                f"{item.system} {item.kind} {item.name!r} differs from "
                f"Terraform: {changed}",
            ))
        else:
            report.items.append(ItemReport(
                item.system, item.kind, item.id, item.name, "ok"))

    # Items Terraform declares but live does not have: deleted out of band.
    for key in sorted(desired_by_key):
        if key not in live_by_key:
            item = desired_by_key[key]
            report.items.append(ItemReport(
                item.system, item.kind, item.id, item.name, "missing"))
            report.findings.append(Finding(
                "missing", severity_for(item.kind),
                f"{item.system} {item.kind} {item.name!r} is declared by "
                f"Terraform but missing live — deleted outside Terraform",
            ))

    report.items.sort(key=lambda i: (i.system, i.kind, i.id))
    return report


def print_report(report: Report) -> None:
    s = report.summary()
    print(f"GhostChange: {s['live_items']} live item(s), {s['desired_items']} desired, "
          f"{s['ok']} ok, {s['drifted']} drifted, {s['unmanaged']} unmanaged, "
          f"{s['missing']} missing, {s['critical']} critical finding(s)")
    print()
    for item in report.items:
        mark = {"ok": "  OK  ", "drifted": "DRIFT ", "unmanaged": "GHOST ", "missing": "GONE  "}[item.status]
        print(f"  [{mark}] {item.system} {item.kind}: {item.name}")
        for d in item.differences:
            print(f"         {d['key']}: live={d['live']!r} desired={d['desired']!r}")
    if report.findings:
        print()
        print("Findings:")
        for f in report.findings:
            print(f"  [{f.severity.upper()}] {f.kind}: {f.detail}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_check(args: argparse.Namespace) -> int:
    """Run the drift check: live + desired + config -> report."""
    try:
        live = parse_items(load_json(args.live, "live snapshot"), "live snapshot")
        desired = parse_items(load_json(args.desired, "desired state"), "desired state")
        config = parse_config(load_json(args.config, "config"))
    except SystemExit as exc:
        # load_json/parse_* exit with code 2 for a CLI run; when main()
        # is called in-process (tests, imports), return that code instead.
        return int(exc.code or 2)

    report = check(live, desired, config)
    print_report(report)

    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2) + "\n",
                                  encoding="utf-8")
        print(f"\nGhostChange: report written to {args.out}")

    if args.strict and report.summary()["critical"]:
        print("GhostChange: --strict: critical drift found, failing", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostchange",
        description="Detect SaaS config drift: what changed in Jamf / Okta / "
                    "CrowdStrike outside Terraform. Report-only by design.")
    sub = parser.add_subparsers(dest="command", required=True)
    check_parser = sub.add_parser(
        "check", help="Compare a live snapshot against Terraform's desired state.")
    check_parser.add_argument("--live", required=True,
                              help="Live config snapshot JSON (from the SaaS APIs).")
    check_parser.add_argument("--desired", required=True,
                              help="Desired state JSON (what Terraform declares).")
    check_parser.add_argument("--config", required=True,
                              help="Config JSON: critical_kinds, ignore_keys.")
    check_parser.add_argument("--out", help="Write the JSON report to this file.")
    check_parser.add_argument("--strict", action="store_true",
                              help="Exit 1 if any critical finding exists. "
                                   "Not used by the PR workflow.")
    check_parser.set_defaults(func=cmd_check)
    return parser


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
