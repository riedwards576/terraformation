#!/usr/bin/env python3
"""AccessGraph — an audit streamliner for Okta-centred access.

The problem it solves (and the one it does not)
------------------------------------------------
Okta is the source of truth for access in this setup, and there is
an established naming convention for the Okta groups that grant
access to third-party systems (Jamf, CrowdStrike, Okta itself).
An admin *can* already audit a user by hand: look at their Okta
group membership, then investigate each group on each system.

That works. It is just slow, and it misses the indirect cases:
a user who is an admin only because their group is nested inside
another group, a group whose name does not follow the convention
so it is never checked, a group that still grants admin even
though nobody is in it any more. AccessGraph does that manual
audit automatically and produces one report:

    user ──▶ Okta groups (direct and nested)
         ──▶ what each group grants, in which system, at which role
         ──▶ findings an auditor would want to see

It is a *report*, not a blocker, and that is deliberate. Admin
access is not elusive here — it is documented in Okta — so this
tool does not pretend to discover hidden privilege. It ties group
membership to third-party access and role, and hands the auditor
the finished map. By default it never fails a run: exit 0 means
"report generated", even if the report contains warnings.
``--strict`` exists for teams that want the opposite — fail if
any warning finding exists — but it is opt-in, and the PR
workflow does *not* use it.

Inputs (both plain JSON)
------------------------
1. A *snapshot* of Okta as it is right now — users, groups, direct
   members, and nested groups (``member_groups``). In production
   this is fetched (read-only) from the Okta API by a workflow
   step before AccessGraph runs. This POC ships a checked-in
   example snapshot in ``examples/snapshot.json`` so the tool can
   be run and tested with no accounts, no credentials, and no
   network. Do not ship the example snapshot as live data.

2. A *mapping* — which Okta group grants what, in which system:
   ``examples/mapping.json``. The mapping also carries the naming
   convention (a regex) and the broad-group threshold. When you
   wire a real provider, the mapping is what you maintain: it is
   the declared link between an Okta group and a third-party role,
   and in a Terraform-managed setup it should be generated from
   the same code that creates the groups and the role assignments,
   so the audit and the code cannot drift apart silently.

What it finds
-------------
* ``admin_grant`` (info) — a group grants an admin role, and to
  how many people. Expected for some groups; listed so the audit
  can see every admin grant in one place.
* ``broad_admin`` (warn) — an admin grant to a group with at
  least ``broad_group_threshold`` members. Admin to a crowd is
  worth a second look.
* ``nested_admin`` (warn) — a user is an admin *only* because a
  group they are in is nested inside an admin-granting group.
  This is the case a manual audit most often misses.
* ``multi_system_admin`` (warn) — one user is an admin in two or
  more systems (Jamf + CrowdStrike + Okta, say).
* ``stale_admin_group`` (warn) — a group that still grants admin
  but has no members at all. It should probably be deleted.
* ``naming_violation`` (warn) — a group whose name does not match
  the naming convention, so it may never have been audited.
* ``unmapped_group`` (warn) — a group with members that has no
  mapping entry, so its third-party access is unknown.
* ``unknown_member`` / ``unknown_member_group`` / ``group_cycle``
  (warn) — data-quality problems in the snapshot itself: a member
  id or a nested group that does not exist, or groups nested in
  a cycle. Cycles are resolved safely (each group is visited
  once); they are reported, not looped on.

Exit codes
----------
0  Report generated. Warnings do not fail the run.
1  Only with ``--strict``: at least one warning finding exists.
2  ERROR — bad input (missing file, invalid JSON, duplicate user
   or group ids, an uncompilable naming regex). No report is
   produced and nothing is passed blind.

Usage
-----
    python3 accessgraph.py audit \\
        --snapshot examples/snapshot.json \\
        --mapping examples/mapping.json \\
        --out access-report.json

    # Start an audit from one user, the way an admin would:
    python3 accessgraph.py audit --snapshot snap.json --mapping map.json --user alice

    # Opt-in strict mode (not used by the PR workflow):
    python3 accessgraph.py audit --snapshot snap.json --mapping map.json --strict

Graph export
------------
The audit above is text and JSON — no picture. The ``graph``
subcommand renders the same audit as a Mermaid flowchart, which
GitHub renders natively in markdown and in PR comments:

    user ──▶ Okta group ──▶ system: role

Solid edges are direct membership; dotted edges are membership
only via nesting (the case a manual audit misses). Admin roles
are highlighted pink. One node per user, group, and role, so a
shared group or role is drawn once, not once per user.

    python3 accessgraph.py graph \\
        --snapshot examples/snapshot.json \\
        --mapping examples/mapping.json \\
        --out access-graph.mmd

    # One user's subgraph, the way an admin would start an audit:
    python3 accessgraph.py graph --snapshot snap.json --mapping map.json --user alice

D2 export
---------
The Mermaid graph is for reviewers in a PR comment. An auditor
gets files from IT/Sec, not PR comments — so the ``d2`` subcommand
renders the same audit as a D2 diagram, which the workflow
compiles to a styled SVG with the open-source D2 CLI and uploads
as an artifact, alongside the ``.d2`` source:

    python3 accessgraph.py d2 \\
        --snapshot examples/snapshot.json \\
        --mapping examples/mapping.json \\
        --out access-graph.d2
    d2 access-graph.d2 access-graph.svg   # needs the D2 CLI (v0.9.0)

    # One user's subgraph:
    python3 accessgraph.py d2 --snapshot snap.json --mapping map.json --user alice
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_BROAD_GROUP_THRESHOLD = 5


@dataclass
class Finding:
    """One thing an auditor should look at, with its severity."""

    kind: str
    severity: str  # "info" or "warn"
    detail: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "severity": self.severity, "detail": self.detail}


@dataclass
class Grant:
    """One effective access: a role in a system, and how it was reached."""

    system: str
    role: str
    admin: bool
    via_groups: list[str] = field(default_factory=list)
    direct: bool = False

    def to_dict(self) -> dict:
        return {
            "system": self.system,
            "role": self.role,
            "admin": self.admin,
            "via_groups": sorted(self.via_groups),
            "direct": self.direct,
        }


@dataclass
class UserAccess:
    """One user's whole effective access, as the audit would show it."""

    user_id: str
    name: str
    email: str
    groups: list[str]  # Direct Okta groups, sorted.
    effective_groups: list[str]  # Direct + nested, sorted.
    access: list[Grant] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.user_id,
            "name": self.name,
            "email": self.email,
            "groups": sorted(self.groups),
            "effective_groups": sorted(self.effective_groups),
            "access": [g.to_dict() for g in sorted(self.access, key=lambda x: (x.system, x.role))],
        }


@dataclass
class AuditReport:
    """The whole audit: every user, every finding, and the counts."""

    overall: str  # "OK" or "STRICT_FAIL"
    users: list[UserAccess] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def summary(self) -> dict:
        admin_grants = sum(1 for f in self.findings if f.kind == "admin_grant")
        warnings = sum(1 for f in self.findings if f.severity == "warn")
        admin_users = sum(
            1 for u in self.users if any(g.admin for g in u.access)
        )
        return {
            "users": len(self.users),
            "admin_users": admin_users,
            "admin_grants": admin_grants,
            "warnings": warnings,
            "findings": len(self.findings),
        }

    def to_dict(self) -> dict:
        return {
            "tool": "accessgraph",
            "version": 1,
            "overall": self.overall,
            "summary": self.summary(),
            "users": [u.to_dict() for u in self.users],
            "findings": [f.to_dict() for f in self.findings],
        }


def load_json(path: Path, what: str) -> dict:
    """Load a JSON file, failing with exit 2 and a clear message if bad."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"AccessGraph: ERROR — {what} file not found: {path}", file=sys.stderr)
        raise SystemExit(2)
    except json.JSONDecodeError as exc:
        print(f"AccessGraph: ERROR — {what} is not valid JSON ({path}): {exc}", file=sys.stderr)
        raise SystemExit(2)


def validate_snapshot(snapshot: dict) -> list[str]:
    """Check a snapshot is sane. Returns a list of errors (empty = OK)."""
    errors: list[str] = []
    users = snapshot.get("users")
    groups = snapshot.get("groups")
    if not isinstance(users, list):
        errors.append("snapshot['users'] must be a list")
    if not isinstance(groups, list):
        errors.append("snapshot['groups'] must be a list")
    if errors:
        return errors
    user_ids = [u.get("id") for u in users if isinstance(u, dict)]
    if len(user_ids) != len(set(user_ids)):
        errors.append("snapshot has duplicate user ids")
    group_names = [g.get("name") for g in groups if isinstance(g, dict)]
    if len(group_names) != len(set(group_names)):
        errors.append("snapshot has duplicate group names")
    for user in users:
        if not isinstance(user, dict) or not user.get("id"):
            errors.append(f"snapshot user without an id: {user!r}")
    for group in groups:
        if not isinstance(group, dict) or not group.get("name"):
            errors.append(f"snapshot group without a name: {group!r}")
    return errors


def find_cycles(groups_by_name: dict) -> list[list[str]]:
    """Find nesting cycles (A includes B includes A). Each is a list of names."""
    cycles: list[list[str]] = []
    state: dict[str, str] = {}  # "visiting" or "done"

    def visit(name: str, stack: list[str]) -> None:
        state[name] = "visiting"
        for child in groups_by_name.get(name, {}).get("member_groups", []) or []:
            if child not in groups_by_name:
                continue
            if state.get(child) == "visiting":
                # The cycle is the part of the stack from the child onwards.
                cycles.append(stack[stack.index(child):] + [child])
            elif state.get(child) != "done":
                visit(child, stack + [child])
        state[name] = "done"

    for name in groups_by_name:
        if state.get(name) != "done":
            visit(name, [name])
    return cycles


def resolve_members(groups_by_name: dict, group_name: str) -> set[str]:
    """All user ids in a group, directly or through nested groups.

    Cycle-safe: each group is visited once, so A-in-B-in-A cannot
    loop forever. A cycle is reported separately by find_cycles().
    """
    seen_groups: set[str] = set()
    members: set[str] = set()
    stack = [group_name]
    while stack:
        name = stack.pop()
        if name in seen_groups or name not in groups_by_name:
            continue
        seen_groups.add(name)
        group = groups_by_name[name]
        members.update(group.get("members", []) or [])
        stack.extend(group.get("member_groups", []) or [])
    return members


def audit(snapshot: dict, mapping: dict) -> AuditReport:
    """Build the audit report. Pure logic — no files, no network."""
    users = {u["id"]: u for u in snapshot.get("users", [])}
    groups_by_name = {g["name"]: g for g in snapshot.get("groups", [])}
    mappings = mapping.get("mappings", {}) or {}
    naming_re = mapping.get("naming_convention")
    pattern = re.compile(naming_re) if naming_re else None
    threshold = int(mapping.get("broad_group_threshold", DEFAULT_BROAD_GROUP_THRESHOLD))

    findings: list[Finding] = []

    # --- Data-quality findings first: they explain odd results below.
    for group in groups_by_name.values():
        for member_id in group.get("members", []) or []:
            if member_id not in users:
                findings.append(Finding(
                    "unknown_member", "warn",
                    f"group {group['name']!r} lists unknown user id {member_id!r}",
                ))
        for child in group.get("member_groups", []) or []:
            if child not in groups_by_name:
                findings.append(Finding(
                    "unknown_member_group", "warn",
                    f"group {group['name']!r} nests unknown group {child!r}",
                ))
    for cycle in find_cycles(groups_by_name):
        findings.append(Finding(
            "group_cycle", "warn",
            "group nesting cycle: " + " -> ".join(cycle),
        ))

    # --- Group-level findings: naming, mapping, admin grants, staleness.
    all_members: dict[str, set[str]] = {
        name: resolve_members(groups_by_name, name) for name in groups_by_name
    }
    for name, group in groups_by_name.items():
        members = all_members[name]
        if pattern and not pattern.match(name):
            findings.append(Finding(
                "naming_violation", "warn",
                f"group {name!r} does not match naming convention {naming_re!r}",
            ))
        if members and name not in mappings:
            findings.append(Finding(
                "unmapped_group", "warn",
                f"group {name!r} has {len(members)} member(s) but no mapping — "
                "its third-party access is unknown",
            ))
        for grant in mappings.get(name, []) or []:
            if grant.get("admin"):
                if not members:
                    findings.append(Finding(
                        "stale_admin_group", "warn",
                        f"group {name!r} still grants admin role "
                        f"{grant['role']!r} in {grant['system']!r} but has no members",
                    ))
                else:
                    findings.append(Finding(
                        "admin_grant", "info",
                        f"group {name!r} grants admin role {grant['role']!r} "
                        f"in {grant['system']!r} to {len(members)} member(s)",
                    ))
                    if len(members) >= threshold:
                        findings.append(Finding(
                            "broad_admin", "warn",
                            f"group {name!r} grants admin role {grant['role']!r} "
                            f"in {grant['system']!r} to {len(members)} member(s) "
                            f"(threshold {threshold})",
                        ))

    # --- Per-user effective access.
    user_access: list[UserAccess] = []
    for user_id, user in sorted(users.items(), key=lambda kv: kv[1].get("name", kv[0])):
        direct_groups = sorted(
            name for name, group in groups_by_name.items()
            if user_id in (group.get("members", []) or [])
        )
        effective_groups = sorted(
            name for name, members in all_members.items() if user_id in members
        )
        grants: dict[tuple[str, str], Grant] = {}
        for group_name in effective_groups:
            for grant in mappings.get(group_name, []) or []:
                key = (grant["system"], grant["role"])
                existing = grants.get(key)
                if existing is None:
                    grants[key] = Grant(
                        system=grant["system"],
                        role=grant["role"],
                        admin=bool(grant.get("admin")),
                        via_groups=[group_name],
                        direct=group_name in direct_groups,
                    )
                else:
                    if group_name not in existing.via_groups:
                        existing.via_groups.append(group_name)
                    if group_name in direct_groups:
                        existing.direct = True
        access = list(grants.values())

        # A user who is an admin only through nesting is easy to
        # miss by hand: their direct groups grant nothing admin,
        # yet their effective access does.
        admin_systems = {g.system for g in access if g.admin}
        if len(admin_systems) >= 2:
            findings.append(Finding(
                "multi_system_admin", "warn",
                f"user {user.get('name', user_id)!r} is an admin in "
                f"{len(admin_systems)} systems: {', '.join(sorted(admin_systems))}",
            ))
        for grant in access:
            if grant.admin and not grant.direct:
                findings.append(Finding(
                    "nested_admin", "warn",
                    f"user {user.get('name', user_id)!r} is an admin "
                    f"({grant.role!r} in {grant.system!r}) only via "
                    f"nested group(s): {', '.join(sorted(grant.via_groups))}",
                ))

        user_access.append(UserAccess(
            user_id=user_id,
            name=user.get("name", user_id),
            email=user.get("email", ""),
            groups=direct_groups,
            effective_groups=effective_groups,
            access=access,
        ))

    return AuditReport(overall="OK", users=user_access, findings=findings)


def print_report(report: AuditReport, only_user: str | None = None) -> None:
    """Human-readable summary, suitable for an auditor or a PR comment."""
    print(f"AccessGraph: {report.summary()['users']} user(s), "
          f"{report.summary()['admin_users']} admin user(s), "
          f"{report.summary()['admin_grants']} admin grant(s), "
          f"{report.summary()['warnings']} warning(s)")
    for user in report.users:
        if only_user and user.user_id != only_user and user.name != only_user:
            continue
        print(f"\n{user.name} ({user.user_id}) — groups: {', '.join(user.groups) or 'none'}")
        if not user.access:
            print("  no mapped third-party access")
        for grant in sorted(user.access, key=lambda g: (g.system, g.role)):
            admin = "ADMIN" if grant.admin else "     "
            via = ", ".join(sorted(grant.via_groups))
            direct = "direct" if grant.direct else "via nesting"
            print(f"  [{admin}] {grant.system}: {grant.role} (via {via}, {direct})")
    if report.findings:
        print("\nFindings:")
        for finding in report.findings:
            print(f"  [{finding.severity.upper():4}] {finding.kind}: {finding.detail}")


def _node_id(prefix: str, text: str) -> str:
    """A Mermaid-safe node id: letters, digits and underscores only."""
    safe = re.sub(r"[^A-Za-z0-9_]", "_", text)
    return f"{prefix}_{safe}"


def render_mermaid(report: AuditReport, only_user: str | None = None) -> str:
    """Render the audit as a Mermaid flowchart: user -> group -> role.

    Pure logic — no files, no network. One node per user, group, and
    role, so a group or role shared by several users is drawn once.
    Solid edges are direct membership; dotted edges are membership
    reached only through nesting. Admin roles are highlighted with
    the ``admin`` class. GitHub renders Mermaid natively in markdown
    and in PR comments, so the output can be pasted straight into
    either.
    """
    users = [u for u in report.users
             if not only_user or u.user_id == only_user or u.name == only_user]
    lines = [
        "graph TD",
        "%% AccessGraph: user --> group --> system: role. "
        "Solid = direct membership, dotted = via nesting. Pink = admin role.",
        "classDef admin fill:#f9c,stroke:#c00,stroke-width:2px;",
    ]
    admin_roles: set[str] = set()
    for user in users:
        user_node = _node_id("u", user.user_id)
        lines.append(f'    {user_node}["{user.name}"]')
        direct = set(user.groups)
        for group in user.effective_groups:
            group_node = _node_id("g", group)
            lines.append(f'    {group_node}["{group}"]')
            if group in direct:
                lines.append(f"    {user_node} --> {group_node}")
            else:
                lines.append(f'    {user_node} -. "nested" .-> {group_node}')
        for grant in sorted(user.access, key=lambda g: (g.system, g.role)):
            role_node = _node_id("r", f"{grant.system}_{grant.role}")
            lines.append(f'    {role_node}["{grant.system}: {grant.role}"]')
            if grant.admin:
                admin_roles.add(role_node)
            for group in sorted(grant.via_groups):
                lines.append(f"    {_node_id('g', group)} --> {role_node}")
    for role_node in sorted(admin_roles):
        lines.append(f"    class {role_node} admin;")
    return "\n".join(lines) + "\n"


def _d2_id(prefix: str, text: str) -> str:
    """A D2-safe node id. D2 keys are case-insensitive, so lowercase."""
    safe = re.sub(r"[^A-Za-z0-9_]", "_", text).lower()
    return f"{prefix}_{safe}"


def render_d2(report: AuditReport, only_user: str | None = None) -> str:
    """Render the audit as a D2 diagram: user -> group -> role.

    Pure logic — no files, no network. One node per user, group, and
    role, so a group or role shared by several users is drawn once.
    Users are ovals, groups rectangles, roles hexagons; solid edges
    are direct membership, dashed edges are membership reached only
    through nesting; admin roles are filled pink with a red border.
    Compile with the D2 CLI: ``d2 access-graph.d2 access-graph.svg``.
    """
    users = [u for u in report.users
             if not only_user or u.user_id == only_user or u.name == only_user]
    lines = [
        "# AccessGraph: user -> group -> system: role. "
        "Solid = direct membership, dashed = via nesting. Pink = admin role.",
        "direction: right",
        "",
    ]
    admin_roles: set[str] = set()
    seen_nodes: set[str] = set()
    seen_role_edges: set[tuple[str, str]] = set()
    for user in users:
        user_node = _d2_id("u", user.user_id)
        lines.append(f'{user_node}: "{user.name}" {{')
        lines.append("  shape: oval")
        lines.append("}")
        direct = set(user.groups)
        for group in user.effective_groups:
            group_node = _d2_id("g", group)
            # A group is one node, however many users share it.
            if group_node not in seen_nodes:
                seen_nodes.add(group_node)
                lines.append(f'{group_node}: "{group}"')
            if group in direct:
                lines.append(f"  {user_node} -> {group_node}")
            else:
                lines.append(f'  {user_node} -> {group_node}: "nested" {{')
                lines.append("    style.stroke-dash: 5")
                lines.append("  }")
        for grant in sorted(user.access, key=lambda g: (g.system, g.role)):
            role_node = _d2_id("r", f"{grant.system}_{grant.role}")
            # A role is one node, however many users hold it.
            if role_node not in seen_nodes:
                seen_nodes.add(role_node)
                lines.append(f'  {role_node}: "{grant.system}: {grant.role}" {{')
                lines.append("    shape: hexagon")
                if grant.admin:
                    lines.append('    style.fill: "#f9c"')
                    lines.append('    style.stroke: "#c00"')
                    lines.append("    style.stroke-width: 2")
                lines.append("  }")
            for group in sorted(grant.via_groups):
                # A group grants a role once, however many users
                # share it — emitting the edge per user would draw
                # parallel arrows for the same fact.
                edge = (_d2_id("g", group), role_node)
                if edge not in seen_role_edges:
                    seen_role_edges.add(edge)
                    lines.append(f"  {edge[0]} -> {edge[1]}")
        lines.append("")
    return "\n".join(lines)


def cmd_d2(args: argparse.Namespace) -> int:
    """Render the audit as a D2 diagram (stdout, or --out file)."""
    try:
        snapshot = load_json(args.snapshot, "snapshot")
        mapping = load_json(args.mapping, "mapping")
    except SystemExit as exc:
        return int(exc.code or 2)

    errors = validate_snapshot(snapshot)
    if errors:
        for error in errors:
            print(f"AccessGraph: ERROR — {error}", file=sys.stderr)
        return 2
    try:
        if mapping.get("naming_convention"):
            re.compile(mapping["naming_convention"])
    except re.error as exc:
        print(f"AccessGraph: ERROR — naming convention is not a valid regex: {exc}", file=sys.stderr)
        return 2

    report = audit(snapshot, mapping)
    if args.user and args.user not in {u.user_id for u in report.users} \
            and args.user not in {u.name for u in report.users}:
        print(f"AccessGraph: ERROR — no user {args.user!r} in snapshot", file=sys.stderr)
        return 2

    text = render_d2(report, only_user=args.user)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"AccessGraph: D2 diagram written to {args.out}")
    else:
        print(text, end="")
    return 0


def cmd_graph(args: argparse.Namespace) -> int:
    """Render the audit as a Mermaid graph (stdout, or --out file)."""
    try:
        snapshot = load_json(args.snapshot, "snapshot")
        mapping = load_json(args.mapping, "mapping")
    except SystemExit as exc:
        return int(exc.code or 2)

    errors = validate_snapshot(snapshot)
    if errors:
        for error in errors:
            print(f"AccessGraph: ERROR — {error}", file=sys.stderr)
        return 2
    try:
        if mapping.get("naming_convention"):
            re.compile(mapping["naming_convention"])
    except re.error as exc:
        print(f"AccessGraph: ERROR — naming convention is not a valid regex: {exc}", file=sys.stderr)
        return 2

    report = audit(snapshot, mapping)
    if args.user and args.user not in {u.user_id for u in report.users} \
            and args.user not in {u.name for u in report.users}:
        print(f"AccessGraph: ERROR — no user {args.user!r} in snapshot", file=sys.stderr)
        return 2

    text = render_mermaid(report, only_user=args.user)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"AccessGraph: graph written to {args.out}")
    else:
        print(text, end="")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Run the audit: snapshot + mapping -> report (0, or 1 in --strict)."""
    try:
        snapshot = load_json(args.snapshot, "snapshot")
        mapping = load_json(args.mapping, "mapping")
    except SystemExit as exc:
        # load_json exits with code 2 for a CLI run; when main() is
        # called in-process (tests, imports), return that code instead.
        return int(exc.code or 2)

    errors = validate_snapshot(snapshot)
    if errors:
        for error in errors:
            print(f"AccessGraph: ERROR — {error}", file=sys.stderr)
        return 2
    try:
        if mapping.get("naming_convention"):
            re.compile(mapping["naming_convention"])
    except re.error as exc:
        print(f"AccessGraph: ERROR — naming convention is not a valid regex: {exc}", file=sys.stderr)
        return 2

    report = audit(snapshot, mapping)
    if args.user and args.user not in {u.user_id for u in report.users} \
            and args.user not in {u.name for u in report.users}:
        print(f"AccessGraph: ERROR — no user {args.user!r} in snapshot", file=sys.stderr)
        return 2

    print_report(report, only_user=args.user)
    if args.out:
        args.out.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nAccessGraph: report written to {args.out}")

    if args.strict and any(f.severity == "warn" for f in report.findings):
        report.overall = "STRICT_FAIL"
        print("AccessGraph: STRICT FAIL — warning finding(s) present.", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accessgraph",
        description="Tie Okta group membership to third-party access and role, for audit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit_cmd = sub.add_parser("audit", help="Audit a snapshot against a group-to-role mapping")
    audit_cmd.add_argument("--snapshot", type=Path, required=True, help="Okta snapshot JSON")
    audit_cmd.add_argument("--mapping", type=Path, required=True, help="Group-to-role mapping JSON")
    audit_cmd.add_argument("--out", type=Path, default=None, help="Write the report JSON here")
    audit_cmd.add_argument("--user", default=None, help="Audit one user only (id or name)")
    audit_cmd.add_argument("--strict", action="store_true",
                           help="Exit 1 if any warning finding exists (off by default)")
    audit_cmd.set_defaults(func=cmd_audit)

    graph_cmd = sub.add_parser("graph", help="Render the audit as a Mermaid flowchart")
    graph_cmd.add_argument("--snapshot", type=Path, required=True, help="Okta snapshot JSON")
    graph_cmd.add_argument("--mapping", type=Path, required=True, help="Group-to-role mapping JSON")
    graph_cmd.add_argument("--out", type=Path, default=None,
                           help="Write the Mermaid diagram here (default: print it)")
    graph_cmd.add_argument("--user", default=None, help="Render one user's subgraph only (id or name)")
    graph_cmd.set_defaults(func=cmd_graph)

    d2_cmd = sub.add_parser("d2", help="Render the audit as a D2 diagram (compile with the D2 CLI)")
    d2_cmd.add_argument("--snapshot", type=Path, required=True, help="Okta snapshot JSON")
    d2_cmd.add_argument("--mapping", type=Path, required=True, help="Group-to-role mapping JSON")
    d2_cmd.add_argument("--out", type=Path, default=None,
                        help="Write the D2 diagram here (default: print it)")
    d2_cmd.add_argument("--user", default=None, help="Render one user's subgraph only (id or name)")
    d2_cmd.set_defaults(func=cmd_d2)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
