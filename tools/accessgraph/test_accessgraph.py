#!/usr/bin/env python3
"""Unit tests for AccessGraph. Standard library only.

Run:  python3 -m unittest test_accessgraph -v
      (from tools/accessgraph/)

The tests use small hand-built snapshots and mappings, so they run
without Okta, Jamf, CrowdStrike, Terraform, or any network access.
One test loads the checked-in examples end to end.
"""

import json
import tempfile
import unittest
from pathlib import Path

import accessgraph

MAPPING = {
    "naming_convention": r"^okta-(jamf|okta|crowdstrike)-[a-z0-9-]+$",
    "broad_group_threshold": 3,
    "mappings": {
        "okta-jamf-admins": [{"system": "jamf", "role": "Jamf Administrator", "admin": True}],
        "okta-jamf-helpdesk": [{"system": "jamf", "role": "Jamf Help Desk", "admin": False}],
        "okta-okta-super-admins": [{"system": "okta", "role": "Okta Super Administrator", "admin": True}],
    },
}


def make_snapshot(users, groups):
    """Build a snapshot dict from (id, name) users and group dicts."""
    return {
        "users": [{"id": uid, "name": name, "email": f"{uid}@example.com"} for uid, name in users],
        "groups": groups,
    }


def group(name, members=None, member_groups=None):
    return {"name": name, "members": members or [], "member_groups": member_groups or []}


def user_access(report, user_id):
    return next(u for u in report.users if u.user_id == user_id)


def findings_of(report, kind):
    return [f for f in report.findings if f.kind == kind]


class TestDirectAccess(unittest.TestCase):
    def test_direct_membership_gives_access(self):
        snapshot = make_snapshot(
            [("alice", "Alice"), ("bob", "Bob")],
            [group("okta-jamf-admins", ["alice"])],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        alice = user_access(report, "alice")
        self.assertEqual(len(alice.access), 1)
        self.assertEqual(alice.access[0].system, "jamf")
        self.assertTrue(alice.access[0].admin)
        self.assertTrue(alice.access[0].direct)
        self.assertEqual(user_access(report, "bob").access, [])

    def test_user_with_no_groups_has_no_access(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [group("okta-jamf-admins", [])],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        self.assertEqual(user_access(report, "alice").access, [])
        self.assertEqual(user_access(report, "alice").groups, [])


class TestNesting(unittest.TestCase):
    def test_nested_group_membership_is_resolved(self):
        # Alice is in okta-jamf-admins, which is nested inside
        # okta-okta-super-admins — so she is an Okta Super Admin,
        # but only indirectly. That is exactly the case a manual
        # audit misses, and the finding should say so.
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [
                group("okta-jamf-admins", ["alice"]),
                group("okta-okta-super-admins", [], ["okta-jamf-admins"]),
            ],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        alice = user_access(report, "alice")
        okta = next(g for g in alice.access if g.system == "okta")
        self.assertTrue(okta.admin)
        self.assertFalse(okta.direct)
        self.assertEqual(okta.via_groups, ["okta-okta-super-admins"])
        self.assertEqual(len(findings_of(report, "nested_admin")), 1)

    def test_group_cycle_does_not_loop(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [
                group("okta-jamf-admins", ["alice"], ["okta-okta-super-admins"]),
                group("okta-okta-super-admins", [], ["okta-jamf-admins"]),
            ],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        alice = user_access(report, "alice")
        # Alice still gets both roles, exactly once each.
        self.assertEqual(len(alice.access), 2)
        self.assertEqual(len(findings_of(report, "group_cycle")), 1)


class TestFindings(unittest.TestCase):
    def test_naming_violation_is_flagged(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [group("Jamf-Admins", ["alice"])],
        )
        mapping = dict(MAPPING)
        mapping["mappings"] = dict(MAPPING["mappings"], **{
            "Jamf-Admins": [{"system": "jamf", "role": "Jamf Administrator", "admin": True}],
        })
        report = accessgraph.audit(snapshot, mapping)
        self.assertEqual(len(findings_of(report, "naming_violation")), 1)

    def test_unmapped_group_with_members_is_flagged(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [group("okta-vpn-users", ["alice"])],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        self.assertEqual(len(findings_of(report, "unmapped_group")), 1)
        # And the user gets no access from it — unknown, not invented.
        self.assertEqual(user_access(report, "alice").access, [])

    def test_stale_admin_group_is_flagged(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [group("okta-jamf-admins", [])],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        self.assertEqual(len(findings_of(report, "stale_admin_group")), 1)
        self.assertEqual(len(findings_of(report, "admin_grant")), 0)

    def test_broad_admin_group_is_flagged_at_threshold(self):
        snapshot = make_snapshot(
            [("a", "A"), ("b", "B"), ("c", "C")],
            [group("okta-jamf-admins", ["a", "b", "c"])],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        self.assertEqual(len(findings_of(report, "broad_admin")), 1)

    def test_multi_system_admin_is_flagged(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [
                group("okta-jamf-admins", ["alice"]),
                group("okta-okta-super-admins", ["alice"]),
            ],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        self.assertEqual(len(findings_of(report, "multi_system_admin")), 1)

    def test_unknown_member_is_flagged_not_crashed_on(self):
        snapshot = make_snapshot(
            [("alice", "Alice")],
            [group("okta-jamf-admins", ["alice", "ghost"])],
        )
        report = accessgraph.audit(snapshot, MAPPING)
        self.assertEqual(len(findings_of(report, "unknown_member")), 1)
        self.assertEqual(len(report.users), 1)  # Only the real user is reported.


class TestCli(unittest.TestCase):
    def test_audit_is_report_only_by_default(self):
        # Warnings present, but the default exit code is still 0:
        # this tool streamlines an audit, it does not block work.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = tmp / "snap.json"
            snap.write_text(json.dumps(make_snapshot(
                [("alice", "Alice")],
                [group("okta-jamf-admins", ["alice"])],
            )))
            mapping_file = tmp / "map.json"
            mapping_file.write_text(json.dumps(MAPPING))
            out = tmp / "report.json"
            rc = accessgraph.main([
                "audit", "--snapshot", str(snap), "--mapping", str(mapping_file),
                "--out", str(out),
            ])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text())
            self.assertEqual(report["tool"], "accessgraph")
            self.assertEqual(report["summary"]["admin_users"], 1)

    def test_strict_mode_fails_on_warnings(self):
        # Three members in an admin group meets the threshold of 3,
        # so this audit has a broad_admin warning — and strict mode
        # is the one mode where a warning fails the run.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = tmp / "snap.json"
            snap.write_text(json.dumps(make_snapshot(
                [("a", "A"), ("b", "B"), ("c", "C")],
                [group("okta-jamf-admins", ["a", "b", "c"])],
            )))
            mapping_file = tmp / "map.json"
            mapping_file.write_text(json.dumps(MAPPING))
            rc = accessgraph.main([
                "audit", "--snapshot", str(snap), "--mapping", str(mapping_file),
                "--strict",
            ])
            self.assertEqual(rc, 1)

    def test_missing_snapshot_is_an_error_not_a_pass(self):
        rc = accessgraph.main([
            "audit", "--snapshot", "nope.json", "--mapping", "nope.json",
        ])
        self.assertEqual(rc, 2)

    def test_unknown_user_flag_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = tmp / "snap.json"
            snap.write_text(json.dumps(make_snapshot([("alice", "Alice")], [])))
            mapping_file = tmp / "map.json"
            mapping_file.write_text(json.dumps(MAPPING))
            rc = accessgraph.main([
                "audit", "--snapshot", str(snap), "--mapping", str(mapping_file),
                "--user", "nobody",
            ])
            self.assertEqual(rc, 2)


class TestExamples(unittest.TestCase):
    def test_checked_in_examples_end_to_end(self):
        # The full example: Alice is an admin in Jamf, CrowdStrike
        # and Okta (the last one only via nesting), Bob is an admin
        # in Jamf and Okta, and the report flags the broad
        # CrowdStrike admin group, the bad group name, the unmapped
        # VPN group, and the stale legacy admin group.
        here = Path(__file__).parent
        snapshot = json.loads((here / "examples" / "snapshot.json").read_text())
        mapping = json.loads((here / "examples" / "mapping.json").read_text())
        report = accessgraph.audit(snapshot, mapping)
        alice = user_access(report, "alice")
        self.assertEqual({g.system for g in alice.access if g.admin},
                         {"jamf", "crowdstrike", "okta"})
        bob = user_access(report, "bob")
        self.assertEqual({g.system for g in bob.access if g.admin}, {"jamf", "okta"})
        self.assertEqual(len(findings_of(report, "broad_admin")), 1)
        # Three names break the convention, which requires the middle
        # token to name the system (jamf / okta / crowdstrike):
        # "Jamf-Admins" (wrong case and shape), "okta-legacy-admins"
        # and "okta-vpn-users" (no system in the middle token).
        self.assertEqual(len(findings_of(report, "naming_violation")), 3)
        self.assertEqual(len(findings_of(report, "unmapped_group")), 1)
        self.assertEqual(len(findings_of(report, "stale_admin_group")), 1)
        self.assertEqual(len(findings_of(report, "nested_admin")), 2)
        self.assertEqual(report.summary()["admin_users"], 6)


if __name__ == "__main__":
    unittest.main()
