#!/usr/bin/env python3
"""Unit tests for CoverageGuard. Standard library only.

Run:  python3 -m unittest test_coverageguard -v
      (from tools/coverageguard/)

The tests use small hand-built snapshots and plans in the
Terraform JSON shape, so they run without Terraform, CrowdStrike,
Jamf, Okta, or any network access.
"""

import json
import tempfile
import unittest
from pathlib import Path

import coverageguard

# Baseline snapshot used by most tests: every dimension sits
# just above the 95% floor (CrowdStrike 98.0%, Jamf 97.8%, Okta 98.0%).
SNAPSHOT = {
    "crowdstrike": {"total_hosts": 200, "sensor_hosts": 196, "uninstall_protection_enabled": True},
    "jamf": {"total_devices": 180, "managed_devices": 176, "filevault_enforced": True},
    "okta": {"total_users": 150, "mfa_users": 147, "mfa_required": True},
}

FLOORS = dict(coverageguard.DEFAULT_FLOORS)


def make_plan(changes):
    """Build a minimal Terraform plan dict from (address, type, actions, after)."""
    return {
        "resource_changes": [
            {
                "address": address,
                "type": resource_type,
                "change": {"actions": actions, "after": after},
            }
            for address, resource_type, actions, after in changes
        ]
    }


def dimension(report, name):
    """Pull one dimension out of a report by name."""
    return next(d for d in report.dimensions if d.name == name)


class TestBaseline(unittest.TestCase):
    def test_noop_plan_passes(self):
        report = coverageguard.check_coverage(SNAPSHOT, make_plan([]), FLOORS)
        self.assertEqual(report.overall, "PASS")
        self.assertEqual(dimension(report, "crowdstrike_sensor_coverage").after, 98.0)

    def test_unknown_resource_types_are_ignored(self):
        # An S3-only plan must not move any coverage number.
        # This is the correct answer for the POC today: it has no
        # Jamf / Okta / CrowdStrike resources yet, so CoverageGuard
        # passes and stays out of the way.
        plan = make_plan([
            ("module.s3.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a"}),
            ("module.s3.aws_s3_bucket.b", "aws_s3_bucket", ["delete"], {}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "PASS")
        self.assertEqual(dimension(report, "okta_mfa_coverage").after, 98.0)

    def test_adding_covered_units_passes(self):
        plan = make_plan([
            ("crowdstrike_sensor.new", "crowdstrike_sensor", ["create"], {}),
            ("jamf_managed_device.new", "jamf_managed_device", ["create"], {}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "PASS")
        self.assertEqual(dimension(report, "crowdstrike_sensor_coverage").after, 98.0)


class TestCoverageFloor(unittest.TestCase):
    def test_ten_uncovered_users_drop_okta_below_floor(self):
        # 147 / 150 = 98.0% before; 147 / 160 = 91.9% after. Floor is 95%.
        plan = make_plan([
            (f"okta_user.u{i}", "okta_user", ["create"], {}) for i in range(10)
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "FAIL")
        self.assertEqual(dimension(report, "okta_mfa_coverage").status, "FAIL")
        self.assertEqual(dimension(report, "okta_mfa_coverage").after, 91.9)

    def test_deleting_sensors_below_floor_fails(self):
        # Removing 10 covered hosts: 186 / 190 = 97.9% — still passes.
        # Removing 20: 176 / 180 = 97.8% — still passes, because the
        # denominator falls with the numerator. So use a plan that
        # *replaces* covered hosts with uncovered ones instead:
        # delete 10 sensors, add 10 bare hosts -> 186 / 200 = 93.0%.
        plan = make_plan(
            [(f"crowdstrike_sensor.h{i}", "crowdstrike_sensor", ["delete"], {}) for i in range(10)]
            + [(f"crowdstrike_host.h{i}", "crowdstrike_host", ["create"], {}) for i in range(10)]
        )
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "FAIL")
        self.assertEqual(dimension(report, "crowdstrike_sensor_coverage").after, 93.0)

    def test_small_drop_stays_above_floor_is_warn_not_fail(self):
        # 147 / 152 = 96.7%: coverage fell, but it is still above 95%.
        # That is a warning for the reviewer, not a block.
        plan = make_plan([
            ("okta_user.u1", "okta_user", ["create"], {}),
            ("okta_user.u2", "okta_user", ["create"], {}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "PASS")
        self.assertEqual(dimension(report, "okta_mfa_coverage").status, "WARN")
        self.assertEqual(dimension(report, "okta_mfa_coverage").after, 96.7)

    def test_exactly_at_floor_passes(self):
        # Baseline is 98.0%; with the floor set to 98.0% exactly,
        # the plan is at the floor, not below it, so it passes.
        floors = dict(FLOORS, crowdstrike_sensor_coverage=98.0)
        report = coverageguard.check_coverage(SNAPSHOT, make_plan([]), floors)
        self.assertEqual(report.overall, "PASS")
        self.assertEqual(dimension(report, "crowdstrike_sensor_coverage").after, 98.0)

    def test_replace_is_net_zero_for_coverage(self):
        plan = make_plan([
            ("crowdstrike_sensor.h1", "crowdstrike_sensor", ["create", "delete"], {}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "PASS")
        self.assertEqual(dimension(report, "crowdstrike_sensor_coverage").after, 98.0)


class TestHardProtections(unittest.TestCase):
    def test_disabling_uninstall_protection_fails(self):
        plan = make_plan([
            ("crowdstrike_prevention_policy.standard", "crowdstrike_prevention_policy",
             ["update"], {"uninstall_protection": False}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "FAIL")
        self.assertEqual(
            dimension(report, "crowdstrike_uninstall_protection_enabled").status, "FAIL")

    def test_disabling_mfa_required_fails(self):
        plan = make_plan([
            ("okta_signon_policy.default", "okta_signon_policy",
             ["update"], {"mfa_required": False}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "FAIL")

    def test_deleting_a_protection_policy_fails(self):
        plan = make_plan([
            ("jamf_disk_encryption_policy.filevault", "jamf_disk_encryption_policy",
             ["delete"], {}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "FAIL")
        self.assertEqual(dimension(report, "jamf_filevault_enforced").status, "FAIL")

    def test_protection_update_with_no_recognised_attribute_is_ignored(self):
        # Do not guess: an update that does not mention the
        # protection setting leaves it at its snapshot value.
        plan = make_plan([
            ("crowdstrike_prevention_policy.standard", "crowdstrike_prevention_policy",
             ["update"], {"name": "standard-v2"}),
        ])
        report = coverageguard.check_coverage(SNAPSHOT, plan, FLOORS)
        self.assertEqual(report.overall, "PASS")


class TestInputErrors(unittest.TestCase):
    def test_snapshot_where_covered_exceeds_total_is_an_error(self):
        bad = {
            "crowdstrike": {"total_hosts": 10, "sensor_hosts": 11, "uninstall_protection_enabled": True},
            "jamf": {"total_devices": 180, "managed_devices": 176, "filevault_enforced": True},
            "okta": {"total_users": 150, "mfa_users": 147, "mfa_required": True},
        }
        self.assertTrue(coverageguard.validate_snapshot(bad))

    def test_check_returns_2_for_a_bad_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = tmp / "snap.json"
            snap.write_text(json.dumps({
                "crowdstrike": {"total_hosts": 10, "sensor_hosts": 11,
                                "uninstall_protection_enabled": True},
                "jamf": {"total_devices": 180, "managed_devices": 176, "filevault_enforced": True},
                "okta": {"total_users": 150, "mfa_users": 147, "mfa_required": True},
            }))
            plan_file = tmp / "plan.json"
            plan_file.write_text(json.dumps(make_plan([])))
            rc = coverageguard.main([
                "check", "--snapshot", str(snap), "--plan", str(plan_file),
            ])
            self.assertEqual(rc, 2)

    def test_cli_writes_report_and_returns_1_on_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = tmp / "snap.json"
            snap.write_text(json.dumps(SNAPSHOT))
            plan_file = tmp / "plan.json"
            plan_file.write_text(json.dumps(make_plan([
                ("crowdstrike_prevention_policy.standard", "crowdstrike_prevention_policy",
                 ["update"], {"uninstall_protection": False}),
            ])))
            out = tmp / "report.json"
            rc = coverageguard.main([
                "check", "--snapshot", str(snap), "--plan", str(plan_file),
                "--out", str(out),
            ])
            self.assertEqual(rc, 1)
            report = json.loads(out.read_text())
            self.assertEqual(report["overall"], "FAIL")
            self.assertEqual(report["tool"], "coverageguard")


if __name__ == "__main__":
    unittest.main()
