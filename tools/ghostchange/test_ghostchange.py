#!/usr/bin/env python3
"""Unit tests for GhostChange. Standard library only.

Run:  python3 -m unittest test_ghostchange -v
      (from tools/ghostchange/)

The tests use small hand-built live/desired snapshots, so they run
without Jamf, Okta, CrowdStrike, Terraform, or any network access.
One test loads the checked-in examples end to end.
"""

import json
import tempfile
import unittest
from pathlib import Path

import ghostchange

CONFIG = {"critical_kinds": ["crowdstrike_prevention_policy", "okta_signon_policy"],
          "ignore_keys": ["last_modified"]}


def item(system, kind, item_id, name, settings=None):
    return {"system": system, "kind": kind, "id": item_id, "name": name,
            "settings": settings or {}}


def run(live_items, desired_items, config=None):
    live = [ghostchange.Item(**i) for i in live_items]
    desired = [ghostchange.Item(**i) for i in desired_items]
    return ghostchange.check(live, desired, config or CONFIG)


def findings_of(report, kind):
    return [f for f in report.findings if f.kind == kind]


class TestNoDrift(unittest.TestCase):
    def test_matching_config_is_clean(self):
        live = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                     {"mfa_required": True})]
        report = run(live, live)
        self.assertEqual(report.summary()["ok"], 1)
        self.assertEqual(report.findings, [])

    def test_ignored_keys_do_not_count_as_drift(self):
        # last_modified changes on every API read. It is metadata,
        # not a config change, so it must never raise a finding.
        live = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                     {"mfa_required": True, "last_modified": "2026-11-11T12:00:00Z"})]
        desired = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                        {"mfa_required": True, "last_modified": "2026-11-01T09:00:00Z"})]
        report = run(live, desired)
        self.assertEqual(report.summary()["ok"], 1)
        self.assertEqual(report.findings, [])


class TestDriftKinds(unittest.TestCase):
    def test_unmanaged_item_is_a_ghost(self):
        # Something exists live that Terraform never declared:
        # somebody made it in a console.
        live = [item("jamf", "jamf_computer_profile", "exc", "Local Admin Exception",
                     {"local_admin": True})]
        report = run(live, [])
        self.assertEqual(len(findings_of(report, "unmanaged")), 1)
        self.assertEqual(report.summary()["unmanaged"], 1)

    def test_changed_setting_is_drifted_with_the_difference(self):
        live = [item("crowdstrike", "crowdstrike_prevention_policy", "prev",
                     "Default prevention", {"uninstall_protection": False})]
        desired = [item("crowdstrike", "crowdstrike_prevention_policy", "prev",
                        "Default prevention", {"uninstall_protection": True})]
        report = run(live, desired)
        drifted = findings_of(report, "drifted")
        self.assertEqual(len(drifted), 1)
        self.assertIn("uninstall_protection", drifted[0].detail)
        item_report = report.items[0]
        self.assertEqual(item_report.differences,
                         [{"key": "uninstall_protection", "live": False, "desired": True}])

    def test_missing_desired_item_is_reported(self):
        desired = [item("crowdstrike", "crowdstrike_sensor_policy", "sens",
                        "Standard sensor", {"sensor_mode": "full"})]
        report = run([], desired)
        self.assertEqual(len(findings_of(report, "missing")), 1)
        self.assertEqual(report.summary()["missing"], 1)

    def test_setting_added_live_is_drift(self):
        live = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                     {"mfa_required": True, "extra_rule": "allow"})]
        desired = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                        {"mfa_required": True})]
        report = run(live, desired)
        self.assertEqual(len(findings_of(report, "drifted")), 1)

    def test_setting_removed_live_is_drift(self):
        live = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                     {"mfa_required": True})]
        desired = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                        {"mfa_required": True, "session_lifetime_hours": 8})]
        report = run(live, desired)
        self.assertEqual(len(findings_of(report, "drifted")), 1)


class TestSeverity(unittest.TestCase):
    def test_drift_in_a_critical_kind_is_critical(self):
        live = [item("crowdstrike", "crowdstrike_prevention_policy", "prev",
                     "Default prevention", {"uninstall_protection": False})]
        desired = [item("crowdstrike", "crowdstrike_prevention_policy", "prev",
                        "Default prevention", {"uninstall_protection": True})]
        report = run(live, desired)
        self.assertEqual(report.findings[0].severity, "critical")

    def test_unmanaged_non_critical_kind_is_only_a_warning(self):
        # Click-ops is common. An unmanaged item in an ordinary kind
        # is a warning, not a critical finding — that is the whole
        # point of this tool being a report, not a blocker.
        live = [item("jamf", "jamf_computer_profile", "exc", "Local Admin Exception",
                     {"local_admin": True})]
        report = run(live, [])
        self.assertEqual(report.findings[0].severity, "warn")
        self.assertEqual(report.summary()["critical"], 0)

    def test_missing_critical_kind_is_critical(self):
        desired = [item("okta", "okta_signon_policy", "mfa", "MFA required",
                        {"mfa_required": True})]
        report = run([], desired)
        self.assertEqual(report.findings[0].severity, "critical")


class TestCli(unittest.TestCase):
    def _write(self, tmp, name, data):
        path = tmp / name
        path.write_text(json.dumps(data))
        return path

    def test_check_is_report_only_by_default(self):
        # Drift present, but the default exit code is still 0:
        # this tool reports drift, it does not block work.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            live = self._write(tmp, "live.json", {"items": [
                item("jamf", "jamf_computer_profile", "exc", "Local Admin Exception",
                     {"local_admin": True})]})
            desired = self._write(tmp, "desired.json", {"items": []})
            config = self._write(tmp, "config.json", CONFIG)
            out = tmp / "report.json"
            rc = ghostchange.main(["check", "--live", str(live), "--desired", str(desired),
                                   "--config", str(config), "--out", str(out)])
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text())
            self.assertEqual(report["tool"], "ghostchange")
            self.assertEqual(report["summary"]["unmanaged"], 1)

    def test_strict_fails_only_on_critical_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            # Non-critical drift only: strict still passes.
            live = self._write(tmp, "live.json", {"items": [
                item("jamf", "jamf_computer_profile", "exc", "Local Admin Exception",
                     {"local_admin": True})]})
            desired = self._write(tmp, "desired.json", {"items": []})
            config = self._write(tmp, "config.json", CONFIG)
            rc = ghostchange.main(["check", "--live", str(live), "--desired", str(desired),
                                   "--config", str(config), "--strict"])
            self.assertEqual(rc, 0)
            # Critical drift: strict fails.
            live2 = self._write(tmp, "live2.json", {"items": [
                item("crowdstrike", "crowdstrike_prevention_policy", "prev",
                     "Default prevention", {"uninstall_protection": False})]})
            desired2 = self._write(tmp, "desired2.json", {"items": [
                item("crowdstrike", "crowdstrike_prevention_policy", "prev",
                     "Default prevention", {"uninstall_protection": True})]})
            rc = ghostchange.main(["check", "--live", str(live2), "--desired", str(desired2),
                                   "--config", str(config), "--strict"])
            self.assertEqual(rc, 1)

    def test_missing_live_file_is_an_error_not_a_pass(self):
        rc = ghostchange.main(["check", "--live", "nope.json", "--desired", "nope.json",
                               "--config", "nope.json"])
        self.assertEqual(rc, 2)

    def test_duplicate_item_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            dup = item("okta", "okta_signon_policy", "mfa", "MFA required", {})
            live = self._write(tmp, "live.json", {"items": [dup, dup]})
            desired = self._write(tmp, "desired.json", {"items": []})
            config = self._write(tmp, "config.json", CONFIG)
            rc = ghostchange.main(["check", "--live", str(live), "--desired", str(desired),
                                   "--config", str(config)])
            self.assertEqual(rc, 2)


class TestExamples(unittest.TestCase):
    def test_checked_in_examples_end_to_end(self):
        # The full example: uninstall protection was turned off in
        # the CrowdStrike console (drifted, critical), a Jamf profile
        # was created in the console (unmanaged), and the standard
        # sensor policy was deleted out of band (missing).
        here = Path(__file__).parent
        live = ghostchange.parse_items(
            json.loads((here / "examples" / "live.json").read_text()), "live")
        desired = ghostchange.parse_items(
            json.loads((here / "examples" / "desired.json").read_text()), "desired")
        config = ghostchange.parse_config(
            json.loads((here / "ghostchange.json").read_text()))
        report = ghostchange.check(live, desired, config)
        summary = report.summary()
        self.assertEqual(summary["ok"], 3)
        self.assertEqual(summary["drifted"], 1)
        self.assertEqual(summary["unmanaged"], 1)
        self.assertEqual(summary["missing"], 1)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(len(report.findings), 3)


if __name__ == "__main__":
    unittest.main()
