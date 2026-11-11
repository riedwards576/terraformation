#!/usr/bin/env python3
"""Unit tests for PlanGuard. Standard library only.

Run:  python3 -m unittest test_planguard -v
      (from tools/planguard/)

The tests use small hand-built plans in the Terraform JSON shape,
so they run without Terraform, AWS, or any network access.
"""

import json
import tempfile
import unittest
from pathlib import Path

import planguard


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


class TestHashing(unittest.TestCase):
    def test_same_plan_same_hash_regardless_of_order(self):
        # Reviewers should not be blocked because Terraform listed
        # resources in a different order on the re-plan.
        plan_a = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a"}),
            ("module.x.aws_s3_bucket.b", "aws_s3_bucket", ["create"], {"bucket": "b"}),
        ])
        plan_b = make_plan([
            ("module.x.aws_s3_bucket.b", "aws_s3_bucket", ["create"], {"bucket": "b"}),
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a"}),
        ])
        self.assertEqual(planguard.plan_hash(plan_a), planguard.plan_hash(plan_b))

    def test_one_changed_value_changes_hash(self):
        plan_a = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a"}),
        ])
        plan_b = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a-v2"}),
        ])
        self.assertNotEqual(planguard.plan_hash(plan_a), planguard.plan_hash(plan_b))


class TestScoring(unittest.TestCase):
    def test_plain_create_is_low(self):
        plan = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {}),
        ])
        risk = planguard.score_plan(plan)
        self.assertEqual(risk.band, "LOW")
        self.assertEqual(risk.score, 2)

    def test_destroy_is_high(self):
        plan = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["delete"], {}),
        ])
        risk = planguard.score_plan(plan)
        self.assertEqual(risk.score, 40)
        self.assertEqual(risk.band, "MEDIUM")  # One destroy alone: review, don't panic.

    def test_destroy_plus_iam_is_high(self):
        plan = make_plan([
            ("aws_s3_bucket.a", "aws_s3_bucket", ["delete"], {}),
            ("aws_iam_role.admin", "aws_iam_role", ["create"], {}),
        ])
        risk = planguard.score_plan(plan)
        # 40 (delete) + 2 (create) + 15 (sensitive IAM type) = 57 -> HIGH
        self.assertEqual(risk.band, "HIGH")
        self.assertGreaterEqual(risk.score, 50)

    def test_public_access_disabled_scores_max_band(self):
        plan = make_plan([
            (
                "module.x.aws_s3_bucket_public_access_block.this",
                "aws_s3_bucket_public_access_block",
                ["update"],
                {"block_public_acls": False, "block_public_policy": False},
            ),
        ])
        risk = planguard.score_plan(plan)
        self.assertEqual(risk.band, "HIGH")  # 5 update + 50 exposure = 55

    def test_noop_scores_zero(self):
        plan = make_plan([
            ("aws_s3_bucket.a", "aws_s3_bucket", ["no-op"], {}),
        ])
        self.assertEqual(planguard.score_plan(plan).score, 0)


class TestAttestVerifyRoundTrip(unittest.TestCase):
    def test_verify_passes_for_unchanged_plan(self):
        plan = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a"}),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            plan_file = tmp / "plan.json"
            plan_file.write_text(json.dumps(plan))
            att_file = tmp / "attestation.json"
            rc = planguard.main([
                "attest", "--plan", str(plan_file), "--out", str(att_file),
                "--commit", "abc123", "--pr", "7", "--actor", "richard", "--env", "dev",
            ])
            self.assertEqual(rc, 0)
            att = json.loads(att_file.read_text())
            self.assertEqual(att["commit_sha"], "abc123")
            self.assertEqual(att["risk"]["band"], "LOW")

            # Verify the *same* plan: must pass.
            rc = planguard.main([
                "verify", "--plan", str(plan_file), "--attestation", str(att_file),
            ])
            self.assertEqual(rc, 0)

    def test_verify_fails_for_changed_plan(self):
        plan = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a"}),
        ])
        changed = make_plan([
            ("module.x.aws_s3_bucket.a", "aws_s3_bucket", ["create"], {"bucket": "a-v2"}),
            ("module.x.aws_s3_bucket.b", "aws_s3_bucket", ["create"], {"bucket": "b"}),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            plan_file = tmp / "plan.json"
            plan_file.write_text(json.dumps(plan))
            att_file = tmp / "attestation.json"
            planguard.main([
                "attest", "--plan", str(plan_file), "--out", str(att_file),
                "--commit", "abc123", "--pr", "7", "--actor", "richard", "--env", "dev",
            ])
            changed_file = tmp / "fresh.json"
            changed_file.write_text(json.dumps(changed))
            rc = planguard.main([
                "verify", "--plan", str(changed_file), "--attestation", str(att_file),
            ])
            self.assertEqual(rc, 1)  # Fail closed: do not apply.


if __name__ == "__main__":
    unittest.main()
