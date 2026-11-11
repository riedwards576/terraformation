#!/usr/bin/env python3
"""PlanGuard — the novel piece of this pipeline.

The problem it solves
----------------------
Most Terraform pipelines have a time-of-check / time-of-use gap:

    PR approves Plan A  →  days pass, code or live state changes
    →  main applies Plan B, which nobody reviewed.

That is exactly the gap SOX / NIST auditors ask about: "prove that
what was applied is what was approved."

What PlanGuard does
--------------------
1. ``attest`` (in the PR job): read ``terraform show -json`` output,
   canonicalise it, hash it (SHA-256), score its risk, and write a
   small ``attestation.json``. The hash is posted in the PR comment
   and stored as a workflow artifact.

2. ``verify`` (in the apply job, *before* ``terraform apply``):
   re-plan, recompute the hash, and compare it to the attested hash.
   If anything differs — one resource, one tag, one value — the job
   fails and nothing is applied. The reviewer must open a new PR.

3. ``score``: a transparent risk score for the plan, so reviewers
   know where to look. Destroys, IAM changes, and public exposure
   score high; a plain S3 bucket create scores low.

Why this is a talking point, not just a script
----------------------------------------------
* It closes a real gap with $0 of tooling — no paid SaaS, no server.
* It is *auditable*: the attestation is a plain JSON file with the
  commit, actor, PR number, plan hash, and risk score in one place.
* It is *fail-closed*: any mismatch, missing file, or unreadable
  plan blocks the apply. There is no "warn and continue" path.

Design notes (and honest limits)
---------------------------------
* Standard library only — no pip installs, so it runs in any
  GitHub Actions runner and in a local checkout.
* The hash covers the canonicalised resource changes, not the raw
  JSON. Raw JSON contains timestamps and ordering that change
  between runs even when the plan is identical, so hashing it
  directly would false-positive on every apply.
* Values that are unknown at plan time (``after_unknown`` in the
  Terraform JSON) are excluded from the hash. A plan that depends
  heavily on computed values will therefore verify less strictly.
  That is documented, not hidden — see ``canonical_resource``.
* This is *attestation*, not cryptographic signing. The next step
  (not in this POC) is to sign the attestation with Sigstore /
  cosign using the same GitHub OIDC identity the pipeline already
  uses. The attestation format is deliberately ready for that:
  add a ``signature`` field, nothing else changes.

Usage
-----
    python3 planguard.py attest --plan plan.json --out attestation.json \\
        --commit $GITHUB_SHA --pr 12 --actor octocat --env dev

    python3 planguard.py verify --plan fresh-plan.json \\
        --attestation attestation.json

    python3 planguard.py score --plan plan.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# --- Risk scoring: what counts as risky, and by how much. -------------
# Keep this table small and explicit. A reviewer should be able to
# read it in 30 seconds and argue with it — that is the point.

# Any resource whose type starts with one of these is security-sensitive.
SENSITIVE_TYPE_PREFIXES = (
    "aws_iam_",          # roles, policies, users — privilege changes
    "aws_kms_",          # encryption keys
    "aws_security_group",
    "aws_db_",           # databases
    "aws_s3_bucket_policy",
)

# Points per change. Caps are applied in score_plan(), not here.
POINTS_CREATE = 2
POINTS_UPDATE = 5
POINTS_REPLACE = 30   # delete + create: data loss / downtime risk
POINTS_DELETE = 40    # destroying something is the riskiest normal action
POINTS_SENSITIVE_TYPE = 15
POINTS_PUBLIC_EXPOSURE = 50

# Score bands. HIGH and above need an extra reviewer (see the workflows).
BANDS = ((80, "CRITICAL"), (50, "HIGH"), (20, "MEDIUM"), (0, "LOW"))


@dataclass
class Finding:
    """One human-readable reason a plan scored points."""

    address: str
    reason: str
    points: int


@dataclass
class RiskScore:
    """The scored result for a whole plan."""

    score: int
    band: str
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "band": self.band,
            "findings": [
                {"address": f.address, "reason": f.reason, "points": f.points}
                for f in self.findings
            ],
        }


def band_for(score: int) -> str:
    """Return the band name for a score (first threshold it reaches)."""
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "LOW"  # Unreachable with the table above, kept for safety.


def canonical_resource(change: dict) -> dict:
    """Reduce one Terraform resource change to the fields that matter.

    Only ``address``, ``type``, ``actions`` and the planned ``after``
    values are hashed. ``after_unknown`` is excluded on purpose:
    those values are not known at plan time, so including them would
    make every re-plan hash differently. ``before`` is excluded too —
    what matters for approval is what *will* exist, not what did.
    """
    after = change.get("change", {}).get("after")
    return {
        "address": change.get("address", ""),
        "type": change.get("type", ""),
        # Sort actions so ["delete", "create"] and ["create", "delete"]
        # hash the same way. Terraform means "replace" either way.
        "actions": sorted(change.get("change", {}).get("actions", [])),
        "after": after,
    }


def canonical_plan(plan: dict) -> dict:
    """Canonical form of a whole plan: sorted, deterministic JSON."""
    changes = plan.get("resource_changes", []) or []
    canonical_changes = sorted(
        (canonical_resource(c) for c in changes),
        key=lambda c: c["address"],
    )
    return {"resource_changes": canonical_changes}


def plan_hash(plan: dict) -> str:
    """SHA-256 of the canonical plan JSON (sorted keys, no whitespace)."""
    canonical = json.dumps(canonical_plan(plan), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def score_plan(plan: dict) -> RiskScore:
    """Score a plan. Transparent on purpose — every point has a reason."""
    findings: list[Finding] = []
    total = 0

    for change in plan.get("resource_changes", []) or []:
        address = change.get("address", "?")
        resource_type = change.get("type", "")
        actions = change.get("change", {}).get("actions", [])
        after = change.get("change", {}).get("after") or {}

        # Base points come from the action itself.
        if actions == ["delete"]:
            points, reason = POINTS_DELETE, "destroys a resource"
        elif actions == ["create", "delete"] or actions == ["delete", "create"]:
            points, reason = POINTS_REPLACE, "replaces a resource (delete + create)"
        elif actions == ["update"]:
            points, reason = POINTS_UPDATE, "updates a resource in place"
        elif actions == ["create"]:
            points, reason = POINTS_CREATE, "creates a resource"
        elif actions == ["no-op"]:
            continue  # No change, no risk, no finding.
        else:
            points, reason = POINTS_UPDATE, f"unusual actions: {actions}"

        findings.append(Finding(address, reason, points))
        total += points

        # Sensitive resource types cost extra, whatever the action.
        if resource_type.startswith(SENSITIVE_TYPE_PREFIXES):
            findings.append(
                Finding(address, f"sensitive type: {resource_type}", POINTS_SENSITIVE_TYPE)
            )
            total += POINTS_SENSITIVE_TYPE

        # Public exposure is the one thing that must never slip through.
        # A public-access block being turned *off* shows up as False here.
        if resource_type == "aws_s3_bucket_public_access_block":
            if after.get("block_public_acls") is False or after.get("block_public_policy") is False:
                findings.append(
                    Finding(address, "S3 public access block disabled", POINTS_PUBLIC_EXPOSURE)
                )
                total += POINTS_PUBLIC_EXPOSURE

    total = min(total, 100)  # Cap: a huge plan is CRITICAL, not 400 points.
    return RiskScore(score=total, band=band_for(total), findings=findings)


def summarise(plan: dict) -> dict:
    """Count creates / updates / deletes / replaces, for the attestation."""
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0}
    for change in plan.get("resource_changes", []) or []:
        actions = change.get("change", {}).get("actions", [])
        if actions == ["create"]:
            counts["create"] += 1
        elif actions == ["update"]:
            counts["update"] += 1
        elif actions == ["delete"]:
            counts["delete"] += 1
        elif set(actions) == {"create", "delete"}:
            counts["replace"] += 1
        else:
            counts["no-op"] += 1
    return counts


def load_plan(path: Path) -> dict:
    """Load a Terraform plan JSON file, failing clearly if it is bad."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"PlanGuard: plan file not found: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"PlanGuard: plan file is not valid JSON ({path}): {exc}")


def cmd_attest(args: argparse.Namespace) -> int:
    """Hash + score a plan and write the attestation file."""
    plan = load_plan(args.plan)
    risk = score_plan(plan)
    attestation = {
        "version": 1,
        "tool": "planguard",
        "plan_sha256": plan_hash(plan),
        "commit_sha": args.commit,
        "pull_request": args.pr,
        "actor": args.actor,
        "environment": args.env,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "risk": risk.to_dict(),
        "resource_summary": summarise(plan),
    }
    args.out.write_text(json.dumps(attestation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PlanGuard: attested {args.plan} -> {args.out}")
    print(f"  plan_sha256: {attestation['plan_sha256']}")
    print(f"  risk: {risk.score} ({risk.band}) — {summarise(plan)}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Re-plan hash must equal the attested hash, or the apply stops."""
    plan = load_plan(args.plan)
    try:
        attestation = json.loads(args.attestation.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"PlanGuard: FAIL — attestation file not found: {args.attestation}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"PlanGuard: FAIL — attestation is not valid JSON: {exc}", file=sys.stderr)
        return 1

    fresh_hash = plan_hash(plan)
    expected_hash = attestation.get("plan_sha256", "")
    if fresh_hash != expected_hash:
        print("PlanGuard: FAIL — plan has changed since it was approved.", file=sys.stderr)
        print(f"  attested: {expected_hash} (commit {attestation.get('commit_sha')}, "
              f"PR #{attestation.get('pull_request')}, by {attestation.get('actor')})", file=sys.stderr)
        print(f"  fresh:    {fresh_hash}", file=sys.stderr)
        print("  Do not apply. Open a new PR so the new plan gets reviewed.", file=sys.stderr)
        return 1

    print(f"PlanGuard: OK — fresh plan matches attested plan ({fresh_hash[:12]}…).")
    print(f"  Approved in PR #{attestation.get('pull_request')} "
          f"by {attestation.get('actor')}, risk was "
          f"{attestation.get('risk', {}).get('score')} "
          f"({attestation.get('risk', {}).get('band')}).")
    return 0


def cmd_score(args: argparse.Namespace) -> int:
    """Print the risk score for a plan, as text or JSON."""
    plan = load_plan(args.plan)
    risk = score_plan(plan)
    if args.format == "json":
        print(json.dumps(risk.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Risk: {risk.score} ({risk.band})")
        for finding in risk.findings:
            print(f"  +{finding.points:2d}  {finding.address}: {finding.reason}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="planguard",
        description="Attest a Terraform plan in a PR, verify it again before apply.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    attest = sub.add_parser("attest", help="Hash + score a plan, write attestation.json")
    attest.add_argument("--plan", type=Path, required=True, help="terraform show -json output")
    attest.add_argument("--out", type=Path, required=True, help="Attestation file to write")
    attest.add_argument("--commit", default="", help="Commit SHA being attested")
    attest.add_argument("--pr", default="", help="Pull request number")
    attest.add_argument("--actor", default="", help="Who triggered the run")
    attest.add_argument("--env", default="", help="Environment (dev / prod)")
    attest.set_defaults(func=cmd_attest)

    verify = sub.add_parser("verify", help="Fail unless the fresh plan matches the attestation")
    verify.add_argument("--plan", type=Path, required=True, help="Fresh plan JSON")
    verify.add_argument("--attestation", type=Path, required=True, help="Attestation from the PR")
    verify.set_defaults(func=cmd_verify)

    score = sub.add_parser("score", help="Print the risk score for a plan")
    score.add_argument("--plan", type=Path, required=True, help="terraform show -json output")
    score.add_argument("--format", choices=["text", "json"], default="text")
    score.set_defaults(func=cmd_score)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
