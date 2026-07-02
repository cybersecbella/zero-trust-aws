#!/usr/bin/env python3
"""
sg_diff.py — AI-assisted Security Group rule reviewer.

Diffs before/after SG JSON snapshots written by ansible/playbooks/harden.yml,
sends the delta to Claude with workload context, and returns structured findings.

Usage (standalone):
    python3 sg_diff.py \\
        --before /tmp/sg_before_web-01.json \\
        --after  /tmp/sg_after_web-01.json  \\
        --instance web-01                   \\
        --role app                          \\
        --env prod                          \\
        --owner platform-team               \\
        [--output findings.json]            \\
        [--fail-on critical]                \\
        [--dry-run]

Called by ansible/playbooks/ai_review.yml after each hardening run.
Exits 0 (clean), 1 (warnings), or 2 (critical findings) so Ansible
can gate the play accordingly.

Environment variables:
    ANTHROPIC_API_KEY   — required (or fetch from AWS Secrets Manager)
    AWS_SECRET_ID       — optional, e.g. prod/anthropic/api-key
                          if set, key is fetched from Secrets Manager
                          and ANTHROPIC_API_KEY is ignored.

IAM permissions (when using Secrets Manager):
    secretsmanager:GetSecretValue on the secret ARN
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Optional

import anthropic
import boto3
from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MODEL          = "claude-sonnet-4-6"
MAX_TOKENS     = 2048
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# Exit codes consumed by ai_review.yml
EXIT_CLEAN    = 0
EXIT_WARNINGS = 1
EXIT_CRITICAL = 2

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class RuleDelta:
    added:    list[dict] = field(default_factory=list)
    removed:  list[dict] = field(default_factory=list)
    unchanged: list[dict] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


@dataclass
class ReviewFinding:
    severity:      str          # critical | high | medium | low | info
    rule_id:       str          # identifies the specific rule
    finding:       str          # plain-English description of the issue
    suggested_fix: str          # concrete remediation
    rule_snapshot: dict         # the raw rule that triggered this


@dataclass
class ReviewResult:
    instance:   str
    role:       str
    env:        str
    findings:   list[ReviewFinding] = field(default_factory=list)
    summary:    str = ""
    clean:      bool = True

    @property
    def max_severity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER.index(f.severity)).severity


# ── API key resolution ────────────────────────────────────────────────────────

def resolve_api_key() -> str:
    """
    Fetch the Anthropic API key.
    Prefers AWS Secrets Manager (AWS_SECRET_ID env var) over a plaintext
    env var — never hardcode keys or pass them on the command line.
    """
    secret_id = os.environ.get("AWS_SECRET_ID")
    if secret_id:
        log.info("Fetching API key from Secrets Manager: %s", secret_id)
        try:
            sm  = boto3.client("secretsmanager")
            val = sm.get_secret_value(SecretId=secret_id)
            # Secret may be a raw string or a JSON dict {"api_key": "sk-ant-..."}
            raw = val.get("SecretString", "")
            try:
                return json.loads(raw)["api_key"]
            except (json.JSONDecodeError, KeyError):
                return raw.strip()
        except ClientError as exc:
            log.error("Secrets Manager fetch failed: %s", exc)
            sys.exit(1)

    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        log.error(
            "No API key found. Set ANTHROPIC_API_KEY or AWS_SECRET_ID."
        )
        sys.exit(1)
    return key


# ── SG snapshot diffing ───────────────────────────────────────────────────────

def _normalise_rule(rule: dict) -> dict:
    """
    Produce a canonical, hashable representation of an SG ingress rule
    so diffs are stable regardless of key ordering or AWS response variation.
    """
    return {
        "protocol":   rule.get("IpProtocol", "-1"),
        "from_port":  rule.get("FromPort",    0),
        "to_port":    rule.get("ToPort",      65535),
        "ipv4_cidrs": sorted(
            r.get("CidrIp", "") for r in rule.get("IpRanges", [])
        ),
        "ipv6_cidrs": sorted(
            r.get("CidrIpv6", "") for r in rule.get("Ipv6Ranges", [])
        ),
        "prefix_lists": sorted(
            r.get("PrefixListId", "") for r in rule.get("PrefixListIds", [])
        ),
        "sg_sources": sorted(
            p.get("GroupId", "") for p in rule.get("UserIdGroupPairs", [])
        ),
    }


def _rule_key(normalised: dict) -> str:
    """Stable string key for set comparison."""
    return json.dumps(normalised, sort_keys=True)


def diff_snapshots(before_path: str, after_path: str) -> RuleDelta:
    """
    Load two SG JSON snapshots and return added/removed/unchanged rules.
    The snapshots contain a list of SG objects each with IpPermissions.
    """
    def load(path: str) -> dict[str, list[dict]]:
        """Returns {sg_id: [normalised_rules]}"""
        with open(path) as fh:
            data = json.load(fh)

        # Handle both a bare list of SGs and the boto3 wrapper shape
        sgs = data if isinstance(data, list) else data.get("SecurityGroups", [])
        result: dict[str, list[dict]] = {}
        for sg in sgs:
            sg_id = sg.get("GroupId", "unknown")
            result[sg_id] = [
                _normalise_rule(r) for r in sg.get("IpPermissions", [])
            ]
        return result

    before = load(before_path)
    after  = load(after_path)

    all_sg_ids = set(before) | set(after)
    delta = RuleDelta()

    for sg_id in all_sg_ids:
        before_rules = {_rule_key(r): r for r in before.get(sg_id, [])}
        after_rules  = {_rule_key(r): r for r in after.get(sg_id, [])}

        for key, rule in after_rules.items():
            enriched = dict(rule, sg_id=sg_id)
            if key not in before_rules:
                delta.added.append(enriched)
            else:
                delta.unchanged.append(enriched)

        for key, rule in before_rules.items():
            if key not in after_rules:
                delta.removed.append(dict(rule, sg_id=sg_id))

    return delta


# ── Prompt construction ───────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior AWS cloud security engineer reviewing Security Group rule changes
after an Ansible CIS Level 2 hardening run on an EC2 instance.

Your job is to identify unintended consequences, security regressions, and
overly permissive rules in the changed rule set. You are NOT reviewing the
hardening itself — only the firewall rule delta.

Be precise and practical. Flag real risks, not theoretical ones. A rule that
opens port 22 to 0.0.0.0/0 on a production app server is critical. A rule that
opens port 443 to 0.0.0.0/0 on a public web server is expected.

Always respond with valid JSON only. No preamble, no markdown, no explanation
outside the JSON structure. Your response must parse with json.loads().

Response schema:
{
  "summary": "One paragraph plain-English summary of the overall risk posture.",
  "clean": true | false,
  "findings": [
    {
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "rule_id": "sg-xxxxxxxx:tcp:22:0.0.0.0/0",
      "finding": "Plain-English description of the specific issue.",
      "suggested_fix": "Concrete remediation action."
    }
  ]
}

Severity guide:
  critical — immediate exploitation risk (public internet to admin ports, all-traffic open)
  high     — significant exposure (wide port ranges, internet access to sensitive services)
  medium   — notable but lower risk (internal over-exposure, missing egress restrictions)
  low      — minor policy deviation, defence-in-depth gap
  info     — observation with no immediate risk

If there are no concerns, return findings: [] and clean: true.
"""


def build_user_prompt(
    instance: str,
    role: str,
    env: str,
    owner: str,
    delta: RuleDelta,
) -> str:
    return f"""
Review the following Security Group rule changes for this EC2 instance:

Instance:    {instance}
Role:        {role}
Environment: {env}
Owner:       {owner}

ADDED rules (newly permitted traffic — highest scrutiny required):
{json.dumps(delta.added, indent=2) if delta.added else "  (none)"}

REMOVED rules (traffic that is now blocked):
{json.dumps(delta.removed, indent=2) if delta.removed else "  (none)"}

UNCHANGED rules (context only — do not flag these unless they interact badly
with the added rules):
{json.dumps(delta.unchanged[:20], indent=2) if delta.unchanged else "  (none)"}
{"  ... and " + str(len(delta.unchanged) - 20) + " more unchanged rules (truncated)" if len(delta.unchanged) > 20 else ""}

Focus your review on the ADDED rules. Consider:
1. Does any added rule expose admin ports (22, 3389, 5985, 5986) to the internet?
2. Does any added rule permit all traffic (-1 protocol) from a broad CIDR?
3. Is any added rule inconsistent with the declared instance role ({role})?
4. Do any added rules interact with unchanged rules to create an unexpected
   attack path (e.g. a new rule that bridges two previously isolated segments)?
5. Are any removed rules security-critical (their removal increases exposure)?

Respond with JSON only.
""".strip()


# ── Claude API call ───────────────────────────────────────────────────────────

def call_claude(
    client: anthropic.Anthropic,
    user_prompt: str,
    dry_run: bool = False,
) -> dict:
    """
    Send the diff prompt to Claude and parse the structured JSON response.
    Returns the parsed findings dict.
    """
    if dry_run:
        log.info("[dry-run] Skipping Claude API call. Returning mock clean result.")
        return {"summary": "Dry run — no API call made.", "clean": True, "findings": []}

    log.info("Calling Claude API (%s) ...", MODEL)
    message = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw = message.content[0].text.strip()
    log.debug("Raw Claude response:\n%s", raw)

    # Strip markdown code fences if the model wraps despite instructions
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        log.error("Claude returned non-JSON response: %s", exc)
        log.error("Raw response: %s", raw)
        sys.exit(1)


# ── Result parsing ────────────────────────────────────────────────────────────

def parse_review_result(
    response: dict,
    instance: str,
    role: str,
    env: str,
    delta: RuleDelta,
) -> ReviewResult:
    """Convert Claude's JSON response into a typed ReviewResult."""
    findings = []
    for raw_f in response.get("findings", []):
        # Match the rule snapshot to the finding's rule_id for traceability
        rule_id = raw_f.get("rule_id", "unknown")
        sg_id   = rule_id.split(":")[0] if ":" in rule_id else "unknown"
        snapshot = next(
            (r for r in delta.added if r.get("sg_id") == sg_id),
            {}
        )
        findings.append(ReviewFinding(
            severity=      raw_f.get("severity",      "info"),
            rule_id=       rule_id,
            finding=       raw_f.get("finding",       ""),
            suggested_fix= raw_f.get("suggested_fix", ""),
            rule_snapshot= snapshot,
        ))

    return ReviewResult(
        instance= instance,
        role=     role,
        env=      env,
        findings= findings,
        summary=  response.get("summary", ""),
        clean=    response.get("clean",   not bool(findings)),
    )


# ── Output formatters ─────────────────────────────────────────────────────────

def print_report(result: ReviewResult, delta: RuleDelta) -> None:
    """Human-readable console report."""
    SEV_COLOURS = {
        "critical": "\033[91m",  # bright red
        "high":     "\033[33m",  # yellow
        "medium":   "\033[93m",  # bright yellow
        "low":      "\033[94m",  # blue
        "info":     "\033[37m",  # grey
    }
    RESET = "\033[0m"

    print(f"\n{'─' * 60}")
    print(f"  AI Rule Review — {result.instance} ({result.env}/{result.role})")
    print(f"{'─' * 60}")
    print(f"  Added rules:   {len(delta.added)}")
    print(f"  Removed rules: {len(delta.removed)}")
    print(f"  Findings:      {len(result.findings)}")
    print(f"  Max severity:  {result.max_severity or 'none'}")
    print(f"{'─' * 60}\n")

    if result.summary:
        print(f"Summary:\n  {result.summary}\n")

    if not result.findings:
        print("  ✓ No issues found.\n")
        return

    for f in sorted(result.findings,
                    key=lambda x: SEVERITY_ORDER.index(x.severity),
                    reverse=True):
        colour = SEV_COLOURS.get(f.severity, "")
        print(f"  {colour}[{f.severity.upper()}]{RESET}  {f.rule_id}")
        print(f"  Finding:     {f.finding}")
        print(f"  Fix:         {f.suggested_fix}")
        print()


def to_json_output(result: ReviewResult) -> dict:
    """Machine-readable output for Ansible consumption."""
    return {
        "instance":     result.instance,
        "role":         result.role,
        "env":          result.env,
        "clean":        result.clean,
        "max_severity": result.max_severity,
        "summary":      result.summary,
        "findings": [
            {
                "severity":      f.severity,
                "rule_id":       f.rule_id,
                "finding":       f.finding,
                "suggested_fix": f.suggested_fix,
            }
            for f in result.findings
        ],
    }


# ── Exit code logic ───────────────────────────────────────────────────────────

def exit_code(result: ReviewResult, fail_on: str) -> int:
    """
    Determine exit code based on max finding severity and the --fail-on threshold.
    Ansible's ai_review.yml checks this to gate the hardening play.
    """
    if not result.findings:
        return EXIT_CLEAN

    max_sev = result.max_severity
    fail_idx = SEVERITY_ORDER.index(fail_on)
    max_idx  = SEVERITY_ORDER.index(max_sev)

    if max_idx >= SEVERITY_ORDER.index("critical"):
        return EXIT_CRITICAL
    if max_idx >= fail_idx:
        return EXIT_WARNINGS
    return EXIT_CLEAN


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace: # pragma: no cover
    p = argparse.ArgumentParser(
        description="AI-assisted Security Group rule reviewer."
    )
    p.add_argument("--before",    required=True,
                   help="Path to pre-hardening SG JSON snapshot.")
    p.add_argument("--after",     required=True,
                   help="Path to post-hardening SG JSON snapshot.")
    p.add_argument("--instance",  required=True,
                   help="Instance hostname or ID (for context).")
    p.add_argument("--role",      default="unknown",
                   help="Instance role tag (e.g. app, bastion, data).")
    p.add_argument("--env",       default="unknown",
                   help="Environment tag (e.g. prod, staging, dev).")
    p.add_argument("--owner",     default="unknown",
                   help="Owner tag (e.g. platform-team).")
    p.add_argument("--output",    metavar="FILE",
                   help="Write JSON findings to this file.")
    p.add_argument("--fail-on",   default="high",
                   choices=SEVERITY_ORDER,
                   help="Exit non-zero if any finding meets this severity. "
                        "Default: high.")
    p.add_argument("--dry-run",   action="store_true",
                   help="Diff and print prompt but skip Claude API call.")
    p.add_argument("--verbose",   action="store_true",
                   help="Log Claude's raw response for debugging.")
    return p.parse_args()


def main() -> None: # pragma: no cover
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # ── Diff ──────────────────────────────────────────────────────────────────
    log.info("Diffing snapshots for %s ...", args.instance)
    delta = diff_snapshots(args.before, args.after)

    if not delta.has_changes:
        log.info("No rule changes detected for %s — skipping review.", args.instance)
        print(json.dumps({"instance": args.instance, "clean": True,
                          "summary": "No rule changes detected.", "findings": []}))
        sys.exit(EXIT_CLEAN)

    log.info("Delta: +%d added, -%d removed, %d unchanged",
             len(delta.added), len(delta.removed), len(delta.unchanged))

    # ── Prompt ────────────────────────────────────────────────────────────────
    user_prompt = build_user_prompt(
        instance=args.instance,
        role=args.role,
        env=args.env,
        owner=args.owner,
        delta=delta,
    )
    log.debug("Prompt:\n%s", user_prompt)

    # ── Claude ────────────────────────────────────────────────────────────────
    api_key = resolve_api_key() if not args.dry_run else "dry-run"
    client  = anthropic.Anthropic(api_key=api_key)
    raw_response = call_claude(client, user_prompt, dry_run=args.dry_run)

    # ── Parse ─────────────────────────────────────────────────────────────────
    result = parse_review_result(
        raw_response, args.instance, args.role, args.env, delta
    )

    # ── Report ────────────────────────────────────────────────────────────────
    print_report(result, delta)

    output = to_json_output(result)
    print(json.dumps(output, indent=2))

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(output, fh, indent=2)
        log.info("Findings written to %s", args.output)

    sys.exit(exit_code(result, args.fail_on))


if __name__ == "__main__": # pragma: no cover
    main()