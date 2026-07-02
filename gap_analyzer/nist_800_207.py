#!/usr/bin/env python3
"""
gap_analyzer/nist_800_207.py — NIST SP 800-207 Zero Trust gap analyzer.

Collects live AWS configuration data, scores each of the seven NIST SP 800-207
zero trust tenets on a 0–3 scale, calls Claude to generate prioritised
remediation recommendations, and exports a markdown report.

Usage:
    python3 nist_800_207.py \\
        [--region us-east-1]   \\
        [--output report.md]   \\
        [--dry-run]            \\
        [--no-ai]              \\
        [--profile my-profile]

Score scale:
    0 — Missing:     control absent or unconfigured
    1 — Partial:     control exists but incomplete or manual
    2 — Implemented: fully configured and operational
    3 — Automated:   enforced by policy and continuously monitored

IAM permissions required:
    SecurityAudit managed policy (covers most read-only calls)
    guardduty:ListDetectors, guardduty:GetDetector
    cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus, cloudtrail:GetTrail
    securityhub:GetEnabledStandards, securityhub:DescribeHub
    accessanalyzer:ListAnalyzers
    inspector2:BatchGetAccountStatus
    config:DescribeConfigurationRecorders, config:DescribeConformancePacks
    wafv2:ListWebACLs
    macie2:GetMacieSession
    sso-admin:ListInstances
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import boto3
import anthropic
from botocore.exceptions import ClientError

try:
    from controls.aws_controls_map import TENETS, SCORE_LABELS, NistTenet, AwsControl
except ImportError:
    from aws_controls_map import TENETS, SCORE_LABELS, NistTenet, AwsControl

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

MODEL      = "claude-sonnet-4-6"
MAX_TOKENS = 4096


# ── Score result ──────────────────────────────────────────────────────────────

@dataclass
class ControlScore:
    control_id: str
    score:      int           # 0–3
    evidence:   str           # what the API call found
    raw:        dict = field(default_factory=dict)  # raw boto3 response snippets


@dataclass
class TenetScore:
    tenet_id:       int
    title:          str
    weighted_score: float     # 0.0–3.0 weighted average of control scores
    max_score:      float     # maximum achievable weighted score
    pct:            float     # weighted_score / max_score * 100
    control_scores: list[ControlScore] = field(default_factory=list)
    label:          str = ""  # SCORE_LABELS[round(weighted_score)]


@dataclass
class GapReport:
    account_id:    str
    region:        str
    generated_at:  str
    tenet_scores:  list[TenetScore] = field(default_factory=list)
    overall_pct:   float = 0.0
    ai_narrative:  str = ""
    ai_priorities: list[str] = field(default_factory=list)


# ── AWS data collectors ───────────────────────────────────────────────────────

def safe_call(fn, *args, default=None, **kwargs):
    """Call a boto3 method, returning default on ClientError."""
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.debug("API call failed (%s): %s", code, exc)
        return default


class AwsCollector:
    """
    Collects AWS configuration state for all gap analyzer controls.
    One instance per run; caches results to avoid duplicate API calls.
    """

    def __init__(self, session: boto3.Session, region: str):
        self.session = session
        self.region  = region
        self._cache: dict = {}

    def _client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region or self.region)

    # ── Tenet 1: resource inventory ───────────────────────────────────────────

    def score_config_recorder(self) -> ControlScore:
        config = self._client("config")
        recorders = safe_call(
            config.describe_configuration_recorders, default={}
        )
        statuses = safe_call(
            config.describe_configuration_recorder_status, default={}
        )

        recs = (recorders or {}).get("ConfigurationRecorders", [])
        stats = (statuses or {}).get("ConfigurationRecordersStatus", [])

        if not recs:
            return ControlScore("ec2.inventory.config", 0,
                                "AWS Config not enabled in this region.", {})

        rec    = recs[0]
        status = stats[0] if stats else {}
        all_types = rec.get("recordingGroup", {}).get("allSupported", False)
        recording = status.get("recording", False)

        # Check for conformance packs (score=3 indicator)
        packs = safe_call(
            config.describe_conformance_packs, default={}
        )
        has_packs = bool((packs or {}).get("ConformancePackDetails"))

        if has_packs and all_types and recording:
            score = 3
            evidence = "Config recording all types with conformance packs."
        elif all_types and recording:
            score = 2
            evidence = "Config enabled recording all supported resource types."
        elif recording:
            score = 1
            evidence = "Config enabled but not recording all resource types."
        else:
            score = 0
            evidence = "Config recorder exists but is not recording."

        return ControlScore("ec2.inventory.config", score, evidence,
                            {"recorder": rec, "status": status})

    def score_ssm_inventory(self) -> ControlScore:
        ssm = self._client("ssm")
        info = safe_call(
            ssm.describe_instance_information,
            Filters=[{"Key": "PingStatus", "Values": ["Online"]}],
            default={}
        )
        instances = (info or {}).get("InstanceInformationList", [])
        count = len(instances)

        ec2 = self._client("ec2")
        running = safe_call(
            ec2.describe_instances,
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}],
            default={}
        )
        reservations  = (running or {}).get("Reservations", [])
        ec2_count = sum(len(r.get("Instances", [])) for r in reservations)

        if count == 0:
            score, evidence = 0, "No instances managed by SSM."
        elif ec2_count > 0 and count >= ec2_count:
            score, evidence = 2, f"All {ec2_count} running EC2 instances managed by SSM."
        else:
            score, evidence = 1, (
                f"{count} of {ec2_count} running instances managed by SSM."
            )

        return ControlScore("ec2.inventory.ssm", score, evidence,
                            {"ssm_count": count, "ec2_count": ec2_count})

    # ── Tenet 2: secure communication ─────────────────────────────────────────

    def score_vpc_flow_logs(self) -> ControlScore:
        ec2 = self._client("ec2")
        vpcs = safe_call(ec2.describe_vpcs, default={})
        vpc_ids = [v["VpcId"] for v in (vpcs or {}).get("Vpcs", [])]

        if not vpc_ids:
            return ControlScore("vpc.flow_logs.enabled", 0,
                                "No VPCs found.", {})

        logs = safe_call(
            ec2.describe_flow_logs,
            Filters=[{"Name": "resource-id", "Values": vpc_ids}],
            default={}
        )
        logged_vpcs = {
            fl["ResourceId"] for fl in (logs or {}).get("FlowLogs", [])
            if fl.get("FlowLogStatus") == "ACTIVE"
        }

        covered = len(logged_vpcs)
        total   = len(vpc_ids)

        if covered == 0:
            score, evidence = 0, f"VPC Flow Logs not enabled on any of {total} VPC(s)."
        elif covered < total:
            score, evidence = 1, (
                f"Flow Logs enabled on {covered}/{total} VPCs. "
                f"Missing: {sorted(set(vpc_ids) - logged_vpcs)[:3]}."
            )
        else:
            score, evidence = 2, f"Flow Logs active on all {total} VPC(s)."

        return ControlScore("vpc.flow_logs.enabled", score, evidence,
                            {"vpcs": vpc_ids, "logged": list(logged_vpcs)})

    # ── Tenet 3: per-session access ────────────────────────────────────────────

    def score_iam_password_policy(self) -> ControlScore:
        iam = self._client("iam")
        policy = safe_call(iam.get_account_password_policy, default={})
        pp = (policy or {}).get("PasswordPolicy", {})

        if not pp:
            return ControlScore("iam.password_policy", 0,
                                "No custom IAM password policy set.", {})

        min_len    = pp.get("MinimumPasswordLength", 0)
        requires   = all([
            pp.get("RequireUppercaseCharacters"),
            pp.get("RequireLowercaseCharacters"),
            pp.get("RequireNumbers"),
            pp.get("RequireSymbols"),
        ])
        max_age    = pp.get("MaxPasswordAge", 999)
        reuse      = pp.get("PasswordReusePrevention", 0)

        if min_len >= 14 and requires and max_age <= 90 and reuse >= 24:
            score = 2
            evidence = f"Password policy meets CIS L1 ({min_len} chars, all complexity, {max_age}-day rotation, {reuse} reuse prevention)."
        elif min_len >= 8 and requires:
            score = 1
            evidence = f"Password policy exists but below CIS L1 (min_len={min_len}, max_age={max_age})."
        else:
            score = 1
            evidence = f"Weak password policy (min_len={min_len}, complexity incomplete)."

        return ControlScore("iam.password_policy", score, evidence, {"policy": pp})

    def score_root_mfa(self) -> ControlScore:
        iam = self._client("iam")
        summary = safe_call(iam.get_account_summary, default={})
        s = (summary or {}).get("SummaryMap", {})

        mfa_active   = s.get("AccountMFAEnabled", 0)
        root_keys    = s.get("AccountAccessKeysPresent", 0)

        if not mfa_active:
            score, evidence = 0, "Root account MFA NOT enabled."
        elif root_keys:
            score, evidence = 1, "Root MFA enabled but root access keys exist — delete them."
        else:
            score, evidence = 2, "Root MFA enabled; no root access keys."

        return ControlScore("iam.mfa.root", score, evidence,
                            {"mfa_active": mfa_active, "root_keys": root_keys})

    # ── Tenet 4: dynamic policy ────────────────────────────────────────────────

    def score_security_groups(self) -> ControlScore:
        ec2  = self._client("ec2")
        sgs  = safe_call(ec2.describe_security_groups, default={})
        sg_list = (sgs or {}).get("SecurityGroups", [])

        risky = []
        for sg in sg_list:
            for rule in sg.get("IpPermissions", []):
                fp = rule.get("FromPort", 0)
                tp = rule.get("ToPort", 65535)
                for cidr in rule.get("IpRanges", []):
                    if cidr.get("CidrIp") == "0.0.0.0/0" and (
                        (fp <= 22 <= tp) or (fp <= 3389 <= tp)
                    ):
                        risky.append(sg["GroupId"])
                for cidr in rule.get("Ipv6Ranges", []):
                    if cidr.get("CidrIpv6") == "::/0" and (
                        (fp <= 22 <= tp) or (fp <= 3389 <= tp)
                    ):
                        risky.append(sg["GroupId"])

        risky = list(set(risky))
        if risky:
            score = 0
            evidence = (
                f"{len(risky)} Security Group(s) allow 0.0.0.0/0 or ::/0 on "
                f"port 22/3389: {risky[:5]}."
            )
        else:
            score = 2
            evidence = (
                f"No Security Groups allow 0.0.0.0/0 or ::/0 on admin ports "
                f"across {len(sg_list)} SG(s) checked."
            )

        return ControlScore("sg.default_deny", score, evidence,
                            {"risky_sgs": risky, "total_sgs": len(sg_list)})

    def score_guardduty(self) -> ControlScore:
        gd = self._client("guardduty")
        detectors = safe_call(gd.list_detectors, default={})
        ids = (detectors or {}).get("DetectorIds", [])

        if not ids:
            return ControlScore("guardduty.enabled", 0,
                                "GuardDuty not enabled in this region.", {})

        det = safe_call(
            gd.get_detector, DetectorId=ids[0], default={}
        )
        status = (det or {}).get("Status", "DISABLED")

        if status == "ENABLED":
            score, evidence = 2, f"GuardDuty enabled (detector {ids[0]})."
        else:
            score, evidence = 1, f"GuardDuty detector exists but status={status}."

        return ControlScore("guardduty.enabled", score, evidence,
                            {"detector_id": ids[0], "status": status})

    def score_security_hub(self) -> ControlScore:
        hub = self._client("securityhub")
        try:
            hub_resp = hub.describe_hub()
        except ClientError as e:
            if "not subscribed" in str(e).lower() or "InvalidAccess" in str(e):
                return ControlScore("securityhub.enabled", 0,
                                    "Security Hub not enabled.", {})
            return ControlScore("securityhub.enabled", 0, str(e), {})

        standards = safe_call(hub.get_enabled_standards, default={})
        subs = (standards or {}).get("StandardsSubscriptions", [])
        std_names = [s.get("StandardsArn", "").split("/")[-2] for s in subs]

        if not subs:
            score, evidence = 1, "Security Hub enabled but no standards subscribed."
        elif len(subs) >= 2:
            score, evidence = 2, f"Security Hub enabled with {len(subs)} standard(s): {std_names}."
        else:
            score, evidence = 2, f"Security Hub enabled with standard: {std_names}."

        return ControlScore("securityhub.enabled", score, evidence,
                            {"standards": std_names})

    # ── Tenet 5: continuous monitoring ────────────────────────────────────────

    def score_cloudtrail(self) -> ControlScore:
        ct = self._client("cloudtrail")
        trails = safe_call(ct.describe_trails, includeShadowTrails=False, default={})
        trail_list = (trails or {}).get("trailList", [])

        if not trail_list:
            return ControlScore("cloudtrail.enabled", 0,
                                "No CloudTrail trails configured.", {})

        multi_region = [t for t in trail_list if t.get("IsMultiRegionTrail")]
        if not multi_region:
            return ControlScore("cloudtrail.enabled", 1,
                                "CloudTrail configured but single-region only.", {})

        trail = multi_region[0]
        validated = trail.get("LogFileValidationEnabled", False)
        has_cw    = bool(trail.get("CloudWatchLogsLogGroupArn"))

        if validated and has_cw:
            score, evidence = 2, (
                f"Multi-region trail '{trail['Name']}' with log validation "
                f"and CloudWatch Logs integration."
            )
        elif validated:
            score, evidence = 2, (
                f"Multi-region trail '{trail['Name']}' with log file validation."
            )
        else:
            score, evidence = 1, (
                f"Multi-region trail '{trail['Name']}' but log validation disabled."
            )

        return ControlScore("cloudtrail.enabled", score, evidence,
                            {"trail": trail.get("Name"), "validated": validated,
                             "cloudwatch": has_cw})

    def score_cloudwatch_alarms(self) -> ControlScore:
        cw = self._client("cloudwatch")
        alarms = safe_call(
            cw.describe_alarms,
            StateValue="OK",
            MaxRecords=100,
            default={}
        )
        all_alarms_resp = safe_call(cw.describe_alarms, MaxRecords=100, default={})
        alarm_names = [
            a["AlarmName"].lower()
            for a in (all_alarms_resp or {}).get("MetricAlarms", [])
        ]

        # CIS benchmark expects alarms for these patterns
        cis_patterns = [
            "root", "unauthorized", "consolesignin", "mfa",
            "iamchanges", "cloudtrailchanges", "networkgw",
            "routetable", "vpc", "securitygroup",
        ]
        matched = sum(
            1 for p in cis_patterns
            if any(p in name for name in alarm_names)
        )

        if matched == 0:
            score, evidence = 0, "No security-related CloudWatch alarms found."
        elif matched < len(cis_patterns) // 2:
            score, evidence = 1, (
                f"Some security alarms ({matched}/{len(cis_patterns)} CIS patterns matched)."
            )
        else:
            score, evidence = 2, (
                f"CIS benchmark alarms in place ({matched}/{len(cis_patterns)} patterns matched)."
            )

        return ControlScore("cloudwatch.alarms", score, evidence,
                            {"matched_patterns": matched,
                             "total_alarms": len(alarm_names)})

    # ── Tenet 6: dynamic auth/authz ───────────────────────────────────────────

    def score_access_analyzer(self) -> ControlScore:
        aa = self._client("accessanalyzer")
        analyzers = safe_call(aa.list_analyzers, default={})
        alist = (analyzers or {}).get("analyzers", [])

        active = [a for a in alist if a.get("status") == "ACTIVE"]
        if not active:
            return ControlScore("iam.access_analyzer", 0,
                                "IAM Access Analyzer not enabled.", {})

        score, evidence = 2, (
            f"Access Analyzer active ({len(active)} analyzer(s))."
        )
        return ControlScore("iam.access_analyzer", score, evidence,
                            {"analyzers": [a["name"] for a in active]})

    def score_unused_credentials(self) -> ControlScore:
        iam = self._client("iam")
        report_resp = safe_call(iam.generate_credential_report, default={})
        if not report_resp:
            return ControlScore("iam.unused_credentials", 0,
                                "Could not generate credential report.", {})

        content_resp = safe_call(iam.get_credential_report, default={})
        if not content_resp:
            return ControlScore("iam.unused_credentials", 1,
                                "Credential report generated but could not be retrieved.", {})

        import csv
        from io import StringIO
        content = content_resp.get("Content", b"").decode("utf-8")
        reader  = csv.DictReader(StringIO(content))

        stale_keys  = []
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)

        for row in reader:
            if row.get("user") == "<root_account>":
                continue
            for key_num in ("1", "2"):
                last_used = row.get(f"access_key_{key_num}_last_used_date", "N/A")
                if last_used not in ("N/A", "no_information", "") :
                    try:
                        lu = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                        if lu < cutoff:
                            stale_keys.append(row["user"])
                    except ValueError:
                        pass

        if stale_keys:
            score, evidence = 1, (
                f"{len(stale_keys)} user(s) with access keys unused >90 days: "
                f"{stale_keys[:3]}{'...' if len(stale_keys) > 3 else ''}."
            )
        else:
            score, evidence = 2, "No access keys unused for >90 days."

        return ControlScore("iam.unused_credentials", score, evidence,
                            {"stale_count": len(stale_keys)})

    # ── Tenet 7: data collection and improvement ───────────────────────────────

    def score_config_conformance_packs(self) -> ControlScore:
        config = self._client("config")
        packs  = safe_call(config.describe_conformance_packs, default={})
        pack_list = (packs or {}).get("ConformancePackDetails", [])

        if not pack_list:
            return ControlScore("config.rules.compliance", 0,
                                "No AWS Config conformance packs deployed.", {})

        names = [p["ConformancePackName"] for p in pack_list]
        score, evidence = 2, f"{len(pack_list)} conformance pack(s) deployed: {names[:3]}."
        return ControlScore("config.rules.compliance", score, evidence,
                            {"packs": names})

    # ── Dispatch table ─────────────────────────────────────────────────────────

    def collect_all(self) -> dict[str, ControlScore]:
        """Run all collectors. Returns {control_id: ControlScore}."""
        collectors = {
            "ec2.inventory.config":      self.score_config_recorder,
            "ec2.inventory.ssm":         self.score_ssm_inventory,
            "vpc.flow_logs.enabled":     self.score_vpc_flow_logs,
            "iam.password_policy":       self.score_iam_password_policy,
            "iam.mfa.root":              self.score_root_mfa,
            "sg.default_deny":           self.score_security_groups,
            "guardduty.enabled":         self.score_guardduty,
            "securityhub.enabled":       self.score_security_hub,
            "cloudtrail.enabled":        self.score_cloudtrail,
            "cloudwatch.alarms":         self.score_cloudwatch_alarms,
            "iam.access_analyzer":       self.score_access_analyzer,
            "iam.unused_credentials":    self.score_unused_credentials,
            "config.rules.compliance":   self.score_config_conformance_packs,
        }
        results: dict[str, ControlScore] = {}
        for control_id, fn in collectors.items():
            log.info("  Assessing %s ...", control_id)
            try:
                results[control_id] = fn()
            except Exception as exc:
                log.warning("  %s failed: %s", control_id, exc)
                results[control_id] = ControlScore(
                    control_id, 0, f"Assessment error: {exc}", {}
                )
        return results


# ── Scoring engine ────────────────────────────────────────────────────────────

def score_tenets(
    control_scores: dict[str, ControlScore]
) -> list[TenetScore]:
    """Compute weighted tenet scores from individual control scores."""
    tenet_scores = []

    for tenet in TENETS:
        weighted_sum = 0.0
        max_sum      = 0.0
        c_scores     = []

        for control in tenet.controls:
            cs = control_scores.get(
                control.control_id,
                ControlScore(control.control_id, 0, "Not assessed.", {}),
            )
            weighted_sum += cs.score * control.weight
            max_sum      += 3.0 * control.weight
            c_scores.append(cs)

        pct = (weighted_sum / max_sum * 100) if max_sum > 0 else 0.0
        raw_score = weighted_sum / (max_sum / 3.0) if max_sum > 0 else 0.0
        label = SCORE_LABELS.get(round(raw_score), "Unknown")

        tenet_scores.append(TenetScore(
            tenet_id=       tenet.tenet_id,
            title=          tenet.title,
            weighted_score= round(raw_score, 2),
            max_score=      3.0,
            pct=            round(pct, 1),
            control_scores= c_scores,
            label=          label,
        ))

    return tenet_scores


# ── Claude narrative ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior AWS cloud security architect writing a Zero Trust gap analysis
report for an engineering audience.

You will receive scored assessments of an AWS account against the seven NIST
SP 800-207 Zero Trust tenets. Each tenet has a score from 0 (missing) to 3
(automated) and evidence strings from live API calls.

Your output must be a JSON object with exactly two keys:
{
  "executive_summary": "3-4 sentence plain-English overview of overall posture",
  "priorities": [
    "Priority 1: <tenet name> — <specific action> — <expected impact>",
    "Priority 2: ...",
    ... (up to 7 priorities, one per tenet that needs improvement)
  ]
}

Rules:
- Order priorities by impact × effort (highest ROI first)
- Each priority must name the specific AWS service or API to configure
- Be concrete — "Enable GuardDuty in all regions via aws guardduty create-detector"
  not "Enable threat detection"
- Do not repeat the score numbers — explain what they mean for the business
- Return valid JSON only — no markdown, no preamble
"""


def build_narrative_prompt(tenet_scores: list[TenetScore], account_id: str) -> str:
    lines = [f"AWS Account: {account_id}\n", "Tenet Scores:\n"]
    for ts in tenet_scores:
        lines.append(f"\nTenet {ts.tenet_id}: {ts.title}")
        lines.append(f"  Score: {ts.weighted_score:.1f}/3.0 ({ts.pct:.0f}%) — {ts.label}")
        for cs in ts.control_scores:
            lines.append(f"  [{cs.score}/3] {cs.control_id}: {cs.evidence}")
    return "\n".join(lines)


def call_claude_for_narrative(
    tenet_scores: list[TenetScore],
    account_id: str,
    api_key: str,
) -> tuple[str, list[str]]:
    """Call Claude and return (executive_summary, priorities)."""
    client = anthropic.Anthropic(api_key=api_key)
    prompt = build_narrative_prompt(tenet_scores, account_id)

    log.info("Calling Claude for narrative (%s) ...", MODEL)
    message = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1].lstrip("json").strip()
        raw = raw.rsplit("```", 1)[0].strip()

    try:
        parsed = json.loads(raw)
        return (
            parsed.get("executive_summary", ""),
            parsed.get("priorities", []),
        )
    except json.JSONDecodeError:
        log.warning("Claude returned non-JSON; using raw text as summary.")
        return raw, []


# ── Markdown report ───────────────────────────────────────────────────────────

SCORE_BARS = {0: "░░░░░", 1: "█░░░░", 2: "███░░", 3: "█████"}
SCORE_EMOJIS = {0: "🔴", 1: "🟠", 2: "🟡", 3: "🟢"}


def render_markdown(report: GapReport) -> str:
    lines = []

    lines += [
        f"# Zero Trust Gap Analysis — NIST SP 800-207",
        f"",
        f"**Account:** `{report.account_id}`  ",
        f"**Region:** `{report.region}`  ",
        f"**Generated:** {report.generated_at}  ",
        f"**Overall score:** {report.overall_pct:.1f}%",
        f"",
    ]

    if report.ai_narrative:
        lines += ["## Executive Summary", "", report.ai_narrative, ""]

    # Score summary table
    lines += [
        "## Tenet Score Summary",
        "",
        "| # | Tenet | Score | Status |",
        "|---|-------|-------|--------|",
    ]
    for ts in report.tenet_scores:
        bar   = SCORE_BARS.get(round(ts.weighted_score), "░░░░░")
        emoji = SCORE_EMOJIS.get(round(ts.weighted_score), "⚪")
        short_title = ts.title[:55] + "…" if len(ts.title) > 55 else ts.title
        lines.append(
            f"| {ts.tenet_id} | {short_title} "
            f"| {bar} {ts.weighted_score:.1f}/3.0 ({ts.pct:.0f}%) "
            f"| {emoji} {ts.label} |"
        )
    lines.append("")

    if report.ai_priorities:
        lines += ["## Remediation Priorities", ""]
        for i, p in enumerate(report.ai_priorities, 1):
            lines.append(f"{i}. {p}")
        lines.append("")

    # Detailed tenet breakdown
    lines += ["## Detailed Findings", ""]
    for ts in report.tenet_scores:
        emoji = SCORE_EMOJIS.get(round(ts.weighted_score), "⚪")
        lines += [
            f"### Tenet {ts.tenet_id}: {ts.title}",
            f"",
            f"**Score:** {emoji} {ts.weighted_score:.1f}/3.0 ({ts.pct:.0f}%) — {ts.label}",
            f"",
            f"| Control | Score | Evidence |",
            f"|---------|-------|----------|",
        ]
        for cs in ts.control_scores:
            e_short = cs.evidence[:90] + "…" if len(cs.evidence) > 90 else cs.evidence
            lines.append(
                f"| `{cs.control_id}` | {cs.score}/3 | {e_short} |"
            )
        lines.append("")

    lines += [
        "---",
        f"*Generated by zero-trust-aws gap analyzer · "
        f"NIST SP 800-207 · {report.generated_at}*",
    ]

    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def resolve_api_key() -> str:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        secret_id = os.environ.get("AWS_SECRET_ID", "")
        if secret_id:
            sm = boto3.client("secretsmanager")
            try:
                val = sm.get_secret_value(SecretId=secret_id)
                raw = val.get("SecretString", "")
                try:
                    return json.loads(raw)["api_key"]
                except (json.JSONDecodeError, KeyError):
                    return raw.strip()
            except ClientError as exc:
                log.error("Secrets Manager: %s", exc)
                sys.exit(1)
        log.error("No API key. Set ANTHROPIC_API_KEY or AWS_SECRET_ID.")
        sys.exit(1)
    return key


def parse_args() -> argparse.Namespace: # pragma: no cover
    p = argparse.ArgumentParser(
        description="NIST SP 800-207 Zero Trust gap analyzer for AWS."
    )
    p.add_argument("--region",  default="us-east-1")
    p.add_argument("--output",  metavar="FILE",
                   help="Write markdown report to file (default: stdout).")
    p.add_argument("--json-output", metavar="FILE",
                   help="Also write raw JSON scores to file.")
    p.add_argument("--dry-run", action="store_true",
                   help="Collect data and score; skip Claude API call.")
    p.add_argument("--no-ai",   action="store_true",
                   help="Skip AI narrative entirely.")
    p.add_argument("--profile", help="AWS named profile.")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


def main() -> None: # pragma: no cover
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    session    = boto3.Session(profile_name=args.profile)
    account_id = session.client("sts").get_caller_identity()["Account"]

    log.info("Gap analysis: account=%s region=%s", account_id, args.region)
    log.info("Collecting AWS configuration data ...")

    collector     = AwsCollector(session, args.region)
    control_scores = collector.collect_all()

    log.info("Scoring tenets ...")
    tenet_scores = score_tenets(control_scores)
    overall_pct  = sum(ts.pct for ts in tenet_scores) / len(tenet_scores)

    report = GapReport(
        account_id=   account_id,
        region=       args.region,
        generated_at= datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        tenet_scores= tenet_scores,
        overall_pct=  round(overall_pct, 1),
    )

    if not args.no_ai and not args.dry_run:
        api_key = resolve_api_key()
        summary, priorities = call_claude_for_narrative(
            tenet_scores, account_id, api_key
        )
        report.ai_narrative  = summary
        report.ai_priorities = priorities

    markdown = render_markdown(report)

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(markdown)
        log.info("Report written to %s", args.output)
    else:
        print(markdown)

    if args.json_output:
        raw_json = {
            "account_id":  report.account_id,
            "region":      report.region,
            "generated_at":report.generated_at,
            "overall_pct": report.overall_pct,
            "tenets": [
                {
                    "tenet_id":       ts.tenet_id,
                    "title":          ts.title,
                    "weighted_score": ts.weighted_score,
                    "pct":            ts.pct,
                    "label":          ts.label,
                    "controls": [
                        {"control_id": cs.control_id,
                         "score": cs.score,
                         "evidence": cs.evidence}
                        for cs in ts.control_scores
                    ],
                }
                for ts in tenet_scores
            ],
        }
        with open(args.json_output, "w") as fh:
            json.dump(raw_json, fh, indent=2)
        log.info("JSON scores written to %s", args.json_output)

    log.info("Overall score: %.1f%%", overall_pct)
    for ts in tenet_scores:
        log.info("  Tenet %d: %.1f/3.0 (%s)", ts.tenet_id,
                 ts.weighted_score, ts.label)


if __name__ == "__main__": # pragma: no cover
    main()