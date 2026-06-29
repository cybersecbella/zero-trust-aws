"""
gap_analyzer/controls/aws_controls_map.py

Maps each of the seven NIST SP 800-207 Zero Trust tenets to:
  - The AWS services and controls that implement them
  - The boto3 API calls used to assess each control
  - Scoring rubric (0=missing, 1=partial, 2=implemented, 3=automated)

This module is data-only — no boto3 calls live here.
All assessment logic lives in nist_800_207.py.

Reference: NIST SP 800-207 Section 2.1 — Zero Trust Tenets
https://doi.org/10.6028/NIST.SP.800-207
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── Score labels ──────────────────────────────────────────────────────────────

SCORE_LABELS = {
    0: "Missing",
    1: "Partial",
    2: "Implemented",
    3: "Automated",
}

SCORE_DESCRIPTIONS = {
    0: "Control absent or not configured.",
    1: "Control exists but is incomplete, misconfigured, or manually operated.",
    2: "Control fully configured and operational.",
    3: "Control is fully automated, enforced by policy, and continuously monitored.",
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class AwsControl:
    """A single AWS control that contributes to a NIST tenet score."""
    control_id:   str          # e.g. "ec2.sg.default_deny"
    name:         str          # human-readable name
    service:      str          # AWS service (e.g. "EC2", "IAM", "GuardDuty")
    description:  str          # what this control does
    boto3_method: str          # how to assess it — e.g. "ec2:DescribeVpcs"
    score_rubric: dict[int, str]  # score → what earns that score
    weight:       float = 1.0  # relative importance within the tenet (1.0 = normal)


@dataclass
class NistTenet:
    """One of the seven NIST SP 800-207 zero trust tenets."""
    tenet_id:    int           # 1–7
    title:       str
    description: str           # verbatim from NIST SP 800-207
    controls:    list[AwsControl] = field(default_factory=list)


# ── The seven NIST tenets with AWS control mappings ───────────────────────────

TENETS: list[NistTenet] = [

    NistTenet(
        tenet_id=1,
        title="All data sources and computing services are considered resources",
        description=(
            "A network may consist of multiple classes of devices. An enterprise "
            "may also choose to classify personally-owned devices as resources if "
            "they can access enterprise-owned resources."
        ),
        controls=[
            AwsControl(
                control_id="ec2.inventory.config",
                name="AWS Config resource inventory",
                service="Config",
                description=(
                    "AWS Config continuously discovers and records EC2 instances, "
                    "RDS databases, S3 buckets, and all other resource types. "
                    "Required for complete resource visibility."
                ),
                boto3_method="config:DescribeConfigurationRecorders",
                score_rubric={
                    0: "AWS Config not enabled in this region.",
                    1: "Config enabled but not recording all resource types.",
                    2: "Config enabled and recording all supported resource types.",
                    3: "Config enabled with conformance packs and auto-remediation rules.",
                },
            ),
            AwsControl(
                control_id="ec2.inventory.ssm",
                name="SSM Systems Manager inventory",
                service="SSM",
                description=(
                    "SSM Inventory collects software, network, and OS configuration "
                    "data from managed instances. Provides visibility into what is "
                    "running on each resource."
                ),
                boto3_method="ssm:DescribeInstanceInformation",
                score_rubric={
                    0: "No instances managed by SSM.",
                    1: "Some instances managed by SSM.",
                    2: "All EC2 instances managed by SSM with inventory enabled.",
                    3: "SSM Fleet Manager with automated patch compliance and drift detection.",
                },
            ),
            AwsControl(
                control_id="ec2.tagging.enforcement",
                name="Resource tagging policy",
                service="Organizations",
                description=(
                    "Tag policies enforce consistent resource classification. "
                    "Required fields: Environment, Owner, DataClassification."
                ),
                boto3_method="organizations:DescribePolicyTypes",
                score_rubric={
                    0: "No tag policies defined.",
                    1: "Tag policies defined but not enforced.",
                    2: "Tag policies enforced via AWS Organizations.",
                    3: "Tag policies enforced with Config rules that auto-remediate untagged resources.",
                },
            ),
        ],
    ),

    NistTenet(
        tenet_id=2,
        title="All communication is secured regardless of network location",
        description=(
            "Network location alone does not imply trust. All communication should "
            "be done in the most secure manner available, protecting confidentiality "
            "and integrity."
        ),
        controls=[
            AwsControl(
                control_id="acm.tls.enforcement",
                name="TLS enforcement via ACM",
                service="ACM",
                description=(
                    "ACM manages TLS certificates for ALB, CloudFront, and API Gateway. "
                    "Enforcing HTTPS-only listeners eliminates plaintext internal traffic."
                ),
                boto3_method="acm:ListCertificates",
                score_rubric={
                    0: "No ACM certificates in use; plaintext traffic present.",
                    1: "Some services use TLS; others do not.",
                    2: "All public endpoints use ACM-managed TLS certificates.",
                    3: "All endpoints (including internal) use TLS; HTTP→HTTPS redirect enforced.",
                },
            ),
            AwsControl(
                control_id="vpc.flow_logs.enabled",
                name="VPC Flow Logs",
                service="EC2",
                description=(
                    "VPC Flow Logs capture metadata for all traffic within the VPC. "
                    "Essential for detecting unencrypted communication and lateral movement."
                ),
                boto3_method="ec2:DescribeFlowLogs",
                score_rubric={
                    0: "VPC Flow Logs not enabled on any VPC.",
                    1: "Flow Logs enabled on some VPCs.",
                    2: "Flow Logs enabled on all VPCs, shipping to CloudWatch or S3.",
                    3: "Flow Logs enabled with automated anomaly detection (GuardDuty/Athena).",
                },
                weight=1.5,
            ),
            AwsControl(
                control_id="macie.s3.encryption",
                name="S3 encryption and Macie",
                service="S3 / Macie",
                description=(
                    "S3 default encryption ensures data at rest is always encrypted. "
                    "Macie detects sensitive data and misconfigured public access."
                ),
                boto3_method="macie2:GetMacieSession",
                score_rubric={
                    0: "S3 buckets without default encryption exist; Macie not enabled.",
                    1: "Most buckets encrypted; Macie not running.",
                    2: "All buckets encrypted with SSE-S3 or SSE-KMS; Macie enabled.",
                    3: "All buckets encrypted with KMS CMK; Macie automated findings with EventBridge.",
                },
            ),
        ],
    ),

    NistTenet(
        tenet_id=3,
        title="Access to individual enterprise resources is granted on a per-session basis",
        description=(
            "Trust in the requester is evaluated before access is granted. Access "
            "should be granted with the least privileges needed to complete the task."
        ),
        controls=[
            AwsControl(
                control_id="iam.roles.instance_profiles",
                name="IAM instance profiles (not long-lived keys)",
                service="IAM",
                description=(
                    "EC2 instances should assume IAM roles via instance profiles "
                    "rather than embedding long-lived access keys. Role credentials "
                    "are rotated automatically every hour."
                ),
                boto3_method="iam:ListAccessKeys",
                score_rubric={
                    0: "Long-lived IAM keys in use on EC2 instances.",
                    1: "Mix of instance profiles and long-lived keys.",
                    2: "All EC2 instances use IAM roles; no embedded access keys.",
                    3: "All roles scoped with conditions (aws:RequestedRegion, aws:SourceVpc); keys audited via Config.",
                },
                weight=1.5,
            ),
            AwsControl(
                control_id="iam.password_policy",
                name="IAM password policy",
                service="IAM",
                description=(
                    "Strong password policy enforces minimum length, complexity, "
                    "rotation, and prevents reuse."
                ),
                boto3_method="iam:GetAccountPasswordPolicy",
                score_rubric={
                    0: "No custom password policy (AWS defaults apply).",
                    1: "Password policy exists but does not meet CIS benchmarks.",
                    2: "Password policy meets CIS Level 1 (14 chars, MFA, rotation).",
                    3: "SSO/IdP enforces authentication; IAM password policy is a backstop only.",
                },
            ),
            AwsControl(
                control_id="iam.mfa.root",
                name="MFA on root account",
                service="IAM",
                description=(
                    "Root account MFA is a CIS benchmark Level 1 control. "
                    "Root should never be used for day-to-day operations."
                ),
                boto3_method="iam:GetAccountSummary",
                score_rubric={
                    0: "Root account MFA not enabled.",
                    1: "Root MFA enabled but root used for operations.",
                    2: "Root MFA enabled; root not used for day-to-day operations.",
                    3: "Root access keys deleted; root login alerting via CloudTrail/EventBridge.",
                },
                weight=1.5,
            ),
            AwsControl(
                control_id="sts.session_policies",
                name="STS session policies and conditions",
                service="STS / IAM",
                description=(
                    "Per-session access is implemented via STS AssumeRole with "
                    "session policies that further restrict permissions below the "
                    "role's identity policy."
                ),
                boto3_method="iam:ListRoles",
                score_rubric={
                    0: "No use of STS session policies or role conditions.",
                    1: "Some roles use conditions; others grant broad access.",
                    2: "All human access via SSO with time-limited sessions.",
                    3: "All access uses STS with session tags and ABAC policies.",
                },
            ),
        ],
    ),

    NistTenet(
        tenet_id=4,
        title="Access to resources is determined by dynamic policy",
        description=(
            "The enterprise collects information about the state of client identity, "
            "application/service, and the requesting asset, and may consider other "
            "behavioral and environmental attributes."
        ),
        controls=[
            AwsControl(
                control_id="sg.default_deny",
                name="Security Group default deny",
                service="EC2",
                description=(
                    "Security Groups are allow-list only. The absence of a permitting "
                    "rule is an implicit deny. This tenet requires validating that "
                    "no Security Group allows unrestricted ingress on admin ports."
                ),
                boto3_method="ec2:DescribeSecurityGroups",
                score_rubric={
                    0: "Security Groups with 0.0.0.0/0 on port 22 or 3389 exist.",
                    1: "Some overly permissive rules exist on non-production accounts.",
                    2: "No Security Group allows 0.0.0.0/0 on admin ports in production.",
                    3: "Security Hub automated findings enforce SG hygiene; drift triggers auto-remediation.",
                },
                weight=2.0,
            ),
            AwsControl(
                control_id="guardduty.enabled",
                name="GuardDuty threat detection",
                service="GuardDuty",
                description=(
                    "GuardDuty provides continuous threat detection using ML and "
                    "threat intelligence. Feeds behavioral signals into dynamic "
                    "access policy decisions."
                ),
                boto3_method="guardduty:ListDetectors",
                score_rubric={
                    0: "GuardDuty not enabled.",
                    1: "GuardDuty enabled in some regions.",
                    2: "GuardDuty enabled in all active regions.",
                    3: "GuardDuty with automated EventBridge responses (isolate, notify, ticket).",
                },
                weight=1.5,
            ),
            AwsControl(
                control_id="securityhub.enabled",
                name="Security Hub centralised findings",
                service="Security Hub",
                description=(
                    "Security Hub aggregates findings from GuardDuty, Inspector, "
                    "Macie, and partner tools into a single pane. Required for "
                    "dynamic policy enforcement at scale."
                ),
                boto3_method="securityhub:GetEnabledStandards",
                score_rubric={
                    0: "Security Hub not enabled.",
                    1: "Security Hub enabled without standards.",
                    2: "Security Hub enabled with CIS AWS Foundations standard.",
                    3: "Security Hub with all standards, automated suppression, and SIEM integration.",
                },
            ),
            AwsControl(
                control_id="waf.enabled",
                name="AWS WAF on public endpoints",
                service="WAF",
                description=(
                    "WAF enforces dynamic request-level policy based on IP reputation, "
                    "rate limiting, and managed rule groups."
                ),
                boto3_method="wafv2:ListWebACLs",
                score_rubric={
                    0: "No WAF on public-facing ALBs or CloudFront.",
                    1: "WAF on some endpoints; others unprotected.",
                    2: "WAF on all public endpoints with AWS managed rules.",
                    3: "WAF with custom rules, rate limiting, and bot control; logs shipped to Athena.",
                },
            ),
        ],
    ),

    NistTenet(
        tenet_id=5,
        title="The enterprise monitors and measures the integrity and security posture of all owned and associated assets",
        description=(
            "The enterprise should monitor assets and log all traffic. Monitoring "
            "and evaluating the security posture of an asset should be an ongoing "
            "process."
        ),
        controls=[
            AwsControl(
                control_id="cloudtrail.enabled",
                name="CloudTrail multi-region trail",
                service="CloudTrail",
                description=(
                    "CloudTrail records all API calls across all regions. A "
                    "multi-region trail with log file validation is the baseline "
                    "for ongoing integrity monitoring."
                ),
                boto3_method="cloudtrail:DescribeTrails",
                score_rubric={
                    0: "No CloudTrail trail configured.",
                    1: "Single-region trail only.",
                    2: "Multi-region trail with log file validation and S3 encryption.",
                    3: "Multi-region trail with CloudWatch Logs integration and alerting on key events.",
                },
                weight=2.0,
            ),
            AwsControl(
                control_id="inspector.enabled",
                name="Amazon Inspector vulnerability scanning",
                service="Inspector",
                description=(
                    "Inspector continuously scans EC2 instances and container images "
                    "for software vulnerabilities and unintended network exposure."
                ),
                boto3_method="inspector2:BatchGetAccountStatus",
                score_rubric={
                    0: "Inspector not enabled.",
                    1: "Inspector enabled for EC2 only.",
                    2: "Inspector enabled for EC2 and ECR.",
                    3: "Inspector enabled for EC2, ECR, and Lambda; findings routed to Security Hub.",
                },
            ),
            AwsControl(
                control_id="cloudwatch.alarms",
                name="CloudWatch alarms on security metrics",
                service="CloudWatch",
                description=(
                    "CIS benchmark requires metric filters and alarms for root login, "
                    "unauthorised API calls, SG changes, and other security events."
                ),
                boto3_method="cloudwatch:DescribeAlarms",
                score_rubric={
                    0: "No security-related CloudWatch alarms.",
                    1: "Some alarms; does not cover CIS benchmark requirements.",
                    2: "All CIS benchmark alarms configured.",
                    3: "CIS alarms plus custom workload alarms; integrated with incident management.",
                },
            ),
        ],
    ),

    NistTenet(
        tenet_id=6,
        title="All resource authentication and authorization is dynamic and strictly enforced before access is allowed",
        description=(
            "This is a constant cycle of obtaining access, scanning and assessing "
            "threats, adapting, and continually reevaluating trust in ongoing "
            "communication."
        ),
        controls=[
            AwsControl(
                control_id="iam.access_analyzer",
                name="IAM Access Analyzer",
                service="IAM Access Analyzer",
                description=(
                    "Access Analyzer identifies resources shared with external "
                    "principals and generates least-privilege policies from "
                    "CloudTrail activity."
                ),
                boto3_method="accessanalyzer:ListAnalyzers",
                score_rubric={
                    0: "Access Analyzer not enabled.",
                    1: "Access Analyzer enabled but findings not actioned.",
                    2: "Access Analyzer enabled; findings reviewed and resolved.",
                    3: "Access Analyzer with automated archiving rules and EventBridge integration.",
                },
                weight=1.5,
            ),
            AwsControl(
                control_id="iam.unused_credentials",
                name="Unused credential rotation",
                service="IAM",
                description=(
                    "IAM Credential Report identifies access keys and passwords "
                    "unused for >90 days. CIS benchmark requires disabling these."
                ),
                boto3_method="iam:GenerateCredentialReport",
                score_rubric={
                    0: "Unused credentials older than 90 days present.",
                    1: "Credentials reviewed manually; some stale credentials remain.",
                    2: "All credentials >90 days disabled or rotated.",
                    3: "Config rule auto-disables credentials unused for >45 days.",
                },
            ),
            AwsControl(
                control_id="cognito.mfa",
                name="Cognito / SSO MFA enforcement",
                service="Cognito / IAM Identity Center",
                description=(
                    "MFA should be enforced for all human access, including the "
                    "AWS console. IAM Identity Center (SSO) is the preferred "
                    "implementation for console MFA."
                ),
                boto3_method="sso-admin:ListInstances",
                score_rubric={
                    0: "No MFA enforcement for console access.",
                    1: "MFA optional; users can bypass.",
                    2: "MFA required for all IAM users accessing the console.",
                    3: "All access via IAM Identity Center with hardware MFA required.",
                },
                weight=1.5,
            ),
        ],
    ),

    NistTenet(
        tenet_id=7,
        title="The enterprise collects as much information as possible about the current state of assets, network infrastructure and communications and uses it to improve its security posture",
        description=(
            "The enterprise should collect data about asset security posture, "
            "network traffic, and access requests. This data is used to improve "
            "policy creation and enforcement."
        ),
        controls=[
            AwsControl(
                control_id="cloudtrail.s3_data_events",
                name="CloudTrail S3 data event logging",
                service="CloudTrail",
                description=(
                    "S3 object-level logging captures GetObject, PutObject, and "
                    "DeleteObject calls. Required for data access visibility."
                ),
                boto3_method="cloudtrail:GetTrail",
                score_rubric={
                    0: "No S3 data event logging.",
                    1: "S3 data events logged for some buckets.",
                    2: "S3 data events logged for all sensitive buckets.",
                    3: "All S3 data events logged; Macie analyses access patterns.",
                },
            ),
            AwsControl(
                control_id="securityhub.standards",
                name="Security Hub compliance standards",
                service="Security Hub",
                description=(
                    "Security Hub standards (CIS, PCI, NIST) continuously evaluate "
                    "resource configurations and feed findings into the security "
                    "data lake for trend analysis."
                ),
                boto3_method="securityhub:GetEnabledStandards",
                score_rubric={
                    0: "No Security Hub standards enabled.",
                    1: "One standard enabled; findings not reviewed.",
                    2: "CIS and NIST standards enabled; findings reviewed weekly.",
                    3: "All standards enabled; findings feed SIEM; weekly trending reports generated.",
                },
            ),
            AwsControl(
                control_id="config.rules.compliance",
                name="AWS Config conformance packs",
                service="Config",
                description=(
                    "Config conformance packs bundle multiple Config rules into a "
                    "deployable package. The Operational Best Practices pack covers "
                    "200+ controls and generates compliance scores over time."
                ),
                boto3_method="config:DescribeConformancePacks",
                score_rubric={
                    0: "No Config rules or conformance packs deployed.",
                    1: "Some Config rules; no conformance pack.",
                    2: "Operational Best Practices conformance pack deployed.",
                    3: "Conformance pack with auto-remediation; compliance score tracked over time.",
                },
            ),
        ],
    ),
]

# ── Lookup helpers ────────────────────────────────────────────────────────────

def get_tenet(tenet_id: int) -> NistTenet:
    for t in TENETS:
        if t.tenet_id == tenet_id:
            return t
    raise ValueError(f"No tenet with id {tenet_id}")


def all_control_ids() -> list[str]:
    return [c.control_id for t in TENETS for c in t.controls]


def get_control(control_id: str) -> tuple[NistTenet, AwsControl]:
    for t in TENETS:
        for c in t.controls:
            if c.control_id == control_id:
                return t, c
    raise ValueError(f"No control with id {control_id}")