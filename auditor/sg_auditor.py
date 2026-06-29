#!/usr/bin/env python3
"""
sg_auditor.py — AWS Security Group auditor
Detects 0.0.0.0/0 and ::/0 ingress on ports 22 and 3389 across all enabled
regions, then posts findings to AWS Security Hub in ASFF format.

Usage:
    python3 sg_auditor.py [--dry-run] [--regions us-east-1 eu-west-1]
                          [--ports 22 3389 8080] [--output findings.json]

IAM permissions required:
    ec2:DescribeRegions
    ec2:DescribeSecurityGroups
    ec2:DescribeNetworkInterfaces
    securityhub:BatchImportFindings
    sts:GetCallerIdentity
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from ipaddress import ip_network
from typing import Iterator

import boto3
from botocore.exceptions import ClientError, EndpointResolutionError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

RISKY_CIDRS_V4 = {"0.0.0.0/0"}
RISKY_CIDRS_V6 = {"::/0"}

SEVERITY_MAP = {
    22:   ("CRITICAL", 90.0),
    3389: ("CRITICAL", 90.0),
}
DEFAULT_SEVERITY = ("HIGH", 70.0)

FINDING_TYPES = ["Software and Configuration Checks/AWS Security Best Practices"]

PRODUCT_NAME = "sg-auditor"
COMPANY_NAME = "custom"

# ── Data helpers ─────────────────────────────────────────────────────────────

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def port_range_contains(from_port: int, to_port: int, target: int) -> bool:
    """True when target falls within an inclusive port range."""
    return from_port <= target <= to_port


def cidr_is_open(cidr: str, family: str) -> bool:
    """True when a CIDR represents unrestricted access for its family."""
    try:
        net = ip_network(cidr, strict=False)
        if family == "v4":
            return net.num_addresses == 2 ** 32
        return net.num_addresses == 2 ** 128
    except ValueError:
        return False


# ── AWS helpers ───────────────────────────────────────────────────────────────

def get_account_id(session: boto3.Session) -> str:
    return session.client("sts").get_caller_identity()["Account"]


def get_enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(Filters=[{"Name": "opt-in-status",
                                           "Values": ["opt-in-not-required", "opted-in"]}])
    return [r["RegionName"] for r in resp["Regions"]]


def paginate(client, method: str, result_key: str, **kwargs) -> Iterator[dict]:
    """Generic paginator wrapper."""
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        yield from page[result_key]


def get_attached_sg_ids(ec2_client) -> set[str]:
    """Return SG IDs actually attached to a network interface (not orphaned)."""
    attached = set()
    for eni in paginate(ec2_client, "describe_network_interfaces",
                        "NetworkInterfaces"):
        for group in eni.get("Groups", []):
            attached.add(group["GroupId"])
    return attached


# ── Core audit logic ──────────────────────────────────────────────────────────

def audit_rule(rule: dict, sg: dict, region: str, target_ports: set[int],
               account_id: str) -> list[dict]:
    """
    Evaluate a single ingress rule.
    Returns a list of raw finding dicts (one per offending port per open CIDR).
    """
    from_port = rule.get("FromPort", 0)
    to_port   = rule.get("ToPort",   65535)

    # Collect open CIDRs in this rule
    open_cidrs: list[tuple[str, str]] = []  # (cidr, family)
    for r in rule.get("IpRanges", []):
        if cidr_is_open(r["CidrIp"], "v4"):
            open_cidrs.append((r["CidrIp"], "v4"))
    for r in rule.get("Ipv6Ranges", []):
        if cidr_is_open(r["CidrIpv6"], "v6"):
            open_cidrs.append((r["CidrIpv6"], "v6"))

    if not open_cidrs:
        return []

    findings = []
    for port in target_ports:
        if not port_range_contains(from_port, to_port, port):
            continue
        for cidr, family in open_cidrs:
            findings.append({
                "sg_id":      sg["GroupId"],
                "sg_name":    sg["GroupName"],
                "vpc_id":     sg.get("VpcId", ""),
                "region":     region,
                "account_id": account_id,
                "port":       port,
                "cidr":       cidr,
                "family":     family,
                "protocol":   rule.get("IpProtocol", "tcp"),
                "from_port":  from_port,
                "to_port":    to_port,
                "sg_tags":    {t["Key"]: t["Value"]
                               for t in sg.get("Tags", [])},
            })
    return findings


def audit_region(session: boto3.Session, region: str, target_ports: set[int],
                 account_id: str, attached_only: bool = True) -> list[dict]:
    """Audit all SGs in a single region. Returns raw finding dicts."""
    try:
        ec2 = session.client("ec2", region_name=region)
        attached_ids = get_attached_sg_ids(ec2) if attached_only else None

        raw_findings = []
        for sg in paginate(ec2, "describe_security_groups", "SecurityGroups"):
            if attached_only and sg["GroupId"] not in attached_ids:
                continue
            for rule in sg.get("IpPermissions", []):
                raw_findings.extend(
                    audit_rule(rule, sg, region, target_ports, account_id)
                )
        return raw_findings

    except (ClientError, EndpointResolutionError) as exc:
        log.warning("Skipping %s — %s", region, exc)
        return []


# ── ASFF formatting ───────────────────────────────────────────────────────────

def finding_id(account_id: str, region: str, sg_id: str,
               port: int, cidr: str) -> str:
    safe_cidr = cidr.replace("/", "_").replace(":", "-")
    return (f"arn:aws:securityhub:{region}:{account_id}:finding/"
            f"{sg_id}-port{port}-{safe_cidr}")


def sg_arn(account_id: str, region: str, sg_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:security-group/{sg_id}"


def to_asff(raw: dict, account_id: str) -> dict:
    """Convert a raw finding dict to an ASFF-formatted Security Hub finding."""
    port          = raw["port"]
    cidr          = raw["cidr"]
    region        = raw["region"]
    sg_id         = raw["sg_id"]
    sg_name       = raw["sg_name"]
    vpc_id        = raw["vpc_id"]
    protocol      = raw["protocol"]
    from_port     = raw["from_port"]
    to_port       = raw["to_port"]
    env_tag       = raw["sg_tags"].get("Environment", "unknown")
    owner_tag     = raw["sg_tags"].get("Owner", "unknown")

    sev_label, sev_score = SEVERITY_MAP.get(port, DEFAULT_SEVERITY)

    port_desc = (f"{from_port}–{to_port}" if from_port != to_port
                 else str(port))
    service   = {22: "SSH", 3389: "RDP"}.get(port, f"port {port}")

    return {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id(account_id, region, sg_id, port, cidr),
        "ProductArn": (f"arn:aws:securityhub:{region}:{account_id}:"
                       f"product/{account_id}/default"),
        "ProductName": PRODUCT_NAME,
        "CompanyName": COMPANY_NAME,
        "Region": region,
        "GeneratorId": f"{PRODUCT_NAME}/overly-permissive-ingress",
        "AwsAccountId": account_id,
        "Types": FINDING_TYPES,
        "CreatedAt": utcnow(),
        "UpdatedAt": utcnow(),
        "Severity": {
            "Label":    sev_label,
            "Original": str(sev_score),
        },
        "Title": (f"Security group {sg_id} allows {service} ingress "
                  f"from {cidr}"),
        "Description": (
            f"Security group '{sg_name}' ({sg_id}) in VPC {vpc_id} "
            f"({region}) has an ingress rule permitting {protocol.upper()} "
            f"on port range {port_desc} from {cidr}. "
            f"This exposes {service} to the public internet. "
            f"Environment: {env_tag}. Owner: {owner_tag}."
        ),
        "Remediation": {
            "Recommendation": {
                "Text": (
                    f"Remove or scope the ingress rule allowing {cidr} on "
                    f"port {port}. Replace with a specific CIDR, a prefix "
                    f"list, or a VPN/bastion security group as the source. "
                    f"For {service}, consider AWS Systems Manager Session "
                    f"Manager to eliminate public port exposure entirely."
                ),
                "Url": (
                    "https://docs.aws.amazon.com/securityhub/latest/userguide/"
                    "ec2-controls.html#ec2-19"
                ),
            }
        },
        "Resources": [
            {
                "Type":      "AwsEc2SecurityGroup",
                "Id":        sg_arn(account_id, region, sg_id),
                "Partition": "aws",
                "Region":    region,
                "Details": {
                    "AwsEc2SecurityGroup": {
                        "GroupId":   sg_id,
                        "GroupName": sg_name,
                        "VpcId":     vpc_id,
                    }
                },
            }
        ],
        "Compliance": {
            "Status": "FAILED",
            "RelatedRequirements": [
                "CIS AWS Foundations 4.1",
                "CIS AWS Foundations 4.2",
                "NIST SP 800-207 Tenet 4",
                "PCI DSS 1.2.1",
            ],
        },
        "WorkflowState": "NEW",
        "Workflow":      {"Status": "NEW"},
        "RecordState":   "ACTIVE",
        "Note": {
            "Text":      f"Auto-generated by {PRODUCT_NAME}",
            "UpdatedBy": PRODUCT_NAME,
            "UpdatedAt": utcnow(),
        },
    }


# ── Security Hub uploader ─────────────────────────────────────────────────────

BATCH_SIZE = 100  # Security Hub max per BatchImportFindings call
 
def post_to_security_hub(session: boto3.Session, region: str,
                         asff_findings: list[dict]) -> dict:
    """Upload findings to Security Hub in the given region."""
    hub = session.client("securityhub", region_name=region)
    results = {"imported": 0, "failed": 0, "errors": []}
 
    for i in range(0, len(asff_findings), BATCH_SIZE):
        batch = asff_findings[i : i + BATCH_SIZE]
        try:
            resp = hub.batch_import_findings(Findings=batch)
            results["imported"] += resp["SuccessCount"]
            results["failed"]   += resp["FailedCount"]
            if resp.get("FailedFindings"):
                results["errors"].extend(resp["FailedFindings"])
        except ClientError as exc:
            log.error("Security Hub BatchImportFindings failed in %s: %s",
                      region, exc)
            results["failed"] += len(batch)
 
    return results

# ── CLI entrypoint ────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Audit AWS Security Groups for open internet ingress."
    )
    p.add_argument("--dry-run", action="store_true",
                   help="Print findings to stdout; do not post to Security Hub.")
    p.add_argument("--regions", nargs="+", metavar="REGION",
                   help="Regions to audit (default: all enabled regions).")
    p.add_argument("--ports", nargs="+", type=int, default=[22, 3389],
                   metavar="PORT",
                   help="Ports to flag (default: 22 3389).")
    p.add_argument("--include-unattached", action="store_true",
                   help="Audit SGs not attached to any ENI (default: skip).")
    p.add_argument("--output", metavar="FILE",
                   help="Write ASFF findings JSON to this file.")
    p.add_argument("--profile", metavar="PROFILE",
                   help="AWS named profile to use.")
    return p.parse_args()


def main() -> None:
    args    = parse_args()
    session = boto3.Session(profile_name=args.profile)

    account_id   = get_account_id(session)
    target_ports = set(args.ports)
    regions      = args.regions or get_enabled_regions(session)
    attached_only = not args.include_unattached

    log.info("Account: %s | Regions: %d | Ports: %s | Attached-only: %s",
             account_id, len(regions), sorted(target_ports), attached_only)

    all_raw: list[dict]  = []
    all_asff: list[dict] = []

    for region in regions:
        log.info("Auditing %s ...", region)
        raw = audit_region(session, region, target_ports,
                           account_id, attached_only)
        if raw:
            log.warning("  ↳ %d finding(s) in %s", len(raw), region)
            all_raw.extend(raw)
            region_asff = [to_asff(r, account_id) for r in raw]
            all_asff.extend(region_asff)

            if not args.dry_run:
                result = post_to_security_hub(session, region, region_asff)
                log.info("  ↳ Security Hub: %d imported, %d failed",
                         result["imported"], result["failed"])
                if result["errors"]:
                    for err in result["errors"]:
                        log.error("    Failed finding: %s", err)
        else:
            log.info("  ↳ clean")

    # Summary
    log.info("─" * 60)
    log.info("Total findings: %d across %d regions", len(all_raw), len(regions))

    by_port = {}
    for r in all_raw:
        by_port.setdefault(r["port"], 0)
        by_port[r["port"]] += 1
    for port, count in sorted(by_port.items()):
        log.info("  Port %d: %d finding(s)", port, count)

    # Optional JSON output
    if args.output and all_asff:
        with open(args.output, "w") as fh:
            json.dump(all_asff, fh, indent=2)
        log.info("ASFF findings written to %s", args.output)

    if args.dry_run and all_asff:
        print(json.dumps(all_asff, indent=2))

    sys.exit(1 if all_raw else 0)


if __name__ == "__main__":
    main()
