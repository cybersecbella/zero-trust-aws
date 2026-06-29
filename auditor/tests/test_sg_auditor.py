"""
auditor/tests/test_sg_auditor.py

Full test suite for sg_auditor.py.
Uses moto to mock AWS — no real credentials needed.

Run with:
    pytest auditor/tests/test_sg_auditor.py -v
    pytest auditor/tests/test_sg_auditor.py -v --cov=auditor/sg_auditor
"""

import json
import sys
import os
import pytest
import boto3
from unittest.mock import patch, MagicMock
from moto import mock_aws

# ── Path setup ────────────────────────────────────────────────────────────────
# Allows running from repo root: pytest auditor/tests/test_sg_auditor.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sg_auditor as aud

ACCOUNT_ID = "123456789012"
REGION     = "us-east-1"


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def base_raw() -> dict:
    """Minimal raw finding dict for ASFF conversion tests."""
    return {
        "sg_id":      "sg-0abc123",
        "sg_name":    "test-sg",
        "vpc_id":     "vpc-0abc",
        "region":     REGION,
        "account_id": ACCOUNT_ID,
        "port":       22,
        "cidr":       "0.0.0.0/0",
        "family":     "v4",
        "protocol":   "tcp",
        "from_port":  22,
        "to_port":    22,
        "sg_tags":    {"Environment": "prod", "Owner": "ops"},
    }


@pytest.fixture
def open_rule_v4() -> dict:
    """SG ingress rule open to 0.0.0.0/0 on port 22."""
    return {
        "IpProtocol": "tcp",
        "FromPort":   22,
        "ToPort":     22,
        "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }


@pytest.fixture
def open_rule_v6() -> dict:
    """SG ingress rule open to ::/0 on port 22."""
    return {
        "IpProtocol": "tcp",
        "FromPort":   22,
        "ToPort":     22,
        "IpRanges":   [],
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }


@pytest.fixture
def scoped_rule() -> dict:
    """SG ingress rule scoped to a private CIDR — should never flag."""
    return {
        "IpProtocol": "tcp",
        "FromPort":   22,
        "ToPort":     22,
        "IpRanges":   [{"CidrIp": "10.0.0.0/8"}],
        "Ipv6Ranges": [],
    }


@pytest.fixture
def sg() -> dict:
    """Minimal Security Group dict."""
    return {
        "GroupId":   "sg-0abc123",
        "GroupName": "test-sg",
        "VpcId":     "vpc-0abc",
        "Tags":      [{"Key": "Environment", "Value": "prod"}],
    }


# ── cidr_is_open ──────────────────────────────────────────────────────────────

class TestCidrIsOpen:

    def test_v4_open(self):
        assert aud.cidr_is_open("0.0.0.0/0", "v4") is True

    def test_v4_private_8(self):
        assert aud.cidr_is_open("10.0.0.0/8", "v4") is False

    def test_v4_private_16(self):
        assert aud.cidr_is_open("192.168.0.0/16", "v4") is False

    def test_v4_single_host(self):
        assert aud.cidr_is_open("203.0.113.1/32", "v4") is False

    def test_v6_open(self):
        assert aud.cidr_is_open("::/0", "v6") is True

    def test_v6_scoped(self):
        assert aud.cidr_is_open("2001:db8::/32", "v6") is False

    def test_invalid_cidr_returns_false(self):
        assert aud.cidr_is_open("not-a-cidr", "v4") is False

    def test_v4_cidr_checked_as_v6_returns_false(self):
        # 0.0.0.0/0 is not the full IPv6 space
        assert aud.cidr_is_open("0.0.0.0/0", "v6") is False


# ── port_range_contains ───────────────────────────────────────────────────────

class TestPortRangeContains:

    def test_exact_match(self):
        assert aud.port_range_contains(22, 22, 22) is True

    def test_within_wide_range(self):
        assert aud.port_range_contains(0, 65535, 22) is True
        assert aud.port_range_contains(0, 65535, 3389) is True

    def test_outside_range(self):
        assert aud.port_range_contains(80, 443, 22) is False

    def test_boundary_low(self):
        assert aud.port_range_contains(22, 100, 22) is True

    def test_boundary_high(self):
        assert aud.port_range_contains(100, 3389, 3389) is True

    def test_just_outside_boundary(self):
        assert aud.port_range_contains(23, 3388, 22) is False
        assert aud.port_range_contains(23, 3388, 3389) is False


# ── finding_id + sg_arn ───────────────────────────────────────────────────────

class TestArns:

    def test_finding_id_v4(self):
        fid = aud.finding_id(ACCOUNT_ID, REGION, "sg-abc", 22, "0.0.0.0/0")
        assert "sg-abc" in fid
        assert "port22" in fid
        assert "0.0.0.0_0" in fid   # / replaced with _
        assert fid.startswith("arn:aws:securityhub:")

    def test_finding_id_v6(self):
        fid = aud.finding_id(ACCOUNT_ID, REGION, "sg-abc", 22, "::/0")
        assert "--" in fid or "-" in fid   # : replaced with -
        assert "/" not in fid.split("finding/")[1]

    def test_finding_id_unique_per_port(self):
        fid22   = aud.finding_id(ACCOUNT_ID, REGION, "sg-abc", 22,   "0.0.0.0/0")
        fid3389 = aud.finding_id(ACCOUNT_ID, REGION, "sg-abc", 3389, "0.0.0.0/0")
        assert fid22 != fid3389

    def test_sg_arn_format(self):
        arn = aud.sg_arn(ACCOUNT_ID, REGION, "sg-abc123")
        assert arn == f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:security-group/sg-abc123"


# ── audit_rule ────────────────────────────────────────────────────────────────

class TestAuditRule:

    def test_open_v4_on_target_port(self, open_rule_v4, sg):
        findings = aud.audit_rule(open_rule_v4, sg, REGION, {22, 3389}, ACCOUNT_ID)
        assert len(findings) == 1
        assert findings[0]["port"] == 22
        assert findings[0]["cidr"] == "0.0.0.0/0"
        assert findings[0]["family"] == "v4"

    def test_open_v6_on_target_port(self, open_rule_v6, sg):
        findings = aud.audit_rule(open_rule_v6, sg, REGION, {22, 3389}, ACCOUNT_ID)
        assert len(findings) == 1
        assert findings[0]["cidr"] == "::/0"
        assert findings[0]["family"] == "v6"

    def test_both_v4_and_v6_open(self, sg):
        rule = {
            "IpProtocol": "tcp",
            "FromPort":   22,
            "ToPort":     22,
            "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        findings = aud.audit_rule(rule, sg, REGION, {22}, ACCOUNT_ID)
        assert len(findings) == 2
        families = {f["family"] for f in findings}
        assert families == {"v4", "v6"}

    def test_scoped_cidr_no_finding(self, scoped_rule, sg):
        findings = aud.audit_rule(scoped_rule, sg, REGION, {22, 3389}, ACCOUNT_ID)
        assert findings == []

    def test_port_not_in_target_set(self, sg):
        rule = {
            "IpProtocol": "tcp",
            "FromPort":   80,
            "ToPort":     80,
            "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }
        findings = aud.audit_rule(rule, sg, REGION, {22, 3389}, ACCOUNT_ID)
        assert findings == []

    def test_wide_port_range_catches_target(self, sg):
        # Rule allows 0–65535 from 0.0.0.0/0 — should flag both 22 and 3389
        rule = {
            "IpProtocol": "tcp",
            "FromPort":   0,
            "ToPort":     65535,
            "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }
        findings = aud.audit_rule(rule, sg, REGION, {22, 3389}, ACCOUNT_ID)
        ports = {f["port"] for f in findings}
        assert 22 in ports
        assert 3389 in ports

    def test_rdp_flagged(self, sg):
        rule = {
            "IpProtocol": "tcp",
            "FromPort":   3389,
            "ToPort":     3389,
            "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }
        findings = aud.audit_rule(rule, sg, REGION, {22, 3389}, ACCOUNT_ID)
        assert len(findings) == 1
        assert findings[0]["port"] == 3389

    def test_finding_carries_sg_metadata(self, open_rule_v4, sg):
        findings = aud.audit_rule(open_rule_v4, sg, REGION, {22}, ACCOUNT_ID)
        f = findings[0]
        assert f["sg_id"]   == "sg-0abc123"
        assert f["sg_name"] == "test-sg"
        assert f["vpc_id"]  == "vpc-0abc"
        assert f["sg_tags"] == {"Environment": "prod"}

    def test_no_ip_ranges_no_finding(self, sg):
        rule = {
            "IpProtocol": "tcp",
            "FromPort":   22,
            "ToPort":     22,
            "IpRanges":   [],
            "Ipv6Ranges": [],
        }
        assert aud.audit_rule(rule, sg, REGION, {22}, ACCOUNT_ID) == []

    def test_default_port_range_when_missing(self, sg):
        # Rules without FromPort/ToPort default to 0–65535
        rule = {
            "IpProtocol": "-1",   # all traffic
            "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
        }
        findings = aud.audit_rule(rule, sg, REGION, {22, 3389}, ACCOUNT_ID)
        assert len(findings) == 2


# ── to_asff ───────────────────────────────────────────────────────────────────

class TestToAsff:

    REQUIRED_KEYS = {
        "SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId",
        "Types", "CreatedAt", "UpdatedAt", "Severity", "Title", "Description",
        "Remediation", "Resources", "Compliance", "WorkflowState", "RecordState",
    }

    def test_required_asff_keys_present(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        missing = self.REQUIRED_KEYS - finding.keys()
        assert not missing, f"Missing ASFF keys: {missing}"

    def test_schema_version(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["SchemaVersion"] == "2018-10-08"

    def test_ssh_severity_critical(self, base_raw):
        base_raw["port"] = 22
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["Severity"]["Label"] == "CRITICAL"

    def test_rdp_severity_critical(self, base_raw):
        base_raw["port"] = 3389
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["Severity"]["Label"] == "CRITICAL"

    def test_non_standard_port_severity_high(self, base_raw):
        base_raw["port"] = 8080
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["Severity"]["Label"] == "HIGH"

    def test_title_contains_sg_id_and_cidr(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert "sg-0abc123" in finding["Title"]
        assert "0.0.0.0/0" in finding["Title"]

    def test_title_contains_service_name_ssh(self, base_raw):
        base_raw["port"] = 22
        assert "SSH" in aud.to_asff(base_raw, ACCOUNT_ID)["Title"]

    def test_title_contains_service_name_rdp(self, base_raw):
        base_raw["port"] = 3389
        assert "RDP" in aud.to_asff(base_raw, ACCOUNT_ID)["Title"]

    def test_ipv6_cidr_in_title(self, base_raw):
        base_raw["cidr"] = "::/0"
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert "::/0" in finding["Title"]

    def test_resource_type(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["Resources"][0]["Type"] == "AwsEc2SecurityGroup"

    def test_resource_id_is_sg_arn(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        rid = finding["Resources"][0]["Id"]
        assert rid.startswith("arn:aws:ec2:")
        assert "sg-0abc123" in rid

    def test_compliance_status_failed(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["Compliance"]["Status"] == "FAILED"

    def test_compliance_cis_requirements(self, base_raw):
        reqs = aud.to_asff(base_raw, ACCOUNT_ID)["Compliance"]["RelatedRequirements"]
        assert "CIS AWS Foundations 4.1" in reqs
        assert "CIS AWS Foundations 4.2" in reqs

    def test_compliance_nist_requirement(self, base_raw):
        reqs = aud.to_asff(base_raw, ACCOUNT_ID)["Compliance"]["RelatedRequirements"]
        assert any("NIST" in r for r in reqs)

    def test_workflow_state_new(self, base_raw):
        finding = aud.to_asff(base_raw, ACCOUNT_ID)
        assert finding["WorkflowState"] == "NEW"
        assert finding["Workflow"]["Status"] == "NEW"

    def test_record_state_active(self, base_raw):
        assert aud.to_asff(base_raw, ACCOUNT_ID)["RecordState"] == "ACTIVE"

    def test_port_range_in_description(self, base_raw):
        base_raw["from_port"] = 20
        base_raw["to_port"]   = 25
        desc = aud.to_asff(base_raw, ACCOUNT_ID)["Description"]
        assert "20" in desc and "25" in desc

    def test_env_tag_in_description(self, base_raw):
        base_raw["sg_tags"] = {"Environment": "staging"}
        desc = aud.to_asff(base_raw, ACCOUNT_ID)["Description"]
        assert "staging" in desc

    def test_missing_tags_use_unknown(self, base_raw):
        base_raw["sg_tags"] = {}
        desc = aud.to_asff(base_raw, ACCOUNT_ID)["Description"]
        assert "unknown" in desc

    def test_finding_id_is_deterministic(self, base_raw):
        f1 = aud.to_asff(base_raw, ACCOUNT_ID)
        f2 = aud.to_asff(base_raw, ACCOUNT_ID)
        assert f1["Id"] == f2["Id"]

    def test_product_arn_contains_account(self, base_raw):
        arn = aud.to_asff(base_raw, ACCOUNT_ID)["ProductArn"]
        assert ACCOUNT_ID in arn

    def test_remediation_url_present(self, base_raw):
        url = aud.to_asff(base_raw, ACCOUNT_ID)["Remediation"]["Recommendation"]["Url"]
        assert url.startswith("https://")


# ── post_to_security_hub ──────────────────────────────────────────────────────

class TestPostToSecurityHub:

    def test_imports_findings_successfully(self, base_raw):
        session = MagicMock()
        hub_client = MagicMock()
        session.client.return_value = hub_client
        hub_client.batch_import_findings.return_value = {
            "SuccessCount": 1,
            "FailedCount":  0,
            "FailedFindings": [],
        }
        findings = [aud.to_asff(base_raw, ACCOUNT_ID)]
        result = aud.post_to_security_hub(session, REGION, findings)
        assert result["imported"] == 1
        assert result["failed"]   == 0
        assert result["errors"]   == []
        hub_client.batch_import_findings.assert_called_once()

    def test_batches_over_100_findings(self, base_raw):
        session = MagicMock()
        hub_client = MagicMock()
        session.client.return_value = hub_client
        hub_client.batch_import_findings.return_value = {
            "SuccessCount": 100,
            "FailedCount":  0,
            "FailedFindings": [],
        }
        findings = []
        for i in range(150):
            raw = dict(base_raw)
            raw["sg_id"] = f"sg-{i:08x}"
            findings.append(aud.to_asff(raw, ACCOUNT_ID))
        result = aud.post_to_security_hub(session, REGION, findings)
        assert hub_client.batch_import_findings.call_count == 2
        first_batch  = hub_client.batch_import_findings.call_args_list[0]
        second_batch = hub_client.batch_import_findings.call_args_list[1]
        assert len(first_batch.kwargs["Findings"])  == 100
        assert len(second_batch.kwargs["Findings"]) == 50
        assert result["failed"] == 0

    def test_client_error_increments_failed(self, base_raw):
        session = MagicMock()
        hub_client = MagicMock()
        session.client.return_value = hub_client
        from botocore.exceptions import ClientError
        hub_client.batch_import_findings.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "BatchImportFindings",
        )
        findings = [aud.to_asff(base_raw, ACCOUNT_ID)]
        result = aud.post_to_security_hub(session, REGION, findings)
        assert result["failed"]   == 1
        assert result["imported"] == 0


# ── audit_region (integration with moto) ─────────────────────────────────────

class TestAuditRegion:

    @mock_aws
    def test_detects_open_ssh_on_attached_sg(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)

        # Create VPC, subnet, SG
        vpc  = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sg   = ec2.create_security_group(
            GroupName="open-ssh", Description="test", VpcId=vpc["VpcId"]
        )
        sg_id = sg["GroupId"]

        # Open port 22 to the world
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort":   22,
                "ToPort":     22,
                "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
            }],
        )

        # Attach SG to an ENI so it's not treated as orphaned
        subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
        ec2.create_network_interface(SubnetId=subnet["SubnetId"], Groups=[sg_id])

        findings = aud.audit_region(session, REGION, {22, 3389}, ACCOUNT_ID,
                                    attached_only=True)
        assert len(findings) == 1
        assert findings[0]["port"]  == 22
        assert findings[0]["sg_id"] == sg_id

    @mock_aws
    def test_skips_orphaned_sg_when_attached_only(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)

        vpc  = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sg   = ec2.create_security_group(
            GroupName="orphan-sg", Description="orphan", VpcId=vpc["VpcId"]
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        # No ENI attached — should be ignored with attached_only=True
        findings = aud.audit_region(session, REGION, {22, 3389}, ACCOUNT_ID,
                                    attached_only=True)
        assert findings == []

    @mock_aws
    def test_includes_orphaned_sg_when_flag_set(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        sg  = ec2.create_security_group(
            GroupName="orphan-sg", Description="orphan", VpcId=vpc["VpcId"]
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        findings = aud.audit_region(session, REGION, {22, 3389}, ACCOUNT_ID,
                                    attached_only=False)
        assert len(findings) == 1

    @mock_aws
    def test_scoped_rule_produces_no_findings(self):
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)

        vpc    = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.0.1.0/24")["Subnet"]
        sg     = ec2.create_security_group(
            GroupName="scoped-sg", Description="scoped", VpcId=vpc["VpcId"]
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }],
        )
        ec2.create_network_interface(SubnetId=subnet["SubnetId"],
                                     Groups=[sg["GroupId"]])

        findings = aud.audit_region(session, REGION, {22, 3389}, ACCOUNT_ID)
        assert findings == []

    @mock_aws
    def test_handles_region_error_gracefully(self):
        from botocore.exceptions import ClientError
        session = boto3.Session(region_name=REGION)
        with patch.object(session, "client",
                          side_effect=ClientError(
                              {"Error": {"Code": "EndpointResolutionError",
                                         "Message": "endpoint error"}},
                              "DescribeSecurityGroups")):
            findings = aud.audit_region(session, "eu-south-99", {22}, ACCOUNT_ID)
        assert findings == []