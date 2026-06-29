"""
gap_analyzer/tests/test_gap_analyzer.py

Full test suite for nist_800_207.py and aws_controls_map.py.
All AWS API calls are mocked — no real credentials required.

Run with:
    pytest gap_analyzer/tests/test_gap_analyzer.py -v
    pytest gap_analyzer/tests/test_gap_analyzer.py -v --cov=gap_analyzer
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch, call
from datetime import datetime, timezone

import pytest

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "controls"))
import aws_controls_map as acm
import nist_800_207 as ga


# ════════════════════════════════════════════════════════════════════════════════
# aws_controls_map.py
# ════════════════════════════════════════════════════════════════════════════════

class TestAwsControlsMap:

    def test_seven_tenets_defined(self):
        assert len(acm.TENETS) == 7

    def test_tenet_ids_are_1_through_7(self):
        ids = [t.tenet_id for t in acm.TENETS]
        assert ids == list(range(1, 8))

    def test_every_tenet_has_title_and_description(self):
        for t in acm.TENETS:
            assert t.title, f"Tenet {t.tenet_id} missing title"
            assert t.description, f"Tenet {t.tenet_id} missing description"

    def test_every_tenet_has_at_least_two_controls(self):
        for t in acm.TENETS:
            assert len(t.controls) >= 2, (
                f"Tenet {t.tenet_id} has only {len(t.controls)} control(s)"
            )

    def test_every_control_has_required_fields(self):
        for t in acm.TENETS:
            for c in t.controls:
                assert c.control_id,   f"{c.control_id}: missing control_id"
                assert c.name,         f"{c.control_id}: missing name"
                assert c.service,      f"{c.control_id}: missing service"
                assert c.description,  f"{c.control_id}: missing description"
                assert c.boto3_method, f"{c.control_id}: missing boto3_method"
                assert c.score_rubric, f"{c.control_id}: empty score_rubric"

    def test_score_rubric_covers_0_to_3(self):
        for t in acm.TENETS:
            for c in t.controls:
                for score in [0, 1, 2, 3]:
                    assert score in c.score_rubric, (
                        f"{c.control_id}: missing rubric for score {score}"
                    )

    def test_all_control_ids_unique(self):
        ids = acm.all_control_ids()
        assert len(ids) == len(set(ids)), "Duplicate control IDs detected"

    def test_get_tenet_returns_correct_tenet(self):
        for i in range(1, 8):
            t = acm.get_tenet(i)
            assert t.tenet_id == i

    def test_get_tenet_raises_on_invalid_id(self):
        with pytest.raises(ValueError):
            acm.get_tenet(0)
        with pytest.raises(ValueError):
            acm.get_tenet(8)

    def test_get_control_returns_correct_control(self):
        tenet, control = acm.get_control("sg.default_deny")
        assert control.control_id == "sg.default_deny"
        assert tenet.tenet_id == 4

    def test_get_control_raises_on_unknown(self):
        with pytest.raises(ValueError):
            acm.get_control("nonexistent.control")

    def test_control_weights_are_positive(self):
        for t in acm.TENETS:
            for c in t.controls:
                assert c.weight > 0, f"{c.control_id}: weight must be positive"

    def test_score_labels_has_four_entries(self):
        assert set(acm.SCORE_LABELS.keys()) == {0, 1, 2, 3}

    def test_critical_controls_have_higher_weight(self):
        _, sg_ctrl = acm.get_control("sg.default_deny")
        assert sg_ctrl.weight > 1.0

        _, ct_ctrl = acm.get_control("cloudtrail.enabled")
        assert ct_ctrl.weight > 1.0


# ════════════════════════════════════════════════════════════════════════════════
# ControlScore / TenetScore / GapReport dataclasses
# ════════════════════════════════════════════════════════════════════════════════

class TestDataclasses:

    def test_control_score_defaults(self):
        cs = ga.ControlScore("test.control", 2, "evidence")
        assert cs.raw == {}

    def test_tenet_score_fields(self):
        ts = ga.TenetScore(
            tenet_id=1, title="Test", weighted_score=2.5,
            max_score=3.0, pct=83.3, label="Implemented"
        )
        assert ts.control_scores == []

    def test_gap_report_defaults(self):
        report = ga.GapReport(
            account_id="123456789012",
            region="us-east-1",
            generated_at="2024-01-01T00:00:00Z",
        )
        assert report.tenet_scores == []
        assert report.ai_narrative == ""
        assert report.ai_priorities == []
        assert report.overall_pct == 0.0


# ════════════════════════════════════════════════════════════════════════════════
# AwsCollector — individual control assessors
# ════════════════════════════════════════════════════════════════════════════════

def make_collector(mock_clients: dict | None = None) -> ga.AwsCollector:
    """Build an AwsCollector with a mocked boto3 session."""
    session = MagicMock()
    collector = ga.AwsCollector(session, "us-east-1")
    if mock_clients:
        def client_factory(service, region_name=None):
            return mock_clients.get(service, MagicMock())
        session.client.side_effect = client_factory
    return collector


class TestScoreConfigRecorder:

    def test_not_enabled_scores_0(self):
        c = make_collector()
        c.session.client.return_value.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": []
        }
        cs = c.score_config_recorder()
        assert cs.score == 0
        assert "not enabled" in cs.evidence.lower()

    def test_recording_all_types_scores_2(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [
                {"name": "default",
                 "recordingGroup": {"allSupported": True}}
            ]
        }
        client_mock.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": True}]
        }
        client_mock.describe_conformance_packs.return_value = {
            "ConformancePackDetails": []
        }
        cs = c.score_config_recorder()
        assert cs.score == 2

    def test_conformance_packs_scores_3(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [
                {"name": "default",
                 "recordingGroup": {"allSupported": True}}
            ]
        }
        client_mock.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": True}]
        }
        client_mock.describe_conformance_packs.return_value = {
            "ConformancePackDetails": [{"ConformancePackName": "Operational-Best-Practices"}]
        }
        cs = c.score_config_recorder()
        assert cs.score == 3

    def test_api_error_returns_score_0(self):
        from botocore.exceptions import ClientError
        c = make_collector()
        c.session.client.return_value.describe_configuration_recorders.side_effect = (
            ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}},
                        "DescribeConfigurationRecorders")
        )
        cs = c.score_config_recorder()
        assert cs.score == 0


class TestScoreVpcFlowLogs:

    def test_no_vpcs_scores_0(self):
        c = make_collector()
        c.session.client.return_value.describe_vpcs.return_value = {"Vpcs": []}
        cs = c.score_vpc_flow_logs()
        assert cs.score == 0

    def test_no_flow_logs_scores_0(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-111"}, {"VpcId": "vpc-222"}]
        }
        client_mock.describe_flow_logs.return_value = {"FlowLogs": []}
        cs = c.score_vpc_flow_logs()
        assert cs.score == 0

    def test_partial_coverage_scores_1(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-111"}, {"VpcId": "vpc-222"}]
        }
        client_mock.describe_flow_logs.return_value = {
            "FlowLogs": [{"ResourceId": "vpc-111", "FlowLogStatus": "ACTIVE"}]
        }
        cs = c.score_vpc_flow_logs()
        assert cs.score == 1
        assert "vpc-222" in cs.evidence

    def test_full_coverage_scores_2(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-111"}, {"VpcId": "vpc-222"}]
        }
        client_mock.describe_flow_logs.return_value = {
            "FlowLogs": [
                {"ResourceId": "vpc-111", "FlowLogStatus": "ACTIVE"},
                {"ResourceId": "vpc-222", "FlowLogStatus": "ACTIVE"},
            ]
        }
        cs = c.score_vpc_flow_logs()
        assert cs.score == 2


class TestScoreIamPasswordPolicy:

    def test_no_policy_scores_0(self):
        from botocore.exceptions import ClientError
        c = make_collector()
        c.session.client.return_value.get_account_password_policy.side_effect = (
            ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "No policy"}},
                "GetAccountPasswordPolicy"
            )
        )
        cs = c.score_iam_password_policy()
        assert cs.score == 0

    def test_weak_policy_scores_1(self):
        c = make_collector()
        c.session.client.return_value.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 8,
                "RequireUppercaseCharacters": False,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
                "MaxPasswordAge": 180,
                "PasswordReusePrevention": 5,
            }
        }
        cs = c.score_iam_password_policy()
        assert cs.score == 1

    def test_strong_policy_scores_2(self):
        c = make_collector()
        c.session.client.return_value.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireUppercaseCharacters": True,
                "RequireLowercaseCharacters": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
                "MaxPasswordAge": 90,
                "PasswordReusePrevention": 24,
            }
        }
        cs = c.score_iam_password_policy()
        assert cs.score == 2


class TestScoreRootMfa:

    def test_mfa_not_enabled_scores_0(self):
        c = make_collector()
        c.session.client.return_value.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}
        }
        cs = c.score_root_mfa()
        assert cs.score == 0
        assert "NOT enabled" in cs.evidence

    def test_mfa_with_root_keys_scores_1(self):
        c = make_collector()
        c.session.client.return_value.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 1}
        }
        cs = c.score_root_mfa()
        assert cs.score == 1
        assert "access keys" in cs.evidence.lower()

    def test_mfa_no_root_keys_scores_2(self):
        c = make_collector()
        c.session.client.return_value.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        }
        cs = c.score_root_mfa()
        assert cs.score == 2


class TestScoreSecurityGroups:

    def test_open_ssh_scores_0(self):
        c = make_collector()
        c.session.client.return_value.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-bad",
                "GroupName": "bad-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 22, "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }
        cs = c.score_security_groups()
        assert cs.score == 0
        assert "sg-bad" in cs.evidence

    def test_open_rdp_ipv6_scores_0(self):
        c = make_collector()
        c.session.client.return_value.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-rdp",
                "GroupName": "rdp-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 3389, "ToPort": 3389,
                    "IpRanges": [],
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }],
            }]
        }
        cs = c.score_security_groups()
        assert cs.score == 0

    def test_scoped_rules_score_2(self):
        c = make_collector()
        c.session.client.return_value.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-good",
                "GroupName": "good-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 443, "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }
        cs = c.score_security_groups()
        assert cs.score == 2

    def test_empty_sgs_score_2(self):
        c = make_collector()
        c.session.client.return_value.describe_security_groups.return_value = {
            "SecurityGroups": []
        }
        cs = c.score_security_groups()
        assert cs.score == 2

    def test_wide_port_range_containing_22_scores_0(self):
        c = make_collector()
        c.session.client.return_value.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-wide",
                "GroupName": "wide-sg",
                "IpPermissions": [{
                    "IpProtocol": "tcp",
                    "FromPort": 0, "ToPort": 65535,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }],
            }]
        }
        cs = c.score_security_groups()
        assert cs.score == 0


class TestScoreGuardDuty:

    def test_not_enabled_scores_0(self):
        c = make_collector()
        c.session.client.return_value.list_detectors.return_value = {
            "DetectorIds": []
        }
        cs = c.score_guardduty()
        assert cs.score == 0

    def test_enabled_scores_2(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.list_detectors.return_value = {"DetectorIds": ["abc123"]}
        client_mock.get_detector.return_value = {"Status": "ENABLED"}
        cs = c.score_guardduty()
        assert cs.score == 2
        assert "abc123" in cs.evidence

    def test_disabled_detector_scores_1(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.list_detectors.return_value = {"DetectorIds": ["abc123"]}
        client_mock.get_detector.return_value = {"Status": "DISABLED"}
        cs = c.score_guardduty()
        assert cs.score == 1


class TestScoreCloudTrail:

    def test_no_trails_scores_0(self):
        c = make_collector()
        c.session.client.return_value.describe_trails.return_value = {
            "trailList": []
        }
        cs = c.score_cloudtrail()
        assert cs.score == 0

    def test_single_region_trail_scores_1(self):
        c = make_collector()
        c.session.client.return_value.describe_trails.return_value = {
            "trailList": [{
                "Name": "single-trail",
                "IsMultiRegionTrail": False,
                "LogFileValidationEnabled": True,
            }]
        }
        cs = c.score_cloudtrail()
        assert cs.score == 1

    def test_multi_region_with_validation_scores_2(self):
        c = make_collector()
        c.session.client.return_value.describe_trails.return_value = {
            "trailList": [{
                "Name": "prod-trail",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": True,
                "CloudWatchLogsLogGroupArn": "arn:aws:logs:us-east-1:123:log-group:ct",
            }]
        }
        cs = c.score_cloudtrail()
        assert cs.score == 2

    def test_multi_region_without_validation_scores_1(self):
        c = make_collector()
        c.session.client.return_value.describe_trails.return_value = {
            "trailList": [{
                "Name": "prod-trail",
                "IsMultiRegionTrail": True,
                "LogFileValidationEnabled": False,
            }]
        }
        cs = c.score_cloudtrail()
        assert cs.score == 1


class TestScoreSecurityHub:

    def test_not_subscribed_scores_0(self):
        from botocore.exceptions import ClientError
        c = make_collector()
        c.session.client.return_value.describe_hub.side_effect = ClientError(
            {"Error": {"Code": "InvalidAccessException",
                       "Message": "not subscribed to AWS Security Hub"}},
            "DescribeHub"
        )
        cs = c.score_security_hub()
        assert cs.score == 0

    def test_no_standards_scores_1(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_hub.return_value = {"HubArn": "arn:..."}
        client_mock.get_enabled_standards.return_value = {
            "StandardsSubscriptions": []
        }
        cs = c.score_security_hub()
        assert cs.score == 1

    def test_multiple_standards_scores_2(self):
        c = make_collector()
        client_mock = c.session.client.return_value
        client_mock.describe_hub.return_value = {"HubArn": "arn:..."}
        client_mock.get_enabled_standards.return_value = {
            "StandardsSubscriptions": [
                {"StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"},
                {"StandardsArn": "arn:aws:securityhub:us-east-1::standards/nist-800-53/v/5.0.0"},
            ]
        }
        cs = c.score_security_hub()
        assert cs.score == 2


class TestScoreAccessAnalyzer:

    def test_not_enabled_scores_0(self):
        c = make_collector()
        c.session.client.return_value.list_analyzers.return_value = {
            "analyzers": []
        }
        cs = c.score_access_analyzer()
        assert cs.score == 0

    def test_active_analyzer_scores_2(self):
        c = make_collector()
        c.session.client.return_value.list_analyzers.return_value = {
            "analyzers": [{"name": "my-analyzer", "status": "ACTIVE"}]
        }
        cs = c.score_access_analyzer()
        assert cs.score == 2

    def test_inactive_analyzer_not_counted(self):
        c = make_collector()
        c.session.client.return_value.list_analyzers.return_value = {
            "analyzers": [{"name": "old-analyzer", "status": "DISABLED"}]
        }
        cs = c.score_access_analyzer()
        assert cs.score == 0


# ════════════════════════════════════════════════════════════════════════════════
# score_tenets — weighted scoring engine
# ════════════════════════════════════════════════════════════════════════════════

class TestScoreTenets:

    def make_all_scores(self, value: int) -> dict[str, ga.ControlScore]:
        return {
            cid: ga.ControlScore(cid, value, "test evidence")
            for cid in acm.all_control_ids()
        }

    def test_all_zeros_produces_zero_pct(self):
        scores = self.make_all_scores(0)
        tenets = ga.score_tenets(scores)
        for ts in tenets:
            assert ts.weighted_score == 0.0
            assert ts.pct == 0.0

    def test_all_threes_produces_100_pct(self):
        scores = self.make_all_scores(3)
        tenets = ga.score_tenets(scores)
        for ts in tenets:
            assert ts.pct == pytest.approx(100.0)
            assert ts.weighted_score == pytest.approx(3.0)

    def test_all_twos_produces_approx_67_pct(self):
        scores = self.make_all_scores(2)
        tenets = ga.score_tenets(scores)
        for ts in tenets:
            assert ts.pct == pytest.approx(66.7, abs=1.0)

    def test_seven_tenet_scores_returned(self):
        scores = self.make_all_scores(2)
        tenets = ga.score_tenets(scores)
        assert len(tenets) == 7

    def test_tenet_ids_are_1_through_7(self):
        scores = self.make_all_scores(1)
        tenets = ga.score_tenets(scores)
        assert [ts.tenet_id for ts in tenets] == list(range(1, 8))

    def test_missing_control_defaults_to_0(self):
        # Empty dict — all controls missing
        tenets = ga.score_tenets({})
        for ts in tenets:
            assert ts.weighted_score == 0.0

    def test_label_assigned_correctly(self):
        scores = self.make_all_scores(3)
        tenets = ga.score_tenets(scores)
        for ts in tenets:
            assert ts.label == "Automated"

    def test_weighted_controls_affect_score(self):
        # For tenet 4 (sg.default_deny has weight=2.0):
        # Score sg.default_deny=0, everything else=3 — should drag down tenet 4 more
        scores = self.make_all_scores(3)
        scores["sg.default_deny"] = ga.ControlScore("sg.default_deny", 0, "open")

        t4 = next(ts for ts in ga.score_tenets(scores) if ts.tenet_id == 4)
        assert t4.pct < 100.0
        assert t4.weighted_score < 3.0

    def test_pct_is_between_0_and_100(self):
        for val in [0, 1, 2, 3]:
            tenets = ga.score_tenets(self.make_all_scores(val))
            for ts in tenets:
                assert 0.0 <= ts.pct <= 100.0

    def test_control_scores_attached_to_tenet(self):
        scores = self.make_all_scores(2)
        tenets = ga.score_tenets(scores)
        for ts in tenets:
            assert len(ts.control_scores) > 0
            for cs in ts.control_scores:
                assert isinstance(cs, ga.ControlScore)


# ════════════════════════════════════════════════════════════════════════════════
# build_narrative_prompt
# ════════════════════════════════════════════════════════════════════════════════

class TestBuildNarrativePrompt:

    def make_tenet_scores(self) -> list[ga.TenetScore]:
        return [
            ga.TenetScore(
                tenet_id=i, title=f"Tenet {i}",
                weighted_score=float(i % 4),
                max_score=3.0, pct=float(i % 4) / 3 * 100,
                label=acm.SCORE_LABELS[i % 4],
                control_scores=[
                    ga.ControlScore(f"ctrl.{i}", i % 4, f"Evidence for tenet {i}")
                ],
            )
            for i in range(1, 8)
        ]

    def test_contains_account_id(self):
        prompt = ga.build_narrative_prompt(self.make_tenet_scores(), "123456789012")
        assert "123456789012" in prompt

    def test_contains_all_seven_tenets(self):
        prompt = ga.build_narrative_prompt(self.make_tenet_scores(), "123456789012")
        for i in range(1, 8):
            assert f"Tenet {i}" in prompt

    def test_contains_evidence_strings(self):
        prompt = ga.build_narrative_prompt(self.make_tenet_scores(), "123456789012")
        assert "Evidence for tenet" in prompt

    def test_contains_score_values(self):
        tss = self.make_tenet_scores()
        prompt = ga.build_narrative_prompt(tss, "123456789012")
        assert "/3.0" in prompt


# ════════════════════════════════════════════════════════════════════════════════
# call_claude_for_narrative
# ════════════════════════════════════════════════════════════════════════════════

class TestCallClaudeForNarrative:

    def make_scores(self) -> list[ga.TenetScore]:
        return [
            ga.TenetScore(tenet_id=i, title=f"T{i}", weighted_score=2.0,
                          max_score=3.0, pct=66.7, label="Implemented")
            for i in range(1, 8)
        ]

    def test_parses_valid_json_response(self):
        payload = {
            "executive_summary": "Good overall posture with gaps in monitoring.",
            "priorities": [
                "Priority 1: Enable GuardDuty in all regions.",
                "Priority 2: Enable VPC Flow Logs on all VPCs.",
            ]
        }
        mock_client = MagicMock()
        mock_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(payload))
        ]

        with patch("anthropic.Anthropic", return_value=mock_client):
            summary, priorities = ga.call_claude_for_narrative(
                self.make_scores(), "123456789012", "sk-ant-test"
            )

        assert summary == payload["executive_summary"]
        assert len(priorities) == 2

    def test_strips_markdown_fences(self):
        payload = {"executive_summary": "Good.", "priorities": ["P1: Fix X."]}
        fenced  = f"```json\n{json.dumps(payload)}\n```"
        mock_client = MagicMock()
        mock_client.messages.create.return_value.content = [MagicMock(text=fenced)]

        with patch("anthropic.Anthropic", return_value=mock_client):
            summary, priorities = ga.call_claude_for_narrative(
                self.make_scores(), "123456789012", "sk-ant-test"
            )

        assert summary == "Good."

    def test_invalid_json_returns_raw_text(self):
        mock_client = MagicMock()
        mock_client.messages.create.return_value.content = [
            MagicMock(text="not json at all, just some text")
        ]

        with patch("anthropic.Anthropic", return_value=mock_client):
            summary, priorities = ga.call_claude_for_narrative(
                self.make_scores(), "123456789012", "sk-ant-test"
            )

        assert "not json" in summary
        assert priorities == []

    def test_uses_correct_model(self):
        payload = {"executive_summary": "ok", "priorities": []}
        mock_client = MagicMock()
        mock_client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(payload))
        ]

        with patch("anthropic.Anthropic", return_value=mock_client):
            ga.call_claude_for_narrative(
                self.make_scores(), "123456789012", "sk-ant-test"
            )

        kwargs = mock_client.messages.create.call_args.kwargs
        assert kwargs["model"] == ga.MODEL


# ════════════════════════════════════════════════════════════════════════════════
# render_markdown
# ════════════════════════════════════════════════════════════════════════════════

class TestRenderMarkdown:

    def make_report(self, overall_pct=65.0) -> ga.GapReport:
        tenet_scores = [
            ga.TenetScore(
                tenet_id=i,
                title=f"Tenet {i} Title",
                weighted_score=2.0,
                max_score=3.0,
                pct=66.7,
                label="Implemented",
                control_scores=[
                    ga.ControlScore(f"ctrl.{i}.a", 2, f"Control {i}A evidence."),
                    ga.ControlScore(f"ctrl.{i}.b", 1, f"Control {i}B evidence."),
                ],
            )
            for i in range(1, 8)
        ]
        return ga.GapReport(
            account_id="123456789012",
            region="us-east-1",
            generated_at="2024-01-15T10:00:00Z",
            tenet_scores=tenet_scores,
            overall_pct=overall_pct,
            ai_narrative="Overall posture is moderate.",
            ai_priorities=["Priority 1: Enable GuardDuty.", "Priority 2: Fix Flow Logs."],
        )

    def test_contains_account_id(self):
        md = ga.render_markdown(self.make_report())
        assert "123456789012" in md

    def test_contains_region(self):
        md = ga.render_markdown(self.make_report())
        assert "us-east-1" in md

    def test_contains_overall_pct(self):
        md = ga.render_markdown(self.make_report(65.0))
        assert "65.0%" in md

    def test_contains_executive_summary(self):
        md = ga.render_markdown(self.make_report())
        assert "Overall posture is moderate." in md

    def test_contains_all_seven_tenets(self):
        md = ga.render_markdown(self.make_report())
        for i in range(1, 8):
            assert f"Tenet {i}" in md

    def test_contains_priorities(self):
        md = ga.render_markdown(self.make_report())
        assert "Enable GuardDuty" in md
        assert "Fix Flow Logs" in md

    def test_contains_control_evidence(self):
        md = ga.render_markdown(self.make_report())
        assert "Control 1A evidence." in md

    def test_contains_score_table(self):
        md = ga.render_markdown(self.make_report())
        assert "| #" in md
        assert "| Tenet |" in md

    def test_report_without_ai_narrative(self):
        report = self.make_report()
        report.ai_narrative  = ""
        report.ai_priorities = []
        md = ga.render_markdown(report)
        assert "Executive Summary" not in md
        assert "Remediation Priorities" not in md
        assert "Tenet 1" in md  # still has tenet details

    def test_is_valid_markdown_string(self):
        md = ga.render_markdown(self.make_report())
        assert isinstance(md, str)
        assert len(md) > 500
        assert md.startswith("# Zero Trust Gap Analysis")

    def test_generated_at_in_output(self):
        md = ga.render_markdown(self.make_report())
        assert "2024-01-15" in md

    def test_score_emojis_present(self):
        md = ga.render_markdown(self.make_report())
        # score 2 = 🟡
        assert "🟡" in md

    def test_score_bar_present(self):
        md = ga.render_markdown(self.make_report())
        assert "███░░" in md  # score 2 bar


# ════════════════════════════════════════════════════════════════════════════════
# safe_call
# ════════════════════════════════════════════════════════════════════════════════

class TestSafeCall:

    def test_returns_result_on_success(self):
        fn = MagicMock(return_value={"key": "value"})
        result = ga.safe_call(fn)
        assert result == {"key": "value"}

    def test_returns_default_on_client_error(self):
        from botocore.exceptions import ClientError
        fn = MagicMock(side_effect=ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "SomeOperation"
        ))
        result = ga.safe_call(fn, default={"fallback": True})
        assert result == {"fallback": True}

    def test_default_is_none(self):
        from botocore.exceptions import ClientError
        fn = MagicMock(side_effect=ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "SomeOperation"
        ))
        assert ga.safe_call(fn) is None

    def test_passes_args_to_fn(self):
        fn = MagicMock(return_value="ok")
        ga.safe_call(fn, "arg1", key="val")
        fn.assert_called_once_with("arg1", key="val")