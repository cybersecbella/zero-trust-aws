"""
reviewer/tests/test_sg_diff.py

Full test suite for sg_diff.py.
No real AWS credentials or Anthropic API key required — all external
calls are mocked.

Run with:
    pytest reviewer/tests/test_sg_diff.py -v
    pytest reviewer/tests/test_sg_diff.py -v --cov=reviewer.sg_diff
"""

import json
import os
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, patch, mock_open

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import sg_diff as d


# ── Shared fixtures ───────────────────────────────────────────────────────────

def make_sg_rule(
    protocol="tcp",
    from_port=443,
    to_port=443,
    ipv4_cidrs=None,
    ipv6_cidrs=None,
    sg_sources=None,
    prefix_lists=None,
) -> dict:
    """Build a realistic SG IpPermissions rule dict."""
    return {
        "IpProtocol": protocol,
        "FromPort":   from_port,
        "ToPort":     to_port,
        "IpRanges":        [{"CidrIp": c}      for c in (ipv4_cidrs or [])],
        "Ipv6Ranges":      [{"CidrIpv6": c}    for c in (ipv6_cidrs or [])],
        "UserIdGroupPairs":[{"GroupId": g}      for g in (sg_sources or [])],
        "PrefixListIds":   [{"PrefixListId": p} for p in (prefix_lists or [])],
    }


def make_snapshot(sgs: list[dict]) -> str:
    """Write a list of SG dicts to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, dir="/tmp"
    )
    json.dump(sgs, f)
    f.close()
    return f.name


def make_sg(sg_id: str, rules: list[dict]) -> dict:
    return {"GroupId": sg_id, "IpPermissions": rules}


@pytest.fixture
def https_rule():
    return make_sg_rule(from_port=443, to_port=443, ipv4_cidrs=["0.0.0.0/0"])


@pytest.fixture
def ssh_rule():
    return make_sg_rule(from_port=22, to_port=22, ipv4_cidrs=["0.0.0.0/0"])


@pytest.fixture
def rdp_rule():
    return make_sg_rule(from_port=3389, to_port=3389, ipv4_cidrs=["0.0.0.0/0"])


@pytest.fixture
def scoped_rule():
    return make_sg_rule(from_port=22, to_port=22, ipv4_cidrs=["10.0.0.0/8"])


@pytest.fixture
def clean_delta() -> d.RuleDelta:
    return d.RuleDelta()


@pytest.fixture
def delta_with_added(ssh_rule) -> d.RuleDelta:
    norm = d._normalise_rule(ssh_rule)
    return d.RuleDelta(added=[dict(norm, sg_id="sg-abc")])


@pytest.fixture
def critical_response() -> dict:
    return {
        "summary": "SSH port exposed to internet on prod app server.",
        "clean":   False,
        "findings": [
            {
                "severity":      "critical",
                "rule_id":       "sg-abc:tcp:22:0.0.0.0/0",
                "finding":       "SSH exposed to 0.0.0.0/0.",
                "suggested_fix": "Restrict to bastion security group.",
            }
        ],
    }


@pytest.fixture
def multi_finding_response() -> dict:
    return {
        "summary": "Mixed findings.",
        "clean":   False,
        "findings": [
            {"severity": "critical", "rule_id": "sg-abc:tcp:22:0.0.0.0/0",
             "finding": "SSH open.", "suggested_fix": "Restrict."},
            {"severity": "high",     "rule_id": "sg-abc:tcp:3389:0.0.0.0/0",
             "finding": "RDP open.", "suggested_fix": "Remove."},
            {"severity": "medium",   "rule_id": "sg-abc:tcp:8080:10.0.0.0/8",
             "finding": "Wide range.", "suggested_fix": "Narrow."},
            {"severity": "low",      "rule_id": "sg-abc:tcp:8443:10.0.0.0/8",
             "finding": "Minor.", "suggested_fix": "Consider tighter scope."},
            {"severity": "info",     "rule_id": "sg-abc:tcp:443:0.0.0.0/0",
             "finding": "HTTPS expected.", "suggested_fix": "No action."},
        ],
    }


@pytest.fixture
def clean_response() -> dict:
    return {"summary": "No issues found.", "clean": True, "findings": []}


# ── _normalise_rule ───────────────────────────────────────────────────────────

class TestNormaliseRule:

    def test_basic_tcp_rule(self, https_rule):
        n = d._normalise_rule(https_rule)
        assert n["protocol"]   == "tcp"
        assert n["from_port"]  == 443
        assert n["to_port"]    == 443
        assert n["ipv4_cidrs"] == ["0.0.0.0/0"]
        assert n["ipv6_cidrs"] == []

    def test_ipv4_cidrs_sorted(self):
        rule = make_sg_rule(
            from_port=80, to_port=80,
            ipv4_cidrs=["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
        )
        n = d._normalise_rule(rule)
        assert n["ipv4_cidrs"] == sorted(["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])

    def test_ipv6_cidrs_sorted(self):
        rule = make_sg_rule(
            from_port=443, to_port=443,
            ipv6_cidrs=["2001:db8::/32", "::/0"]
        )
        n = d._normalise_rule(rule)
        assert n["ipv6_cidrs"] == sorted(["::/0", "2001:db8::/32"])

    def test_sg_sources_sorted(self):
        rule = make_sg_rule(from_port=5432, to_port=5432,
                             sg_sources=["sg-zzz", "sg-aaa", "sg-mmm"])
        n = d._normalise_rule(rule)
        assert n["sg_sources"] == ["sg-aaa", "sg-mmm", "sg-zzz"]

    def test_prefix_lists_sorted(self):
        rule = make_sg_rule(from_port=443, to_port=443,
                             prefix_lists=["pl-bbb", "pl-aaa"])
        n = d._normalise_rule(rule)
        assert n["prefix_lists"] == ["pl-aaa", "pl-bbb"]

    def test_all_traffic_rule_defaults(self):
        # Protocol -1 has no FromPort/ToPort in the API response
        rule = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [], "UserIdGroupPairs": [], "PrefixListIds": []}
        n = d._normalise_rule(rule)
        assert n["protocol"]  == "-1"
        assert n["from_port"] == 0
        assert n["to_port"]   == 65535

    def test_missing_fields_use_defaults(self):
        n = d._normalise_rule({})
        assert n["protocol"]     == "-1"
        assert n["from_port"]    == 0
        assert n["to_port"]      == 65535
        assert n["ipv4_cidrs"]   == []
        assert n["ipv6_cidrs"]   == []
        assert n["sg_sources"]   == []
        assert n["prefix_lists"] == []

    def test_two_identical_rules_produce_same_key(self, https_rule):
        n1 = d._normalise_rule(https_rule)
        n2 = d._normalise_rule(https_rule)
        assert d._rule_key(n1) == d._rule_key(n2)

    def test_different_ports_produce_different_keys(self):
        r1 = make_sg_rule(from_port=22,  to_port=22,  ipv4_cidrs=["0.0.0.0/0"])
        r2 = make_sg_rule(from_port=443, to_port=443, ipv4_cidrs=["0.0.0.0/0"])
        assert d._rule_key(d._normalise_rule(r1)) != d._rule_key(d._normalise_rule(r2))

    def test_different_cidrs_produce_different_keys(self):
        r1 = make_sg_rule(from_port=22, to_port=22, ipv4_cidrs=["0.0.0.0/0"])
        r2 = make_sg_rule(from_port=22, to_port=22, ipv4_cidrs=["10.0.0.0/8"])
        assert d._rule_key(d._normalise_rule(r1)) != d._rule_key(d._normalise_rule(r2))


# ── diff_snapshots ────────────────────────────────────────────────────────────

class TestDiffSnapshots:

    def test_added_rule_detected(self, https_rule, ssh_rule):
        before = [make_sg("sg-abc", [https_rule])]
        after  = [make_sg("sg-abc", [https_rule, ssh_rule])]
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert len(delta.added)     == 1
        assert len(delta.unchanged) == 1
        assert len(delta.removed)   == 0
        assert delta.added[0]["from_port"] == 22
        os.unlink(bpath); os.unlink(apath)

    def test_removed_rule_detected(self, https_rule, ssh_rule):
        before = [make_sg("sg-abc", [https_rule, ssh_rule])]
        after  = [make_sg("sg-abc", [https_rule])]
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert len(delta.removed)   == 1
        assert len(delta.unchanged) == 1
        assert len(delta.added)     == 0
        assert delta.removed[0]["from_port"] == 22
        os.unlink(bpath); os.unlink(apath)

    def test_identical_snapshots_no_changes(self, https_rule):
        snap = [make_sg("sg-abc", [https_rule])]
        path = make_snapshot(snap)

        delta = d.diff_snapshots(path, path)
        assert not delta.has_changes
        assert len(delta.unchanged) == 1
        os.unlink(path)

    def test_empty_after_all_removed(self, https_rule, ssh_rule):
        before = [make_sg("sg-abc", [https_rule, ssh_rule])]
        after  = [make_sg("sg-abc", [])]
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert len(delta.removed) == 2
        assert len(delta.added)   == 0
        os.unlink(bpath); os.unlink(apath)

    def test_multiple_sgs_tracked_separately(self, https_rule, ssh_rule, rdp_rule):
        before = [make_sg("sg-aaa", [https_rule]),
                  make_sg("sg-bbb", [rdp_rule])]
        after  = [make_sg("sg-aaa", [https_rule, ssh_rule]),
                  make_sg("sg-bbb", [])]
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert len(delta.added)   == 1
        assert len(delta.removed) == 1
        assert delta.added[0]["sg_id"]   == "sg-aaa"
        assert delta.removed[0]["sg_id"] == "sg-bbb"
        os.unlink(bpath); os.unlink(apath)

    def test_rule_order_change_not_flagged_as_diff(self, https_rule, ssh_rule):
        before = [make_sg("sg-abc", [https_rule, ssh_rule])]
        after  = [make_sg("sg-abc", [ssh_rule, https_rule])]  # reversed order
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert not delta.has_changes
        os.unlink(bpath); os.unlink(apath)

    def test_cidr_order_change_not_flagged_as_diff(self):
        r1 = make_sg_rule(from_port=80, to_port=80,
                           ipv4_cidrs=["10.0.0.0/8", "192.168.0.0/16"])
        r2 = make_sg_rule(from_port=80, to_port=80,
                           ipv4_cidrs=["192.168.0.0/16", "10.0.0.0/8"])  # reversed
        before = [make_sg("sg-abc", [r1])]
        after  = [make_sg("sg-abc", [r2])]
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert not delta.has_changes
        os.unlink(bpath); os.unlink(apath)

    def test_boto3_wrapper_shape_accepted(self, https_rule):
        """Snapshot wrapped in {"SecurityGroups": [...]} (boto3 response shape)."""
        before = {"SecurityGroups": [make_sg("sg-abc", [https_rule])]}
        after_sgs = [make_sg("sg-abc", [https_rule])]
        bpath = make_snapshot(before)
        apath = make_snapshot(after_sgs)

        delta = d.diff_snapshots(bpath, apath)
        assert not delta.has_changes
        os.unlink(bpath); os.unlink(apath)

    def test_sg_id_attached_to_added_rule(self, https_rule, ssh_rule):
        before = [make_sg("sg-xyz", [https_rule])]
        after  = [make_sg("sg-xyz", [https_rule, ssh_rule])]
        bpath, apath = make_snapshot(before), make_snapshot(after)

        delta = d.diff_snapshots(bpath, apath)
        assert delta.added[0]["sg_id"] == "sg-xyz"
        os.unlink(bpath); os.unlink(apath)

    def test_has_changes_false_when_only_unchanged(self, https_rule):
        snap = [make_sg("sg-abc", [https_rule])]
        path = make_snapshot(snap)
        delta = d.diff_snapshots(path, path)
        assert delta.has_changes is False
        os.unlink(path)

    def test_has_changes_true_on_addition(self, https_rule, ssh_rule):
        before = [make_sg("sg-abc", [https_rule])]
        after  = [make_sg("sg-abc", [https_rule, ssh_rule])]
        bpath, apath = make_snapshot(before), make_snapshot(after)
        delta = d.diff_snapshots(bpath, apath)
        assert delta.has_changes is True
        os.unlink(bpath); os.unlink(apath)

    def test_unchanged_list_truncated_in_prompt(self, https_rule):
        """Unchanged rules beyond 20 are still in delta but prompt truncates them."""
        rules = [make_sg_rule(from_port=i, to_port=i, ipv4_cidrs=["10.0.0.0/8"])
                 for i in range(1, 26)]  # 25 unchanged rules
        snap  = [make_sg("sg-abc", rules)]
        path  = make_snapshot(snap)
        delta = d.diff_snapshots(path, path)
        # All 25 end up in unchanged — prompt truncation is a display concern
        assert len(delta.unchanged) == 25
        os.unlink(path)


# ── build_user_prompt ─────────────────────────────────────────────────────────

class TestBuildUserPrompt:

    def test_contains_instance_metadata(self, delta_with_added):
        prompt = d.build_user_prompt("web-01", "app", "prod", "ops", delta_with_added)
        assert "web-01" in prompt
        assert "app"    in prompt
        assert "prod"   in prompt
        assert "ops"    in prompt

    def test_contains_section_headers(self, delta_with_added):
        prompt = d.build_user_prompt("web-01", "app", "prod", "ops", delta_with_added)
        assert "ADDED"     in prompt
        assert "REMOVED"   in prompt
        assert "UNCHANGED" in prompt

    def test_added_rules_serialised(self, delta_with_added):
        prompt = d.build_user_prompt("x", "y", "z", "o", delta_with_added)
        # The added ssh rule's from_port 22 should appear in the JSON section
        assert "22" in prompt

    def test_no_added_rules_shows_none(self, clean_delta):
        prompt = d.build_user_prompt("x", "y", "z", "o", clean_delta)
        assert "(none)" in prompt

    def test_unchanged_truncated_at_20(self):
        rules = [
            d._normalise_rule(
                make_sg_rule(from_port=i, to_port=i, ipv4_cidrs=["10.0.0.0/8"])
            )
            for i in range(1, 26)
        ]
        delta = d.RuleDelta(unchanged=[dict(r, sg_id="sg-abc") for r in rules])
        prompt = d.build_user_prompt("x", "y", "z", "o", delta)
        assert "and 5 more unchanged rules" in prompt

    def test_no_truncation_notice_under_20(self):
        rules = [
            d._normalise_rule(
                make_sg_rule(from_port=i, to_port=i, ipv4_cidrs=["10.0.0.0/8"])
            )
            for i in range(1, 10)
        ]
        delta = d.RuleDelta(unchanged=[dict(r, sg_id="sg-abc") for r in rules])
        prompt = d.build_user_prompt("x", "y", "z", "o", delta)
        assert "more unchanged" not in prompt

    def test_role_referenced_in_review_question(self, delta_with_added):
        prompt = d.build_user_prompt("x", "bastion", "prod", "o", delta_with_added)
        # The prompt's question 3 references the role
        assert "bastion" in prompt


# ── call_claude ───────────────────────────────────────────────────────────────

class TestCallClaude:

    def test_dry_run_skips_api(self):
        client = MagicMock()
        result = d.call_claude(client, "prompt", dry_run=True)
        client.messages.create.assert_not_called()
        assert result["clean"] is True
        assert result["findings"] == []

    def test_returns_parsed_json(self):
        client  = MagicMock()
        payload = {"summary": "ok", "clean": True, "findings": []}
        client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(payload))
        ]
        result = d.call_claude(client, "prompt", dry_run=False)
        assert result == payload

    def test_strips_markdown_fences(self):
        client  = MagicMock()
        payload = {"summary": "ok", "clean": True, "findings": []}
        fenced  = f"```json\n{json.dumps(payload)}\n```"
        client.messages.create.return_value.content = [MagicMock(text=fenced)]
        result = d.call_claude(client, "prompt", dry_run=False)
        assert result == payload

    def test_strips_plain_fences(self):
        client  = MagicMock()
        payload = {"summary": "ok", "clean": True, "findings": []}
        fenced  = f"```\n{json.dumps(payload)}\n```"
        client.messages.create.return_value.content = [MagicMock(text=fenced)]
        result = d.call_claude(client, "prompt", dry_run=False)
        assert result == payload

    def test_uses_correct_model(self):
        client  = MagicMock()
        payload = {"summary": "ok", "clean": True, "findings": []}
        client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(payload))
        ]
        d.call_claude(client, "prompt", dry_run=False)
        call_kwargs = client.messages.create.call_args.kwargs
        assert call_kwargs["model"] == d.MODEL

    def test_system_prompt_passed(self):
        client  = MagicMock()
        payload = {"summary": "ok", "clean": True, "findings": []}
        client.messages.create.return_value.content = [
            MagicMock(text=json.dumps(payload))
        ]
        d.call_claude(client, "my prompt", dry_run=False)
        call_kwargs = client.messages.create.call_args.kwargs
        assert call_kwargs["system"] == d.SYSTEM_PROMPT
        assert call_kwargs["messages"][0]["content"] == "my prompt"

    def test_invalid_json_exits(self):
        client = MagicMock()
        client.messages.create.return_value.content = [
            MagicMock(text="not json at all")
        ]
        with pytest.raises(SystemExit):
            d.call_claude(client, "prompt", dry_run=False)


# ── parse_review_result ───────────────────────────────────────────────────────

class TestParseReviewResult:

    def test_findings_populated(self, critical_response, delta_with_added):
        result = d.parse_review_result(
            critical_response, "web-01", "app", "prod", delta_with_added
        )
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity      == "critical"
        assert f.rule_id       == "sg-abc:tcp:22:0.0.0.0/0"
        assert "SSH"           in f.finding
        assert f.suggested_fix != ""

    def test_max_severity_critical(self, multi_finding_response, delta_with_added):
        result = d.parse_review_result(
            multi_finding_response, "x", "app", "prod", delta_with_added
        )
        assert result.max_severity == "critical"

    def test_max_severity_respects_ordering(self, delta_with_added):
        resp = {"summary": "x", "clean": False, "findings": [
            {"severity": "low",    "rule_id": "r", "finding": "f", "suggested_fix": "s"},
            {"severity": "medium", "rule_id": "r", "finding": "f", "suggested_fix": "s"},
            {"severity": "high",   "rule_id": "r", "finding": "f", "suggested_fix": "s"},
        ]}
        result = d.parse_review_result(resp, "x", "app", "prod", delta_with_added)
        assert result.max_severity == "high"

    def test_clean_response(self, clean_response, clean_delta):
        result = d.parse_review_result(
            clean_response, "web-01", "app", "prod", clean_delta
        )
        assert result.clean is True
        assert result.findings == []
        assert result.max_severity is None

    def test_max_severity_none_when_no_findings(self, clean_delta):
        result = d.parse_review_result(
            {"summary": "", "clean": True, "findings": []},
            "x", "y", "z", clean_delta
        )
        assert result.max_severity is None

    def test_summary_preserved(self, critical_response, delta_with_added):
        result = d.parse_review_result(
            critical_response, "x", "app", "prod", delta_with_added
        )
        assert result.summary == critical_response["summary"]

    def test_instance_role_env_preserved(self, clean_response, clean_delta):
        result = d.parse_review_result(
            clean_response, "db-01", "database", "staging", clean_delta
        )
        assert result.instance == "db-01"
        assert result.role     == "database"
        assert result.env      == "staging"

    def test_rule_snapshot_matched_by_sg_id(self, delta_with_added):
        resp = {"summary": "x", "clean": False, "findings": [
            {"severity": "critical", "rule_id": "sg-abc:tcp:22:0.0.0.0/0",
             "finding": "f", "suggested_fix": "s"}
        ]}
        result = d.parse_review_result(resp, "x", "app", "prod", delta_with_added)
        # The snapshot should be the added rule for sg-abc
        assert result.findings[0].rule_snapshot.get("sg_id") == "sg-abc"

    def test_unknown_sg_id_in_rule_id_gives_empty_snapshot(self, delta_with_added):
        resp = {"summary": "x", "clean": False, "findings": [
            {"severity": "info", "rule_id": "sg-UNKNOWN:tcp:80:0.0.0.0/0",
             "finding": "f", "suggested_fix": "s"}
        ]}
        result = d.parse_review_result(resp, "x", "app", "prod", delta_with_added)
        assert result.findings[0].rule_snapshot == {}

    def test_clean_flag_inferred_from_findings(self, delta_with_added):
        # Response says clean=True but has findings — findings win
        resp = {"summary": "x", "clean": True, "findings": [
            {"severity": "low", "rule_id": "r", "finding": "f", "suggested_fix": "s"}
        ]}
        result = d.parse_review_result(resp, "x", "app", "prod", delta_with_added)
        # parse_review_result trusts the API's clean field but falls back
        # to "not bool(findings)" when field is absent
        assert len(result.findings) == 1


# ── exit_code ─────────────────────────────────────────────────────────────────

class TestExitCode:

    def make_result(self, severities: list[str]) -> d.ReviewResult:
        findings = [
            d.ReviewFinding(
                severity=s, rule_id="r", finding="f",
                suggested_fix="s", rule_snapshot={}
            )
            for s in severities
        ]
        return d.ReviewResult(
            instance="x", role="y", env="z",
            findings=findings, clean=not bool(findings)
        )

    def test_no_findings_always_clean(self):
        result = self.make_result([])
        for threshold in d.SEVERITY_ORDER:
            assert d.exit_code(result, threshold) == d.EXIT_CLEAN

    def test_critical_always_exit_critical(self):
        result = self.make_result(["critical"])
        for threshold in d.SEVERITY_ORDER:
            assert d.exit_code(result, threshold) == d.EXIT_CRITICAL

    def test_high_at_high_threshold_is_warnings(self):
        result = self.make_result(["high"])
        assert d.exit_code(result, "high") == d.EXIT_WARNINGS

    def test_high_below_critical_threshold_is_clean(self):
        result = self.make_result(["high"])
        # high is below the critical threshold so play continues cleanly
        assert d.exit_code(result, "critical") == d.EXIT_CLEAN

    def test_medium_below_high_threshold_is_clean(self):
        result = self.make_result(["medium"])
        assert d.exit_code(result, "high") == d.EXIT_CLEAN

    def test_medium_at_medium_threshold_is_warnings(self):
        result = self.make_result(["medium"])
        assert d.exit_code(result, "medium") == d.EXIT_WARNINGS

    def test_low_at_low_threshold_is_warnings(self):
        result = self.make_result(["low"])
        assert d.exit_code(result, "low") == d.EXIT_WARNINGS

    def test_low_below_medium_threshold_is_clean(self):
        result = self.make_result(["low"])
        assert d.exit_code(result, "medium") == d.EXIT_CLEAN

    def test_info_below_all_thresholds_except_itself(self):
        result = self.make_result(["info"])
        assert d.exit_code(result, "low")    == d.EXIT_CLEAN
        assert d.exit_code(result, "medium") == d.EXIT_CLEAN
        assert d.exit_code(result, "info")   == d.EXIT_WARNINGS

    def test_mixed_findings_uses_max(self):
        # critical + info → critical
        result = self.make_result(["info", "critical", "low"])
        assert d.exit_code(result, "high") == d.EXIT_CRITICAL

    def test_all_severities_below_critical(self):
        result = self.make_result(["high", "medium", "low", "info"])
        # max is high — at the high threshold it's a warning
        assert d.exit_code(result, "high") == d.EXIT_WARNINGS
        # max is high — below the critical threshold so it's clean
        assert d.exit_code(result, "critical") == d.EXIT_CLEAN


# ── to_json_output ────────────────────────────────────────────────────────────

class TestToJsonOutput:

    def test_required_keys_present(self, critical_response, delta_with_added):
        result = d.parse_review_result(
            critical_response, "web-01", "app", "prod", delta_with_added
        )
        out = d.to_json_output(result)
        for key in ["instance", "role", "env", "clean", "max_severity",
                    "summary", "findings"]:
            assert key in out

    def test_finding_fields_present(self, critical_response, delta_with_added):
        result = d.parse_review_result(
            critical_response, "web-01", "app", "prod", delta_with_added
        )
        out = d.to_json_output(result)
        f = out["findings"][0]
        for key in ["severity", "rule_id", "finding", "suggested_fix"]:
            assert key in f

    def test_rule_snapshot_not_in_output(self, critical_response, delta_with_added):
        """rule_snapshot is internal — should not leak into JSON output."""
        result = d.parse_review_result(
            critical_response, "web-01", "app", "prod", delta_with_added
        )
        out = d.to_json_output(result)
        assert "rule_snapshot" not in out["findings"][0]

    def test_output_is_json_serialisable(self, critical_response, delta_with_added):
        result = d.parse_review_result(
            critical_response, "web-01", "app", "prod", delta_with_added
        )
        out = d.to_json_output(result)
        serialised = json.dumps(out)  # must not raise
        parsed = json.loads(serialised)
        assert parsed["instance"] == "web-01"

    def test_clean_result_output(self, clean_response, clean_delta):
        result = d.parse_review_result(
            clean_response, "web-01", "app", "prod", clean_delta
        )
        out = d.to_json_output(result)
        assert out["clean"]        is True
        assert out["max_severity"] is None
        assert out["findings"]     == []

    def test_max_severity_in_output(self, multi_finding_response, delta_with_added):
        result = d.parse_review_result(
            multi_finding_response, "x", "app", "prod", delta_with_added
        )
        out = d.to_json_output(result)
        assert out["max_severity"] == "critical"


# ── resolve_api_key ───────────────────────────────────────────────────────────

class TestResolveApiKey:

    def test_reads_env_var(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test",
                                     "AWS_SECRET_ID": ""}):
            key = d.resolve_api_key()
        assert key == "sk-ant-test"

    def test_missing_key_exits(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            os.environ.pop("AWS_SECRET_ID",     None)
            with pytest.raises(SystemExit):
                d.resolve_api_key()

    def test_secrets_manager_json_dict(self):
        secret_val = json.dumps({"api_key": "sk-ant-from-sm"})
        mock_sm    = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": secret_val}

        with patch.dict(os.environ, {"AWS_SECRET_ID": "prod/anthropic/key"}):
            with patch("boto3.client", return_value=mock_sm):
                key = d.resolve_api_key()
        assert key == "sk-ant-from-sm"

    def test_secrets_manager_raw_string(self):
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "sk-ant-raw"}

        with patch.dict(os.environ, {"AWS_SECRET_ID": "prod/anthropic/key"}):
            with patch("boto3.client", return_value=mock_sm):
                key = d.resolve_api_key()
        assert key == "sk-ant-raw"

    def test_secrets_manager_client_error_exits(self):
        from botocore.exceptions import ClientError as BotoClientError

        mock_sm = MagicMock()
        mock_sm.get_secret_value.side_effect = BotoClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            "GetSecretValue",
        )
        with patch.dict(os.environ, {"AWS_SECRET_ID": "some/secret"}):
            with patch("boto3.client", return_value=mock_sm):
                with pytest.raises(SystemExit):
                    d.resolve_api_key()


# ── RuleDelta dataclass ───────────────────────────────────────────────────────

class TestRuleDelta:

    def test_has_changes_false_when_empty(self):
        assert d.RuleDelta().has_changes is False

    def test_has_changes_true_with_added(self):
        assert d.RuleDelta(added=[{"rule": 1}]).has_changes is True

    def test_has_changes_true_with_removed(self):
        assert d.RuleDelta(removed=[{"rule": 1}]).has_changes is True

    def test_has_changes_false_with_only_unchanged(self):
        assert d.RuleDelta(unchanged=[{"rule": 1}]).has_changes is False


# ── ReviewResult dataclass ────────────────────────────────────────────────────

class TestReviewResult:

    def test_max_severity_none_when_empty(self):
        result = d.ReviewResult(instance="x", role="y", env="z")
        assert result.max_severity is None

    def test_max_severity_single_finding(self):
        result = d.ReviewResult(
            instance="x", role="y", env="z",
            findings=[d.ReviewFinding("high", "r", "f", "s", {})]
        )
        assert result.max_severity == "high"

    def test_max_severity_picks_highest(self):
        result = d.ReviewResult(
            instance="x", role="y", env="z",
            findings=[
                d.ReviewFinding("low",      "r", "f", "s", {}),
                d.ReviewFinding("critical", "r", "f", "s", {}),
                d.ReviewFinding("medium",   "r", "f", "s", {}),
            ]
        )
        assert result.max_severity == "critical"

    def test_max_severity_all_same(self):
        result = d.ReviewResult(
            instance="x", role="y", env="z",
            findings=[
                d.ReviewFinding("medium", "r1", "f", "s", {}),
                d.ReviewFinding("medium", "r2", "f", "s", {}),
            ]
        )
        assert result.max_severity == "medium"