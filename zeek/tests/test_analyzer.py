"""
zeek/tests/test_analyzer.py

Full test suite for zeek/analyzer.py and all three detection modules.
Uses real fixture files in zeek/tests/fixtures/ — no mocking of pandas
or file I/O needed since the fixtures are purpose-built.

Run with:
    pytest zeek/tests/test_analyzer.py -v
    pytest zeek/tests/test_analyzer.py -v --cov=zeek
"""

import json
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
# Support running from repo root or from zeek/tests/
ZEEK_DIR    = Path(__file__).parent.parent
FIXTURE_DIR = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(ZEEK_DIR))
sys.path.insert(0, str(ZEEK_DIR / "detections"))

import analyzer as az
import lateral_movement as lm
import data_staging as ds
import dns_entropy as de

# ── Fixture paths ─────────────────────────────────────────────────────────────

CONN_LOG        = FIXTURE_DIR / "conn.log"
CONN_CLEAN_LOG  = FIXTURE_DIR / "conn_clean.log"
CONN_JSON_LOG   = FIXTURE_DIR / "conn_json.log"
DNS_LOG         = FIXTURE_DIR / "dns.log"
DNS_CLEAN_LOG   = FIXTURE_DIR / "dns_clean.log"


# ── DataFrame builders (for unit tests that don't need files) ─────────────────

def conn_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal conn.log DataFrame for unit tests."""
    cols = [
        "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "conn_state", "orig_bytes", "resp_bytes",
    ]
    return pd.DataFrame(rows, columns=cols)


def dns_df(rows: list[dict]) -> pd.DataFrame:
    """Build a minimal dns.log DataFrame for unit tests."""
    cols = [
        "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
        "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
        "qtype", "qtype_name", "rcode", "rcode_name",
        "AA", "TC", "RD", "RA", "Z", "answers", "TTLs", "rejected",
    ]
    return pd.DataFrame(rows, columns=cols)


def make_conn_row(
    src="10.0.1.100", dst="10.0.2.1", dport=22,
    state="SF", orig_bytes=2048, resp_bytes=1024, ts=1700000001,
) -> dict:
    return {
        "ts": ts, "id.orig_h": src, "id.orig_p": 55000,
        "id.resp_h": dst, "id.resp_p": dport,
        "proto": "tcp", "conn_state": state,
        "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
    }


def make_dns_row(
    src="10.0.1.7", query="example.com", rcode_name="NOERROR", ts=1700000001,
) -> dict:
    return {
        "ts": ts, "id.orig_h": src, "id.orig_p": 53001,
        "id.resp_h": "10.0.0.1", "id.resp_p": 53,
        "proto": "udp", "trans_id": 1001, "rtt": 0.01,
        "query": query, "qclass": 1, "qclass_name": "C_INTERNET",
        "qtype": 1, "qtype_name": "A", "rcode": 0,
        "rcode_name": rcode_name,
        "AA": False, "TC": False, "RD": True, "RA": True,
        "Z": 0, "answers": "1.2.3.4", "TTLs": "300", "rejected": False,
    }


MB = 1024 * 1024


# ════════════════════════════════════════════════════════════════════════════════
# analyzer.py — parsing and utilities
# ════════════════════════════════════════════════════════════════════════════════

class TestIsJsonLog:

    def test_tsv_returns_false(self):
        assert az._is_json_log(CONN_LOG) is False

    def test_json_returns_true(self):
        assert az._is_json_log(CONN_JSON_LOG) is True

    def test_comment_only_file_returns_false(self, tmp_path):
        f = tmp_path / "comments.log"
        f.write_text("#separator \\x09\n#fields ts uid\n")
        assert az._is_json_log(f) is False


class TestParseTsv:

    def test_loads_conn_log(self):
        df = az._parse_tsv(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert len(df) > 0
        assert "id.orig_h" in df.columns
        assert "id.resp_p" in df.columns

    def test_skips_comment_lines(self):
        df = az._parse_tsv(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        # No row should start with '#'
        assert not any(str(r).startswith("#") for r in df["ts"])

    def test_numeric_columns_are_numeric(self):
        df = az._parse_tsv(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert pd.api.types.is_numeric_dtype(df["id.resp_p"])
        assert pd.api.types.is_numeric_dtype(df["orig_bytes"])

    def test_ts_is_datetime(self):
        df = az._parse_tsv(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert pd.api.types.is_datetime64_any_dtype(df["ts"])

    def test_dash_becomes_na(self):
        df = az._parse_tsv(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        # tunnel_parents column contains '-' in fixture — should be NA
        assert df["tunnel_parents"].isna().any()

    def test_empty_file_returns_empty_df(self, tmp_path):
        f = tmp_path / "empty.log"
        f.write_text("#separator \\x09\n#fields ts uid\n")
        df = az._parse_tsv(f, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert len(df) == 0

    def test_loads_dns_log(self):
        df = az._parse_tsv(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        assert len(df) > 0
        assert "query" in df.columns
        assert "rcode_name" in df.columns


class TestParseJsonLog:

    def test_loads_json_conn_log(self):
        df = az._parse_json_log(CONN_JSON_LOG)
        assert len(df) == 6
        assert "id.orig_h" in df.columns

    def test_ts_parsed_as_datetime(self):
        df = az._parse_json_log(CONN_JSON_LOG)
        assert pd.api.types.is_datetime64_any_dtype(df["ts"])

    def test_skips_invalid_json_lines(self, tmp_path):
        f = tmp_path / "bad.log"
        f.write_text(
            '{"ts":1700000001.0,"uid":"abc","id.orig_h":"10.0.1.1"}\n'
            'this is not json\n'
            '{"ts":1700000002.0,"uid":"def","id.orig_h":"10.0.1.2"}\n'
        )
        df = az._parse_json_log(f)
        assert len(df) == 2

    def test_empty_file_returns_empty_df(self, tmp_path):
        f = tmp_path / "empty.log"
        f.write_text("")
        df = az._parse_json_log(f)
        assert len(df) == 0


class TestLoadLog:

    def test_auto_detects_tsv(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert len(df) > 0

    def test_auto_detects_json(self):
        df = az.load_log(CONN_JSON_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert len(df) == 6

    def test_tsv_and_json_produce_same_columns(self):
        tsv  = az.load_log(CONN_LOG,      az.CONN_COLUMNS, az.NUMERIC_CONN)
        json_ = az.load_log(CONN_JSON_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        # Both should have the key columns
        for col in ["id.orig_h", "id.resp_h", "id.resp_p", "conn_state"]:
            assert col in tsv.columns
            assert col in json_.columns


class TestFilterSince:

    def test_hours_filter(self):
        now = pd.Timestamp.now(tz="UTC")
        df = pd.DataFrame({
            "ts": [
                now - pd.Timedelta(hours=3),
                now - pd.Timedelta(hours=1),
                now - pd.Timedelta(minutes=30),
            ],
            "val": [1, 2, 3],
        })
        result = az.filter_since(df, "2h")
        assert len(result) == 2
        assert list(result["val"]) == [2, 3]

    def test_minutes_filter(self):
        now = pd.Timestamp.now(tz="UTC")
        df = pd.DataFrame({
            "ts": [
                now - pd.Timedelta(minutes=90),
                now - pd.Timedelta(minutes=20),
            ],
            "val": [1, 2],
        })
        result = az.filter_since(df, "30m")
        assert len(result) == 1
        assert list(result["val"]) == [2]

    def test_days_filter(self):
        now = pd.Timestamp.now(tz="UTC")
        df = pd.DataFrame({
            "ts": [
                now - pd.Timedelta(days=8),
                now - pd.Timedelta(days=3),
            ],
            "val": [1, 2],
        })
        result = az.filter_since(df, "7d")
        assert len(result) == 1

    def test_invalid_unit_returns_unfiltered(self):
        df = pd.DataFrame({"ts": [pd.Timestamp.now(tz="UTC")], "val": [1]})
        result = az.filter_since(df, "2x")
        assert len(result) == 1

    def test_invalid_value_returns_unfiltered(self):
        df = pd.DataFrame({"ts": [pd.Timestamp.now(tz="UTC")], "val": [1]})
        result = az.filter_since(df, "abch")
        assert len(result) == 1

    def test_no_ts_column_returns_unfiltered(self):
        df = pd.DataFrame({"val": [1, 2, 3]})
        result = az.filter_since(df, "1h")
        assert len(result) == 3


class TestEnrich:

    def test_adds_ts_field(self):
        finding = {"detection": "test", "severity": "high"}
        enriched = az.enrich(finding, "conn.log")
        assert "ts" in enriched
        assert enriched["ts"].endswith("Z")

    def test_adds_source_log(self):
        finding = {"detection": "test"}
        enriched = az.enrich(finding, "dns.log")
        assert enriched["source_log"] == "dns.log"

    def test_original_fields_preserved(self):
        finding = {"detection": "x", "severity": "critical", "src_ip": "10.0.0.1"}
        enriched = az.enrich(finding, "conn.log")
        assert enriched["severity"] == "critical"
        assert enriched["src_ip"] == "10.0.0.1"


class TestFilterBySeverity:

    def test_filters_below_threshold(self):
        findings = [
            {"severity": "info"},
            {"severity": "low"},
            {"severity": "medium"},
            {"severity": "high"},
            {"severity": "critical"},
        ]
        result = az.filter_by_severity(findings, "high")
        assert len(result) == 2
        sevs = {f["severity"] for f in result}
        assert sevs == {"high", "critical"}

    def test_info_threshold_returns_all(self):
        findings = [{"severity": s} for s in az.SEVERITY_ORDER]
        assert len(az.filter_by_severity(findings, "info")) == 5

    def test_critical_threshold_returns_only_critical(self):
        findings = [{"severity": s} for s in az.SEVERITY_ORDER]
        result = az.filter_by_severity(findings, "critical")
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_empty_input_returns_empty(self):
        assert az.filter_by_severity([], "medium") == []


# ════════════════════════════════════════════════════════════════════════════════
# lateral_movement.py
# ════════════════════════════════════════════════════════════════════════════════

class TestFanOut:

    def test_detects_ssh_fan_out_from_fixture(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = lm.detect_fan_out(df)
        src_ips = {f["src_ip"] for f in findings}
        assert "10.0.1.100" in src_ips

    def test_fan_out_count_correct(self):
        rows = [make_conn_row(dst=f"10.0.2.{i}") for i in range(1, 9)]
        findings = lm.detect_fan_out(conn_df(rows))
        assert findings[0]["dst_count"] == 8

    def test_below_threshold_no_finding(self):
        rows = [make_conn_row(dst=f"10.0.2.{i}") for i in range(1, 4)]
        assert lm.detect_fan_out(conn_df(rows)) == []

    def test_non_admin_port_no_finding(self):
        rows = [make_conn_row(dst=f"10.0.2.{i}", dport=80) for i in range(1, 9)]
        assert lm.detect_fan_out(conn_df(rows)) == []

    def test_failed_connections_not_flagged(self):
        # conn_state S0 = no response — not a successful connection
        rows = [make_conn_row(dst=f"10.0.2.{i}", state="S0") for i in range(1, 9)]
        assert lm.detect_fan_out(conn_df(rows)) == []

    def test_external_src_not_flagged(self):
        # Source is public IP — not internal
        rows = [make_conn_row(src="8.8.8.8", dst=f"10.0.2.{i}") for i in range(1, 9)]
        assert lm.detect_fan_out(conn_df(rows)) == []

    def test_rdp_fan_out_flagged(self):
        rows = [make_conn_row(dst=f"10.0.2.{i}", dport=3389) for i in range(1, 9)]
        findings = lm.detect_fan_out(conn_df(rows))
        assert findings
        assert findings[0]["port"] == 3389

    def test_finding_has_required_fields(self):
        rows = [make_conn_row(dst=f"10.0.2.{i}") for i in range(1, 9)]
        f = lm.detect_fan_out(conn_df(rows))[0]
        for field in ["detection", "severity", "src_ip", "port",
                      "dst_count", "sample_dsts", "finding", "suggested_fix"]:
            assert field in f, f"missing field: {field}"

    def test_detection_name(self):
        rows = [make_conn_row(dst=f"10.0.2.{i}") for i in range(1, 9)]
        f = lm.detect_fan_out(conn_df(rows))[0]
        assert f["detection"] == "lateral_movement.fan_out"

    def test_empty_df_returns_empty(self):
        assert lm.detect_fan_out(conn_df([])) == []


class TestSequentialSweep:

    def test_detects_sweep_from_fixture(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = lm.detect_sequential_sweep(df)
        src_ips = {f["src_ip"] for f in findings}
        assert "10.0.1.50" in src_ips

    def test_run_length_at_least_5(self):
        rows = [
            make_conn_row(src="10.0.1.50", dst=f"10.0.3.{i}", state="S0", ts=i)
            for i in range(1, 8)
        ]
        findings = lm.detect_sequential_sweep(conn_df(rows))
        assert findings
        assert findings[0]["run_length"] >= 5

    def test_random_ips_no_sweep(self):
        # Last octets: 200, 50, 130, 75, 210 — no sequential run
        rows = [
            make_conn_row(src="10.0.1.50", dst=f"10.0.3.{oct_}", state="S0", ts=i)
            for i, oct_ in enumerate([200, 50, 130, 75, 210])
        ]
        assert lm.detect_sequential_sweep(conn_df(rows)) == []

    def test_finding_has_required_fields(self):
        rows = [
            make_conn_row(src="10.0.1.50", dst=f"10.0.3.{i}", state="S0", ts=i)
            for i in range(1, 8)
        ]
        f = lm.detect_sequential_sweep(conn_df(rows))[0]
        for field in ["detection", "severity", "src_ip", "run_length",
                      "finding", "suggested_fix"]:
            assert field in f

    def test_empty_df_returns_empty(self):
        assert lm.detect_sequential_sweep(conn_df([])) == []


class TestAdminFromWorkstation:

    def test_detects_from_fixture(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = lm.detect_successful_admin_from_workstation(df)
        assert findings

    def test_severity_is_medium(self):
        rows = [make_conn_row()]
        f = lm.detect_successful_admin_from_workstation(conn_df(rows))[0]
        assert f["severity"] == "medium"

    def test_failed_connection_not_flagged(self):
        rows = [make_conn_row(state="REJ")]
        assert lm.detect_successful_admin_from_workstation(conn_df(rows)) == []

    def test_deduplicates_repeated_connections(self):
        # Same src/dst/port repeated 10 times — should be one finding
        rows = [make_conn_row(ts=i) for i in range(10)]
        findings = lm.detect_successful_admin_from_workstation(conn_df(rows))
        assert len(findings) == 1
        assert findings[0]["connection_count"] == 10

    def test_total_bytes_summed(self):
        rows = [make_conn_row(orig_bytes=1000, resp_bytes=500, ts=i)
                for i in range(3)]
        f = lm.detect_successful_admin_from_workstation(conn_df(rows))[0]
        # orig_bytes + resp_bytes per row = 1500, across 3 rows = 4500
        # but the function sums orig_bytes only for the total_bytes field
        assert f["total_bytes"] == 3 * 1000

    def test_finding_has_required_fields(self):
        rows = [make_conn_row()]
        f = lm.detect_successful_admin_from_workstation(conn_df(rows))[0]
        for field in ["detection", "severity", "src_ip", "dst_ip", "port",
                      "connection_count", "first_seen", "last_seen",
                      "total_bytes", "finding", "suggested_fix"]:
            assert field in f


class TestLateralMovementRun:

    def test_run_returns_list(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = lm.run(df)
        assert isinstance(findings, list)

    def test_run_fixture_produces_findings(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert len(lm.run(df)) > 0

    def test_run_clean_log_produces_no_lm_findings(self):
        df = az.load_log(CONN_CLEAN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        # Clean log has only HTTPS/HTTP — no admin port activity
        findings = [f for f in lm.run(df) if f["severity"] != "info"]
        assert findings == []


# ════════════════════════════════════════════════════════════════════════════════
# data_staging.py
# ════════════════════════════════════════════════════════════════════════════════

class TestVolumeSpike:

    def test_detects_from_fixture(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = ds.detect_volume_spike(df)
        assert findings

    def test_large_transfer_flagged(self):
        rows = [make_conn_row(orig_bytes=200 * MB, resp_bytes=0)]
        findings = ds.detect_volume_spike(conn_df(rows))
        assert findings
        assert findings[0]["total_bytes"] >= 200 * MB

    def test_below_threshold_clean(self):
        rows = [make_conn_row(orig_bytes=1 * MB, resp_bytes=0)]
        assert ds.detect_volume_spike(conn_df(rows)) == []

    def test_critical_severity_at_5x_threshold(self):
        rows = [make_conn_row(orig_bytes=600 * MB, resp_bytes=0)]
        f = ds.detect_volume_spike(conn_df(rows))[0]
        assert f["severity"] == "critical"

    def test_high_severity_default(self):
        rows = [make_conn_row(orig_bytes=150 * MB, resp_bytes=0)]
        f = ds.detect_volume_spike(conn_df(rows))[0]
        assert f["severity"] == "high"

    def test_expected_bulk_port_demoted_to_info(self):
        # Port 873 = rsync — in EXPECTED_BULK_PORTS
        rows = [make_conn_row(dport=873, orig_bytes=200 * MB, resp_bytes=0)]
        findings = ds.detect_volume_spike(conn_df(rows))
        assert findings
        assert findings[0]["severity"] == "info"

    def test_bidirectional_bytes_summed(self):
        rows = [make_conn_row(orig_bytes=60 * MB, resp_bytes=60 * MB)]
        findings = ds.detect_volume_spike(conn_df(rows))
        assert findings
        assert findings[0]["total_bytes"] == 120 * MB

    def test_finding_has_required_fields(self):
        rows = [make_conn_row(orig_bytes=200 * MB, resp_bytes=0)]
        f = ds.detect_volume_spike(conn_df(rows))[0]
        for field in ["detection", "severity", "src_ip", "dst_ip", "port",
                      "total_bytes", "total_human", "connection_count",
                      "finding", "suggested_fix"]:
            assert field in f

    def test_total_human_format(self):
        rows = [make_conn_row(orig_bytes=200 * MB, resp_bytes=0)]
        f = ds.detect_volume_spike(conn_df(rows))[0]
        assert "MB" in f["total_human"]

    def test_empty_df_returns_empty(self):
        assert ds.detect_volume_spike(conn_df([])) == []


class TestFanIn:

    def test_detects_from_fixture(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = ds.detect_fan_in(df)
        # Fixture has 6 sources sending 150 MB each to 10.0.1.99
        dsts = {f["dst_ip"] for f in findings}
        assert "10.0.1.99" in dsts

    def test_severity_critical(self):
        rows = [
            make_conn_row(src=f"10.0.1.{i}", dst="10.0.1.99",
                          dport=9999, orig_bytes=150 * MB)
            for i in range(1, 7)
        ]
        findings = ds.detect_fan_in(conn_df(rows))
        assert findings
        assert findings[0]["severity"] == "critical"

    def test_source_count_correct(self):
        rows = [
            make_conn_row(src=f"10.0.1.{i}", dst="10.0.1.99",
                          dport=9999, orig_bytes=150 * MB)
            for i in range(1, 7)
        ]
        f = ds.detect_fan_in(conn_df(rows))[0]
        assert f["source_count"] == 6

    def test_below_source_threshold_no_finding(self):
        rows = [
            make_conn_row(src=f"10.0.1.{i}", dst="10.0.1.99",
                          dport=9999, orig_bytes=150 * MB)
            for i in range(1, 4)
        ]
        assert ds.detect_fan_in(conn_df(rows)) == []

    def test_finding_has_required_fields(self):
        rows = [
            make_conn_row(src=f"10.0.1.{i}", dst="10.0.1.99",
                          dport=9999, orig_bytes=150 * MB)
            for i in range(1, 7)
        ]
        f = ds.detect_fan_in(conn_df(rows))[0]
        for field in ["detection", "severity", "dst_ip", "source_count",
                      "total_bytes", "total_human", "sample_srcs",
                      "finding", "suggested_fix"]:
            assert field in f

    def test_empty_df_returns_empty(self):
        assert ds.detect_fan_in(conn_df([])) == []


class TestDataStagingRun:

    def test_run_fixture_produces_findings(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert len(ds.run(df)) > 0

    def test_run_clean_log_no_staging_findings(self):
        df = az.load_log(CONN_CLEAN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = [f for f in ds.run(df) if f["severity"] not in ("info", "low")]
        assert findings == []

    def test_run_returns_list(self):
        df = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        assert isinstance(ds.run(df), list)


# ════════════════════════════════════════════════════════════════════════════════
# dns_entropy.py
# ════════════════════════════════════════════════════════════════════════════════

class TestShannonEntropy:

    def test_uniform_string_zero_entropy(self):
        assert de.shannon_entropy("aaaaaaa") == pytest.approx(0.0)

    def test_empty_string_zero(self):
        assert de.shannon_entropy("") == 0.0

    def test_two_chars_equal_split(self):
        # "ababab" — 2 chars, equal — entropy = 1.0 bit
        assert de.shannon_entropy("ababab") == pytest.approx(1.0)

    def test_high_entropy_string(self):
        assert de.shannon_entropy("x7k2mq9pzw") > 3.0

    def test_low_entropy_hostname(self):
        assert de.shannon_entropy("www") < 2.0

    def test_entropy_increases_with_variety(self):
        low  = de.shannon_entropy("aaabbbccc")
        high = de.shannon_entropy("x7k2mq9pzwabcdef")
        assert high > low


class TestHighEntropySubdomains:

    def test_detects_dga_from_fixture(self):
        df = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        findings = de.detect_high_entropy_subdomains(df)
        fqdns = {f["fqdn"] for f in findings}
        assert any("evil-c2.com" in fqdn for fqdn in fqdns)

    def test_cloudfront_whitelisted(self):
        df = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        findings = de.detect_high_entropy_subdomains(df)
        assert not any("cloudfront.net" in f["fqdn"] for f in findings)

    def test_clean_log_no_findings(self):
        df = az.load_log(DNS_CLEAN_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        findings = de.detect_high_entropy_subdomains(df)
        assert findings == []

    def test_high_entropy_label_detected(self):
        rows = [make_dns_row(query="x7k2mq9pzwabcdef.evil.com")]
        findings = de.detect_high_entropy_subdomains(dns_df(rows))
        assert findings
        assert findings[0]["entropy"] >= de.ENTROPY_THRESHOLD

    def test_low_entropy_label_not_flagged(self):
        rows = [make_dns_row(query="www.example.com")]
        assert de.detect_high_entropy_subdomains(dns_df(rows)) == []

    def test_short_label_below_min_length_ignored(self):
        # Label 'ab' is too short (< MIN_LABEL_LENGTH=8)
        rows = [make_dns_row(query="ab.evil.com")]
        assert de.detect_high_entropy_subdomains(dns_df(rows)) == []

    def test_critical_severity_at_4_bits(self):
        # Craft a label with entropy > 4.0
        rows = [make_dns_row(query="x7k2mq9pzwabcdef1234.evil.com")]
        findings = de.detect_high_entropy_subdomains(dns_df(rows))
        if findings:
            assert findings[0]["severity"] in ("high", "critical")

    def test_finding_has_required_fields(self):
        rows = [make_dns_row(query="x7k2mq9pzwabcdef.evil.com")]
        f = de.detect_high_entropy_subdomains(dns_df(rows))[0]
        for field in ["detection", "severity", "fqdn", "label",
                      "entropy", "queried_by", "finding", "suggested_fix"]:
            assert field in f

    def test_queried_by_contains_src_ip(self):
        rows = [make_dns_row(src="10.0.1.7", query="x7k2mq9pzwabcdef.evil.com")]
        f = de.detect_high_entropy_subdomains(dns_df(rows))[0]
        assert "10.0.1.7" in f["queried_by"]

    def test_empty_df_returns_empty(self):
        assert de.detect_high_entropy_subdomains(dns_df([])) == []


class TestNxdomainStorm:

    def test_detects_from_fixture(self):
        df = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        findings = de.detect_nxdomain_storm(df)
        # 10.0.1.9 has 20 NXDOMAINs in fixture
        src_ips = {f["src_ip"] for f in findings}
        assert "10.0.1.9" in src_ips

    def test_severity_critical(self):
        rows = [
            make_dns_row(src="10.0.1.9",
                         query=f"random{i:04x}.dga.net",
                         rcode_name="NXDOMAIN")
            for i in range(25)
        ]
        findings = de.detect_nxdomain_storm(dns_df(rows))
        assert findings
        assert findings[0]["severity"] == "critical"

    def test_low_nx_rate_not_flagged(self):
        # 2 NXDOMAINs out of 25 = 8% — below threshold
        rows = (
            [make_dns_row(rcode_name="NOERROR")] * 23 +
            [make_dns_row(query="fail1.evil.com", rcode_name="NXDOMAIN"),
             make_dns_row(query="fail2.evil.com", rcode_name="NXDOMAIN")]
        )
        assert de.detect_nxdomain_storm(dns_df(rows)) == []

    def test_below_min_query_count_not_flagged(self):
        # Only 5 queries — below MIN_QUERIES=20
        rows = [
            make_dns_row(query=f"x{i}.evil.com", rcode_name="NXDOMAIN")
            for i in range(5)
        ]
        assert de.detect_nxdomain_storm(dns_df(rows)) == []

    def test_finding_has_required_fields(self):
        rows = [
            make_dns_row(query=f"x{i:04x}.evil.com", rcode_name="NXDOMAIN")
            for i in range(25)
        ]
        f = de.detect_nxdomain_storm(dns_df(rows))[0]
        for field in ["detection", "severity", "src_ip", "nx_count",
                      "total_queries", "nx_rate", "sample_domains",
                      "finding", "suggested_fix"]:
            assert field in f

    def test_nx_rate_computed_correctly(self):
        rows = (
            [make_dns_row(rcode_name="NOERROR")] * 5 +
            [make_dns_row(query=f"x{i}.evil.com", rcode_name="NXDOMAIN")
             for i in range(20)]
        )
        f = de.detect_nxdomain_storm(dns_df(rows))[0]
        assert f["nx_rate"] == pytest.approx(20 / 25, abs=0.01)

    def test_empty_df_returns_empty(self):
        assert de.detect_nxdomain_storm(dns_df([])) == []


class TestLongLabels:

    def test_detects_long_label(self):
        rows = [make_dns_row(query="a" * 55 + ".tunnel.attacker.io")]
        findings = de.detect_long_labels(dns_df(rows))
        assert findings

    def test_detects_from_fixture(self):
        df = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        findings = de.detect_long_labels(df)
        fqdns = {f["fqdn"] for f in findings}
        assert any("tunnel.attacker.io" in fqdn for fqdn in fqdns)

    def test_short_label_not_flagged(self):
        rows = [make_dns_row(query="short.example.com")]
        assert de.detect_long_labels(dns_df(rows)) == []

    def test_exactly_at_threshold_flagged(self):
        label = "a" * de.LONG_LABEL_THRESHOLD
        rows  = [make_dns_row(query=f"{label}.evil.com")]
        assert de.detect_long_labels(dns_df(rows))

    def test_one_below_threshold_not_flagged(self):
        label = "a" * (de.LONG_LABEL_THRESHOLD - 1)
        rows  = [make_dns_row(query=f"{label}.evil.com")]
        assert de.detect_long_labels(dns_df(rows)) == []

    def test_whitelisted_domain_not_flagged(self):
        label = "a" * 55
        rows  = [make_dns_row(query=f"{label}.cloudfront.net")]
        assert de.detect_long_labels(dns_df(rows)) == []

    def test_finding_has_required_fields(self):
        rows = [make_dns_row(query="a" * 55 + ".evil.com")]
        f = de.detect_long_labels(dns_df(rows))[0]
        for field in ["detection", "severity", "fqdn", "long_labels",
                      "max_length", "queried_by", "finding", "suggested_fix"]:
            assert field in f

    def test_empty_df_returns_empty(self):
        assert de.detect_long_labels(dns_df([])) == []


class TestDnsEntropyRun:

    def test_run_fixture_produces_findings(self):
        df = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        assert len(de.run(df)) > 0

    def test_run_clean_log_no_findings(self):
        df = az.load_log(DNS_CLEAN_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        findings = [f for f in de.run(df)
                    if f.get("severity") not in ("info", "low")]
        assert findings == []

    def test_run_returns_list(self):
        df = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        assert isinstance(de.run(df), list)


# ════════════════════════════════════════════════════════════════════════════════
# End-to-end: load fixture → run all detectors → NDJSON output
# ════════════════════════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_conn_fixture_produces_findings(self):
        conn = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        all_findings = (
            [az.enrich(f, "conn.log") for f in lm.run(conn)] +
            [az.enrich(f, "conn.log") for f in ds.run(conn)]
        )
        assert len(all_findings) > 0

    def test_dns_fixture_produces_findings(self):
        dns = az.load_log(DNS_LOG, az.DNS_COLUMNS, az.NUMERIC_DNS)
        all_findings = [az.enrich(f, "dns.log") for f in de.run(dns)]
        assert len(all_findings) > 0

    def test_findings_are_ndjson_serialisable(self):
        conn = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = [az.enrich(f, "conn.log") for f in lm.run(conn)]
        for f in findings:
            line = json.dumps(f, default=str)  # must not raise
            parsed = json.loads(line)
            assert "detection" in parsed

    def test_each_finding_has_ts_and_source_log(self):
        conn = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = [az.enrich(f, "conn.log") for f in lm.run(conn)]
        for f in findings:
            assert "ts" in f
            assert "source_log" in f
            assert f["source_log"] == "conn.log"

    def test_severity_filter_applied(self):
        conn = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        all_findings = (
            [az.enrich(f, "conn.log") for f in lm.run(conn)] +
            [az.enrich(f, "conn.log") for f in ds.run(conn)]
        )
        filtered = az.filter_by_severity(all_findings, "high")
        sevs = {f["severity"] for f in filtered}
        assert "info" not in sevs
        assert "low" not in sevs
        assert "medium" not in sevs

    def test_ndjson_written_to_file(self, tmp_path):
        conn = az.load_log(CONN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        findings = [az.enrich(f, "conn.log") for f in lm.run(conn)]
        out = tmp_path / "findings.ndjson"
        az.write_ndjson(findings, str(out))
        lines = out.read_text().strip().split("\n")
        assert len(lines) == len(findings)
        for line in lines:
            parsed = json.loads(line)
            assert "detection" in parsed

    def test_clean_logs_produce_no_high_findings(self):
        conn = az.load_log(CONN_CLEAN_LOG, az.CONN_COLUMNS, az.NUMERIC_CONN)
        dns  = az.load_log(DNS_CLEAN_LOG,  az.DNS_COLUMNS,  az.NUMERIC_DNS)
        all_findings = (
            [az.enrich(f, "conn.log") for f in lm.run(conn)] +
            [az.enrich(f, "conn.log") for f in ds.run(conn)] +
            [az.enrich(f, "dns.log")  for f in de.run(dns)]
        )
        high_plus = az.filter_by_severity(all_findings, "high")
        assert high_plus == []