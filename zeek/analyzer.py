#!/usr/bin/env python3
"""
zeek/analyzer.py — Zeek log analyser for lateral movement and data staging.

Parses Zeek conn.log and dns.log, runs three detection modules, and outputs
NDJSON findings to stdout or a file.

Usage:
    python3 analyzer.py \\
        --conn  /path/to/conn.log  \\
        --dns   /path/to/dns.log   \\
        [--output findings.ndjson] \\
        [--since 2h]               \\
        [--min-severity medium]    \\
        [--dry-run]

Output format:
    One JSON object per line (NDJSON). Each finding contains:
        detection, severity, finding, suggested_fix, ts (UTC), + detector fields

    Designed for ingestion into S3/Athena, OpenSearch, or CloudWatch Logs.
    Exit code: 0 = clean, 1 = findings present.

Zeek log format:
    Zeek writes TSV with a header block. Both the default TSV format and
    JSON format (LogAscii::use_json=T) are supported.

    Required conn.log fields:
        ts, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
        proto, conn_state, orig_bytes, resp_bytes, duration

    Required dns.log fields:
        ts, id.orig_h, id.resp_h, proto, query, rcode_name
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pandas as pd

# Detection modules — import from detections/ subpackage when installed,
# or directly when running from the zeek/ directory
try:
    from detections import lateral_movement, data_staging, dns_entropy
except ImportError:
    # Running from repo root or tests
    import lateral_movement
    import data_staging
    import dns_entropy

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

# ── Zeek log parsing ──────────────────────────────────────────────────────────

# Zeek conn.log column names in TSV order
CONN_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
    "resp_ip_bytes", "tunnel_parents",
]

DNS_COLUMNS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
    "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD",
    "RA", "Z", "answers", "TTLs", "rejected",
]

NUMERIC_CONN = [
    "id.orig_p", "id.resp_p", "orig_bytes", "resp_bytes",
    "duration", "orig_pkts", "resp_pkts",
]

NUMERIC_DNS = ["id.orig_p", "id.resp_p", "trans_id", "rcode"]


def _is_json_log(path: Path) -> bool:
    """Peek at the first non-comment line to determine if log is JSON."""
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                return line.startswith("{")
    return False


def _parse_tsv(path: Path, columns: list[str], numeric: list[str]) -> pd.DataFrame:
    """
    Parse a Zeek TSV log file.
    Handles the Zeek header block (#separator, #fields, #types, #open, #close).
    Missing values ('-' in Zeek) are converted to NaN.
    """
    rows = []
    with open(path) as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            rows.append(line.rstrip("\n").split("\t"))

    if not rows:
        log.warning("%s: no data rows found", path)
        return pd.DataFrame(columns=columns)

    # Pad or truncate rows to match expected column count
    n = len(columns)
    rows = [r[:n] + [""] * (n - len(r)) for r in rows]

    df = pd.DataFrame(rows, columns=columns)
    df.replace("-", pd.NA, inplace=True)

    for col in numeric:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(
            pd.to_numeric(df["ts"], errors="coerce"),
            unit="s", utc=True, errors="coerce",
        )

    return df


def _parse_json_log(path: Path) -> pd.DataFrame:
    """Parse a Zeek JSON-format log (LogAscii::use_json=T)."""
    records = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    if "ts" in df.columns:
        df["ts"] = pd.to_datetime(df["ts"], unit="s", utc=True, errors="coerce")

    return df


def load_log(path: Path, columns: list[str], numeric: list[str]) -> pd.DataFrame:
    """Auto-detect format and parse a Zeek log file."""
    log.info("Loading %s ...", path)
    if _is_json_log(path):
        df = _parse_json_log(path)
    else:
        df = _parse_tsv(path, columns, numeric)
    log.info("  ↳ %d rows loaded", len(df))
    return df


def filter_since(df: pd.DataFrame, since: str) -> pd.DataFrame:
    """
    Filter DataFrame to rows within the --since window.
    Accepts: Nh (hours), Nm (minutes), Nd (days). e.g. '2h', '30m', '7d'
    """
    if "ts" not in df.columns or df["ts"].isna().all():
        return df

    unit = since[-1].lower()
    try:
        value = int(since[:-1])
    except ValueError:
        log.warning("Invalid --since value '%s' — ignoring filter", since)
        return df

    delta = {
        "h": timedelta(hours=value),
        "m": timedelta(minutes=value),
        "d": timedelta(days=value),
    }.get(unit)

    if delta is None:
        log.warning("Unknown time unit in --since '%s' — use h/m/d", since)
        return df

    cutoff = pd.Timestamp.now(tz="UTC") - delta
    before = len(df)
    df = df[df["ts"] >= cutoff]
    log.info("  ↳ --since %s: %d → %d rows", since, before, len(df))
    return df


# ── Finding enrichment ────────────────────────────────────────────────────────

def enrich(finding: dict, source_log: str) -> dict:
    """Add metadata fields to every finding for downstream ingestion."""
    return {
        "ts":         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_log": source_log,
        **finding,
    }


def filter_by_severity(
    findings: list[dict], min_severity: str
) -> list[dict]:
    threshold = SEVERITY_ORDER.index(min_severity)
    return [
        f for f in findings
        if SEVERITY_ORDER.index(f.get("severity", "info")) >= threshold
    ]


# ── Output ────────────────────────────────────────────────────────────────────

def write_ndjson(findings: list[dict], output_path: str | None) -> None:
    lines = [json.dumps(f, default=str) for f in findings]
    if output_path:
        with open(output_path, "w") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        log.info("Findings written to %s", output_path)
    else:
        for line in lines:
            print(line)


def print_summary(findings: list[dict]) -> None:
    log.info("─" * 60)
    log.info("Total findings: %d", len(findings))
    by_sev: dict[str, int] = {}
    by_det: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        det = f.get("detection", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        by_det[det] = by_det.get(det, 0) + 1

    for sev in reversed(SEVERITY_ORDER):
        if sev in by_sev:
            log.info("  [%s] %d", sev.upper(), by_sev[sev])

    log.info("By detector:")
    for det, count in sorted(by_det.items()):
        log.info("  %s: %d", det, count)


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Zeek log analyser — lateral movement and data staging."
    )
    p.add_argument("--conn",  metavar="FILE",
                   help="Path to Zeek conn.log (TSV or JSON format).")
    p.add_argument("--dns",   metavar="FILE",
                   help="Path to Zeek dns.log (TSV or JSON format).")
    p.add_argument("--output", metavar="FILE",
                   help="Write NDJSON findings to this file (default: stdout).")
    p.add_argument("--since",  metavar="WINDOW", default=None,
                   help="Only analyse events from last N hours/minutes/days "
                        "(e.g. 2h, 30m, 7d). Default: entire log.")
    p.add_argument("--min-severity", default="low",
                   choices=SEVERITY_ORDER,
                   help="Suppress findings below this severity (default: low).")
    p.add_argument("--dry-run", action="store_true",
                   help="Parse logs and print row counts but skip detections.")
    p.add_argument("--verbose", action="store_true",
                   help="Enable DEBUG logging.")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.conn and not args.dns:
        log.error("Provide at least one of --conn or --dns.")
        sys.exit(1)

    all_findings: list[dict] = []

    # ── conn.log ──────────────────────────────────────────────────────────────
    if args.conn:
        conn_path = Path(args.conn)
        if not conn_path.exists():
            log.error("conn.log not found: %s", conn_path)
            sys.exit(1)

        conn_df = load_log(conn_path, CONN_COLUMNS, NUMERIC_CONN)

        if args.since:
            conn_df = filter_since(conn_df, args.since)

        if args.dry_run:
            log.info("[dry-run] conn.log: %d rows — skipping detections", len(conn_df))
        else:
            log.info("Running lateral movement detections ...")
            lm_findings = [enrich(f, "conn.log") for f in lateral_movement.run(conn_df)]
            log.info("Running data staging detections ...")
            ds_findings = [enrich(f, "conn.log") for f in data_staging.run(conn_df)]
            all_findings.extend(lm_findings + ds_findings)

    # ── dns.log ───────────────────────────────────────────────────────────────
    if args.dns:
        dns_path = Path(args.dns)
        if not dns_path.exists():
            log.error("dns.log not found: %s", dns_path)
            sys.exit(1)

        dns_df = load_log(dns_path, DNS_COLUMNS, NUMERIC_DNS)

        if args.since:
            dns_df = filter_since(dns_df, args.since)

        if args.dry_run:
            log.info("[dry-run] dns.log: %d rows — skipping detections", len(dns_df))
        else:
            log.info("Running DNS entropy detections ...")
            dns_findings = [enrich(f, "dns.log") for f in dns_entropy.run(dns_df)]
            all_findings.extend(dns_findings)

    if not args.dry_run:
        # Filter by minimum severity
        all_findings = filter_by_severity(all_findings, args.min_severity)

        # Sort: critical first, then by detection name for stable output
        all_findings.sort(
            key=lambda f: (
                -SEVERITY_ORDER.index(f.get("severity", "info")),
                f.get("detection", ""),
            )
        )

        print_summary(all_findings)
        write_ndjson(all_findings, args.output)

    sys.exit(1 if all_findings else 0)


if __name__ == "__main__":
    main()