"""
zeek/detections/data_staging.py

Detects data staging patterns in Zeek conn.log data.

Data staging = an attacker aggregating stolen data on an internal host
before exfiltration. Signals:

  - Volume spike: a single src→dst pair transfers more than VOLUME_THRESHOLD
    bytes in a rolling WINDOW_SECS window
  - Fan-in: a single destination receives large transfers from many internal
    sources (collection point / staging host)
  - Unusual protocol: large transfers on non-standard ports (not 80/443/
    common file share ports) between internal hosts

Tuning:
    VOLUME_THRESHOLD_MB    — per-pair transfer threshold (default 100 MB)
    FAN_IN_SOURCE_THRESHOLD — distinct sources to a single dst before flagging
    WINDOW_SECS            — rolling window for volume aggregation
    EXPECTED_BULK_PORTS    — ports where large transfers are normal (backup,
                             NFS, etc.) — transfers on these are demoted to info
"""

from __future__ import annotations

import ipaddress
import logging

import pandas as pd

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

VOLUME_THRESHOLD_MB      = 100          # flag pairs transferring > this
VOLUME_THRESHOLD_BYTES   = VOLUME_THRESHOLD_MB * 1024 * 1024
FAN_IN_SOURCE_THRESHOLD  = 5            # distinct srcs to one dst
WINDOW_SECS              = 3600         # 1-hour rolling window

# Ports where bulk transfers are expected — suppress volume findings
EXPECTED_BULK_PORTS = {
    20, 21,          # FTP
    111, 2049,       # NFS
    137, 138, 139,   # SMB/NetBIOS (flagged by lateral movement instead)
    445,             # SMB
    873,             # rsync
    3260,            # iSCSI
    8200,            # Vault / backup agents
    9000,            # object storage (MinIO etc.)
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _mb(b: float) -> str:
    return f"{b / 1_048_576:.1f} MB"


# ── Detection functions ───────────────────────────────────────────────────────

def detect_volume_spike(df: pd.DataFrame) -> list[dict]:
    """
    Flag src→dst pairs where total bytes transferred in the log window
    exceeds VOLUME_THRESHOLD_BYTES.

    Uses orig_bytes + resp_bytes so bidirectional transfers are counted.
    Large file copies, database dumps, and backup exfil all appear here.
    """
    findings = []

    mask = (
        df["id.orig_h"].apply(_is_private) &
        df["id.resp_h"].apply(_is_private)
    )
    internal = df[mask].copy()

    if internal.empty:
        return findings

    internal["total_bytes"] = (
        internal["orig_bytes"].fillna(0) +
        internal["resp_bytes"].fillna(0)
    )

    grouped = (
        internal
        .groupby(["id.orig_h", "id.resp_h", "id.resp_p"])
        .agg(
            total_bytes=("total_bytes", "sum"),
            connection_count=("ts", "count"),
            first_seen=("ts", "min"),
            last_seen=("ts", "max"),
        )
        .reset_index()
    )

    flagged = grouped[grouped["total_bytes"] >= VOLUME_THRESHOLD_BYTES]

    for _, row in flagged.iterrows():
        src   = row["id.orig_h"]
        dst   = row["id.resp_h"]
        port  = int(row["id.resp_p"])
        total = int(row["total_bytes"])
        count = int(row["connection_count"])

        severity = "high"
        if port in EXPECTED_BULK_PORTS:
            severity = "info"
        elif total >= VOLUME_THRESHOLD_BYTES * 5:
            severity = "critical"

        findings.append({
            "detection":        "data_staging.volume_spike",
            "severity":         severity,
            "src_ip":           src,
            "dst_ip":           dst,
            "port":             port,
            "total_bytes":      total,
            "total_human":      _mb(total),
            "connection_count": count,
            "first_seen":       str(row["first_seen"]),
            "last_seen":        str(row["last_seen"]),
            "finding": (
                f"{src} transferred {_mb(total)} to {dst} on port {port} "
                f"across {count} connection(s) — exceeds {VOLUME_THRESHOLD_MB} MB "
                f"threshold. Possible data staging prior to exfiltration."
            ),
            "suggested_fix": (
                f"Verify whether {src}→{dst} on port {port} is an authorised "
                f"transfer (backup job, replication, etc.). If unexpected, "
                f"isolate {dst} and check for staging directories. "
                f"Add the port to EXPECTED_BULK_PORTS if this is a known "
                f"bulk-transfer path."
            ),
        })

    log.info("volume_spike: %d finding(s)", len(findings))
    return findings


def detect_fan_in(df: pd.DataFrame) -> list[dict]:
    """
    Flag destination IPs that receive large transfers from many distinct
    internal sources — characteristic of a data collection / staging host.

    An attacker who has compromised multiple hosts will often move data to
    a single staging point before exfiltration.
    """
    findings = []

    mask = (
        df["id.orig_h"].apply(_is_private) &
        df["id.resp_h"].apply(_is_private)
    )
    internal = df[mask].copy()

    if internal.empty:
        return findings

    internal["total_bytes"] = (
        internal["orig_bytes"].fillna(0) +
        internal["resp_bytes"].fillna(0)
    )

    # Only consider pairs that cross the volume threshold individually
    pair_volume = (
        internal
        .groupby(["id.orig_h", "id.resp_h"])["total_bytes"]
        .sum()
        .reset_index()
    )
    heavy_pairs = pair_volume[
        pair_volume["total_bytes"] >= VOLUME_THRESHOLD_BYTES
    ]

    if heavy_pairs.empty:
        return findings

    # Count distinct heavy sources per destination
    dst_counts = (
        heavy_pairs
        .groupby("id.resp_h")
        .agg(
            source_count=("id.orig_h", "nunique"),
            total_bytes=("total_bytes", "sum"),
            sources=("id.orig_h", lambda x: x.tolist()),
        )
        .reset_index()
    )

    flagged = dst_counts[
        dst_counts["source_count"] >= FAN_IN_SOURCE_THRESHOLD
    ]

    for _, row in flagged.iterrows():
        dst     = row["id.resp_h"]
        count   = int(row["source_count"])
        total   = int(row["total_bytes"])
        sources = row["sources"][:5]  # sample for context

        findings.append({
            "detection":    "data_staging.fan_in",
            "severity":     "critical",
            "dst_ip":       dst,
            "source_count": count,
            "total_bytes":  total,
            "total_human":  _mb(total),
            "sample_srcs":  sources,
            "finding": (
                f"{dst} received large transfers (>{VOLUME_THRESHOLD_MB} MB each) "
                f"from {count} distinct internal sources ({_mb(total)} total). "
                f"This is a strong indicator of a data staging host. "
                f"Sample sources: {', '.join(sources[:3])}{'...' if count > 3 else ''}."
            ),
            "suggested_fix": (
                f"Treat {dst} as a potential staging host. Isolate it immediately, "
                f"capture a memory image, and audit its filesystem for aggregated "
                f"data. Review VPC flow logs and block egress to untrusted IPs."
            ),
        })

    log.info("fan_in: %d finding(s)", len(findings))
    return findings


def detect_unusual_protocol_bulk(df: pd.DataFrame) -> list[dict]:
    """
    Flag large internal transfers on ports that are neither common file
    transfer ports nor flagged by other detectors.

    Attackers often use custom ports or common application ports (HTTP/8080)
    to blend data exfiltration with normal traffic.
    """
    findings = []

    # Ports that are expected to carry bulk traffic — skip these
    skip_ports = EXPECTED_BULK_PORTS | {80, 443, 8080, 8443, 3306, 5432, 27017}

    mask = (
        df["id.orig_h"].apply(_is_private) &
        df["id.resp_h"].apply(_is_private) &
        (~df["id.resp_p"].isin(skip_ports))
    )
    internal = df[mask].copy()

    if internal.empty:
        return findings

    internal["total_bytes"] = (
        internal["orig_bytes"].fillna(0) +
        internal["resp_bytes"].fillna(0)
    )

    grouped = (
        internal
        .groupby(["id.orig_h", "id.resp_h", "id.resp_p"])
        .agg(total_bytes=("total_bytes", "sum"))
        .reset_index()
    )

    # Higher threshold for this detector — reduce noise on non-standard ports
    threshold = VOLUME_THRESHOLD_BYTES * 2
    flagged   = grouped[grouped["total_bytes"] >= threshold]

    for _, row in flagged.iterrows():
        src   = row["id.orig_h"]
        dst   = row["id.resp_h"]
        port  = int(row["id.resp_p"])
        total = int(row["total_bytes"])

        findings.append({
            "detection":   "data_staging.unusual_protocol_bulk",
            "severity":    "high",
            "src_ip":      src,
            "dst_ip":      dst,
            "port":        port,
            "total_bytes": total,
            "total_human": _mb(total),
            "finding": (
                f"{src} transferred {_mb(total)} to {dst} on non-standard "
                f"port {port}. Large transfers on unusual ports may indicate "
                f"custom exfiltration tooling or tunnelled data."
            ),
            "suggested_fix": (
                f"Verify the service running on {dst}:{port}. If this port "
                f"is a known application, add it to EXPECTED_BULK_PORTS. "
                f"If unexpected, block via Security Group and investigate "
                f"both endpoints for compromise."
            ),
        })

    log.info("unusual_protocol_bulk: %d finding(s)", len(findings))
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def run(df: pd.DataFrame) -> list[dict]:
    """Run all data staging detectors. Returns combined findings list."""
    return (
        detect_volume_spike(df) +
        detect_fan_in(df) +
        detect_unusual_protocol_bulk(df)
    )