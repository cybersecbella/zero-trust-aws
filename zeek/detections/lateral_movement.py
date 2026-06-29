"""
zeek/detections/lateral_movement.py

Detects lateral movement patterns in Zeek conn.log data.

Signals detected:
  - Fan-out: one internal source connecting to many internal destinations
    on admin/lateral-movement ports (22, 445, 3389, 5985, 5986, 135, 139)
  - Sequential sweep: connections to incrementally addressed hosts
    (port scan / credential spray behaviour)
  - Successful admin connections from non-bastion internal hosts
    (conn_state SF = full handshake completed)

Tuning:
    FAN_OUT_THRESHOLD   — distinct dst IPs before flagging fan-out (default 5)
    ADMIN_PORTS         — ports treated as lateral movement indicators
    BASTION_CIDRS       — internal ranges expected to initiate admin sessions;
                          connections from these are demoted to 'info'
"""

from __future__ import annotations

import ipaddress
import logging
from typing import TYPE_CHECKING

import pandas as pd

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

ADMIN_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}

FAN_OUT_THRESHOLD = 5          # distinct internal dsts before flagging
SWEEP_WINDOW_SECS = 300        # time window for sequential sweep detection

# CIDRs expected to initiate admin sessions — demote findings to info
BASTION_CIDRS: list[str] = [
    # "10.0.1.0/24",  # example bastion subnet — populate for your environment
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_bastion(ip: str) -> bool:
    if not BASTION_CIDRS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False)
                   for c in BASTION_CIDRS)
    except ValueError:
        return False


def _last_octet(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip)) & 0xFF
    except ValueError:
        return -1


# ── Detection functions ───────────────────────────────────────────────────────

def detect_fan_out(df: pd.DataFrame) -> list[dict]:
    """
    Flag source IPs that connect to >= FAN_OUT_THRESHOLD distinct internal
    destinations on lateral movement ports.

    A fan-out of 5+ internal admin-port connections from a single host is a
    strong credential-spray or worm-propagation indicator.
    """
    findings = []

    # Filter to internal→internal admin-port successful connections
    mask = (
        df["id.orig_h"].apply(_is_private) &
        df["id.resp_h"].apply(_is_private) &
        df["id.resp_p"].isin(ADMIN_PORTS) &
        (df["conn_state"] == "SF")
    )
    internal = df[mask].copy()

    if internal.empty:
        return findings

    # Count distinct dst IPs per (src, port)
    grouped = (
        internal
        .groupby(["id.orig_h", "id.resp_p"])["id.resp_h"]
        .nunique()
        .reset_index()
        .rename(columns={"id.resp_h": "distinct_dsts"})
    )

    flagged = grouped[grouped["distinct_dsts"] >= FAN_OUT_THRESHOLD]

    for _, row in flagged.iterrows():
        src  = row["id.orig_h"]
        port = int(row["id.resp_p"])
        count = int(row["distinct_dsts"])
        severity = "critical" if count >= FAN_OUT_THRESHOLD * 3 else "high"
        if _is_bastion(src):
            severity = "info"

        # Collect sample dst IPs for context
        sample_dsts = (
            internal[
                (internal["id.orig_h"] == src) &
                (internal["id.resp_p"] == port)
            ]["id.resp_h"]
            .unique()[:5]
            .tolist()
        )

        findings.append({
            "detection":    "lateral_movement.fan_out",
            "severity":     severity,
            "src_ip":       src,
            "port":         port,
            "dst_count":    count,
            "sample_dsts":  sample_dsts,
            "finding": (
                f"{src} made successful admin connections (port {port}) "
                f"to {count} distinct internal hosts — possible credential "
                f"spray or lateral movement."
            ),
            "suggested_fix": (
                f"Investigate {src} for compromise. If this is expected "
                f"behaviour, add the source subnet to BASTION_CIDRS. "
                f"Consider restricting port {port} via Security Group to "
                f"only authorised jump hosts."
            ),
        })

    log.info("fan_out: %d finding(s)", len(findings))
    return findings


def detect_sequential_sweep(df: pd.DataFrame) -> list[dict]:
    """
    Flag hosts that connect to sequentially addressed internal IPs within
    a short time window — characteristic of automated network scanning.

    Sequential = last octets of dst IPs form an increasing run of >= 5.
    """
    findings = []

    mask = (
        df["id.orig_h"].apply(_is_private) &
        df["id.resp_h"].apply(_is_private) &
        df["id.resp_p"].isin(ADMIN_PORTS)
    )
    internal = df[mask].copy()

    if internal.empty:
        return findings

    internal = internal.sort_values("ts")

    for src, group in internal.groupby("id.orig_h"):
        group = group.sort_values("ts")
        octets = group["id.resp_h"].apply(_last_octet).tolist()

        # Sliding window: find runs of increasing last octets
        max_run = 1
        run     = 1
        for i in range(1, len(octets)):
            if octets[i] == octets[i - 1] + 1:
                run += 1
                max_run = max(max_run, run)
            else:
                run = 1

        if max_run >= 5:
            severity = "high" if not _is_bastion(src) else "info"
            findings.append({
                "detection":  "lateral_movement.sequential_sweep",
                "severity":   severity,
                "src_ip":     src,
                "run_length": max_run,
                "finding": (
                    f"{src} connected to {max_run} sequentially addressed "
                    f"internal hosts on admin ports — likely automated "
                    f"network scanning."
                ),
                "suggested_fix": (
                    f"Investigate {src} immediately. Block east-west scanning "
                    f"via VPC Security Group rules restricting admin ports to "
                    f"authorised sources only."
                ),
            })

    log.info("sequential_sweep: %d finding(s)", len(findings))
    return findings


def detect_successful_admin_from_workstation(df: pd.DataFrame) -> list[dict]:
    """
    Flag successful (conn_state=SF) admin-port connections between internal
    hosts where the source is NOT a known bastion.

    In a zero-trust environment, workstation→server admin sessions should
    not exist — all admin access should funnel through a jump host or SSM.
    """
    findings = []

    mask = (
        df["id.orig_h"].apply(_is_private) &
        df["id.resp_h"].apply(_is_private) &
        df["id.resp_p"].isin(ADMIN_PORTS) &
        (df["conn_state"] == "SF") &
        (~df["id.orig_h"].apply(_is_bastion))
    )
    flagged = df[mask].copy()

    if flagged.empty:
        return findings

    # Deduplicate: one finding per (src, dst, port) pair
    deduped = (
        flagged
        .groupby(["id.orig_h", "id.resp_h", "id.resp_p"])
        .agg(
            connection_count=("ts", "count"),
            first_seen=("ts", "min"),
            last_seen=("ts", "max"),
            total_bytes=("orig_bytes", "sum"),
        )
        .reset_index()
    )

    for _, row in deduped.iterrows():
        src   = row["id.orig_h"]
        dst   = row["id.resp_h"]
        port  = int(row["id.resp_p"])
        count = int(row["connection_count"])

        findings.append({
            "detection":        "lateral_movement.admin_from_workstation",
            "severity":         "medium",
            "src_ip":           src,
            "dst_ip":           dst,
            "port":             port,
            "connection_count": count,
            "first_seen":       str(row["first_seen"]),
            "last_seen":        str(row["last_seen"]),
            "total_bytes":      int(row["total_bytes"]),
            "finding": (
                f"{src} made {count} successful admin connection(s) "
                f"(port {port}) to {dst} — non-bastion internal source. "
                f"Zero-trust policy requires all admin sessions to route "
                f"through a designated jump host or SSM Session Manager."
            ),
            "suggested_fix": (
                f"Verify whether {src} should have direct admin access to "
                f"{dst}. If not, block via Security Group and route through "
                f"SSM. If expected, add {src} subnet to BASTION_CIDRS."
            ),
        })

    log.info("admin_from_workstation: %d finding(s)", len(findings))
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def run(df: pd.DataFrame) -> list[dict]:
    """Run all lateral movement detectors. Returns combined findings list."""
    return (
        detect_fan_out(df) +
        detect_sequential_sweep(df) +
        detect_successful_admin_from_workstation(df)
    )