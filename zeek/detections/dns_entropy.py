"""
zeek/detections/dns_entropy.py

Detects suspicious DNS patterns in Zeek dns.log data using Shannon entropy
and query behaviour analysis.

Signals detected:
  - High-entropy subdomains: potential DGA (Domain Generation Algorithm)
    or DNS tunnelling (e.g. data encoded in subdomain labels)
  - Query volume spike: single internal host making unusually high query
    volume in a short window (C2 beaconing, data exfil over DNS)
  - Long subdomain labels: labels >50 chars are a DNS tunnelling indicator
  - NX domain storm: high NXDOMAIN rate from one host (DGA trying domains
    until it finds a live C2)

Tuning:
    ENTROPY_THRESHOLD       — bits; labels above this are flagged (default 3.5)
    MIN_LABEL_LENGTH        — ignore labels shorter than this (default 8)
    QUERY_VOLUME_THRESHOLD  — queries/hour from one host before flagging
    NX_RATE_THRESHOLD       — fraction of queries returning NXDOMAIN
    LONG_LABEL_THRESHOLD    — label character length for tunnelling flag
    WHITELIST_DOMAINS       — known-good high-entropy domains (CDNs etc.)
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from collections import Counter

import pandas as pd

log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

ENTROPY_THRESHOLD      = 3.5    # Shannon bits per character
MIN_LABEL_LENGTH       = 8      # ignore short labels (hex chars, UUIDs)
QUERY_VOLUME_THRESHOLD = 500    # queries/hour from one src before flagging
NX_RATE_THRESHOLD      = 0.7    # fraction of NXDOMAINs from one host
LONG_LABEL_THRESHOLD   = 50     # label length for tunnelling detection

# High-entropy but legitimate domains — suppress findings for these
WHITELIST_DOMAINS: set[str] = {
    "cloudfront.net",
    "amazonaws.com",
    "akamaiedge.net",
    "fastly.net",
    "googleusercontent.com",
    "azureedge.net",
    "1e100.net",          # Google
    "akamaitechnologies.com",
}

# ── Shannon entropy ───────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy (bits per character) of string s.
    Higher = more random. Legitimate hostnames cluster around 2.0–3.0.
    DGA/tunnel labels often exceed 3.5.
    """
    if not s:
        return 0.0
    counts = Counter(s.lower())
    total  = len(s)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


def _extract_labels(fqdn: str) -> list[str]:
    """Return individual DNS labels from an FQDN, excluding TLD and registrable."""
    parts = fqdn.rstrip(".").split(".")
    # Skip TLD and registrable domain (last two parts) — focus on subdomains
    return parts[:-2] if len(parts) > 2 else []


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _is_whitelisted(fqdn: str) -> bool:
    fqdn = fqdn.lower().rstrip(".")
    return any(fqdn == w or fqdn.endswith("." + w) for w in WHITELIST_DOMAINS)


# ── Detection functions ───────────────────────────────────────────────────────

def detect_high_entropy_subdomains(df: pd.DataFrame) -> list[dict]:
    """
    Flag DNS queries whose subdomain labels have Shannon entropy above
    ENTROPY_THRESHOLD. Filters out whitelisted CDN domains.

    High entropy in a subdomain usually means one of:
      - DGA: malware cycling through generated domains to find live C2
      - DNS tunnel: data encoded in subdomain labels (iodine, dnscat2)
    """
    findings = []

    if "query" not in df.columns:
        log.warning("dns.log missing 'query' column — skipping entropy detection")
        return findings

    # Work with unique queries to avoid duplicate findings
    queries = df.dropna(subset=["query"])["query"].unique()

    flagged_domains: list[dict] = []
    for fqdn in queries:
        if _is_whitelisted(fqdn):
            continue

        labels = _extract_labels(str(fqdn))
        for label in labels:
            if len(label) < MIN_LABEL_LENGTH:
                continue
            ent = shannon_entropy(label)
            if ent >= ENTROPY_THRESHOLD:
                flagged_domains.append({
                    "fqdn":    fqdn,
                    "label":   label,
                    "entropy": round(ent, 3),
                })
                break  # one finding per FQDN

    if not flagged_domains:
        return findings

    # Attach querying hosts for each flagged domain
    for entry in flagged_domains:
        fqdn = entry["fqdn"]
        srcs = df[df["query"] == fqdn]["id.orig_h"].dropna().unique().tolist()
        internal_srcs = [s for s in srcs if _is_private(s)]

        severity = "high"
        if entry["entropy"] >= 4.0:
            severity = "critical"

        findings.append({
            "detection":    "dns_entropy.high_entropy_subdomain",
            "severity":     severity,
            "fqdn":         fqdn,
            "label":        entry["label"],
            "entropy":      entry["entropy"],
            "queried_by":   internal_srcs[:10],
            "finding": (
                f"DNS query for '{fqdn}' contains high-entropy subdomain "
                f"label '{entry['label']}' (entropy {entry['entropy']:.2f} bits). "
                f"Queried by: {', '.join(internal_srcs[:3])}. "
                f"Possible DGA domain or DNS tunnel."
            ),
            "suggested_fix": (
                f"Block DNS resolution for '{fqdn}' at the resolver level. "
                f"Investigate querying hosts for C2 implants. "
                f"If this domain is a known CDN, add its TLD to WHITELIST_DOMAINS."
            ),
        })

    log.info("high_entropy_subdomain: %d finding(s)", len(findings))
    return findings


def detect_query_volume_spike(df: pd.DataFrame) -> list[dict]:
    """
    Flag internal hosts generating unusually high DNS query volumes.
    High-volume beaconing is a C2 indicator — malware polling a DNS
    endpoint at regular intervals produces a characteristic spike.
    """
    findings = []

    if "id.orig_h" not in df.columns:
        return findings

    internal = df[df["id.orig_h"].apply(_is_private)].copy()
    if internal.empty:
        return findings

    # Compute queries per hour per source
    time_range_hours = max(
        (internal["ts"].max() - internal["ts"].min()).total_seconds() / 3600,
        1.0,
    ) if pd.api.types.is_datetime64_any_dtype(internal["ts"]) else 1.0

    query_counts = (
        internal
        .groupby("id.orig_h")
        .size()
        .reset_index(name="query_count")
    )
    query_counts["queries_per_hour"] = (
        query_counts["query_count"] / time_range_hours
    )

    flagged = query_counts[
        query_counts["queries_per_hour"] >= QUERY_VOLUME_THRESHOLD
    ]

    for _, row in flagged.iterrows():
        src   = row["id.orig_h"]
        count = int(row["query_count"])
        rate  = float(row["queries_per_hour"])

        # Sample the domains this host queried
        sample_queries = (
            internal[internal["id.orig_h"] == src]["query"]
            .dropna()
            .unique()[:5]
            .tolist()
        )

        findings.append({
            "detection":      "dns_entropy.query_volume_spike",
            "severity":       "high",
            "src_ip":         src,
            "query_count":    count,
            "queries_per_hr": round(rate, 1),
            "sample_queries": sample_queries,
            "finding": (
                f"{src} generated {count} DNS queries "
                f"({rate:.0f}/hr) — exceeds threshold of "
                f"{QUERY_VOLUME_THRESHOLD}/hr. "
                f"Possible C2 beaconing or DNS-based data exfiltration. "
                f"Sample queries: {', '.join(sample_queries[:3])}."
            ),
            "suggested_fix": (
                f"Investigate {src} for C2 implants. Review the queried "
                f"domains for DGA patterns. Consider rate-limiting DNS "
                f"queries at the resolver and enabling DNS query logging "
                f"in Route 53 Resolver."
            ),
        })

    log.info("query_volume_spike: %d finding(s)", len(findings))
    return findings


def detect_long_labels(df: pd.DataFrame) -> list[dict]:
    """
    Flag DNS queries containing labels longer than LONG_LABEL_THRESHOLD.
    DNS tunnelling tools (iodine, dnscat2) encode data in long subdomain
    labels. Legitimate hostnames rarely exceed 30–40 characters per label.
    """
    findings = []

    if "query" not in df.columns:
        return findings

    queries = df.dropna(subset=["query"])["query"].unique()

    for fqdn in queries:
        if _is_whitelisted(fqdn):
            continue
        labels = str(fqdn).rstrip(".").split(".")
        long_labels = [l for l in labels if len(l) >= LONG_LABEL_THRESHOLD]
        if not long_labels:
            continue

        srcs = df[df["query"] == fqdn]["id.orig_h"].dropna().unique().tolist()
        internal_srcs = [s for s in srcs if _is_private(s)]

        findings.append({
            "detection":   "dns_entropy.long_label",
            "severity":    "high",
            "fqdn":        fqdn,
            "long_labels": long_labels,
            "max_length":  max(len(l) for l in long_labels),
            "queried_by":  internal_srcs[:10],
            "finding": (
                f"DNS query for '{fqdn}' contains label(s) longer than "
                f"{LONG_LABEL_THRESHOLD} chars: "
                f"{', '.join(f'{l[:20]}...' for l in long_labels[:2])}. "
                f"Long labels are a primary indicator of DNS tunnelling."
            ),
            "suggested_fix": (
                f"Block DNS resolution for '{fqdn}'. Investigate querying "
                f"hosts ({', '.join(internal_srcs[:3])}) for DNS tunnel "
                f"clients (iodine, dnscat2, dns2tcp). Enable DNS firewall "
                f"rules in Route 53 Resolver to block long-label queries."
            ),
        })

    log.info("long_labels: %d finding(s)", len(findings))
    return findings


def detect_nxdomain_storm(df: pd.DataFrame) -> list[dict]:
    """
    Flag hosts with a high ratio of NXDOMAIN responses — characteristic of
    DGA malware cycling through candidate domains until it finds a live C2.
    Requires 'rcode_name' or 'rcode' column in dns.log.
    """
    findings = []

    rcode_col = None
    if "rcode_name" in df.columns:
        rcode_col = "rcode_name"
        nx_value  = "NXDOMAIN"
    elif "rcode" in df.columns:
        rcode_col = "rcode"
        nx_value  = 3   # IANA rcode 3 = NXDOMAIN
    else:
        log.debug("No rcode column in dns.log — skipping NXDOMAIN storm detection")
        return findings

    internal = df[df["id.orig_h"].apply(_is_private)].copy()
    if internal.empty:
        return findings
    
    total_counts = internal.groupby("id.orig_h").size().rename("total")
    nx_counts    = (
        internal[internal[rcode_col] == nx_value]
        .groupby("id.orig_h")
        .size()
        .rename("nx_count")
    )
    per_host = pd.concat([total_counts, nx_counts], axis=1).fillna(0).reset_index()
    per_host["nx_rate"] = per_host["nx_count"] / per_host["total"].clip(lower=1)

    # Minimum query volume to avoid flagging hosts with 1 NXDOMAIN
    MIN_QUERIES = 20
    flagged = per_host[
        (per_host["total"] >= MIN_QUERIES) &
        (per_host["nx_rate"] >= NX_RATE_THRESHOLD)
    ]

    for _, row in flagged.iterrows():
        src      = row["id.orig_h"]
        nx_count = int(row["nx_count"])
        total    = int(row["total"])
        rate     = float(row["nx_rate"])

        # Sample the NX'd domains
        nx_queries = (
            internal[
                (internal["id.orig_h"] == src) &
                (internal[rcode_col] == nx_value)
            ]["query"]
            .dropna()
            .unique()[:5]
            .tolist()
        )

        findings.append({
            "detection":      "dns_entropy.nxdomain_storm",
            "severity":       "critical",
            "src_ip":         src,
            "nx_count":       nx_count,
            "total_queries":  total,
            "nx_rate":        round(rate, 3),
            "sample_domains": nx_queries,
            "finding": (
                f"{src} received NXDOMAIN on {nx_count}/{total} DNS queries "
                f"({rate * 100:.0f}% NXDOMAIN rate). "
                f"High NXDOMAIN rates indicate DGA malware cycling through "
                f"generated domains to locate a live C2 server. "
                f"Sample failed domains: {', '.join(nx_queries[:3])}."
            ),
            "suggested_fix": (
                f"Isolate {src} immediately — high NXDOMAIN rates are a "
                f"reliable DGA indicator. Collect the failed domain list, "
                f"run them through a DGA classifier, and block the domain "
                f"family at the DNS resolver. Capture memory for forensic "
                f"analysis."
            ),
        })

    log.info("nxdomain_storm: %d finding(s)", len(findings))
    return findings


# ── Public API ────────────────────────────────────────────────────────────────

def run(df: pd.DataFrame) -> list[dict]:
    """Run all DNS entropy detectors. Returns combined findings list."""
    return (
        detect_high_entropy_subdomains(df) +
        detect_query_volume_spike(df) +
        detect_long_labels(df) +
        detect_nxdomain_storm(df)
    )