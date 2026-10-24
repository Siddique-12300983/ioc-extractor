"""Render extracted IOCs as a table, JSON or CSV."""

from __future__ import annotations

import csv
import io
import json
from typing import Dict, List

from .defang import defang as _defang
from .extract import IOC_TYPES

_LABELS = {
    "ipv4": "IPv4", "ipv6": "IPv6", "domains": "Domains", "urls": "URLs",
    "emails": "Emails", "md5": "MD5", "sha1": "SHA1", "sha256": "SHA256", "cve": "CVE",
}


def _maybe_defang(iocs: Dict[str, List[str]], defang: bool) -> Dict[str, List[str]]:
    if not defang:
        return iocs
    out = {}
    for k, values in iocs.items():
        if k in ("md5", "sha1", "sha256", "cve"):
            out[k] = list(values)          # hashes and CVEs are not defanged
        else:
            out[k] = [_defang(v) for v in values]
    return out


def to_json(iocs: Dict[str, List[str]], defang: bool = False) -> str:
    return json.dumps(_maybe_defang(iocs, defang), indent=2)


def to_csv(iocs: Dict[str, List[str]], defang: bool = False) -> str:
    iocs = _maybe_defang(iocs, defang)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value"])
    for key in IOC_TYPES:
        for value in iocs[key]:
            writer.writerow([key, value])
    return buf.getvalue()


def to_table(iocs: Dict[str, List[str]], defang: bool = False) -> str:
    iocs = _maybe_defang(iocs, defang)
    total = sum(len(v) for v in iocs.values())
    lines = ["IOC extraction report", "=" * 40]
    for key in IOC_TYPES:
        values = iocs[key]
        if not values:
            continue
        lines.append(f"\n{_LABELS[key]} ({len(values)})")
        for v in values:
            lines.append(f"  {v}")
    lines.append("\n" + "-" * 40)
    lines.append(f"total indicators: {total}")
    return "\n".join(lines)
