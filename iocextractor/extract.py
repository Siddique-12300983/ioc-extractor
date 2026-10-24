"""Pull indicators out of text and return them deduped and sorted."""

from __future__ import annotations

import ipaddress
from typing import Dict, List

from . import patterns
from .defang import refang as _refang

# Output order is fixed so reports read the same every time.
IOC_TYPES = ("ipv4", "ipv6", "domains", "urls", "emails", "md5", "sha1", "sha256", "cve")


def _strip_trailing_punct(url: str) -> str:
    return url.rstrip(".,;:!?\"')]}>")


def _looks_like_file(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in patterns.FILE_EXTENSIONS


# "Private" here means genuinely internal: RFC1918, loopback and link-local.
# Documentation ranges (203.0.113.0/24 etc.) are deliberately NOT included,
# since in a report they stand in for real routable attacker addresses.
_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/8",
        "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(obj in net for net in _PRIVATE_NETS if net.version == obj.version)


def extract(text: str, refang: bool = True, filter_private: bool = False) -> Dict[str, List[str]]:
    """Extract IOCs from text.

    refang:         undo hxxp/[.]/[at] notation before matching (default on).
    filter_private: drop RFC1918, loopback, link-local and reserved IPs.
    """
    if refang:
        text = _refang(text)

    urls = {_strip_trailing_punct(m) for m in patterns.URL.findall(text)}
    emails = {e.lower() for e in patterns.EMAIL.findall(text)}

    # Domains come from standalone matches plus the hosts of URLs and emails, so
    # the domain inventory is complete. IPs and file-like names are removed.
    domains = set()
    for d in patterns.DOMAIN.findall(text):
        d = d.lower().rstrip(".")
        if not _looks_like_file(d) and not patterns.IPV4.fullmatch(d):
            domains.add(d)
    for e in emails:
        domains.add(e.split("@", 1)[1])
    for u in urls:
        host = _host_from_url(u)
        if host and not _looks_like_file(host):
            domains.add(host)

    ipv4 = set(patterns.IPV4.findall(text))
    if filter_private:
        ipv4 = {ip for ip in ipv4 if not _is_private_ip(ip)}

    ipv6 = {ip.lower() for ip in patterns.IPV6.findall(text)}
    if filter_private:
        ipv6 = {ip for ip in ipv6 if not _is_private_ip(ip)}

    # Domains that are actually an IP host should not appear in the domain list.
    domains = {d for d in domains if not patterns.IPV4.fullmatch(d)}

    result = {
        "ipv4": ipv4,
        "ipv6": ipv6,
        "domains": domains,
        "urls": urls,
        "emails": emails,
        "md5": {h.lower() for h in patterns.MD5.findall(text)},
        "sha1": {h.lower() for h in patterns.SHA1.findall(text)},
        "sha256": {h.lower() for h in patterns.SHA256.findall(text)},
        "cve": {c.upper() for c in patterns.CVE.findall(text)},
    }
    return {k: sorted(result[k]) for k in IOC_TYPES}


def _host_from_url(url: str) -> str:
    """Pull the hostname out of a URL without needing a real scheme parse."""
    rest = url.split("://", 1)[-1]
    host = rest.split("/", 1)[0].split("?", 1)[0]
    host = host.split("@")[-1]          # strip user:pass@
    host = host.split(":", 1)[0]        # strip port
    return host.lower()
