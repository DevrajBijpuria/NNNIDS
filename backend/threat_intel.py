import ipaddress

_KNOWN_C2_IPS: dict[str, str] = {
    "10.0.0.50": "Simulated C2 server — attacker node alpha",
    "10.0.0.51": "Simulated C2 server — attacker node beta",
}
_KNOWN_MALICIOUS_CIDRS: list[tuple[str, str]] = [
    ("192.0.2.0/24",    "TEST-NET — should never appear in real traffic"),
    ("198.51.100.0/24", "TEST-NET-2 — documentation range"),
    ("203.0.113.0/24",  "TEST-NET-3 — documentation range"),
]

_TRUSTED_CIDRS: list[tuple[str, str]] = [
    # Google DNS
    ("8.8.8.0/24",          "Google DNS"),
    ("8.8.4.0/24",          "Google DNS"),
    # Google CDN / Services
    ("142.250.0.0/15",      "Google CDN"),
    ("142.251.0.0/16",      "Google CDN"),
    ("172.217.0.0/16",      "Google CDN"),
    ("216.58.192.0/19",     "Google CDN"),
    ("216.239.32.0/19",     "Google GFE"),   # covers 216.239.32-63.x
    ("74.125.0.0/16",       "Google Infrastructure"),
    ("64.233.160.0/19",     "Google Infrastructure"),
    ("192.178.0.0/16",      "Google LLC"),
    ("108.177.0.0/17",      "Google Infrastructure"),
    ("209.85.128.0/17",     "Google Infrastructure"),
    # Google Cloud Platform — full published ranges
    ("34.0.0.0/9",          "Google Cloud"),   # 34.0–34.127
    ("34.128.0.0/10",       "Google Cloud"),   # 34.128–34.191
    ("34.192.0.0/10",       "Google Cloud"),   # 34.192–34.255
    ("35.184.0.0/13",       "Google Cloud"),   # 35.184–35.191
    ("35.192.0.0/11",       "Google Cloud"),   # 35.192–35.223
    ("35.224.0.0/12",       "Google Cloud"),   # 35.224–35.239
    ("35.240.0.0/13",       "Google Cloud"),   # 35.240–35.247
    ("146.148.0.0/17",      "Google Cloud"),
    ("107.178.0.0/16",      "Google Cloud"),
    ("104.154.0.0/15",      "Google Cloud"),
    ("104.196.0.0/14",      "Google Cloud"),
    ("130.211.0.0/22",      "Google Cloud LB"),
    # Cloudflare
    ("1.1.1.0/24",          "Cloudflare DNS"),
    ("1.0.0.0/24",          "Cloudflare DNS"),
    ("104.16.0.0/13",       "Cloudflare CDN"),
    ("104.24.0.0/14",       "Cloudflare CDN"),
    ("172.64.0.0/13",       "Cloudflare CDN"),
    ("131.0.72.0/22",       "Cloudflare CDN"),
    ("162.158.0.0/15",      "Cloudflare CDN"),
    ("198.41.128.0/17",     "Cloudflare CDN"),
    # Fastly
    ("199.232.0.0/16",      "Fastly CDN"),
    ("151.101.0.0/16",      "Fastly CDN"),
    # Amazon / AWS
    ("52.0.0.0/8",          "Amazon AWS"),
    ("54.0.0.0/8",          "Amazon AWS"),
    ("3.0.0.0/8",           "Amazon AWS"),
    ("13.0.0.0/8",          "Amazon AWS"),
    ("18.0.0.0/8",          "Amazon AWS"),
    ("99.77.0.0/16",        "Amazon CloudFront"),
    ("205.251.192.0/19",    "Amazon CloudFront"),
    # Microsoft / Azure
    ("20.0.0.0/8",          "Microsoft Azure"),
    ("40.0.0.0/8",          "Microsoft Azure"),
    ("52.224.0.0/11",       "Microsoft Azure"),
    ("13.64.0.0/11",        "Microsoft Azure"),
    ("204.79.197.0/24",     "Microsoft Bing/CDN"),
    ("150.171.0.0/16",      "Microsoft CDN"),
    ("23.75.0.0/16",        "Microsoft CDN"),
    # Akamai
    ("23.32.0.0/11",        "Akamai CDN"),
    ("23.192.0.0/11",       "Akamai CDN"),    # covers 23.192–23.223
    ("23.0.0.0/12",         "Akamai CDN"),    # covers 23.0–23.15
    ("104.64.0.0/10",       "Akamai CDN"),
    ("184.84.0.0/14",       "Akamai CDN"),    # covers 184.84–184.87
    ("170.114.0.0/16",      "Akamai CDN"),
    ("2.16.0.0/13",         "Akamai CDN"),
    ("96.16.0.0/15",        "Akamai CDN"),
    ("72.246.0.0/15",       "Akamai CDN"),
    ("72.154.0.0/15",       "Akamai CDN"),    # covers 72.154 and 72.155
    # Miscellaneous well-known safe ranges
    ("163.70.128.0/17",     "Zscaler/CDN"),
    ("160.79.104.0/21",     "Zscaler CDN"),
    ("148.113.0.0/16",      "OVH Cloud"),
]


def _build_networks(entries: list[tuple[str, str]]) -> list[tuple[ipaddress.IPv4Network, str]]:
    result = []
    for cidr, reason in entries:
        try:
            result.append((ipaddress.IPv4Network(cidr, strict=False), reason))
        except ValueError:
            pass
    return result


_MALICIOUS_NETWORKS = _build_networks(_KNOWN_MALICIOUS_CIDRS)
_TRUSTED_NETWORKS   = _build_networks(_TRUSTED_CIDRS)


class ThreatIntelFeed:

    def is_trusted(self, ip: str) -> tuple[bool, str]:
        """Return (True, reason) if IP belongs to a known good provider."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False, ""
        for network, reason in _TRUSTED_NETWORKS:
            if addr in network:
                return True, reason
        return False, ""

    def is_malicious(self, ip: str) -> tuple[bool, str]:
        """Return (True, reason) if IP is a known threat. Always False for trusted IPs."""
        trusted, _ = self.is_trusted(ip)
        if trusted:
            return False, ""

        if ip in _KNOWN_C2_IPS:
            return True, _KNOWN_C2_IPS[ip]

        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False, ""

        for network, reason in _MALICIOUS_NETWORKS:
            if addr in network:
                return True, f"IP in malicious range {network} — {reason}"

        return False, ""
