from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SAFE_KEYWORD_RE = re.compile(r"^[a-zA-Z0-9\s\-_.]{1,200}$")
ALLOWED_HOSTS = frozenset(
    {
        "services.nvd.nist.gov",
        "api.osv.dev",
        "api.first.org",
        "www.cisa.gov",
        "raw.githubusercontent.com",
        "api.abuseipdb.com",
        "api.greynoise.io",
        "api.shodan.io",
        "mb-api.abuse.ch",
        "www.virustotal.com",
        "urlscan.io",
        "crt.sh",
        "www.circl.lu",
        "api.msrc.microsoft.com",
        "access.redhat.com",
        "ubuntu.com",
        "api.github.com",
        "threatfox-api.abuse.ch",
        "api.ransomwhe.re",
        "gitlab.com",
        "cveawg.mitre.org",
        "api.vulncheck.com",
        "hashlookup.circl.lu",
        "api.pwnedpasswords.com",
    }
)

# Only these URL schemes may ever be fetched. Everything else (file, gopher,
# dict, ftp, data, ...) is an SSRF/local-file-read vector and is rejected.
ALLOWED_SCHEMES = frozenset({"http", "https"})


def normalize_cve(cve_id: str) -> str | None:
    s = cve_id.strip().upper()
    return s if CVE_RE.match(s) else None


def sanitize_keyword(query: str) -> str | None:
    q = query.strip()
    return q if SAFE_KEYWORD_RE.match(q) else None


def validate_url_host(url: str) -> None:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Blocked request to unauthorized host: {host}")


def validate_scheme(url: str) -> None:
    """Reject any URL whose scheme is not http/https (plan 3.4).

    Blocks file://, gopher://, dict://, ftp://, data:// and similar SSRF /
    local-file-read vectors.
    """
    scheme = (urlparse(url).scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Blocked URL scheme: {scheme or '(none)'}")


def _ip_is_disallowed(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if an IP is private/loopback/link-local/reserved/multicast.

    IPv4-mapped IPv6 addresses are unwrapped first so an attacker cannot smuggle
    an internal IPv4 target (e.g. ::ffff:127.0.0.1) past the check.
    """
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def resolve_and_check_host(host: str) -> None:
    """Resolve a hostname's IPs and reject if ANY of them is non-public.

    Synchronous helper used to defend against DNS rebinding / hostnames that
    point at internal addresses, in addition to the allowlist check. Raises
    ValueError on any disallowed resolved address.
    """
    if not host:
        raise ValueError("Blocked request: missing hostname")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve host: {host}") from exc

    resolved: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        resolved.add(ip_str)
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValueError(f"Invalid resolved IP for {host}: {ip_str}") from None
        if _ip_is_disallowed(addr):
            raise ValueError(f"Blocked request: {host} resolves to non-public IP {ip_str}")
    if not resolved:
        raise ValueError(f"Could not resolve host: {host}")


async def validate_outbound_url(url: str, client=None) -> None:
    """Full SSRF check for an outbound URL (plan 3.4).

    Performs, in order:
      1. scheme allowlist (http/https only),
      2. host allowlist (ALLOWED_HOSTS),
      3. DNS resolution + rejection of any private/loopback/link-local/
         reserved/multicast/unspecified resolved IP.

    The ``client`` argument is accepted for call-site compatibility (callers may
    pass their shared httpx.AsyncClient); DNS resolution itself uses the stdlib
    resolver. Raises ValueError on any violation.
    """
    validate_scheme(url)
    validate_url_host(url)
    host = urlparse(url).hostname
    resolve_and_check_host(host or "")


_SENSITIVE_PARAMS = re.compile(
    r"((?:apikey|api_key|key|token|access_token|secret)=)[^&]+",
    re.IGNORECASE,
)


def sanitize_url_for_log(url: str) -> str:
    return _SENSITIVE_PARAMS.sub(r"\1***REDACTED***", url)


def validate_ip_address(ip: str) -> str:
    """Validate and return a normalized IP address.

    Raises ValueError for invalid or private/reserved addresses.
    """
    addr = ipaddress.ip_address(ip.strip())
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        raise ValueError(f"Private/reserved IP not allowed: {ip}")
    return str(addr)


def validate_hash(hash_str: str) -> str | None:
    """Validate MD5 (32 hex), SHA1 (40 hex), or SHA256 (64 hex) hash."""
    h = hash_str.strip().lower()
    if len(h) in (32, 40, 64) and all(c in "0123456789abcdef" for c in h):
        return h
    return None
