import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import SecretStr

load_dotenv()

# ── Secret hygiene (plan 3.5) ────────────────────────────────────────────────
# Secrets are wrapped in pydantic.SecretStr for masked storage (repr/str of a
# SecretStr never reveals the underlying value, preventing accidental leakage in
# logs, tracebacks, or debug dumps). For backward compatibility the existing
# module-level *str* constants below are KEPT exactly as-is, because ~20 api/
# modules import them directly. Full migration of every call site to
# get_secret()/SECRETS is a follow-up task — do not remove the plain constants.

# Registry of secret env var names that should receive masked SecretStr storage.
_SECRET_ENV_VARS: tuple[str, ...] = (
    "NVD_API_KEY",
    "GITHUB_TOKEN",
    "VULNCHECK_TOKEN",
    "ABUSEIPDB_KEY",
    "VIRUSTOTAL_KEY",
    "URLSCAN_KEY",
    "SHODAN_KEY",
    "GREYNOISE_API_KEY",
    "CIRCL_PDNS_USER",
    "CIRCL_PDNS_PASS",
)


def _load_secret(name: str) -> SecretStr:
    """Wrap an environment-sourced secret in a SecretStr for masked storage."""
    return SecretStr(os.getenv(name, ""))


# Masked storage map: name -> SecretStr. Use get_secret() to read the raw value.
SECRETS: dict[str, SecretStr] = {name: _load_secret(name) for name in _SECRET_ENV_VARS}


def get_secret(name: str) -> str:
    """Safely retrieve the raw value of a stored secret by name.

    Reads from the masked SECRETS map; returns "" for unknown names so callers
    never crash on a missing key. This is the preferred accessor going forward.
    """
    secret = SECRETS.get(name)
    if secret is None:
        return ""
    return secret.get_secret_value()


def redact(value: str) -> str:
    """Mask a secret value for safe display/logging.

    Reveals at most the first and last 2 chars of sufficiently long values and
    masks the middle; short or empty values are fully masked.
    """
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
VULNCHECK_TOKEN: str = os.getenv("VULNCHECK_TOKEN", "")

_default_cache = Path.home() / ".cve-mcp" / "cache.db"
CACHE_DB_PATH: str = os.getenv("CACHE_DB_PATH") or str(_default_cache)

# Rate limits (requests per second)
# With key: 50 req / 30 s = 1.667 r/s; without: 5 req / 30 s = 0.167 r/s
NVD_RATE = 50 / 30 if NVD_API_KEY else 5 / 30
NVD_BURST = 5 if NVD_API_KEY else 2

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BASE = "https://api.osv.dev/v1"
EPSS_BASE = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORY_BASE = "https://api.github.com/advisories"
MITRE_BASE = "https://cveawg.mitre.org/api/cve"
VULNCHECK_BASE = "https://api.vulncheck.com/v3/index/vulncheck-nvd2"
VULNCHECK_INDEX_BASE = "https://api.vulncheck.com/v3/index"
HASHLOOKUP_BASE = "https://hashlookup.circl.lu"
HIBP_PWNED_BASE = "https://api.pwnedpasswords.com"

_default_base = Path.home() / ".cve-mcp"
AUDIT_LOG_PATH: str = os.getenv("AUDIT_LOG_PATH") or str(_default_base / "audit.log")
KEV_FALLBACK: str = "https://raw.githubusercontent.com/cisagov/kev-data/main/data/known_exploited_vulnerabilities.json"

REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "30"))
MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
MAX_SEARCH_LIMIT: int = 50
MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10MB

# ── Threat Intelligence API Keys ────────────────────────────────────────────
ABUSEIPDB_KEY: str = os.getenv("ABUSEIPDB_KEY", "")
VIRUSTOTAL_KEY: str = os.getenv("VIRUSTOTAL_KEY", "")
URLSCAN_KEY: str = os.getenv("URLSCAN_KEY", "")
SHODAN_KEY: str = os.getenv("SHODAN_KEY", "")
GREYNOISE_API_KEY: str = os.getenv("GREYNOISE_API_KEY", "")
CIRCL_PDNS_USER: str = os.getenv("CIRCL_PDNS_USER", "")
CIRCL_PDNS_PASS: str = os.getenv("CIRCL_PDNS_PASS", "")

# ── Threat Intel API Base URLs ───────────────────────────────────────────────
ABUSEIPDB_BASE: str = "https://api.abuseipdb.com/api/v2"
GREYNOISE_BASE: str = "https://api.greynoise.io/v3"
SHODAN_BASE: str = "https://api.shodan.io"
MALWAREBAZAAR_BASE: str = "https://mb-api.abuse.ch/api/v1"
VIRUSTOTAL_BASE: str = "https://www.virustotal.com/api/v3"
URLSCAN_BASE: str = "https://urlscan.io/api/v1"
CRTSH_BASE: str = "https://crt.sh"
CIRCL_PDNS_BASE: str = "https://www.circl.lu/pdns/query"
MSRC_BASE: str = "https://api.msrc.microsoft.com/cvrf/v2.0"
REDHAT_SECURITY_BASE: str = "https://access.redhat.com/hydra/rest/securitydata"
UBUNTU_SECURITY_BASE: str = "https://ubuntu.com/security/cves"
THREATFOX_BASE: str = "https://threatfox-api.abuse.ch/api/v1"
RANSOMWHERE_BASE: str = "https://api.ransomwhe.re"
MITRE_ATTACK_BASE: str = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
)
