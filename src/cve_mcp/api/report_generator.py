from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

import httpx

from cve_mcp.api.attack_mapping import get_attack_mapping
from cve_mcp.api.epss_client import get_epss
from cve_mcp.api.exploit_intel import check_exploit_availability
from cve_mcp.api.kev_client import fetch_kev_catalog, lookup_kev
from cve_mcp.api.nvd_client import fetch_cve
from cve_mcp.api.poc_checker import search_poc_existence
from cve_mcp.api.rate_limiter import TokenBucketRateLimiter
from cve_mcp.api.vendor_advisory import get_vendor_advisory
from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.utils.risk_scorer import score_cve

logger = logging.getLogger(__name__)


def _get_description(descriptions: list[dict]) -> str:
    """Extract English description from NVD descriptions list."""
    for d in descriptions:
        if d.get("lang") == "en":
            return d.get("value", "")
    return descriptions[0].get("value", "No description") if descriptions else "No description"


def _get_cvss_info(metrics: dict) -> tuple[str, float, str, str]:
    """Extract CVSS vector, score, severity, and version from metrics."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            d = entries[0].get("cvssData", {})
            return (
                d.get("vectorString", ""),
                float(d.get("baseScore", 0.0)),
                d.get("baseSeverity", ""),
                d.get("version", ""),
            )
    return ("", 0.0, "", "")


def _get_weaknesses(weaknesses: list[dict]) -> list[str]:
    """Extract CWE IDs from weaknesses list."""
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val and val != "NVD-CWE-Other":
                cwes.append(val)
    return cwes


def _get_affected_products(nvd_data) -> list[str]:
    """Extract affected product names from NVD configurations."""
    products = []
    if nvd_data is None:
        return products

    descriptions = getattr(nvd_data, "descriptions", [])
    if isinstance(descriptions, list):
        # Try to extract vendor/product from description text
        desc_text = _get_description(descriptions)
        # NVD descriptions often mention the product in the first sentence
        if desc_text and desc_text != "No description":
            first_sentence = desc_text.split(".")[0] if "." in desc_text else desc_text[:200]
            products.append(first_sentence)

    references = getattr(nvd_data, "references", [])
    if isinstance(references, list):
        for ref in references[:5]:
            url = ref.get("url", "")
            tags = ref.get("tags", [])
            if "Vendor Advisory" in tags and url:
                products.append(f"Vendor Advisory: {url}")

    return products


def _safe(val, name: str = "", default=None):
    """Return val if it's not an Exception, otherwise log and return default."""
    if isinstance(val, Exception):
        logger.warning("API call '%s' failed: %s", name, val)
        return default
    return val


async def _fetch_nvd_data(
    cve_id: str, client: httpx.AsyncClient, limiter: TokenBucketRateLimiter | None, cache: VulnCache
):
    if limiter is None:
        raise ValueError("TokenBucketRateLimiter is required for NVD API calls")
    return await fetch_cve(cve_id, client, limiter, cache)


async def _fetch_epss_single(cve_id: str, client: httpx.AsyncClient, cache: VulnCache):
    """Fetch EPSS score for a single CVE and return the matching EPSSScore or None."""
    scores = await get_epss([cve_id], client, cache)
    for s in scores:
        if s.cve == cve_id:
            return s
    return None


async def _fetch_kev_entry(cve_id: str, client: httpx.AsyncClient, cache: VulnCache):
    """Fetch KEV catalog and look up a specific CVE."""
    catalog = await fetch_kev_catalog(client, cache)
    return lookup_kev(catalog, cve_id)


def _build_executive_report(
    cve_id: str,
    nvd_data,
    epss_data,
    kev_entry,
    exploit_data: dict | None,
    attack_data: dict | None,
    vendor_data: dict | None,
    score_result: dict,
    include_remediation: bool,
) -> str:
    """Build executive format report (~200 words)."""
    risk_score = score_result["risk_score"]
    risk_label = score_result["risk_label"]
    urgency = score_result["urgency"]

    # Extract CVSS info
    cvss_vector, cvss_score, cvss_severity, cvss_version = ("", 0.0, "", "")
    description = "No description available."
    if nvd_data is not None:
        cvss_vector, cvss_score, cvss_severity, cvss_version = _get_cvss_info(nvd_data.metrics)
        description = _get_description(nvd_data.descriptions)

    # KEV status
    kev_status = "Not in CISA KEV catalog"
    if kev_entry is not None:
        kev_status = f"Listed in CISA KEV catalog (added {kev_entry.dateAdded})"
        if (
            kev_entry.knownRansomwareCampaignUse
            and kev_entry.knownRansomwareCampaignUse.lower() != "unknown"
        ):
            kev_status += f", ransomware use: {kev_entry.knownRansomwareCampaignUse}"

    # Exploit status
    exploit_status = "No known public exploits"
    if exploit_data and exploit_data.get("has_public_exploit"):
        poc_count = exploit_data.get("poc_count", 0)
        exploit_status = f"{poc_count} public exploit(s)/PoC(s) identified on GitHub"

    # EPSS info
    epss_str = "EPSS data unavailable"
    if epss_data is not None:
        epss_pct = float(epss_data.epss) * 100
        epss_str = f"{epss_pct:.2f}% probability of exploitation in next 30 days"

    lines = [
        f"EXECUTIVE VULNERABILITY BRIEF -- {cve_id}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 60,
        "",
        f"Risk Level: {risk_label} (Score: {risk_score}/100)",
        f"Action Required: {urgency}",
        "",
        f"A {risk_label.lower()}-severity vulnerability has been identified.",
        f"{description[:300]}",
        "",
        f"CVSS Score: {cvss_score} ({cvss_severity})"
        if cvss_score
        else "CVSS Score: Not available",
        f"EPSS: {epss_str}",
        f"KEV Status: {kev_status}",
        f"Exploits: {exploit_status}",
    ]

    # Affected products
    if nvd_data is not None:
        products = _get_affected_products(nvd_data)
        if products:
            lines.append("")
            lines.append("Affected:")
            for p in products[:3]:
                lines.append(f"  - {p[:150]}")

    if include_remediation:
        lines.append("")
        lines.append("Recommended Action:")
        if vendor_data and (
            vendor_data.get("microsoft") or vendor_data.get("redhat") or vendor_data.get("ubuntu")
        ):
            lines.append("  Apply vendor-provided patches immediately:")
            for msrc in (vendor_data.get("microsoft") or [])[:2]:
                if msrc.get("article_url"):
                    lines.append(f"  - Microsoft: {msrc['article_url']}")
                elif msrc.get("title"):
                    lines.append(f"  - Microsoft: {msrc['title']}")
            for rh in (vendor_data.get("redhat") or [])[:2]:
                if rh.get("advisory"):
                    lines.append(f"  - Red Hat: {rh['advisory']}")
            for ub in (vendor_data.get("ubuntu") or [])[:2]:
                if ub.get("package") and ub.get("status"):
                    lines.append(f"  - Ubuntu: {ub['package']} ({ub['status']})")
        else:
            lines.append("  Monitor vendor channels for patch availability.")
            lines.append("  Consider compensating controls until a patch is released.")

        if kev_entry and kev_entry.dueDate:
            lines.append(f"  CISA remediation deadline: {kev_entry.dueDate}")

    return "\n".join(lines)


def _build_technical_report(
    cve_id: str,
    nvd_data,
    epss_data,
    kev_entry,
    exploit_data: dict | None,
    attack_data: dict | None,
    vendor_data: dict | None,
    score_result: dict,
    include_remediation: bool,
) -> str:
    """Build technical format report (~500 words)."""
    risk_score = score_result["risk_score"]
    risk_label = score_result["risk_label"]
    urgency = score_result["urgency"]

    lines = [
        f"TECHNICAL ADVISORY -- {cve_id}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 60,
        "",
    ]

    # CVE identification
    lines.append(f"CVE ID: {cve_id}")
    lines.append(f"Risk Score: {risk_score}/100 ({risk_label})")
    lines.append(f"Action: {urgency}")

    # CVSS details
    if nvd_data is not None:
        cvss_vector, cvss_score, cvss_severity, cvss_version = _get_cvss_info(nvd_data.metrics)
        lines.append("")
        lines.append("-- CVSS Details --")
        lines.append(f"Score: {cvss_score} ({cvss_severity})")
        if cvss_vector:
            lines.append(f"Vector: {cvss_vector}")
        if cvss_version:
            lines.append(f"Version: CVSS v{cvss_version}")

        # Weaknesses
        cwes = _get_weaknesses(nvd_data.weaknesses)
        if cwes:
            lines.append(f"CWE(s): {', '.join(cwes)}")

        # Status and dates
        lines.append("")
        lines.append("-- Timeline --")
        lines.append(f"Status: {nvd_data.vulnStatus}")
        lines.append(f"Published: {nvd_data.published[:10] if nvd_data.published else 'N/A'}")
        lines.append(
            f"Last Modified: {nvd_data.lastModified[:10] if nvd_data.lastModified else 'N/A'}"
        )

        # Description
        desc = _get_description(nvd_data.descriptions)
        lines.append("")
        lines.append("-- Description --")
        lines.append(desc)
    else:
        lines.append("")
        lines.append("NVD data unavailable for this CVE.")

    # EPSS
    lines.append("")
    lines.append("-- Exploit Prediction (EPSS) --")
    if epss_data is not None:
        lines.append(f"Probability: {float(epss_data.epss) * 100:.4f}%")
        lines.append(f"Percentile: {float(epss_data.percentile) * 100:.2f}th")
        lines.append(f"Score Date: {epss_data.date}")
    else:
        lines.append("EPSS data unavailable.")

    # KEV
    lines.append("")
    lines.append("-- CISA KEV Status --")
    if kev_entry is not None:
        lines.append("In KEV: YES")
        lines.append(f"Vulnerability: {kev_entry.vulnerabilityName}")
        lines.append(f"Vendor/Project: {kev_entry.vendorProject} / {kev_entry.product}")
        lines.append(f"Date Added: {kev_entry.dateAdded}")
        lines.append(f"Remediation Due: {kev_entry.dueDate}")
        lines.append(f"Ransomware Use: {kev_entry.knownRansomwareCampaignUse or 'Unknown'}")
    else:
        lines.append("In KEV: NO")

    # Exploit availability
    lines.append("")
    lines.append("-- Exploit Availability --")
    if exploit_data and exploit_data.get("has_public_exploit"):
        lines.append(f"Public Exploits: YES ({exploit_data.get('poc_count', 0)} found)")
        for poc in exploit_data.get("github_pocs", [])[:5]:
            stars = poc.get("stars", 0)
            lines.append(f"  - {poc.get('repo', 'N/A')} ({stars} stars)")
            lines.append(f"    URL: {poc.get('url', 'N/A')}")
            if poc.get("description"):
                lines.append(f"    {poc['description'][:150]}")
    else:
        lines.append("Public Exploits: None identified")

    # ATT&CK mapping
    lines.append("")
    lines.append("-- MITRE ATT&CK Mapping --")
    if attack_data and attack_data.get("techniques"):
        for tech in attack_data["techniques"][:5]:
            tid = tech.get("technique_id", "N/A")
            name = tech.get("name", "N/A")
            tactics = ", ".join(tech.get("tactics", []))
            lines.append(f"  {tid}: {name}")
            if tactics:
                lines.append(f"    Tactics: {tactics}")
        if attack_data.get("threat_groups"):
            lines.append(
                f"  Associated Threat Groups: {', '.join(attack_data['threat_groups'][:10])}"
            )
    else:
        lines.append("  No ATT&CK techniques mapped to this CVE.")

    # Vendor advisories
    lines.append("")
    lines.append("-- Vendor Advisories --")
    if vendor_data:
        has_advisories = False
        for msrc in (vendor_data.get("microsoft") or [])[:3]:
            has_advisories = True
            lines.append(
                f"  Microsoft: {msrc.get('title', 'N/A')} (Severity: {msrc.get('severity', 'N/A')})"
            )
            if msrc.get("article_url"):
                lines.append(f"    URL: {msrc['article_url']}")
        for rh in (vendor_data.get("redhat") or [])[:3]:
            has_advisories = True
            product = rh.get("product_name", "N/A")
            advisory = rh.get("advisory", "N/A")
            lines.append(f"  Red Hat: {advisory} - {product}")
        for ub in (vendor_data.get("ubuntu") or [])[:3]:
            has_advisories = True
            pkg = ub.get("package", "N/A")
            status = ub.get("status", "N/A")
            release = ub.get("release", "")
            lines.append(f"  Ubuntu: {pkg} ({release}) - {status}")
        if not has_advisories:
            lines.append("  No vendor advisories found.")
    else:
        lines.append("  Vendor advisory data unavailable.")

    if include_remediation:
        lines.append("")
        lines.append("-- Remediation --")
        if vendor_data and (
            vendor_data.get("microsoft") or vendor_data.get("redhat") or vendor_data.get("ubuntu")
        ):
            lines.append("  1. Apply vendor patches listed above as soon as possible.")
        else:
            lines.append("  1. Monitor vendor channels for patch availability.")
        lines.append("  2. Evaluate exposure using the CVSS vector components.")
        if kev_entry:
            lines.append(f"  3. CISA requires remediation by {kev_entry.dueDate}.")
        if exploit_data and exploit_data.get("has_public_exploit"):
            lines.append("  4. Public exploits exist -- prioritize immediate patching.")
            lines.append("  5. Deploy IDS/IPS signatures and WAF rules if applicable.")

    return "\n".join(lines)


def _build_full_report(
    cve_id: str,
    nvd_data,
    epss_data,
    kev_entry,
    exploit_data: dict | None,
    attack_data: dict | None,
    vendor_data: dict | None,
    score_result: dict,
    include_remediation: bool,
) -> str:
    """Build comprehensive format report (~1000 words)."""
    risk_score = score_result["risk_score"]
    risk_label = score_result["risk_label"]
    urgency = score_result["urgency"]
    components = score_result.get("components", {})

    lines = [
        f"COMPREHENSIVE VULNERABILITY REPORT -- {cve_id}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "=" * 70,
        "",
    ]

    # Section 1: Executive Summary
    lines.append("1. EXECUTIVE SUMMARY")
    lines.append("-" * 40)
    lines.append(f"CVE Identifier: {cve_id}")
    lines.append(f"Composite Risk Score: {risk_score}/100 ({risk_label})")
    lines.append(f"Required Action: {urgency}")
    lines.append("")

    if nvd_data is not None:
        desc = _get_description(nvd_data.descriptions)
        lines.append(f"Summary: {desc}")
    else:
        lines.append("Summary: NVD data unavailable.")
    lines.append("")

    # Section 2: CVSS Analysis
    lines.append("2. CVSS ANALYSIS")
    lines.append("-" * 40)
    if nvd_data is not None:
        cvss_vector, cvss_score, cvss_severity, cvss_version = _get_cvss_info(nvd_data.metrics)
        lines.append(f"CVSS Version: {cvss_version if cvss_version else 'N/A'}")
        lines.append(f"Base Score: {cvss_score}")
        lines.append(f"Severity: {cvss_severity}")
        lines.append(f"Vector String: {cvss_vector if cvss_vector else 'N/A'}")

        # Parse vector components if CVSS v3.x
        if cvss_vector and ("CVSS:3" in cvss_vector):
            lines.append("")
            lines.append("Vector Breakdown:")
            vector_parts = cvss_vector.split("/")
            component_labels = {
                "AV": "Attack Vector",
                "AC": "Attack Complexity",
                "PR": "Privileges Required",
                "UI": "User Interaction",
                "S": "Scope",
                "C": "Confidentiality Impact",
                "I": "Integrity Impact",
                "A": "Availability Impact",
            }
            for part in vector_parts:
                if ":" in part:
                    key, val = part.split(":", 1)
                    label = component_labels.get(key, key)
                    lines.append(f"  {label}: {val}")

        # Weaknesses
        cwes = _get_weaknesses(nvd_data.weaknesses)
        if cwes:
            lines.append("")
            lines.append(f"Weaknesses: {', '.join(cwes)}")
    else:
        lines.append("CVSS data unavailable.")
    lines.append("")

    # Section 3: Exploit Prediction Scoring System
    lines.append("3. EXPLOIT PREDICTION (EPSS)")
    lines.append("-" * 40)
    if epss_data is not None:
        epss_prob = float(epss_data.epss) * 100
        epss_pctl = float(epss_data.percentile) * 100
        lines.append(f"Exploitation Probability: {epss_prob:.4f}%")
        lines.append(f"Percentile Rank: {epss_pctl:.2f}th")
        lines.append(f"Assessment Date: {epss_data.date}")
        lines.append("")
        if epss_prob > 50:
            lines.append("Assessment: HIGH exploitation likelihood. This CVE is in the top tier")
            lines.append("of vulnerabilities most likely to be exploited in the wild.")
        elif epss_prob > 10:
            lines.append("Assessment: ELEVATED exploitation likelihood. This CVE has a")
            lines.append("significantly above-average probability of exploitation.")
        elif epss_prob > 1:
            lines.append("Assessment: MODERATE exploitation likelihood.")
        else:
            lines.append("Assessment: LOW exploitation likelihood based on current data.")
    else:
        lines.append("EPSS data unavailable for this CVE.")
    lines.append("")

    # Section 4: CISA Known Exploited Vulnerabilities
    lines.append("4. CISA KEV CATALOG STATUS")
    lines.append("-" * 40)
    if kev_entry is not None:
        lines.append("Status: LISTED in CISA Known Exploited Vulnerabilities catalog")
        lines.append(f"Vulnerability Name: {kev_entry.vulnerabilityName}")
        lines.append(f"Vendor/Project: {kev_entry.vendorProject}")
        lines.append(f"Product: {kev_entry.product}")
        lines.append(f"Date Added: {kev_entry.dateAdded}")
        lines.append(f"Remediation Due Date: {kev_entry.dueDate}")
        lines.append(f"Known Ransomware Use: {kev_entry.knownRansomwareCampaignUse or 'Unknown'}")
        lines.append("")
        lines.append("Note: Federal agencies are required to remediate KEV-listed")
        lines.append("vulnerabilities by the due date per BOD 22-01.")
    else:
        lines.append("Status: NOT listed in CISA KEV catalog.")
        lines.append("This vulnerability has not been confirmed as actively exploited by CISA.")
    lines.append("")

    # Section 5: Exploit & PoC Availability
    lines.append("5. EXPLOIT AND PoC AVAILABILITY")
    lines.append("-" * 40)
    if exploit_data and exploit_data.get("has_public_exploit"):
        poc_count = exploit_data.get("poc_count", 0)
        lines.append(f"Public Exploits Found: YES ({poc_count} repositories)")
        lines.append("")
        for i, poc in enumerate(exploit_data.get("github_pocs", [])[:10], 1):
            lines.append(f"  PoC #{i}:")
            lines.append(f"    Repository: {poc.get('repo', 'N/A')}")
            lines.append(f"    URL: {poc.get('url', 'N/A')}")
            lines.append(f"    Stars: {poc.get('stars', 0)} | Forks: {poc.get('forks', 0)}")
            lines.append(f"    Language: {poc.get('language', 'N/A')}")
            if poc.get("description"):
                lines.append(f"    Description: {poc['description'][:250]}")
            lines.append(f"    Created: {poc.get('created_at', 'N/A')}")
            lines.append(f"    Updated: {poc.get('updated_at', 'N/A')}")
            lines.append("")
    else:
        lines.append("Public Exploits Found: NONE")
        lines.append("No public proof-of-concept code identified on GitHub.")
    lines.append("")

    # Section 6: MITRE ATT&CK Mapping
    lines.append("6. MITRE ATT&CK MAPPING")
    lines.append("-" * 40)
    if attack_data and attack_data.get("techniques"):
        lines.append(f"Mapped Techniques: {len(attack_data['techniques'])}")
        lines.append("")
        for tech in attack_data["techniques"][:10]:
            tid = tech.get("technique_id", "N/A")
            name = tech.get("name", "N/A")
            tactics = ", ".join(tech.get("tactics", []))
            platforms = ", ".join(tech.get("platforms", []))
            lines.append(f"  {tid}: {name}")
            if tactics:
                lines.append(f"    Tactics: {tactics}")
            if platforms:
                lines.append(f"    Platforms: {platforms}")
            if tech.get("url"):
                lines.append(f"    Reference: {tech['url']}")
            if tech.get("description"):
                lines.append(f"    Detail: {tech['description'][:300]}")
            lines.append("")

        if attack_data.get("threat_groups"):
            lines.append("  Associated Threat Groups:")
            for group in attack_data["threat_groups"][:15]:
                lines.append(f"    - {group}")
            lines.append("")
    else:
        lines.append("No ATT&CK techniques directly mapped to this CVE.")
    lines.append("")

    # Section 7: Vendor Advisories
    lines.append("7. VENDOR ADVISORIES")
    lines.append("-" * 40)
    has_advisories = False
    if vendor_data:
        # Microsoft
        for msrc in (vendor_data.get("microsoft") or [])[:5]:
            has_advisories = True
            lines.append("  Microsoft Security Response Center:")
            lines.append(f"    Title: {msrc.get('title', 'N/A')}")
            lines.append(f"    Severity: {msrc.get('severity', 'N/A')}")
            lines.append(f"    Impact: {msrc.get('impact', 'N/A')}")
            if msrc.get("product"):
                lines.append(f"    Product: {msrc['product']}")
            if msrc.get("article_url"):
                lines.append(f"    URL: {msrc['article_url']}")
            lines.append(f"    Release Date: {msrc.get('release_date', 'N/A')}")
            lines.append("")

        # Red Hat
        for rh in (vendor_data.get("redhat") or [])[:5]:
            has_advisories = True
            lines.append("  Red Hat Security Advisory:")
            lines.append(f"    Product: {rh.get('product_name', 'N/A')}")
            lines.append(f"    Advisory: {rh.get('advisory', 'N/A')}")
            lines.append(f"    Package: {rh.get('package', 'N/A')}")
            lines.append(f"    Severity: {rh.get('severity', 'N/A')}")
            lines.append(f"    Fix State: {rh.get('fixed_state', 'N/A')}")
            if rh.get("cvss3_score"):
                lines.append(f"    CVSS3: {rh['cvss3_score']}")
            if rh.get("bugzilla_url"):
                lines.append(f"    Bugzilla: {rh['bugzilla_url']}")
            lines.append(f"    Release Date: {rh.get('release_date', 'N/A')}")
            lines.append("")

        # Ubuntu
        for ub in (vendor_data.get("ubuntu") or [])[:5]:
            has_advisories = True
            lines.append("  Ubuntu Security Notice:")
            lines.append(f"    Package: {ub.get('package', 'N/A')}")
            lines.append(f"    Release: {ub.get('release', 'N/A')}")
            lines.append(f"    Status: {ub.get('status', 'N/A')}")
            lines.append(f"    Priority: {ub.get('priority', 'N/A')}")
            lines.append("")

    if not has_advisories:
        lines.append("  No vendor advisories found for this CVE.")
    lines.append("")

    # Section 8: Risk Scoring Breakdown
    lines.append("8. RISK SCORING BREAKDOWN")
    lines.append("-" * 40)
    lines.append(f"Composite Risk Score: {risk_score}/100")
    lines.append(f"Risk Label: {risk_label}")
    lines.append(f"Urgency: {urgency}")
    lines.append("")
    if components:
        lines.append("Component Scores:")
        lines.append(f"  CVSS Base Score: {components.get('cvss_score', 'N/A')}")
        lines.append(f"  CVSS Contribution: {components.get('cvss_contribution', 'N/A')}")
        lines.append(f"  EPSS Probability: {components.get('epss_probability', 'N/A')}")
        lines.append(f"  EPSS Contribution: {components.get('epss_contribution', 'N/A')}")
        lines.append(f"  In KEV Catalog: {'Yes' if components.get('in_kev') else 'No'}")
        lines.append(f"  KEV Contribution: {components.get('kev_contribution', 0)}")
        lines.append(f"  PoC Confidence: {components.get('poc_confidence', 'NONE')}")
        lines.append(f"  PoC Contribution: {components.get('poc_contribution', 0)}")
    boosters = score_result.get("boosters_applied", [])
    if boosters:
        lines.append(f"  Boost Multipliers: {', '.join(boosters)}")
    days = score_result.get("days_since_published")
    if days is not None:
        lines.append(f"  Days Since Published: {days}")
    lines.append("")

    # Section 9: Timeline
    lines.append("9. TIMELINE")
    lines.append("-" * 40)
    if nvd_data is not None:
        lines.append(f"NVD Published: {nvd_data.published[:10] if nvd_data.published else 'N/A'}")
        lines.append(
            f"NVD Last Modified: {nvd_data.lastModified[:10] if nvd_data.lastModified else 'N/A'}"
        )
    if kev_entry is not None:
        lines.append(f"KEV Added: {kev_entry.dateAdded}")
        lines.append(f"Remediation Due: {kev_entry.dueDate}")
    if epss_data is not None:
        lines.append(f"EPSS Assessment Date: {epss_data.date}")
    lines.append("")

    # Section 10: Remediation
    if include_remediation:
        lines.append("10. DETAILED REMEDIATION GUIDANCE")
        lines.append("-" * 40)

        step = 1
        if kev_entry:
            lines.append(f"  {step}. This vulnerability is in the CISA KEV catalog.")
            lines.append(f"     Federal agencies must remediate by {kev_entry.dueDate}.")
            lines.append("     All organizations should treat this as urgent.")
            step += 1

        if vendor_data and (
            vendor_data.get("microsoft") or vendor_data.get("redhat") or vendor_data.get("ubuntu")
        ):
            lines.append(f"  {step}. Apply vendor patches:")
            for msrc in (vendor_data.get("microsoft") or [])[:3]:
                if msrc.get("article_url"):
                    lines.append(f"     - Microsoft: {msrc['article_url']}")
            for rh in (vendor_data.get("redhat") or [])[:3]:
                if rh.get("advisory"):
                    lines.append(f"     - Red Hat {rh['advisory']}: {rh.get('package', '')}")
            for ub in (vendor_data.get("ubuntu") or [])[:3]:
                if ub.get("package"):
                    lines.append(f"     - Ubuntu: update {ub['package']}")
            step += 1
        else:
            lines.append(f"  {step}. No vendor patches identified. Monitor vendor channels.")
            step += 1

        if exploit_data and exploit_data.get("has_public_exploit"):
            lines.append(f"  {step}. Public exploits exist. Implement compensating controls:")
            lines.append("     - Deploy WAF/IPS rules targeting this vulnerability.")
            lines.append("     - Increase monitoring for indicators of exploitation.")
            lines.append("     - Consider isolating affected systems until patched.")
            step += 1

        if attack_data and attack_data.get("techniques"):
            tactics = set()
            for tech in attack_data["techniques"]:
                for t in tech.get("tactics", []):
                    tactics.add(t)
            if tactics:
                lines.append(f"  {step}. Monitor for ATT&CK tactics: {', '.join(sorted(tactics))}")
                step += 1

        lines.append(f"  {step}. Validate remediation through vulnerability scanning.")
        step += 1
        lines.append(f"  {step}. Document remediation actions for compliance reporting.")

        # NVD references
        if nvd_data and nvd_data.references:
            lines.append("")
            lines.append("  Additional References:")
            for ref in nvd_data.references[:10]:
                url = ref.get("url", "")
                tags = ref.get("tags", [])
                tag_str = f" [{', '.join(tags)}]" if tags else ""
                if url:
                    lines.append(f"    - {url}{tag_str}")

    return "\n".join(lines)


async def build_vuln_report(
    cve_id: str,
    format: str,
    include_remediation: bool,
    client: httpx.AsyncClient,
    cache: VulnCache,
    limiter: TokenBucketRateLimiter | None = None,
) -> dict:
    """Build a vulnerability report for a single CVE.

    Gathers data from NVD, EPSS, KEV, GitHub exploits, ATT&CK, and vendor
    advisories concurrently, computes a risk score, and generates a formatted
    report.

    Args:
        cve_id: CVE identifier (e.g., CVE-2021-44228)
        format: Report format - "executive", "technical", or "full"
        include_remediation: Whether to include remediation guidance
        client: httpx async client for API calls
        cache: VulnCache instance for caching

    Returns:
        Dict with cve_id, format, report_text, risk_score, risk_label,
        urgency, generated_at, and data_sources_used.
    """
    # Gather all data concurrently
    results = await asyncio.gather(
        _fetch_nvd_data(cve_id, client, limiter, cache),
        _fetch_epss_single(cve_id, client, cache),
        _fetch_kev_entry(cve_id, client, cache),
        check_exploit_availability(cve_id, client, cache),
        get_attack_mapping(cve_id, client, cache),
        get_vendor_advisory(cve_id, client, cache),
        search_poc_existence(cve_id, client, cache),
        return_exceptions=True,
    )

    nvd_data = _safe(results[0], "NVD")
    epss_data = _safe(results[1], "EPSS")
    kev_entry = _safe(results[2], "KEV")
    exploit_data = _safe(results[3], "Exploit")
    attack_data = _safe(results[4], "ATT&CK")
    vendor_data = _safe(results[5], "Vendor")
    poc_data = _safe(results[6], "PoC")

    # Build EPSS dict for risk scorer (expects {"probability": float})
    epss_dict = None
    if epss_data is not None:
        epss_dict = {"probability": float(epss_data.epss)}

    # Compute risk score using score_cve(cve_id, nvd_data, epss_data, kev_entry, poc_result)
    score_result = score_cve(
        cve_id,
        nvd_data,
        epss_dict,
        kev_entry,
        poc_data,
    )

    # Build report text based on format
    if format == "executive":
        report_text = _build_executive_report(
            cve_id,
            nvd_data,
            epss_data,
            kev_entry,
            exploit_data,
            attack_data,
            vendor_data,
            score_result,
            include_remediation,
        )
    elif format == "technical":
        report_text = _build_technical_report(
            cve_id,
            nvd_data,
            epss_data,
            kev_entry,
            exploit_data,
            attack_data,
            vendor_data,
            score_result,
            include_remediation,
        )
    else:  # "full"
        report_text = _build_full_report(
            cve_id,
            nvd_data,
            epss_data,
            kev_entry,
            exploit_data,
            attack_data,
            vendor_data,
            score_result,
            include_remediation,
        )

    return {
        "cve_id": cve_id,
        "format": format,
        "report_text": report_text,
        "risk_score": score_result["risk_score"],
        "risk_label": score_result["risk_label"],
        "urgency": score_result["urgency"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_sources_used": [
            s
            for s, v in [
                ("NVD", nvd_data),
                ("EPSS", epss_data),
                ("KEV", kev_entry),
                ("ExploitDB", exploit_data),
                ("ATT&CK", attack_data),
                ("Vendor", vendor_data),
                ("PoC", poc_data),
            ]
            if v is not None
        ],
    }


async def build_cve_comparison(
    cve_ids: list[str],
    client: httpx.AsyncClient,
    cache: VulnCache,
    limiter: TokenBucketRateLimiter | None = None,
) -> dict:
    """Compare multiple CVEs by gathering data and scoring each one.

    Fetches NVD, EPSS, KEV, and exploit data for each CVE concurrently,
    computes risk scores, sorts by severity, and assigns patch priority
    rankings.

    Args:
        cve_ids: List of CVE identifiers to compare
        client: httpx async client for API calls
        cache: VulnCache instance for caching

    Returns:
        Dict with comparison_matrix (sorted by risk_score), summary text,
        and generated_at timestamp.
    """

    async def _score_single(cve_id: str) -> dict:
        results = await asyncio.gather(
            _fetch_nvd_data(cve_id, client, limiter, cache),
            _fetch_epss_single(cve_id, client, cache),
            _fetch_kev_entry(cve_id, client, cache),
            check_exploit_availability(cve_id, client, cache),
            search_poc_existence(cve_id, client, cache),
            return_exceptions=True,
        )

        nvd = _safe(results[0], "NVD")
        epss = _safe(results[1], "EPSS")
        kev = _safe(results[2], "KEV")
        exploit = _safe(results[3], "Exploit")
        poc = _safe(results[4], "PoC")

        # Build EPSS dict for risk scorer
        epss_dict = None
        if epss is not None:
            epss_dict = {"probability": float(epss.epss)}

        score_result = score_cve(cve_id, nvd, epss_dict, kev, poc)

        # Extract CVSS score
        cvss_score = 0.0
        if nvd is not None:
            _, cvss_score, _, _ = _get_cvss_info(nvd.metrics)

        # Extract EPSS probability
        epss_probability = 0.0
        if epss is not None:
            epss_probability = float(epss.epss)

        # KEV status
        in_kev = kev is not None

        # Exploit status
        has_exploit = exploit is not None and exploit.get("has_public_exploit", False)

        return {
            "cve_id": cve_id,
            "cvss_score": cvss_score,
            "epss_probability": epss_probability,
            "in_kev": in_kev,
            "has_exploit": has_exploit,
            "risk_score": score_result["risk_score"],
            "risk_label": score_result["risk_label"],
            "urgency": score_result["urgency"],
            "components": score_result.get("components", {}),
        }

    # Score all CVEs concurrently
    all_results = await asyncio.gather(
        *[_score_single(c) for c in cve_ids],
        return_exceptions=True,
    )

    # Filter out exceptions
    valid_results = []
    for i, r in enumerate(all_results):
        if isinstance(r, Exception):
            logger.warning("Failed to score %s: %s", cve_ids[i], r)
        else:
            valid_results.append(r)

    # Sort by risk_score descending
    sorted_results = sorted(valid_results, key=lambda x: x["risk_score"], reverse=True)

    # Build comparison matrix with patch priority ranks
    comparison_matrix = []
    for rank, r in enumerate(sorted_results, 1):
        comparison_matrix.append(
            {
                "cve_id": r["cve_id"],
                "cvss_score": r["cvss_score"],
                "epss_probability": r["epss_probability"],
                "in_kev": r["in_kev"],
                "has_exploit": r["has_exploit"],
                "risk_score": r["risk_score"],
                "risk_label": r["risk_label"],
                "urgency": r["urgency"],
                "patch_priority_rank": rank,
            }
        )

    # Build summary
    top_cve = sorted_results[0]["cve_id"] if sorted_results else "N/A"
    top_score = sorted_results[0]["risk_score"] if sorted_results else 0
    kev_count = sum(1 for r in sorted_results if r["in_kev"])

    return {
        "comparison_matrix": comparison_matrix,
        "summary": (
            f"{len(cve_ids)} CVEs analyzed. "
            f"Top priority: {top_cve} (score: {top_score}). "
            f"{kev_count} in KEV catalog."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
