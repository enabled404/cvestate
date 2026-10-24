"""Static source-trust table for CVE / threat-intelligence data providers.

This module assigns a *static* trust profile to every external data source used
across the cve-mcp server (NVD, VulnCheck, EPSS/FIRST, CISA KEV, OSV, CIRCL,
MITRE ATT&CK, GitHub advisories, AbuseIPDB, GreyNoise, Shodan, VirusTotal,
urlscan, ThreatFox, MalwareBazaar, community PoC repositories, ...). Downstream
tools can use it to weight, label, or caveat enriched results by provenance
("this PoC came from a community GitHub repo — treat with care" vs. "this
exploited-in-the-wild flag came from CISA KEV — authoritative").

The Admiralty / NATO model
==========================
The trust profile follows the **Admiralty System** (a.k.a. the NATO System,
codified in STANAG 2511 / Allied Joint Doctrine for Intelligence, JP 2-0 Appendix
B). It rates intelligence on two independent axes, expressed as a two-character
code such as ``A1`` or ``C3``:

1. **Reliability of the source** — a letter ``A``..``F`` describing how
   trustworthy the *provider* has historically been (its track record,
   authority, and independence), regardless of any single datum:

   ===== =====================================================================
   Grade Meaning
   ===== =====================================================================
   A     Completely reliable     — no doubt of authenticity, trustworthiness,
                                    competence; history of complete reliability.
   B     Usually reliable        — minor doubts; history of mostly valid info.
   C     Fairly reliable         — some doubt; provided valid info in the past.
   D     Not usually reliable    — significant doubt; some valid info before.
   E     Unreliable              — history of invalid information.
   F     Cannot be judged        — no basis to evaluate reliability.
   ===== =====================================================================

2. **Credibility of the information** — a digit ``1``..``6`` describing how
   well a typical datum from the source can be corroborated / confirmed:

   ===== =====================================================================
   Grade Meaning
   ===== =====================================================================
   1     Confirmed by other independent sources; logical; consistent.
   2     Probably true          — not confirmed, but logical and consistent.
   3     Possibly true          — not confirmed, reasonably logical, agrees
                                   with some other information.
   4     Doubtfully true        — not confirmed, possible but not logical.
   5     Improbable             — not confirmed, not logical, contradicted.
   6     Cannot be judged       — no basis to evaluate validity.
   ===== =====================================================================

Lower letters/digits are *better* (``A1`` is the strongest possible rating).

The 0–100 trust anchor
======================
In addition to the categorical Admiralty code, each source carries a numeric
``trust`` anchored on a 0–100 scale where **50 means "no opinion" / neutral**.
This mirrors CIRCL's hashlookup ``trust_level`` convention (0 = known bad /
fully distrusted, 50 = no opinion, 100 = fully trusted), which CIRCL documents
for its public hashlookup service. Anchoring on 50 keeps the scale interpretable
when a source has no track record either way, and lets callers do simple
arithmetic weighting without special-casing "unknown".

``authority`` classifies the *type* of organisation behind the source:

* ``"government"`` — government / public-sector CERT or agency (CISA, NIST).
* ``"standards"``  — non-profit standards body / coordinating org (FIRST, MITRE,
                     CIRCL, OpenSSF/OSV).
* ``"vendor"``     — commercial security vendor / platform (VulnCheck, Shodan,
                     VirusTotal, GreyNoise, AbuseIPDB, abuse.ch, urlscan,
                     GitHub).
* ``"community"``  — crowd-sourced / volunteer-maintained data (public PoC repos).

Rationale for the anchor grades
-------------------------------
* **NVD, CISA KEV, EPSS/FIRST** → ``A`` reliability. These are the
  authoritative primary sources: NVD is run by NIST, the KEV catalog by CISA
  (both U.S. government), and EPSS by FIRST.org (the global standards body for
  incident response). They are the canonical references the whole industry
  builds on.
* **MITRE ATT&CK, OSV** → ``A`` reliability. MITRE is a federally funded R&D
  centre and the steward of CVE/ATT&CK; OSV is the OpenSSF/Google-backed open
  vulnerability database aggregating authoritative upstream advisories.
* **GitHub Security Advisories (GHSA)** → ``A`` reliability. Curated, reviewed
  advisories that map to CVEs and feed the GitHub Advisory Database.
* **CIRCL** → ``B`` reliability. A respected national CERT (Luxembourg) and a
  long-standing, well-operated service, but a regional aggregator rather than
  the global primary of record — hence one notch below ``A``.
* **VulnCheck, Shodan, VirusTotal, GreyNoise, AbuseIPDB, abuse.ch
  (ThreatFox / MalwareBazaar), urlscan.io** → ``B`` reliability. Reputable
  commercial / non-profit security platforms with strong track records; their
  data is high quality but vendor-curated and sometimes derived/aggregated, so
  it warrants light corroboration before high-stakes action.
* **Community PoC repositories** (random public GitHub/exploit repos surfaced by
  the PoC checker) → ``C``–``D`` reliability. Unvetted, crowd-sourced code of
  highly variable quality; the *existence* of a PoC is a useful signal, but the
  content must be treated with caution and independently verified.

Everything here is intentionally **static** — it encodes editorial judgement
about source classes, not per-request scoring. ``score_cve`` and other dynamic
scorers remain the place for per-CVE computation.
"""

from __future__ import annotations

from typing import Literal, TypedDict

Reliability = Literal["A", "B", "C", "D", "E", "F"]
Authority = Literal["government", "standards", "vendor", "community"]


class SourceTrust(TypedDict):
    """Static trust profile for a single data source.

    Attributes
    ----------
    reliability:
        Admiralty source-reliability grade ``A``..``F`` (``A`` = best).
    credibility:
        Admiralty information-credibility grade ``1``..``6`` (``1`` = best).
    trust:
        0–100 trust anchor; ``50`` = no opinion (CIRCL hashlookup convention).
    authority:
        Organisation type behind the source.
    """

    reliability: Reliability
    credibility: int
    trust: int
    authority: Authority


# ---------------------------------------------------------------------------
# Static source-trust table.
#
# Keys are the canonical source identifiers used throughout this repo. Lookups
# via ``get_source_trust`` are case-insensitive and tolerant of common aliases
# (see ``_ALIASES`` below), so callers may pass e.g. "nvd", "CISA KEV", or
# "abuse.ch".
# ---------------------------------------------------------------------------
SOURCE_TRUST: dict[str, SourceTrust] = {
    # --- A-grade: authoritative primary sources of record ------------------
    # NVD — NIST's National Vulnerability Database. U.S. government primary
    # reference for CVE enrichment (CVSS, CPE, references). Admiralty A1.
    "NVD": {
        "reliability": "A",
        "credibility": 1,
        "trust": 98,
        "authority": "government",
    },
    # CISA KEV — Known Exploited Vulnerabilities catalog. CISA only lists a CVE
    # after confirming active, real-world exploitation: the gold standard for
    # "exploited in the wild". Admiralty A1.
    "CISA KEV": {
        "reliability": "A",
        "credibility": 1,
        "trust": 99,
        "authority": "government",
    },
    # EPSS / FIRST — Exploit Prediction Scoring System, maintained by FIRST.org,
    # the global standards body for incident response. Authoritative but a
    # *probabilistic forecast*, so credibility 2 (probably true, not confirmed).
    "EPSS/FIRST": {
        "reliability": "A",
        "credibility": 2,
        "trust": 92,
        "authority": "standards",
    },
    # MITRE ATT&CK — adversary TTP knowledge base from MITRE, the CVE steward
    # and a federally funded R&D centre. Authoritative reference framework.
    "MITRE ATT&CK": {
        "reliability": "A",
        "credibility": 1,
        "trust": 96,
        "authority": "standards",
    },
    # OSV — Open Source Vulnerability database (OpenSSF / Google), aggregating
    # authoritative upstream ecosystem advisories with precise affected-range
    # data. Admiralty A1.
    "OSV": {
        "reliability": "A",
        "credibility": 1,
        "trust": 95,
        "authority": "standards",
    },
    # GitHub Security Advisories (GHSA) — reviewed, CVE-mapped advisories curated
    # by GitHub's security team and the broader maintainer community.
    "GitHub advisories": {
        "reliability": "A",
        "credibility": 2,
        "trust": 90,
        "authority": "vendor",
    },
    # --- B-grade: usually reliable vendor / regional sources ---------------
    # CIRCL — Computer Incident Response Center Luxembourg. National CERT;
    # well-operated passive DNS / hashlookup services. Regional aggregator, one
    # notch below the global primaries.
    "CIRCL": {
        "reliability": "B",
        "credibility": 2,
        "trust": 85,
        "authority": "standards",
    },
    # VulnCheck — commercial vulnerability-intelligence platform (exploit/PoC
    # enrichment, KEV mirror). High quality but vendor-curated/aggregated.
    "VulnCheck": {
        "reliability": "B",
        "credibility": 2,
        "trust": 84,
        "authority": "vendor",
    },
    # Shodan — internet-wide scanning platform. Excellent for exposure data;
    # observational and point-in-time, so credibility 2.
    "Shodan": {
        "reliability": "B",
        "credibility": 2,
        "trust": 82,
        "authority": "vendor",
    },
    # VirusTotal — multi-engine file/URL/hash reputation aggregator. Strong
    # corroboration signal, but engine verdicts vary and can include FPs.
    "VirusTotal": {
        "reliability": "B",
        "credibility": 2,
        "trust": 80,
        "authority": "vendor",
    },
    # GreyNoise — internet background-noise / mass-scan intelligence. Reputable;
    # classifies benign vs. malicious scanners with good fidelity.
    "GreyNoise": {
        "reliability": "B",
        "credibility": 2,
        "trust": 80,
        "authority": "vendor",
    },
    # AbuseIPDB — crowd-reported IP abuse database. Reputable vendor curation
    # over community reports; confidence scores are heuristic, so credibility 3.
    "AbuseIPDB": {
        "reliability": "B",
        "credibility": 3,
        "trust": 72,
        "authority": "vendor",
    },
    # urlscan.io — automated URL sandbox / scanner. Solid technical evidence;
    # verdicts are heuristic and submission-quality dependent.
    "urlscan": {
        "reliability": "B",
        "credibility": 3,
        "trust": 74,
        "authority": "vendor",
    },
    # ThreatFox (abuse.ch) — community-fed IOC database, vetted by abuse.ch.
    # Reputable operator; individual IOCs are crowd-sourced.
    "ThreatFox": {
        "reliability": "B",
        "credibility": 3,
        "trust": 76,
        "authority": "vendor",
    },
    # MalwareBazaar (abuse.ch) — malware-sample sharing platform run by abuse.ch.
    # Samples/hashes are concrete artifacts; tagging is partly community-driven.
    "MalwareBazaar": {
        "reliability": "B",
        "credibility": 2,
        "trust": 80,
        "authority": "vendor",
    },
    # --- C/D-grade: unvetted community sources -----------------------------
    # Community PoC repositories — arbitrary public GitHub / exploit repos
    # surfaced by the PoC checker. The *existence* of a PoC is a useful signal,
    # but quality is highly variable and unverified: fairly-to-not-usually
    # reliable, possibly-to-doubtfully true.
    "community PoC repos": {
        "reliability": "C",
        "credibility": 4,
        "trust": 45,
        "authority": "community",
    },
}


# Default profile returned for unknown sources: Admiralty "cannot be judged"
# on both axes, with the CIRCL "no opinion" trust anchor of 50.
_DEFAULT_TRUST: SourceTrust = {
    "reliability": "F",
    "credibility": 6,
    "trust": 50,
    "authority": "community",
}


# Case-insensitive alias map → canonical key in SOURCE_TRUST. Lets callers pass
# the many spellings these sources appear under across the codebase / APIs.
_ALIASES: dict[str, str] = {
    "nvd": "NVD",
    "national vulnerability database": "NVD",
    "nist": "NVD",
    "nist nvd": "NVD",
    "kev": "CISA KEV",
    "cisa": "CISA KEV",
    "cisa kev": "CISA KEV",
    "cisa kev catalog": "CISA KEV",
    "known exploited vulnerabilities": "CISA KEV",
    "epss": "EPSS/FIRST",
    "first": "EPSS/FIRST",
    "first.org": "EPSS/FIRST",
    "epss/first": "EPSS/FIRST",
    "epss (first)": "EPSS/FIRST",
    "mitre": "MITRE ATT&CK",
    "mitre att&ck": "MITRE ATT&CK",
    "att&ck": "MITRE ATT&CK",
    "attack": "MITRE ATT&CK",
    "osv": "OSV",
    "osv.dev": "OSV",
    "open source vulnerabilities": "OSV",
    "github": "GitHub advisories",
    "github advisories": "GitHub advisories",
    "github security advisories": "GitHub advisories",
    "ghsa": "GitHub advisories",
    "github advisory database": "GitHub advisories",
    "circl": "CIRCL",
    "circl pdns": "CIRCL",
    "circl hashlookup": "CIRCL",
    "vulncheck": "VulnCheck",
    "shodan": "Shodan",
    "virustotal": "VirusTotal",
    "vt": "VirusTotal",
    "greynoise": "GreyNoise",
    "grey noise": "GreyNoise",
    "abuseipdb": "AbuseIPDB",
    "abuse ipdb": "AbuseIPDB",
    "urlscan": "urlscan",
    "urlscan.io": "urlscan",
    "threatfox": "ThreatFox",
    "threat fox": "ThreatFox",
    "malwarebazaar": "MalwareBazaar",
    "malware bazaar": "MalwareBazaar",
    "abuse.ch": "ThreatFox",
    "community poc repos": "community PoC repos",
    "community poc": "community PoC repos",
    "poc": "community PoC repos",
    "poc repos": "community PoC repos",
    "github poc": "community PoC repos",
    "exploit-db": "community PoC repos",
    "exploitdb": "community PoC repos",
}


def get_source_trust(name: str) -> SourceTrust:
    """Return the static trust profile for a named data source.

    Lookup is forgiving: it matches the canonical ``SOURCE_TRUST`` keys first,
    then a set of common aliases / spellings, both case-insensitively. Unknown
    sources fall back to a safe default of Admiralty ``F6`` ("reliability and
    credibility cannot be judged") with a neutral 0–100 trust anchor of ``50``
    ("no opinion"), classified as ``community`` authority.

    Parameters
    ----------
    name:
        A source identifier, e.g. ``"NVD"``, ``"cisa kev"``, ``"abuse.ch"``,
        ``"github advisories"``, ``"community PoC repos"``.

    Returns
    -------
    SourceTrust
        A *copy* of the matched profile (so callers may mutate it freely without
        corrupting the shared table), or a copy of the safe default.
    """
    if not name or not isinstance(name, str):
        return dict(_DEFAULT_TRUST)  # type: ignore[return-value]

    raw = name.strip()

    # Exact canonical match.
    if raw in SOURCE_TRUST:
        return dict(SOURCE_TRUST[raw])  # type: ignore[return-value]

    key = raw.lower()

    # Case-insensitive canonical match.
    for canonical in SOURCE_TRUST:
        if canonical.lower() == key:
            return dict(SOURCE_TRUST[canonical])  # type: ignore[return-value]

    # Alias match.
    canonical = _ALIASES.get(key)
    if canonical is not None and canonical in SOURCE_TRUST:
        return dict(SOURCE_TRUST[canonical])  # type: ignore[return-value]

    return dict(_DEFAULT_TRUST)  # type: ignore[return-value]


def admiralty_code(name: str) -> str:
    """Return the two-character Admiralty code (e.g. ``"A1"``) for a source.

    Convenience helper for compact display/labelling. Unknown sources yield
    ``"F6"`` (cannot be judged on either axis).
    """
    profile = get_source_trust(name)
    return f"{profile['reliability']}{profile['credibility']}"


__all__ = [
    "SourceTrust",
    "SOURCE_TRUST",
    "get_source_trust",
    "admiralty_code",
]
