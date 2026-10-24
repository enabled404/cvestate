"""Experimental SSVC-style gated decision path (scoring_version=2, plan 2.5).

This module implements a *gated, qualitative* alternative to the numeric
``score_cve`` risk scorer in :mod:`cve_mcp.utils.risk_scorer`. Rather than
summing weighted contributions into a 0-100 number, it walks a decision
tree and emits an **action band** (``Act`` / ``Attend`` / ``Track*`` /
``Track``). This is the Stakeholder-Specific Vulnerability Categorization
(SSVC) approach championed by CISA and the CERT/CC, which deliberately
avoids numeric weighting in favour of explainable, reproducible decisions.

The decision tree implemented here is the published **CISA "Deployer"
decision model** (CISA SSVC Guide, v2.0.3 / the ``CISA-Coordinator`` model
shipped with the CERT/CC SSVC project). Its decision points are:

* **Exploitation** -- ``none`` / ``poc`` / ``active``
      Evidence of exploitation in the wild. ``active`` means reliable,
      widely available, observed-in-the-wild exploitation (the CISA KEV
      catalogue is the canonical "active" signal). ``poc`` means a public
      proof-of-concept or weaponized exploit exists but active in-the-wild
      exploitation is not (yet) confirmed. ``none`` means no public PoC and
      no observed exploitation.

* **Automatable** -- ``no`` / ``yes``
      Can an attacker reliably automate steps 1-4 of the kill chain
      (reconnaissance, weaponization, delivery, exploitation) across many
      targets? Open, internet-facing exposure combined with a usable
      exploit makes automation realistic.

* **Technical Impact** -- ``partial`` / ``total``
      How much control does successful exploitation grant. Used here with
      ``cvss_score`` as a severity proxy (CVSS >= 9.0 -> ``total``).

* **Mission & Well-being** -- ``low`` / ``medium`` / ``high``
      Combined mission prevalence and public well-being impact. Used here
      with ``cvss_score`` as a severity proxy.

The full 3x2x2x3 = 36-row decision table below is transcribed faithfully
from the published CISA model. Because the public tool surface for this
release exposes ``exposure`` and ``cvss_score`` (a severity proxy) rather
than directly soliciting Automatable / Technical Impact / Mission values,
this module *derives* those decision points from the available signals in a
documented, conservative way (per CISA guidance, unknown exposure defaults
to ``open``).

References
----------
* CISA SSVC Guide (508c PDF) -- decision points and Track/Track*/Attend/Act
  outcome definitions.
* CERT/CC SSVC project, ``CISA-Coordinator`` decision model
  (https://github.com/CERTCC/SSVC).
* SSVC System Exposure decision point
  (https://certcc.github.io/SSVC/reference/decision_points/system_exposure/).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Canonical CISA "Deployer" decision table.
#
# Key:  (exploitation, automatable, technical_impact)
# Value: 3-tuple of outcomes for mission_wellbeing in (low, medium, high)
#
# Transcribed from the published CISA SSVC decision model (36 branches:
# 3 Exploitation x 2 Automatable x 2 Technical Impact x 3 Mission&Well-being).
# Outcomes are one of: "Track", "Track*", "Attend", "Act".
# ---------------------------------------------------------------------------
_DECISION_TABLE: dict[tuple[str, str, str], tuple[str, str, str]] = {
    # Exploitation: none
    ("none", "no", "partial"): ("Track", "Track", "Track"),
    ("none", "no", "total"): ("Track", "Track", "Track*"),
    ("none", "yes", "partial"): ("Track", "Track", "Attend"),
    ("none", "yes", "total"): ("Track", "Track", "Attend"),
    # Exploitation: poc
    ("poc", "no", "partial"): ("Track", "Track", "Track*"),
    ("poc", "no", "total"): ("Track", "Track*", "Attend"),
    ("poc", "yes", "partial"): ("Track", "Track", "Attend"),
    ("poc", "yes", "total"): ("Track", "Track*", "Attend"),
    # Exploitation: active
    ("active", "no", "partial"): ("Track", "Track", "Attend"),
    ("active", "no", "total"): ("Track", "Attend", "Act"),
    ("active", "yes", "partial"): ("Attend", "Attend", "Act"),
    ("active", "yes", "total"): ("Attend", "Act", "Act"),
}

# Outcome priority ordering (higher index == more urgent) used for any
# clamping/validation and for the human-readable rationale.
_OUTCOME_PRIORITY: dict[str, int] = {
    "Track": 0,
    "Track*": 1,
    "Attend": 2,
    "Act": 3,
}

# Action guidance per outcome, paraphrasing the CISA outcome definitions.
_ACTION_GUIDANCE: dict[str, str] = {
    "Track": (
        "No action required at this time; remediate within standard "
        "update timelines and reassess if new information emerges."
    ),
    "Track*": (
        "Monitor closely for change; the vulnerability has characteristics "
        "that may warrant reassessment, but remediate within standard "
        "update timelines."
    ),
    "Attend": (
        "Requires attention from supervisory staff; remediate sooner than "
        "standard update timelines and consider mitigations or notification."
    ),
    "Act": (
        "Requires immediate attention from supervisory and leadership staff; "
        "remediate as soon as possible (patch, isolate, or mitigate)."
    ),
}

# Recognized PoC-confidence labels that indicate a public/weaponized exploit.
# Mirrors the labels produced by the project's PoC discovery tooling and
# consumed by risk_scorer.score_cve.
_POC_LABELS_WEAPONIZED: frozenset[str] = frozenset(
    {
        "WEAPONIZED",
        "PUBLIC_EXPLOIT_REMOTE",
        "PUBLIC_EXPLOIT",
        "PUBLIC_POC_HIGH_QUALITY",
        "PUBLIC_POC_LOW_QUALITY",
        # tolerate common free-form variants
        "PUBLIC",
        "POC",
        "PROOF_OF_CONCEPT",
    }
)

# Valid SSVC System Exposure values (per CERT/CC). Unknown -> "open".
_EXPOSURE_VALUES: frozenset[str] = frozenset({"small", "controlled", "open"})


def _classify_exploitation(*, in_kev: bool, epss_probability: float, poc_confidence: str) -> str:
    """Map raw signals onto the SSVC Exploitation axis.

    * ``active`` -- the CVE is in the CISA KEV catalogue (canonical
      observed-in-the-wild signal), or EPSS estimates a very high
      (>= 0.90) 30-day exploitation probability, which the SSVC guidance
      treats as equivalent evidence of active exploitation pressure.
    * ``poc`` -- a public proof-of-concept or weaponized exploit exists,
      or EPSS is non-trivial (>= 0.10) indicating credible exploitability.
    * ``none`` -- no public PoC and no observed exploitation.
    """
    if in_kev:
        return "active"

    label = (poc_confidence or "NONE").strip().upper()

    # Very high EPSS is strong evidence of active exploitation pressure.
    if epss_probability >= 0.90:
        return "active"

    if label in _POC_LABELS_WEAPONIZED and label != "NONE":
        return "poc"

    # Credible (non-trivial) exploitation probability implies a usable path.
    if epss_probability >= 0.10:
        return "poc"

    return "none"


def _normalize_exposure(exposure: str) -> str:
    """Normalize the System Exposure value; unknown defaults to ``open``.

    CISA guidance: if a deployer cannot determine exposure, assume ``open``
    (the conservative choice).
    """
    value = (exposure or "").strip().lower()
    if value in _EXPOSURE_VALUES:
        return value
    return "open"


def _classify_automatable(*, exposure: str, exploitation: str, epss_probability: float) -> str:
    """Derive the SSVC Automatable axis from exposure and exploitability.

    Reliable automation of kill-chain steps 1-4 requires both a usable
    exploit and an attack surface reachable at scale. We therefore treat
    automation as ``yes`` when the system is openly reachable AND there is
    real exploitation evidence/pressure (active exploitation, a public PoC,
    or a non-trivial EPSS probability). Controlled/small exposure or the
    absence of any exploit path makes broad automation implausible (``no``).
    """
    if exposure != "open":
        return "no"
    if exploitation == "active":
        return "yes"
    if exploitation == "poc":
        return "yes"
    if epss_probability >= 0.10:
        return "yes"
    return "no"


def _classify_technical_impact(cvss_score: float) -> str:
    """Use CVSS base score as a severity proxy for Technical Impact.

    CVSS >= 9.0 (Critical) is treated as ``total`` system impact; anything
    below is treated as ``partial``.
    """
    return "total" if cvss_score >= 9.0 else "partial"


def _classify_mission_wellbeing(cvss_score: float) -> str:
    """Use CVSS base score as a severity proxy for Mission & Well-being.

    Without organisation-specific mission/well-being taxonomies, CVSS
    severity bands are used as a conservative stand-in:
    * ``high``   -- CVSS >= 9.0 (Critical)
    * ``medium`` -- 7.0 <= CVSS < 9.0 (High)
    * ``low``    -- CVSS < 7.0
    """
    if cvss_score >= 9.0:
        return "high"
    if cvss_score >= 7.0:
        return "medium"
    return "low"


def ssvc_decision(
    *,
    in_kev: bool,
    epss_probability: float,
    poc_confidence: str,
    cvss_score: float,
    exposure: str = "open",
) -> dict:
    """Compute an SSVC-style (non-numeric, gated) decision for a CVE.

    This is an experimental, qualitative alternative to the weighted numeric
    risk score. It walks the published CISA "Deployer" SSVC decision tree and
    returns an action band rather than a 0-100 number, so that the decision is
    explainable and reproducible.

    Parameters
    ----------
    in_kev:
        Whether the CVE is in the CISA Known Exploited Vulnerabilities
        catalogue (the canonical "active exploitation" signal).
    epss_probability:
        EPSS 30-day exploitation probability in ``[0.0, 1.0]``.
    poc_confidence:
        Proof-of-concept confidence label (e.g. ``"WEAPONIZED"``,
        ``"PUBLIC_EXPLOIT"``, ``"NONE"``) as produced by the project's PoC
        discovery tooling.
    cvss_score:
        CVSS base score in ``[0.0, 10.0]``, used as a severity proxy for the
        Technical Impact and Mission & Well-being decision points.
    exposure:
        SSVC System Exposure: ``"small"``, ``"controlled"``, or ``"open"``.
        Any unrecognised value defaults to ``"open"`` per CISA guidance.

    Returns
    -------
    dict
        ``{"scoring_version": "2.0", "exploitation": str, "exposure": str,
        "decision": dict, "action": str, "rationale": str}`` where
        ``decision`` records every derived SSVC decision point and the
        resulting outcome, ``action`` is the CISA outcome band
        (``"Act"`` / ``"Attend"`` / ``"Track*"`` / ``"Track"``), and
        ``rationale`` is a human-readable explanation of the path taken.
    """
    # ── Defensive coercion of inputs ─────────────────────────────────────
    try:
        epss_probability = float(epss_probability)
    except (TypeError, ValueError):
        epss_probability = 0.0
    epss_probability = max(0.0, min(1.0, epss_probability))

    try:
        cvss_score = float(cvss_score)
    except (TypeError, ValueError):
        cvss_score = 0.0
    cvss_score = max(0.0, min(10.0, cvss_score))

    in_kev = bool(in_kev)

    # ── Derive SSVC decision points ──────────────────────────────────────
    exploitation = _classify_exploitation(
        in_kev=in_kev,
        epss_probability=epss_probability,
        poc_confidence=poc_confidence,
    )
    exposure_norm = _normalize_exposure(exposure)
    automatable = _classify_automatable(
        exposure=exposure_norm,
        exploitation=exploitation,
        epss_probability=epss_probability,
    )
    technical_impact = _classify_technical_impact(cvss_score)
    mission_wellbeing = _classify_mission_wellbeing(cvss_score)

    # ── Walk the decision table ──────────────────────────────────────────
    outcomes = _DECISION_TABLE[(exploitation, automatable, technical_impact)]
    mw_index = {"low": 0, "medium": 1, "high": 2}[mission_wellbeing]
    action = outcomes[mw_index]

    # ── Build a human-readable rationale of the gated path ───────────────
    exploitation_reason = {
        "active": (
            "in the CISA KEV catalogue (active exploitation)"
            if in_kev
            else "very high EPSS probability (active exploitation pressure)"
        ),
        "poc": "a public/weaponized exploit or credible EPSS probability exists",
        "none": "no public proof-of-concept and no observed exploitation",
    }[exploitation]

    rationale = (
        f"SSVC Deployer decision: Exploitation={exploitation} "
        f"({exploitation_reason}); System Exposure={exposure_norm}; "
        f"Automatable={automatable}; Technical Impact={technical_impact} "
        f"(CVSS {cvss_score:g} severity proxy); "
        f"Mission & Well-being={mission_wellbeing} (CVSS {cvss_score:g} "
        f"severity proxy). This path resolves to '{action}': "
        f"{_ACTION_GUIDANCE[action]}"
    )

    return {
        "scoring_version": "2.0",
        "exploitation": exploitation,
        "exposure": exposure_norm,
        "decision": {
            "exploitation": exploitation,
            "automatable": automatable,
            "technical_impact": technical_impact,
            "mission_wellbeing": mission_wellbeing,
            "exposure": exposure_norm,
            "outcome": action,
            "outcome_priority": _OUTCOME_PRIORITY[action],
        },
        "action": action,
        "rationale": rationale,
    }
