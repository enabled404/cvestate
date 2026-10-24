from __future__ import annotations

from datetime import datetime, timezone


def _extract_cvss_score(nvd_data) -> float:
    """Extract the best available CVSS base score from NVD data.

    Handles CVERecord objects, plain dicts, and None.
    Tries CVSS v3.1, then v3.0, then v2.0.
    """
    if nvd_data is None:
        return 0.0

    # Try object attributes first (CVERecord-style with direct score attrs)
    for attr in ("cvss_v31_score", "cvss_v30_score", "cvss_v2_score"):
        val = getattr(nvd_data, attr, None)
        if val is not None:
            return float(val)

    # Try dict-style direct keys
    if isinstance(nvd_data, dict):
        for key in ("cvss_v31_score", "cvss_v30_score", "cvss_v2_score"):
            val = nvd_data.get(key)
            if val is not None:
                return float(val)

    # Extract from nested metrics structure (NVD API format)
    metrics = None
    if isinstance(nvd_data, dict):
        metrics = nvd_data.get("metrics", {})
    else:
        metrics = getattr(nvd_data, "metrics", None)

    if metrics and isinstance(metrics, dict):
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(metric_key, [])
            if entries and isinstance(entries, list) and len(entries) > 0:
                cvss_data = entries[0].get("cvssData", {})
                base_score = cvss_data.get("baseScore")
                if base_score is not None:
                    return float(base_score)

    return 0.0


def _extract_published_date(nvd_data) -> datetime | None:
    """Extract the published date from NVD data as a timezone-aware datetime."""
    if nvd_data is None:
        return None

    raw = None

    # Try object attribute
    for attr in ("published_date", "published"):
        val = getattr(nvd_data, attr, None)
        if val is not None:
            raw = val
            break

    # Try dict keys
    if raw is None and isinstance(nvd_data, dict):
        for key in ("published_date", "published"):
            val = nvd_data.get(key)
            if val is not None:
                raw = val
                break

    if raw is None:
        return None

    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw

    if isinstance(raw, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(raw, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        # Try ISO format with timezone info
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass

    return None


def _extract_product(nvd_data) -> str:
    """Try to extract a product name from NVD data for recommendation text."""
    if nvd_data is None:
        return ""

    # Try object attributes
    product = getattr(nvd_data, "product", None)
    if product:
        return str(product)

    # Try dict
    if isinstance(nvd_data, dict):
        product = nvd_data.get("product", "")
        if product:
            return str(product)

    return ""


def score_cve(
    cve_id: str,
    nvd_data,
    epss_data: dict | None,
    kev_entry,
    poc_result: dict | None,
) -> dict:
    """Compute a composite risk score for a CVE.

    Combines CVSS base score, EPSS exploitation probability, CISA KEV
    catalog membership, and proof-of-concept availability into a single
    0-100 risk score with urgency guidance.
    """
    # ── CVSS extraction ──────────────────────────────────────────────
    cvss_score = _extract_cvss_score(nvd_data)

    # ── EPSS extraction ──────────────────────────────────────────────
    epss_probability = epss_data.get("probability", 0.0) if epss_data else 0.0

    # ── KEV check ────────────────────────────────────────────────────
    in_kev = bool(kev_entry) and kev_entry != {}

    # ── PoC confidence ───────────────────────────────────────────────
    poc_confidence = poc_result.get("confidence", "NONE") if poc_result else "NONE"
    poc_score_map = {
        "WEAPONIZED": 15,
        "PUBLIC_EXPLOIT_REMOTE": 12,
        "PUBLIC_EXPLOIT": 10,
        "PUBLIC_POC_HIGH_QUALITY": 7,
        "PUBLIC_POC_LOW_QUALITY": 3,
        "NONE": 0,
    }

    # ── Score contributions ──────────────────────────────────────────
    cvss_contribution = (cvss_score / 10.0) * 20.0
    epss_contribution = epss_probability * 100 * 0.35
    kev_contribution = 30.0 if in_kev else 0.0
    poc_contribution = poc_score_map.get(poc_confidence, 0)

    base_score = cvss_contribution + epss_contribution + kev_contribution + poc_contribution

    # ── Boost multipliers ────────────────────────────────────────────
    multiplier = 1.0
    boosters_applied: list[str] = []

    if in_kev and poc_confidence != "NONE":
        multiplier *= 1.15
        boosters_applied.append("KEV+PoC")

    if cvss_score >= 9.0 and epss_probability > 0.7:
        multiplier *= 1.10
        boosters_applied.append("CVSS>=9+EPSS>0.7")

    published_dt = _extract_published_date(nvd_data)
    days_since_published: int | None = None
    if published_dt is not None:
        delta = datetime.now(timezone.utc) - published_dt
        days_since_published = delta.days
        if days_since_published <= 7:
            multiplier *= 1.05
            boosters_applied.append("Published<7days")

    risk_score = min(100.0, round(base_score * multiplier, 2))

    # ── Risk label ───────────────────────────────────────────────────
    if risk_score <= 25:
        risk_label = "LOW"
    elif risk_score <= 50:
        risk_label = "MEDIUM"
    elif risk_score <= 75:
        risk_label = "HIGH"
    else:
        risk_label = "CRITICAL"

    # ── KEV hard override (plan 2.5) ──────────────────────────────────
    # CISA KEV membership means the vulnerability is *known to be exploited in
    # the wild*. That is the single strongest exploitation signal we have, so it
    # acts as a hard override: the label can never be lower than CRITICAL and the
    # numeric score is raised into the critical band. The linear sum above stays
    # the v1 default for the score, but KEV membership clamps the floor.
    if in_kev:
        risk_label = "CRITICAL"
        risk_score = max(risk_score, 76.0)

    # ── Urgency ──────────────────────────────────────────────────────
    if in_kev and epss_probability > 0.5:
        urgency = "PATCH IMMEDIATELY"
    elif in_kev:
        urgency = "PATCH WITHIN 24 HOURS"
    elif epss_probability > 0.5:
        urgency = "PATCH WITHIN 72 HOURS"
    elif cvss_score >= 9.0:
        urgency = "PATCH THIS WEEK"
    elif cvss_score >= 7.0:
        urgency = "PATCH THIS MONTH"
    else:
        urgency = "SCHEDULE FOR NEXT CYCLE"

    # ── Recommendation ───────────────────────────────────────────────
    product = _extract_product(nvd_data)
    product_clause = f" affecting {product}" if product else ""

    if urgency == "PATCH IMMEDIATELY":
        recommendation = (
            f"{cve_id}{product_clause} is actively exploited and in the CISA KEV catalog "
            f"with high exploitation probability; apply vendor patches immediately."
        )
    elif urgency == "PATCH WITHIN 24 HOURS":
        recommendation = (
            f"{cve_id}{product_clause} is listed in the CISA KEV catalog; "
            f"apply available patches within 24 hours."
        )
    elif urgency == "PATCH WITHIN 72 HOURS":
        recommendation = (
            f"{cve_id}{product_clause} has a high exploitation probability (EPSS {epss_probability:.1%}); "
            f"prioritize patching within 72 hours."
        )
    elif urgency == "PATCH THIS WEEK":
        recommendation = (
            f"{cve_id}{product_clause} has a critical CVSS score of {cvss_score}; "
            f"schedule patching this week."
        )
    elif urgency == "PATCH THIS MONTH":
        recommendation = (
            f"{cve_id}{product_clause} has a high CVSS score of {cvss_score}; "
            f"include in the next monthly patch cycle."
        )
    else:
        recommendation = (
            f"{cve_id}{product_clause} poses lower immediate risk; "
            f"schedule remediation for the next maintenance cycle."
        )

    return {
        "cve_id": cve_id,
        "scoring_version": "1.0",
        "risk_score": risk_score,
        "risk_label": risk_label,
        "urgency": urgency,
        "recommendation": recommendation,
        "components": {
            "cvss_score": cvss_score,
            "epss_probability": epss_probability,
            "in_kev": in_kev,
            "poc_confidence": poc_confidence,
            "cvss_contribution": round(cvss_contribution, 2),
            "epss_contribution": round(epss_contribution, 2),
            "kev_contribution": kev_contribution,
            "poc_contribution": poc_contribution,
            # CVSS measures *severity* (potential impact), not exploitation
            # likelihood. Per Allodi & Massacci ("Comparing Vulnerability
            # Severity and Exploits Using Case-Control Studies", ACM TISSEC
            # 2014), CVSS base score is a poor predictor of in-the-wild
            # exploitation; EPSS and KEV carry the exploitation signal here.
            "cvss_role": "severity",
        },
        "boosters_applied": boosters_applied,
        "days_since_published": days_since_published,
    }
