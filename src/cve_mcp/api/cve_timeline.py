from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from cve_mcp.models import CVERecord, EPSSScore, KEVEntry

logger = logging.getLogger(__name__)


def _parse_date(date_str: str) -> datetime | None:
    """Parse various date formats encountered in CVE data."""
    if not date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str.split("+")[0].split("Z")[0], fmt)
        except ValueError:
            continue
    return None


def _days_between(date1: str, date2: str) -> int:
    """Calculate days between two date strings. Returns -1 if either is missing."""
    d1 = _parse_date(date1)
    d2 = _parse_date(date2)
    if d1 is None or d2 is None:
        return -1
    return abs((d2 - d1).days)


def get_cve_timeline(
    cve_id: str,
    nvd_record: CVERecord | dict | None,
    epss_scores: list[EPSSScore | dict],
    kev_entry: KEVEntry | dict | None,
) -> dict:
    """Build a CVE timeline from already-fetched NVD, EPSS, and KEV data.

    Pure computation -- no HTTP calls. Takes data objects as input and computes
    timeline metrics.

    Args:
        cve_id: The CVE identifier.
        nvd_record: CVERecord or dict from NVD fetch, or None.
        epss_scores: List of EPSSScore or dicts from EPSS fetch.
        kev_entry: KEVEntry or dict from KEV catalog lookup, or None.

    Returns:
        Dict with key dates and computed metrics:
        - nvd_published: when NVD first published the CVE
        - epss_date: date of the latest EPSS score
        - kev_date_added: when CISA added the CVE to the KEV catalog
        - patch_lag_days: days from nvd_published to kev_date_added
        - exploit_window_days: days from nvd_published to first EPSS > 0.5
    """
    result: dict[str, Any] = {
        "cve_id": cve_id,
        "nvd_published": "",
        "nvd_last_modified": "",
        "epss_score": 0.0,
        "epss_percentile": 0.0,
        "epss_date": "",
        "kev_date_added": "",
        "kev_due_date": "",
        "kev_ransomware": "",
        "patch_lag_days": -1,
        "exploit_window_days": -1,
    }

    # Extract NVD dates
    if nvd_record is not None:
        if isinstance(nvd_record, dict):
            result["nvd_published"] = nvd_record.get("published", "")
            result["nvd_last_modified"] = nvd_record.get("lastModified", "")
        else:
            result["nvd_published"] = nvd_record.published
            result["nvd_last_modified"] = nvd_record.lastModified

    # Extract EPSS data -- find the score for this CVE
    epss_match = None
    for score in epss_scores:
        if isinstance(score, dict):
            if score.get("cve", "") == cve_id:
                epss_match = score
                break
        else:
            if score.cve == cve_id:
                epss_match = score
                break

    if epss_match is not None:
        if isinstance(epss_match, dict):
            result["epss_score"] = epss_match.get("epss", 0.0)
            result["epss_percentile"] = epss_match.get("percentile", 0.0)
            result["epss_date"] = epss_match.get("date", "")
        else:
            result["epss_score"] = epss_match.epss
            result["epss_percentile"] = epss_match.percentile
            result["epss_date"] = epss_match.date

    # Extract KEV data
    if kev_entry is not None:
        if isinstance(kev_entry, dict):
            result["kev_date_added"] = kev_entry.get("dateAdded", "")
            result["kev_due_date"] = kev_entry.get("dueDate", "")
            result["kev_ransomware"] = kev_entry.get("knownRansomwareCampaignUse", "")
        else:
            result["kev_date_added"] = kev_entry.dateAdded
            result["kev_due_date"] = kev_entry.dueDate
            result["kev_ransomware"] = kev_entry.knownRansomwareCampaignUse

    # Compute derived metrics
    nvd_pub = result["nvd_published"]
    kev_added = result["kev_date_added"]

    # patch_lag_days: days from NVD publication to KEV addition
    if nvd_pub and kev_added:
        result["patch_lag_days"] = _days_between(nvd_pub, kev_added)

    # exploit_window_days: days from NVD publication to first EPSS > 0.5
    if nvd_pub and result["epss_score"] > 0.5 and result["epss_date"]:
        result["exploit_window_days"] = _days_between(nvd_pub, result["epss_date"])
    elif nvd_pub and kev_added:
        # Fallback: use KEV addition date as exploit indicator
        result["exploit_window_days"] = _days_between(nvd_pub, kev_added)

    return result
