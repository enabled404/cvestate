from __future__ import annotations

from cve_mcp.utils.risk_scorer import score_cve


def test_score_all_none():
    result = score_cve("CVE-2021-0001", None, None, None, None)
    assert result["risk_score"] == 0.0
    assert result["risk_label"] == "LOW"


def test_score_kev_contribution():
    result = score_cve("CVE-2021-0001", None, None, {"id": "CVE-2021-0001"}, None)
    assert result["components"]["kev_contribution"] == 30.0
    assert result["components"]["in_kev"] is True


def test_score_label_low():
    result = score_cve("CVE-2021-0001", None, None, None, None)
    assert result["risk_label"] == "LOW"


def test_score_capped_at_100():
    # High CVSS + KEV + high EPSS + PoC should not exceed 100
    class FakeCVE:
        cvss_v31_score = 10.0
        cvss_v30_score = None
        cvss_v2_score = None
        published_date = None

    epss = {"probability": 0.99}
    kev = {"id": "CVE-2021-0001"}
    poc = {"confidence": "WEAPONIZED"}
    result = score_cve("CVE-2021-0001", FakeCVE(), epss, kev, poc)
    assert result["risk_score"] <= 100.0


def test_score_booster_kev_plus_poc():
    class FakeCVE:
        cvss_v31_score = 7.0
        cvss_v30_score = None
        cvss_v2_score = None
        published_date = None

    epss = {"probability": 0.1}
    kev = {"id": "CVE-X"}
    poc = {"confidence": "PUBLIC_EXPLOIT"}
    result = score_cve("CVE-X", FakeCVE(), epss, kev, poc)
    assert "KEV+PoC" in result["boosters_applied"]


def test_score_urgency_patch_immediately():
    class FakeCVE:
        cvss_v31_score = 9.0
        cvss_v30_score = None
        cvss_v2_score = None
        published_date = None

    epss = {"probability": 0.8}
    kev = {"id": "CVE-X"}
    result = score_cve("CVE-X", FakeCVE(), epss, kev, None)
    assert result["urgency"] == "PATCH IMMEDIATELY"
