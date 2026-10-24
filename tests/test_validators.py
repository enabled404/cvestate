from __future__ import annotations

import pytest

from cve_mcp.utils.validators import normalize_cve, validate_hash, validate_ip_address


def test_normalize_cve_valid():
    assert normalize_cve("CVE-2021-44228") == "CVE-2021-44228"


def test_normalize_cve_lowercase():
    assert normalize_cve("cve-2021-44228") == "CVE-2021-44228"


def test_normalize_cve_invalid():
    assert normalize_cve("NOT-A-CVE") is None


def test_normalize_cve_empty():
    assert normalize_cve("") is None


def test_validate_ip_private():
    with pytest.raises(ValueError):
        validate_ip_address("192.168.1.1")


def test_validate_ip_loopback():
    with pytest.raises(ValueError):
        validate_ip_address("127.0.0.1")


def test_validate_ip_valid():
    assert validate_ip_address("8.8.8.8") == "8.8.8.8"


def test_validate_hash_sha256_valid():
    h = "a" * 64
    assert validate_hash(h) == h


def test_validate_hash_invalid_chars():
    # validate_hash returns None for invalid input (does not raise)
    assert validate_hash("xyz" + "a" * 61) is None


def test_validate_hash_wrong_length():
    # 20 hex chars is not a valid hash length (must be 32, 40, or 64)
    assert validate_hash("ab" * 10) is None
