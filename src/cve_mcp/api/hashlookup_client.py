"""Async client for the CIRCL hashlookup service (https://hashlookup.circl.lu).

CIRCL hashlookup is a public, free, no-auth, best-effort REST service backed by
the NSRL (National Software Reference Library) Reference Data Set and a number of
Linux distribution package datasets. It answers the question "is this file hash a
*known* file?" — a hit is a strong signal the file is a legitimate, widely
distributed OS/application artifact (i.e. a known-good allowlist entry), while a
miss simply means the file is not recognized (it does NOT prove maliciousness).

This module exposes a single-hash lookup that auto-detects the digest algorithm
by length (MD5 / SHA-1 / SHA-256), queries the matching
``GET /lookup/{algo}/{hash}`` endpoint, and returns a normalized result dict.

Key reference points (verified against the live service):
  * Endpoints: ``GET /lookup/md5/{md5}``, ``GET /lookup/sha1/{sha1}``,
    ``GET /lookup/sha256/{sha256}``. Hashes are case-insensitive hex.
  * HTTP 200 -> the hash is known (record returned). HTTP 404 with a body of
    ``{"message": "Non existing <ALGO>", "query": "..."}`` -> not found. HTTP 400
    -> malformed hash.
  * ``hashlookup:trust`` is an integer on a 0-100 scale where 50 means
    "no opinion" (neutral), > 50 means increasing known-good confidence, and
    < 50 means weaker reputation.
  * A record whose ``source`` is ``NSRL`` is treated here as known-good with a
    floor trust of > 50, because presence in the NSRL RDS is itself a
    positive known-good indicator regardless of the (often neutral) trust value.

Docs / API:
  * https://www.circl.lu/services/hashlookup/
  * https://hashlookup.circl.lu/swagger.json
"""

from __future__ import annotations

import logging

import httpx

from cve_mcp.config import MAX_RESPONSE_BYTES

logger = logging.getLogger(__name__)

# Base URL for the CIRCL hashlookup REST API. Defined locally on purpose — this
# module must not edit config.py.
HASHLOOKUP_BASE = "https://hashlookup.circl.lu"

# Cache lifetime for hashlookup results. Known-file metadata is effectively
# static, so a long TTL is appropriate. Mirrors the 24h convention used by the
# sibling hash_intel client.
TTL_HASHLOOKUP = 86400  # 24 hours

# Map digest hex length -> (algorithm path segment, human label).
_ALGO_BY_LENGTH: dict[int, str] = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}

# Trust floor applied to NSRL hits whose own trust value is neutral/missing.
_NSRL_TRUST_FLOOR = 75


def _detect_algorithm(hash_str: str) -> str | None:
    """Return the hashlookup algorithm path segment for ``hash_str``.

    Auto-detects md5/sha1/sha256 purely from the hex length. Returns ``None`` if
    the input is not a valid-looking hex digest of a supported length.
    """
    h = hash_str.strip().lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        return None
    return _ALGO_BY_LENGTH.get(len(h))


def _empty_result(hash_str: str, algorithm: str | None = None) -> dict:
    """Build the canonical not-found / unknown result skeleton."""
    return {
        "hash": hash_str,
        "algorithm": algorithm or "",
        "found": False,
        "known_good": False,
        "file_name": "",
        "product_name": "",
        "trust": 0,
        "source": "CIRCL hashlookup",
        "raw": {},
    }


def _coerce_trust(value: object) -> int:
    """Coerce the ``hashlookup:trust`` field to an int, defaulting to 50.

    The live API returns an integer, but the field can be absent or arrive as a
    numeric string in some datasets, so parse defensively. 50 ("no opinion") is
    the documented neutral default when no signal is present.
    """
    if isinstance(value, bool):  # bool is a subclass of int — reject explicitly
        return 50
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except (ValueError, TypeError):
            return 50
    return 50


def _extract_product_name(body: dict) -> str:
    """Pull a human-readable product name out of a single-lookup record.

    On single lookups ``ProductCode`` is a nested object carrying
    ``ProductName``; on slimmer (e.g. bulk) records it may be a flat string.
    Both shapes are handled defensively.
    """
    product = body.get("ProductCode")
    if isinstance(product, dict):
        name = product.get("ProductName")
        if isinstance(name, str):
            return name
    elif isinstance(product, str):
        return product
    return ""


def _is_not_found_body(body: object) -> bool:
    """Return True if a 200/other body actually encodes a 'not found' message."""
    if isinstance(body, dict):
        message = body.get("message")
        if isinstance(message, str) and message.lower().startswith("non existing"):
            return True
    return False


async def lookup_hash_circl(
    hash_str: str,
    client: httpx.AsyncClient,
    cache=None,
) -> dict:
    """Look up a file hash against the CIRCL hashlookup (NSRL) known-file service.

    Auto-detects the digest algorithm (MD5/SHA-1/SHA-256) from the hash length
    and queries the matching ``GET /lookup/{algo}/{hash}`` endpoint. No
    authentication is used (the service is public and free).

    Args:
        hash_str: An MD5 (32), SHA-1 (40) or SHA-256 (64) hex digest. Case and
            surrounding whitespace are normalized.
        client: A shared ``httpx.AsyncClient`` used for the request.
        cache: Optional ``VulnCache``-compatible object (async ``get``/``set``).
            When supplied, results are cached under ``hashlookup:{algo}:{hash}``
            with a 24h TTL.

    Returns:
        A normalized dict with keys:
            ``found`` (bool): hash is known to CIRCL/NSRL/distro datasets.
            ``known_good`` (bool): present and treated as a known-good allowlist
                hit (NSRL record present, or trust > 50).
            ``file_name`` (str): known filename, if any.
            ``product_name`` (str): human-readable product name, if any.
            ``trust`` (int): the ``hashlookup:trust`` value (0-100), possibly
                floored for NSRL hits.
            ``source`` (str): always ``"CIRCL hashlookup"``.
            ``raw`` (dict): a subset of the upstream record for provenance.
        Plus ``hash`` and ``algorithm`` echoing the (normalized) input. Unknown
        hashes, malformed input, and transport errors all yield ``found=False``.
    """
    normalized = hash_str.strip().lower()
    algorithm = _detect_algorithm(normalized)

    if algorithm is None:
        logger.warning("hashlookup: unsupported/invalid hash length for %r", hash_str)
        return _empty_result(normalized)

    cache_key = f"hashlookup:{algorithm}:{normalized}"
    if cache is not None:
        cached = await cache.get(cache_key)
        if cached is not None:
            return cached

    result = _empty_result(normalized, algorithm)

    try:
        resp = await client.get(
            f"{HASHLOOKUP_BASE}/lookup/{algorithm}/{normalized}",
            headers={"Accept": "application/json"},
        )

        # Guard against oversized responses before reading the body.
        content_length = resp.headers.get("content-length")
        if content_length and int(content_length) > MAX_RESPONSE_BYTES:
            raise ValueError("hashlookup response too large (Content-Length)")
        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ValueError("hashlookup response too large (actual body)")

        if resp.status_code == 404:
            # Documented not-found shape — normal, leave found=False.
            logger.debug("hashlookup: %s not found (404)", normalized)
        elif resp.status_code == 400:
            # Malformed hash per the upstream service.
            logger.warning("hashlookup: malformed hash rejected (400): %s", normalized)
        elif resp.status_code == 200:
            try:
                body = resp.json()
            except ValueError as exc:
                logger.warning("hashlookup: invalid JSON for %s: %s", normalized, exc)
                body = None

            if isinstance(body, dict) and not _is_not_found_body(body):
                trust = _coerce_trust(body.get("hashlookup:trust"))
                source = body.get("source")
                source_str = source if isinstance(source, str) else ""
                is_nsrl = source_str.upper() == "NSRL"

                # A present NSRL record is treated as known-good with a trust
                # floor, since NSRL presence is itself a positive signal even
                # when the per-record trust is the neutral default of 50.
                if is_nsrl and trust <= 50:
                    trust = _NSRL_TRUST_FLOOR

                known_good = is_nsrl or trust > 50

                file_name = body.get("FileName")
                result.update(
                    {
                        "found": True,
                        "known_good": known_good,
                        "file_name": file_name if isinstance(file_name, str) else "",
                        "product_name": _extract_product_name(body),
                        "trust": trust,
                        "source": "CIRCL hashlookup",
                        "raw": {
                            "MD5": body.get("MD5"),
                            "SHA-1": body.get("SHA-1"),
                            "SHA-256": body.get("SHA-256"),
                            "FileName": body.get("FileName"),
                            "FileSize": body.get("FileSize"),
                            "ProductName": _extract_product_name(body) or None,
                            "source": source_str or None,
                            "db": body.get("db"),
                            "hashlookup:trust": body.get("hashlookup:trust"),
                        },
                    }
                )
            elif _is_not_found_body(body):
                logger.debug("hashlookup: %s not found (200 not-existing body)", normalized)
        else:
            logger.warning(
                "hashlookup: unexpected status %s for %s",
                resp.status_code,
                normalized,
            )
    except httpx.TimeoutException as exc:
        logger.warning("hashlookup: timeout for %s: %s", normalized, exc)
    except httpx.HTTPError as exc:
        logger.warning("hashlookup: HTTP error for %s: %s", normalized, exc)
    except Exception as exc:  # noqa: BLE001 — best-effort enrichment, never fatal
        logger.warning("hashlookup: error for %s: %s", normalized, exc)

    if cache is not None:
        await cache.set(cache_key, result, TTL_HASHLOOKUP)

    return result
