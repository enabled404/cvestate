from __future__ import annotations

"""Keyless Have I Been Pwned (HIBP) Pwned Passwords range check.

This module implements the HIBP *Pwned Passwords* range query using the
k-anonymity model, which requires **no API key and no authentication**
(https://haveibeenpwned.com/API/v3).

Privacy model (k-anonymity)
---------------------------
The plaintext password is hashed locally with SHA-1. Only the **first 5
uppercase hex characters** of the digest (the "prefix") ever leave this
process. The remote endpoint returns every breached suffix that shares that
prefix (roughly 800-1000 records), and the matching of the remaining 35
characters (the "suffix") happens entirely **client-side**. The full password
and the full hash are therefore never transmitted and are never logged.

To further defeat response-size fingerprinting, requests are sent with the
``Add-Padding: true`` header; the server then pads the response with decoy
records whose count is ``0``. Those decoy lines are discarded before matching,
since a real breach entry always has a count >= 1.
"""

import asyncio
import hashlib
import logging

import httpx

from cve_mcp.config import MAX_RESPONSE_BYTES, MAX_RETRIES, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

# Pwned Passwords range endpoint. The {prefix} is the first 5 uppercase hex
# chars of the SHA-1 digest. This endpoint is keyless / unauthenticated.
HIBP_RANGE_BASE = "https://api.pwnedpasswords.com/range"

# Descriptive User-Agent — HIBP requests one and rejects blank UAs on some
# endpoints. Must not contain any password-derived data.
_USER_AGENT = "cve-mcp-threat-intel-server"

SOURCE_LABEL = "HIBP Pwned Passwords (k-anonymity)"


async def check_password_pwned(password: str, client: httpx.AsyncClient) -> dict:
    """Check whether a password appears in the HIBP Pwned Passwords corpus.

    Uses the keyless k-anonymity range API: only the first 5 characters of the
    password's SHA-1 hash are sent to the server. The full password and full
    hash never leave this process and are never logged.

    Args:
        password: The plaintext password to check. Never transmitted or logged.
        client: A shared ``httpx.AsyncClient`` instance.

    Returns:
        A dict with::

            {
                "pwned": bool,   # True if the password was found in a breach
                "count": int,    # Number of times it appears in the corpus
                "source": str,   # SOURCE_LABEL
            }

        On a network failure, timeout, or repeated rate-limiting, the function
        degrades gracefully by returning ``pwned=False``, ``count=0`` and an
        ``error`` key describing the failure, rather than raising — so callers
        can surface "lookup unavailable" without leaking the password.
    """
    if not isinstance(password, str) or password == "":
        return {"pwned": False, "count": 0, "source": SOURCE_LABEL, "error": "empty password"}

    # 1. SHA-1 of the UTF-8 password bytes -> 40 hex chars, uppercased.
    sha1_hex = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()  # noqa: S324
    # 2. Split into 5-char prefix and 35-char suffix (5 + 35 = 40).
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]

    # Defensive: only the prefix may ever appear in logs / requests.
    url = f"{HIBP_RANGE_BASE}/{prefix}"

    last_error: str = ""
    # Retry loop with exponential backoff, mainly to ride out 429 rate limits.
    for attempt in range(MAX_RETRIES):
        try:
            resp = await client.get(
                url,
                headers={
                    "Add-Padding": "true",
                    "User-Agent": _USER_AGENT,
                    "Accept": "text/plain",
                },
                timeout=REQUEST_TIMEOUT,
            )

            # Handle rate limiting (429) with Retry-After-aware backoff.
            if resp.status_code == 429:
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                wait = retry_after if retry_after is not None else _backoff_seconds(attempt)
                last_error = "rate limited (HTTP 429)"
                logger.warning(
                    "HIBP rate limited for prefix %s (attempt %d/%d); waiting %.1fs",
                    prefix,
                    attempt + 1,
                    MAX_RETRIES,
                    wait,
                )
                if attempt + 1 < MAX_RETRIES:
                    await asyncio.sleep(wait)
                    continue
                break

            resp.raise_for_status()

            # Guard against absurdly large bodies before reading text.
            content_length = resp.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                raise ValueError("HIBP response too large (Content-Length)")
            body_bytes = resp.content
            if len(body_bytes) > MAX_RESPONSE_BYTES:
                raise ValueError("HIBP response too large (actual body)")

            count = _match_suffix(resp.text, suffix)
            return {
                "pwned": count > 0,
                "count": count,
                "source": SOURCE_LABEL,
            }

        except httpx.TimeoutException as exc:
            last_error = f"timeout: {exc}"
            logger.warning(
                "HIBP timeout for prefix %s (attempt %d/%d): %s",
                prefix,
                attempt + 1,
                MAX_RETRIES,
                exc,
            )
            if attempt + 1 < MAX_RETRIES:
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            break
        except httpx.HTTPStatusError as exc:
            # Non-429 HTTP error — do not retry; report gracefully.
            last_error = f"HTTP {exc.response.status_code}"
            logger.warning("HIBP HTTP error for prefix %s: %s", prefix, last_error)
            break
        except httpx.RequestError as exc:
            last_error = f"network error: {exc}"
            logger.warning(
                "HIBP network error for prefix %s (attempt %d/%d): %s",
                prefix,
                attempt + 1,
                MAX_RETRIES,
                exc,
            )
            if attempt + 1 < MAX_RETRIES:
                await asyncio.sleep(_backoff_seconds(attempt))
                continue
            break
        except ValueError as exc:
            last_error = str(exc)
            logger.warning("HIBP parse/size error for prefix %s: %s", prefix, exc)
            break

    return {
        "pwned": False,
        "count": 0,
        "source": SOURCE_LABEL,
        "error": last_error or "lookup failed",
    }


def _match_suffix(body: str, suffix: str) -> int:
    """Parse a Pwned Passwords range response body and return the breach count.

    The body is plaintext with one ``SUFFIX:COUNT`` record per line
    (LF-separated, suffixes uppercase hex). With ``Add-Padding: true`` the
    server injects decoy records whose count is ``0``; those are discarded.

    Args:
        body: The raw response text.
        suffix: The 35-char SHA-1 suffix to match (any case).

    Returns:
        The breach occurrence count, or ``0`` if the suffix is not present.
    """
    target = suffix.strip().upper()
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        line_suffix, sep, count_str = line.partition(":")
        if not sep:
            # Malformed line without a colon — skip defensively.
            continue
        try:
            count = int(count_str.strip())
        except ValueError:
            continue
        # Padding decoys always have count 0 and must be ignored.
        if count <= 0:
            continue
        if line_suffix.strip().upper() == target:
            return count
    return 0


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a numeric (delta-seconds) Retry-After header value, if present."""
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    if seconds < 0:
        return None
    # Cap the wait so a hostile/huge header can't stall the caller indefinitely.
    return min(seconds, 60.0)


def _backoff_seconds(attempt: int) -> float:
    """Exponential backoff: 0.5s, 1s, 2s, ... capped at 8s."""
    return min(0.5 * (2**attempt), 8.0)
