from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from cve_mcp.cache.sqlite_cache import VulnCache
from cve_mcp.config import MITRE_ATTACK_BASE

logger = logging.getLogger(__name__)

TTL_ATTACK = 86400  # 24 hours — ATT&CK data changes infrequently

# In-memory cache for the full ATT&CK dataset to avoid re-downloading the ~50MB file
_attack_data: dict[str, Any] | None = None
_attack_data_timestamp: float = 0.0
_attack_data_ttl: float = 86400.0  # Refresh once per day


async def _load_attack_data(client: httpx.AsyncClient) -> dict[str, Any] | None:
    """Lazily load the MITRE ATT&CK Enterprise dataset.

    Downloads the full enterprise-attack.json (~50MB) only when needed,
    caches it in-memory with a 24-hour TTL. Uses streaming to avoid loading
    the entire response into memory at once before parsing.
    """
    global _attack_data, _attack_data_timestamp

    now = time.time()
    if _attack_data is not None and (now - _attack_data_timestamp) < _attack_data_ttl:
        return _attack_data

    url = f"{MITRE_ATTACK_BASE}/enterprise-attack.json"
    logger.info("Downloading MITRE ATT&CK Enterprise dataset from %s", url)

    try:
        # Stream the response to manage memory for the ~50MB file
        chunks = []
        total_bytes = 0
        max_bytes = 60 * 1024 * 1024  # 60MB hard limit

        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            async for chunk in resp.aiter_bytes(chunk_size=65536):
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise ValueError(f"ATT&CK dataset exceeds {max_bytes // (1024 * 1024)}MB limit")
                chunks.append(chunk)

        import json

        raw = b"".join(chunks)
        data = json.loads(raw)
        del raw, chunks

        _attack_data = data
        _attack_data_timestamp = now
        object_count = len(data.get("objects", []))
        logger.info(
            "ATT&CK dataset loaded: %d objects, %.1f MB", object_count, total_bytes / (1024 * 1024)
        )
        return data

    except httpx.HTTPStatusError as exc:
        logger.error("ATT&CK download failed (HTTP %d)", exc.response.status_code)
        return None
    except Exception as exc:
        logger.error("ATT&CK download error: %s", exc)
        return None


def _extract_techniques(attack_data: dict[str, Any]) -> list[dict]:
    """Extract all attack-pattern (technique) objects from the dataset."""
    techniques = []
    for obj in attack_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        techniques.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": (obj.get("description", "") or "")[:500],
                "tactics": tactics,
                "url": url,
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
        )

    return techniques


def _extract_groups(attack_data: dict[str, Any]) -> list[dict]:
    """Extract all intrusion-set (threat group) objects from the dataset."""
    groups = []
    for obj in attack_data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        ext_refs = obj.get("external_references", [])
        group_id = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                group_id = ref.get("external_id", "")
                break

        groups.append(
            {
                "group_id": group_id,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": (obj.get("description", "") or "")[:500],
            }
        )

    return groups


def _find_techniques_for_cve(attack_data: dict[str, Any], cve_id: str) -> list[dict]:
    """Find ATT&CK techniques that reference a specific CVE ID.

    Searches technique descriptions and external references for the CVE ID.
    """
    cve_upper = cve_id.upper()
    matching = []

    for obj in attack_data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        # Check if CVE appears in description
        description = obj.get("description", "") or ""
        found_in_desc = cve_upper in description.upper()

        # Check external references
        found_in_refs = False
        for ref in obj.get("external_references", []):
            ref_desc = ref.get("description", "") or ""
            ref_url = ref.get("url", "") or ""
            if cve_upper in ref_desc.upper() or cve_upper in ref_url.upper():
                found_in_refs = True
                break

        if not found_in_desc and not found_in_refs:
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = ""
        url = ""
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                break

        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase.get("phase_name", ""))

        matching.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": description[:500],
                "tactics": tactics,
                "url": url,
                "platforms": obj.get("x_mitre_platforms", []),
            }
        )

    return matching


def _find_groups_using_techniques(
    attack_data: dict[str, Any], technique_ids: set[str]
) -> list[str]:
    """Find threat groups that use any of the given technique IDs.

    Resolves ATT&CK relationship objects (type=relationship, relationship_type=uses)
    between intrusion-sets and attack-patterns.
    """
    if not technique_ids:
        return []

    # Build ID mappings
    id_to_technique: dict[str, str] = {}
    id_to_group: dict[str, str] = {}

    for obj in attack_data.get("objects", []):
        obj_type = obj.get("type", "")
        stix_id = obj.get("id", "")

        if obj_type == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    if ext_id in technique_ids:
                        id_to_technique[stix_id] = ext_id
                    break

        elif obj_type == "intrusion-set":
            if not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
                id_to_group[stix_id] = obj.get("name", "")

    # Find relationships: group -> uses -> technique
    group_names: set[str] = set()
    for obj in attack_data.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        source = obj.get("source_ref", "")
        target = obj.get("target_ref", "")
        if source in id_to_group and target in id_to_technique:
            group_names.add(id_to_group[source])

    return sorted(group_names)


async def get_attack_mapping(
    cve_id: str,
    client: httpx.AsyncClient,
    cache: VulnCache,
) -> dict:
    """Map a CVE to MITRE ATT&CK techniques and associated threat groups.

    Downloads and caches the ATT&CK dataset lazily. Searches for techniques
    that reference the CVE, then finds threat groups known to use those techniques.

    Returns a dict with cve_id, techniques list, and threat_groups list.
    """
    cache_key = f"attack:{cve_id}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    result = {
        "cve_id": cve_id,
        "techniques": [],
        "threat_groups": [],
    }

    attack_data = await _load_attack_data(client)
    if attack_data is None:
        logger.warning("ATT&CK dataset unavailable, cannot map %s", cve_id)
        return result

    techniques = _find_techniques_for_cve(attack_data, cve_id)
    result["techniques"] = techniques

    if techniques:
        technique_ids = {t["technique_id"] for t in techniques if t["technique_id"]}
        result["threat_groups"] = _find_groups_using_techniques(attack_data, technique_ids)

    await cache.set(cache_key, result, TTL_ATTACK)
    return result
