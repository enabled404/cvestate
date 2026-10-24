"""SBOM and lockfile parsers that feed the Watchtower estate store.

Supported inputs:
  * CycloneDX JSON (.cdx.json / SBOM exports)
  * SPDX JSON (.spdx.json)
  * requirements.txt (pip)
  * package-lock.json (npm, lockfile v1 and v2/v3)
  * go.mod (Go modules)

Every parser returns ``list[Package]`` with OSV ecosystem names so the
snapshot engine can query OSV without translation. Detection order:
filename hint first, then content sniffing. Unparseable input raises
``ValueError`` with a human-readable message.
"""

from __future__ import annotations

import json
import re
from urllib.parse import unquote

from cve_mcp.watchtower.models import Package

# Package URL (purl) type -> OSV ecosystem name.
PURL_ECOSYSTEMS: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "golang": "Go",
    "maven": "Maven",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "swift": "SwiftURL",
    "cocoapods": "CocoaPods",
    "githubactions": "GitHub Actions",
    "deb": "Debian",
    "rpm": "Red Hat",
    "apk": "Alpine",
    "conda": "Conda",
    "cpan": "CPAN",
    "cran": "CRAN",
    "hackage": "Hackage",
}

# Ecosystems the snapshot engine can query through OSV. Packages outside
# this set are stored (the estate remembers them) but skipped at scan time.
QUERYABLE_ECOSYSTEMS = set(PURL_ECOSYSTEMS.values()) | {"PyPI", "npm", "Go"}

UNKNOWN_ECOSYSTEM = "unknown"


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """Parse a package URL into (ecosystem, name, version).

    Returns None when the purl is malformed. Maven purls carry a namespace
    (groupId) which OSV expects joined to the artifact name with a colon.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    # Strip qualifiers (?...) and subpath (#...)
    body = body.split("?", 1)[0].split("#", 1)[0]
    ptype, _, rest = body.partition("/")
    if not ptype or not rest:
        return None
    if "@" in rest:
        name_part, _, version = rest.rpartition("@")
    else:
        name_part, version = rest, ""
    segments = [unquote(s) for s in name_part.split("/") if s]
    if not segments:
        return None
    name = segments[-1]
    if ptype.lower() == "maven" and len(segments) >= 2:
        name = f"{segments[-2]}:{segments[-1]}"
    elif len(segments) >= 2 and ptype.lower() in {"npm", "golang"}:
        # npm scopes (@angular/core) and Go module paths keep their path.
        name = "/".join(segments)
    ecosystem = PURL_ECOSYSTEMS.get(ptype.lower(), ptype)
    return ecosystem, name, unquote(version)


def _dedupe(packages: list[Package]) -> list[Package]:
    seen: dict[tuple[str, str, str], Package] = {}
    for pkg in packages:
        seen.setdefault(pkg.key, pkg)
    return list(seen.values())


# ── CycloneDX ───────────────────────────────────────────────────────────────


def parse_cyclonedx(data: dict, source: str = "") -> list[Package]:
    packages: list[Package] = []
    # NOTE: metadata.component is the SBOM's subject (the product the SBOM
    # describes), not one of its dependencies, so it is not ingested.
    components = data.get("components") or []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        if comp.get("type") not in (None, "library", "application", "framework"):
            continue
        purl = comp.get("purl") or ""
        parsed = parse_purl(purl) if purl else None
        if parsed:
            ecosystem, name, version = parsed
            version = version or (comp.get("version") or "")
        else:
            ecosystem = UNKNOWN_ECOSYSTEM
            name = comp.get("name") or ""
            version = comp.get("version") or ""
        if name:
            packages.append(Package(ecosystem, name, version, source=source))
    return _dedupe(packages)


# ── SPDX ────────────────────────────────────────────────────────────────────


def parse_spdx(data: dict, source: str = "") -> list[Package]:
    packages: list[Package] = []
    for pkg in data.get("packages") or []:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get("name") or ""
        if not name or name == "NOASSERTION":
            continue
        version = pkg.get("versionInfo") or ""
        ecosystem = UNKNOWN_ECOSYSTEM
        for ref in pkg.get("externalRefs") or []:
            if not isinstance(ref, dict):
                continue
            if ref.get("referenceType") == "purl":
                parsed = parse_purl(ref.get("referenceLocator") or "")
                if parsed:
                    ecosystem, name, purl_version = parsed
                    version = version or purl_version
                break
        packages.append(Package(ecosystem, name, version, source=source))
    return _dedupe(packages)


# ── requirements.txt ────────────────────────────────────────────────────────

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?"
    r"\s*(?:===?|>=|<=|~=|!=|>)\s*(?P<version>[^;\s]+)?"
)


def parse_requirements(text: str, source: str = "") -> list[Package]:
    packages: list[Package] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-", "git+", "http://", "https://")):
            continue
        line = line.split(" #", 1)[0].strip()  # inline comment
        line = line.split(";", 1)[0].strip()  # environment marker
        match = _REQ_LINE.match(line)
        if match:
            packages.append(
                Package("PyPI", match.group("name"), (match.group("version") or ""), source=source)
            )
        elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", line):
            packages.append(Package("PyPI", line, "", source=source))
    return _dedupe(packages)


# ── package-lock.json ───────────────────────────────────────────────────────


def parse_package_lock(data: dict, source: str = "") -> list[Package]:
    packages: list[Package] = []
    lock_packages = data.get("packages")
    if isinstance(lock_packages, dict) and lock_packages:
        # lockfileVersion 2/3: keys are install paths ("node_modules/<name>",
        # "" is the root project itself and is skipped).
        for path, info in lock_packages.items():
            if not path or "node_modules/" not in path or not isinstance(info, dict):
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            version = info.get("version") or ""
            if name:
                packages.append(Package("npm", name, version, source=source))
        if packages:
            return _dedupe(packages)
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        # lockfileVersion 1: flat name -> {version} map.
        for name, info in dependencies.items():
            version = info.get("version") or "" if isinstance(info, dict) else ""
            packages.append(Package("npm", name, version, source=source))
    return _dedupe(packages)


# ── go.mod ──────────────────────────────────────────────────────────────────

_GO_REQUIRE = re.compile(r"^(?P<name>[^\s]+)\s+(?P<version>v[^\s]+)")


def parse_go_mod(text: str, source: str = "") -> list[Package]:
    packages: list[Package] = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        candidate = ""
        if in_block:
            candidate = line
        elif line.startswith("require "):
            candidate = line[len("require ") :].strip()
        if candidate:
            match = _GO_REQUIRE.match(candidate)
            if match:
                packages.append(
                    Package("Go", match.group("name"), match.group("version"), source=source)
                )
    return _dedupe(packages)


# ── Entry point ─────────────────────────────────────────────────────────────


def detect_format(text: str, filename: str = "") -> str:
    """Return one of: cyclonedx, spdx, package-lock, go-mod, requirements."""
    name = filename.rsplit("/", 1)[-1].lower()
    if name == "package-lock.json":
        return "package-lock"
    if name == "go.mod":
        return "go-mod"
    if name.endswith(".cdx.json") or "cyclonedx" in name:
        return "cyclonedx"
    if name.endswith(".spdx.json") or "spdx" in name:
        return "spdx"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"

    stripped = text.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict):
            if data.get("bomFormat") == "CycloneDX":
                return "cyclonedx"
            if "spdxVersion" in data:
                return "spdx"
            if "lockfileVersion" in data or ("packages" in data and "dependencies" in data):
                return "package-lock"
    if stripped.startswith("module ") or "\nmodule " in text:
        return "go-mod"
    return "requirements"


def parse_estate_text(text: str, filename: str = "") -> list[Package]:
    """Parse SBOM or lockfile content into estate packages.

    Raises ValueError with a readable message when the input matches no
    supported format or yields zero packages.
    """
    if not text or not text.strip():
        raise ValueError("Input is empty — paste an SBOM or lockfile's contents.")
    if len(text) > 10 * 1024 * 1024:
        raise ValueError("Input too large (max 10 MB).")

    fmt = detect_format(text, filename)
    source = filename or fmt
    if fmt in ("cyclonedx", "spdx", "package-lock"):
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"Invalid JSON for {fmt} input: {exc}") from exc
        if fmt == "cyclonedx":
            packages = parse_cyclonedx(data, source)
        elif fmt == "spdx":
            packages = parse_spdx(data, source)
        else:
            packages = parse_package_lock(data, source)
    elif fmt == "go-mod":
        packages = parse_go_mod(text, source)
    else:
        packages = parse_requirements(text, source)

    if not packages:
        raise ValueError(
            f"No packages found in the input (detected format: {fmt}). "
            "Supported: CycloneDX JSON, SPDX JSON, requirements.txt, "
            "package-lock.json, go.mod."
        )
    return packages
