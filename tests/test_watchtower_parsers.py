"""Watchtower parser tests — SBOM and lockfile ingestion (all offline)."""

from __future__ import annotations

import json

import pytest

from cve_mcp.watchtower.parsers import (
    parse_estate_text,
    parse_purl,
    parse_requirements,
)

CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "log4j-core",
            "version": "2.14.1",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        },
        {
            "type": "library",
            "name": "requests",
            "version": "2.19.1",
            "purl": "pkg:pypi/requests@2.19.1",
        },
        {"type": "library", "name": "mystery-lib", "version": "0.1"},
        {"type": "operating-system", "name": "linux", "version": "6.0"},
    ],
}

SPDX = {
    "spdxVersion": "SPDX-2.3",
    "name": "demo",
    "packages": [
        {
            "name": "lodash",
            "versionInfo": "4.17.20",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/lodash@4.17.20",
                }
            ],
        },
        {"name": "internal-tool", "versionInfo": "1.2.3"},
        {"name": "NOASSERTION"},
    ],
}

PACKAGE_LOCK_V3 = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/@angular/core": {"version": "17.0.0"},
        "node_modules/a/node_modules/b": {"version": "2.0.0"},
    },
}

PACKAGE_LOCK_V1 = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 1,
    "dependencies": {
        "express": {"version": "4.17.1"},
        "lodash": {"version": "4.17.20"},
    },
}

GO_MOD = """module example.com/demo

go 1.22

require github.com/gorilla/mux v1.8.1

require (
\tgithub.com/sirupsen/logrus v1.9.3 // indirect
\tgolang.org/x/crypto v0.17.0
)
"""


def test_cyclonedx_parses_components_and_purls():
    packages = parse_estate_text(json.dumps(CYCLONEDX), "estate.cdx.json")
    keys = {p.key for p in packages}
    assert ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1") in keys
    assert ("PyPI", "requests", "2.19.1") in keys
    # No purl -> stored with unknown ecosystem; non-library types skipped.
    assert ("unknown", "mystery-lib", "0.1") in keys
    assert all(p.name != "linux" for p in packages)


def test_spdx_parses_purl_refs_and_fallback():
    packages = parse_estate_text(json.dumps(SPDX), "estate.spdx.json")
    keys = {p.key for p in packages}
    assert ("npm", "lodash", "4.17.20") in keys
    assert ("unknown", "internal-tool", "1.2.3") in keys
    assert all(p.name != "NOASSERTION" for p in packages)


def test_package_lock_v3_paths():
    packages = parse_estate_text(json.dumps(PACKAGE_LOCK_V3), "package-lock.json")
    keys = {p.key for p in packages}
    assert ("npm", "lodash", "4.17.20") in keys
    assert ("npm", "@angular/core", "17.0.0") in keys
    assert ("npm", "b", "2.0.0") in keys  # nested node_modules path
    assert all(p.name != "demo" for p in packages)  # root project skipped


def test_package_lock_v1_dependencies():
    packages = parse_estate_text(json.dumps(PACKAGE_LOCK_V1), "package-lock.json")
    keys = {p.key for p in packages}
    assert ("npm", "express", "4.17.1") in keys
    assert ("npm", "lodash", "4.17.20") in keys


def test_go_mod_single_and_block_requires():
    packages = parse_estate_text(GO_MOD, "go.mod")
    keys = {p.key for p in packages}
    assert ("Go", "github.com/gorilla/mux", "v1.8.1") in keys
    assert ("Go", "github.com/sirupsen/logrus", "v1.9.3") in keys
    assert ("Go", "golang.org/x/crypto", "v0.17.0") in keys


def test_requirements_pinned_range_and_extras():
    text = (
        "requests==2.19.1\n"
        "django>=3.2  # web framework\n"
        "uvicorn[standard]==0.29.0\n"
        "# a comment\n"
        "-r other-requirements.txt\n"
        "flask; python_version < '3.12'\n"
    )
    packages = parse_requirements(text)
    keys = {p.key for p in packages}
    assert ("PyPI", "requests", "2.19.1") in keys
    assert ("PyPI", "django", "3.2") in keys
    assert ("PyPI", "uvicorn", "0.29.0") in keys
    assert ("PyPI", "flask", "") in keys


def test_purl_maven_namespace_joined_with_colon():
    assert parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1") == (
        "Maven",
        "org.apache.logging.log4j:log4j-core",
        "2.14.1",
    )


def test_purl_npm_scope_kept():
    assert parse_purl("pkg:npm/%40angular/core@17.0.0") == ("npm", "@angular/core", "17.0.0")


def test_purl_golang_path_kept():
    assert parse_purl("pkg:golang/github.com/gorilla/mux@v1.8.1") == (
        "Go",
        "github.com/gorilla/mux",
        "v1.8.1",
    )


def test_purl_malformed_returns_none():
    assert parse_purl("") is None
    assert parse_purl("not-a-purl") is None
    assert parse_purl("pkg:") is None


def test_format_detection_by_content_without_filename():
    assert parse_estate_text(json.dumps(CYCLONEDX))[0].ecosystem in {"Maven", "PyPI", "unknown"}
    assert parse_estate_text(json.dumps(SPDX))[0].name == "lodash"
    assert parse_estate_text(GO_MOD)[0].ecosystem == "Go"
    assert parse_estate_text("requests==2.19.1")[0].name == "requests"


def test_empty_input_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_estate_text("   ")


def test_unrecognized_input_raises():
    with pytest.raises(ValueError, match="No packages found"):
        parse_estate_text("!!! not a real file !!!")


def test_duplicate_components_deduped():
    data = {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.19.1",
                "purl": "pkg:pypi/requests@2.19.1",
            },
            {
                "type": "library",
                "name": "requests",
                "version": "2.19.1",
                "purl": "pkg:pypi/requests@2.19.1",
            },
        ],
    }
    assert len(parse_estate_text(json.dumps(data))) == 1
