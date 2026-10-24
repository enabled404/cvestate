# Changelog

All notable changes to CVEstate are documented here. Entries for
0.2.0 and 0.1.0 record the upstream CVE MCP Server releases that
CVEstate builds on.
This project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-10-24

First CVEstate release. CVEstate extends the CVE MCP Server (see the
0.2.0 and 0.1.0 entries below) with Watchtower, a persistent estate
watch. The base server answered one lookup at a time and forgot every
answer; Watchtower gives the project a memory of your software estate
and reports what changed against it.

### Added
- **Watchtower estate store** — a persistent SQLite inventory (WAL mode, mirroring the base cache's pragmas) at `~/.cve-mcp/estate.db` (override with `WATCHTOWER_DB_PATH`). Re-adding a package updates `last_seen` and preserves `first_seen`, so the estate remembers when each package entered your stack.
- **SBOM and lockfile ingestion** — parsers for CycloneDX JSON, SPDX JSON, `requirements.txt`, `package-lock.json` (v1–v3), and `go.mod`, with PURL-to-OSV-ecosystem mapping and deduplication.
- **Snapshot engine** — each scan snapshots the estate's exposure using the base project's own intel clients (OSV for package vulnerabilities, the CISA KEV catalog, batched EPSS): findings per installed package with KEV status, KEV dates, and EPSS scores.
- **Diff engine** — compares consecutive snapshots and classifies the movement: NEW_KEV (a carried CVE became known-exploited), EPSS_SPIKE (delta at or above a configurable threshold, default 10 points), NEW_EXPOSURE, RESOLVED, and package additions/removals.
- **Delta brief** — a prioritized patch brief in the `triage_cve` report style: KEV additions first, EPSS spikes second, new exposure third, resolved items noted.
- **Four new MCP tools** — `estate_add`, `estate_scan`, `watch_diff`, `watch_brief` (32 tools total), registered in the base server's style with audit records and timeouts.
- **`cve-watch` CLI** — `add`, `list`, `scan`, `diff`, `brief` subcommands mirroring the MCP tools, with a `--fixture` offline mode (fixture intel provider included) used by the demo in `examples/watchtower/`.
- **Offline demo** — `examples/watchtower/` ships a four-source demo estate plus day-1/day-2 fixture intel that reproduces the launch scenario: CVE-2021-44228 entering KEV against an installed log4j-core 2.14.1, EPSS 31% → 97%.
- 48 new tests (78 total, all passing): parsers, store, engine, brief, and tool registration.

### Fixed
- **Fresh installs start again.** The base project's `mcp[cli]>=1.7.0` requirement had no upper bound, and mcp 2.x removed `mcp.server.fastmcp`, so a fresh `pip install` crashed on import before the server could start. CVEstate pins `mcp[cli]>=1.7.0,<2.0.0` — the same fix the upstream dependabot branch proposed — which also turns the project's existing CI green again.
- The stale upstream `uv.lock` (which still resolved the crashing mcp 2.x line) was removed; pip is the supported install path.

### Changed
- Project renamed to **CVEstate** for this release line. The runtime names existing users script against are unchanged: the Python package stays `cve_mcp`, the MCP server name stays `cve-mcp`, and the console scripts stay `cve-mcp` and `cve-watch`.
- Package metadata corrected: the license classifier now reads Apache-2.0, matching the LICENSE file (the base metadata said MIT).
- Full suite: 78 tests passing (30 base tests intact, 48 new Watchtower tests).

## [Unreleased]

### Added
- (Next release items go here)

## [0.2.0] — 2026-06-22

### Added
- **`triage_cve` orchestrator tool** — one-call CVE triage that fans out NVD + EPSS + CISA KEV (+ public PoC discovery for `depth != "quick"`) concurrently via `utils.fanout.fan_out`, computes the composite risk score, and returns a formatted report. `depth` is `quick` / `standard` (default) / `deep`; `deep` additionally emits an SSVC v2 gated decision (`utils.ssvc.ssvc_decision`).
- **Transparent NVD fallback** — when NIST NVD is unreachable/throttled, `triage_cve` automatically falls back to the VulnCheck NVD++ index (`api.vulncheck_client.fetch_cve_vulncheck`).
- **New upstream sources** — VulnCheck NVD++, CIRCL hashlookup (`hashlookup.circl.lu`), and the HIBP Pwned Passwords range API (`api.pwnedpasswords.com`); the latter two require no API key.
- **MCP resources** — `kev://catalog` (pre-warmed KEV catalog summary), `epss://scores/{cve_id}` (per-CVE EPSS score), and `manifest://tool-hash` (SHA-256 over the canonical JSON of every registered tool's `{name, description, inputSchema}`, sorted).
- **MCP prompts** — `patch_decision(cve_id, asset_context="internet-facing")`, `compare_and_prioritize`, and `dependency_triage`, all guiding the model to call `triage_cve`.
- **Streamable-HTTP transport** — `MCP_TRANSPORT=http` serves streamable-HTTP on `HOST:PORT` (default `0.0.0.0:8000`, stateless); anything else keeps stdio. Bundled `Dockerfile` + `.dockerignore`.
- `health_check` now also reports the scoring version, the tool-manifest hash, cache read-back status, KEV catalog size, and which optional API keys are configured (names/yes-no only — never the key values).

### Changed
- **KEV hard-override scoring** — a CISA KEV-listed CVE is now always labelled `CRITICAL` with a risk score clamped to `≥ 76`, regardless of CVSS/EPSS (KEV = confirmed in-the-wild exploitation). The linear weighted sum remains the v1 default for the numeric score otherwise.
- Risk scorer now reports `scoring_version` (`"1.0"`) and documents CVSS as a *severity* (not exploitation-likelihood) signal in its component breakdown (per Allodi & Massacci 2014).
- SQLite cache opens with WAL journal mode + tuned pragmas (`synchronous=NORMAL`, `busy_timeout`, `temp_store=MEMORY`, `cache_size`) for better concurrency on local disk.

### Security
- The server **never registers a sampling handler / never issues `sampling/createMessage`** (Unit 42 MCP-sampling prompt-injection / exfiltration attack vector).
- Added outbound URL hardening helpers (`validators.validate_scheme`, `validate_outbound_url`, DNS-resolution SSRF check) and extended the host allowlist to the new sources.
- Secrets are wrapped in `pydantic.SecretStr` (`config.SECRETS` / `get_secret` / `redact`) for masked storage; `health_check` reports key presence without revealing values.

## [0.1.0] — 2026-04-14

### Added
- Initial public release with 27 MCP security intelligence tools across 21 APIs
- **Core Vulnerability Intelligence (8 tools):** `lookup_cve`, `search_cves`, `get_epss_score`, `check_kev`, `parse_cvss`, `get_cve_summary`, `check_package_vulns`, `health_check`
- **Exploit & ATT&CK Intelligence (4 tools):** `check_exploit_availability`, `get_vendor_advisory`, `get_attack_mapping`, `get_cve_timeline`
- **Advanced Risk & Reporting (4 tools):** `check_poc_exists`, `calculate_risk_score`, `generate_vuln_report`, `compare_cves`
- **Network Intelligence (4 tools):** `check_ip_reputation`, `get_domain_intel`, `passive_dns_lookup`, `shodan_host_lookup`
- **Threat Intelligence (4 tools):** `lookup_file_hash`, `check_url_safety`, `lookup_malware_family`, `check_ransomware_intel`
- **DevSecOps (3 tools):** `scan_dependencies`, `scan_container_packages`, `scan_repo_secrets`
- Composite risk scoring engine: CVSS×0.20 + EPSS×0.35 + KEV×0.30 + PoC×0.15 with boost multipliers
- PoC confidence ladder: WEAPONIZED → PUBLIC_EXPLOIT_REMOTE → PUBLIC_EXPLOIT → PUBLIC_POC_HIGH_QUALITY → PUBLIC_POC_LOW_QUALITY → NONE
- aiosqlite response cache with per-source TTLs (1h CVEs, 6h EPSS, 24h ATT&CK)
- Token bucket rate limiter for NVD API (5 req/30s without key, 50 req/30s with key)
- Private IP blocking for all network tools (RFC 1918, loopback, link-local)
- `defusedxml` protection for all XML parsing
- Structured audit logging — no keys, no payloads, timing and status only
- GreyNoise v3 API support (`/v3/ip/{ip}` — the `/v3/community` endpoint was deprecated January 2026)
- CIRCL Passive DNS with HTTP Basic Auth
