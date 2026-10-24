# CVEstate 1.0.0 — Launch drafts (DO NOT POST, for Saad's approval)

## LinkedIn post

Releasing CVEstate 1.0.0 today. It's an MCP security intelligence server with a memory, and the memory is the part I built. It's called Watchtower.

Here is the gap that bothered me. Every vulnerability tool I use answers lookups. You ask about a CVE and you get the full record back, CVSS, EPSS, KEV status, timeline, all of it. Then the tool forgets everything. Your estate never enters the picture, so the question that actually drives patching goes unanswered: what changed against the packages I run, since the last time I looked. I've spent enough mornings rechecking the same CVEs by hand to know that gap is where things slip.

Watchtower gives the server a memory. You feed it your SBOMs and lockfiles once, CycloneDX, SPDX, requirements.txt, package-lock.json, go.mod, and it keeps a persistent inventory of your estate. Every scan snapshots your exposure using live OSV, CISA KEV, and EPSS data, and diffs the new snapshot against the previous one. The brief it prints leads with new KEV listings against your installed versions, then EPSS spikes, then fresh disclosures, in that order, because that is the order a patch queue should run in. It ships as four MCP tools, estate_add, estate_scan, watch_diff, and watch_brief, plus a cve-watch CLI that runs the same watch from cron.

The demo is small and it still made the point better than I could. Eight packages from four files, log4j-core 2.14.1 among them. On day one, CVE-2021-44228 sits in the exposure list at 31 percent EPSS with no KEV listing. On day two it enters KEV with a due date and its EPSS is at 97 percent. A lookup tool shows you the same record on both days. CVEstate flagged the change, ranked it PATCH NOW, and put the CISA due date next to it, 2026-11-07. The demo runs fully offline and ships in the repo, so you can watch it happen yourself.

Underneath Watchtower sits the CVE MCP Server by Mahipal Jangra, 28 intelligence tools and a one-call triage orchestrator that I kept intact and built on. One repair ships with this release and it matters. A fresh install of the base project crashed on startup because its MCP dependency had no upper bound and MCP 2.x removed the module it imports. I pinned the dependency to the 1.x line, the fix the project's own dependabot branch had proposed, and fresh installs start again. The full suite runs at 78 tests, the original 30 untouched and 48 new ones covering the estate store, the parsers, the snapshot engine, and the diff.

Teams drown in CVE volume and patch in the order people shout. A watch that knows your estate and speaks up when something moves is how I want that queue ordered. The repo is enabled404/cvestate on GitHub, link in the first comment. Feed it your SBOM, run two scans, and tell me where the brief gets your stack wrong.

#VulnerabilityManagement #MCP #AppSec

## First comment (post immediately after publishing)

Here is the repo: https://github.com/enabled404/cvestate

Watchtower lives in src/cve_mcp/watchtower and the offline demo is in examples/watchtower. Run it against your own SBOM and open an issue where the brief misreads your stack.

## X thread

**1/**
Releasing CVEstate 1.0.0 today. It is an MCP security intel server with a memory called Watchtower. Your SBOM goes in once, and every scan after that reports what changed against your stack: new KEV listings, EPSS spikes, fresh CVEs on installed versions.

**2/**
The demo that sold me: 8 packages, log4j-core 2.14.1 inside. Day 1, CVE-2021-44228 sits at 31% EPSS, no KEV. Day 2, it enters KEV with a due date and EPSS hits 97%. The brief flagged it PATCH NOW. A lookup tool shows the same record on both days.

**3/**
It builds on the open source CVE MCP Server (28 intel tools, one-call triage). I added Watchtower, 4 MCP tools and a CLI, plus one repair: fresh installs crashed on an unpinned MCP dependency, now pinned to the 1.x line. 78 tests green, 30 original and 48 new.

**4/**
Repo: https://github.com/enabled404/cvestate. The offline demo ships in examples/watchtower. Feed it your SBOM, run two scans, and tell me where the brief gets your stack wrong.
