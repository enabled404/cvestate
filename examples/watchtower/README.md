# Watchtower offline demo

The files in this directory reproduce the CVEstate launch demo end to
end, fully offline. The demo estate is assembled from four real-format
sources, and the exposure snapshots run against two fixture intel
files, so no API keys and no network are involved.

| File | Role |
|---|---|
| `estate.cdx.json` | CycloneDX SBOM (log4j-core 2.14.1, lodash 4.17.20) |
| `requirements.txt` | Python lockfile (requests 2.19.1, django 3.2.0) |
| `package-lock.json` | npm lockfile |
| `go.mod` | Go module file |
| `intel_v1.json` | Day 1 intel: CVE-2021-44228 present, EPSS 31%, absent from KEV |
| `intel_v2.json` | Day 2 intel: CVE-2021-44228 enters CISA KEV, EPSS spikes to 97%, one new CVE disclosed against lodash |

Run it from the repository root after `pip install -e .`:

```bash
export WATCHTOWER_DB_PATH=/tmp/demo-estate.db

cve-watch add examples/watchtower/estate.cdx.json
cve-watch add examples/watchtower/requirements.txt
cve-watch add examples/watchtower/package-lock.json
cve-watch add examples/watchtower/go.mod

cve-watch scan --label baseline --fixture examples/watchtower/intel_v1.json
cve-watch scan --label day2     --fixture examples/watchtower/intel_v2.json

cve-watch diff
cve-watch brief
```

The brief leads with the change that matters: CVE-2021-44228 became
KEV-listed against log4j-core 2.14.1 in your estate, with a remediation
due date, ranked above everything else that moved.
