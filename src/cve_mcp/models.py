from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CVSSData(BaseModel):
    model_config = ConfigDict(extra="ignore")
    version: str
    vectorString: str
    baseScore: float = Field(ge=0.0, le=10.0)
    baseSeverity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    attackVector: str = ""
    attackComplexity: str = ""
    privilegesRequired: str = ""
    userInteraction: str = ""


class CVERecord(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    published: str
    lastModified: str
    vulnStatus: str = ""
    descriptions: list[dict] = []
    metrics: dict = {}
    weaknesses: list[dict] = []
    references: list[dict] = []


class EPSSScore(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve: str
    epss: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=1.0)
    date: str


class KEVEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cveID: str
    vendorProject: str = ""
    product: str = ""
    vulnerabilityName: str = ""
    dateAdded: str = ""
    dueDate: str = ""
    knownRansomwareCampaignUse: str = ""


class IPReputationResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ip: str
    abuse_score: int = Field(ge=0, le=100, default=0)
    country_code: str = ""
    isp: str = ""
    is_tor: bool = False
    total_reports: int = 0
    # GreyNoise fields
    noise: bool = False
    riot: bool = False
    classification: str = ""
    noise_name: str = ""


class FileHashResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hash: str
    found: bool = False
    file_name: str = ""
    file_type: str = ""
    malware_family: str = ""
    tags: list[str] = []
    # VirusTotal fields
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_undetected: int = 0
    vt_total: int = 0


class URLScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    url: str
    domain: str = ""
    malicious: bool = False
    score: int = 0
    categories: list[str] = []
    screenshot: str = ""


class DomainIntelResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    domain: str
    certificates: list[dict] = []
    subdomains: list[str] = []
    pdns_records: list[dict] = []


class VendorAdvisoryResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    microsoft: list[dict] = []
    redhat: list[dict] = []
    ubuntu: list[dict] = []


class ExploitResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    github_pocs: list[dict] = []
    has_public_exploit: bool = False
    poc_count: int = 0


class AttackMappingResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    techniques: list[dict] = []
    threat_groups: list[str] = []


class MalwareFamilyResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    ioc: str
    malware_family: str = ""
    confidence: int = 0
    ioc_type: str = ""
    tags: list[str] = []


class RansomwareResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    address: str
    family: str = ""
    found: bool = False
    transactions: int = 0


class CVETimelineResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    nvd_published: str = ""
    epss_date: str = ""
    kev_date_added: str = ""
    patch_lag_days: int = -1
    exploit_window_days: int = -1


class DependencyScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    package: str
    ecosystem: str
    version: str = ""
    vuln_count: int = 0
    vulns: list[dict] = []
