from __future__ import annotations
from typing import TypedDict, Optional, List


class CVSSMetrics(TypedDict):
    version: str
    baseScore: float
    baseSeverity: str
    vectorString: str
    attackVector: str
    attackComplexity: str
    privilegesRequired: str
    userInteraction: str
    confidentialityImpact: str
    integrityImpact: str
    availabilityImpact: str


class AffectedProduct(TypedDict):
    vendor: str
    product: str
    versions: List[str]


class NVDEnrichment(TypedDict):
    cve_id: str
    description: str
    published_date: str
    last_modified: str
    cvss_v31: Optional[CVSSMetrics]
    cvss_v40: Optional[CVSSMetrics]
    cwe_ids: List[str]
    affected_products: List[AffectedProduct]
    references: List[str]


class EPSSData(TypedDict):
    cve_id: str
    epss_score: float
    epss_percentile: float
    model_version: str
    score_date: str


class KEVEntry(TypedDict):
    cve_id: str
    in_kev: bool
    vendor_project: Optional[str]
    product: Optional[str]
    vulnerability_name: Optional[str]
    date_added: Optional[str]
    required_action: Optional[str]
    due_date: Optional[str]
    ransomware_use: Optional[str]


class ExploitInfo(TypedDict):
    cve_id: str
    has_public_exploit: bool
    has_poc_only: bool
    exploit_count: int
    exploit_links: List[str]
    exploit_types: List[str]
    source_error: Optional[str]


class OSVData(TypedDict):
    cve_id: str
    osv_id: Optional[str]
    aliases: List[str]
    summary: Optional[str]
    affected_packages: List[dict]
    severity: List[dict]


class ATTACKMapping(TypedDict):
    cve_id: str
    techniques: List[str]
    technique_names: List[str]
    tactics: List[str]


class EnrichedCVE(TypedDict):
    cve_id: str
    nvd: Optional[NVDEnrichment]
    epss: Optional[EPSSData]
    kev: Optional[KEVEntry]
    exploit: Optional[ExploitInfo]
    osv: Optional[OSVData]
    attack: Optional[ATTACKMapping]
    enrichment_timestamp: str
    enrichment_errors: List[str]


class ScoredCVE(TypedDict):
    cve_id: str
    cvss_score_raw: float
    epss_score_raw: float
    kev_bonus: float
    exploit_bonus: float
    ransomware_bonus: float
    composite_score: Optional[float]
    priority_category: str
    patch_timeline: str
    enriched: EnrichedCVE
    score_reasoning: str
    data_flags: List[str]


class RecommendationOutput(TypedDict):
    cve_id: str
    priority_category: str
    patch_timeline: str
    composite_score: Optional[float]
    cvss_vector: Optional[str]
    affected_systems: List[str]
    remediation_summary: str
    immediate_actions: List[str]
    workarounds: List[str]
    references: List[str]
    attack_surface: str
    ciso_summary: str


class AuditEntry(TypedDict):
    timestamp: str
    cve_id: str
    agent: str
    action: str
    inputs: dict
    outputs: dict
    sources_used: List[str]
    reasoning: str
    success: bool
    errors: List[str]
