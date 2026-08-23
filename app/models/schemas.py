from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class RubricItem(BaseModel):
    score: int
    max: int = 100
    label: str
    risk: str  # low, medium, high, critical

class RubricBreakdown(BaseModel):
    data_sharing: RubricItem
    retention: RubricItem
    tracking_cookies: RubricItem
    user_rights: RubricItem
    breach_history: RubricItem
    readability: RubricItem

class DPDPCompliance(BaseModel):
    compliant: bool
    grievance_officer: Optional[str] = None
    grievance_email: Optional[str] = None
    redressal_period_days: Optional[int] = 30
    erasure_right_disclosed: bool = False
    notes: Optional[str] = None

class GDPRCompliance(BaseModel):
    compliant: bool
    dpo_contact: Optional[str] = None
    lawful_basis_stated: bool = False
    erasure_art17_disclosed: bool = False
    notes: Optional[str] = None

class CCPACompliance(BaseModel):
    compliant: bool
    opt_out_link: Optional[str] = None
    do_not_sell: bool = False

class RegionalCompliance(BaseModel):
    dpdp: DPDPCompliance
    gdpr: GDPRCompliance
    ccpa: CCPACompliance

class KeyClause(BaseModel):
    type: str  # positive, negative, neutral
    text: str

class PolicyRatingResponse(BaseModel):
    domain: str
    name: str
    grade: str
    score: int
    color: str
    summary: str
    rubric: RubricBreakdown
    compliance: RegionalCompliance
    key_clauses: List[KeyClause]
    category: str
    source: str = "cache"

class AnalyzeUrlRequest(BaseModel):
    url: str

class DeletionNoticeRequest(BaseModel):
    site_domain: str
    site_name: str
    legal_basis: str  # dpdp, gdpr, ccpa
    user_name: str
    user_email: str
    user_phone: Optional[str] = None
    account_identifier: Optional[str] = None
    grievance_email: str
    specific_demands: Optional[List[str]] = None

class DeletionRequestModel(BaseModel):
    id: str
    site_domain: str
    site_name: str
    legal_basis: str
    user_name: str
    user_email: str
    user_phone: Optional[str] = None
    account_identifier: Optional[str] = None
    grievance_email: str
    status: str
    created_at: str
    updated_at: str
    notes: Optional[str] = None

class StatusUpdateRequest(BaseModel):
    status: str  # Sent, Acknowledged, In Progress, Resolved, Escalated
    notes: Optional[str] = None

class PasswordCheckRequest(BaseModel):
    password: Optional[str] = None
    sha1_prefix: Optional[str] = None
    sha1_suffix: Optional[str] = None

class EmailCheckRequest(BaseModel):
    email: str

class ActionToggleRequest(BaseModel):
    action_id: str


# ===== Admin Dashboard & Website Management Schemas =====

class WebsiteListItem(BaseModel):
    domain: str
    name: Optional[str] = None
    overall_score: Optional[float] = None
    grade: Optional[str] = None
    grade_color: Optional[str] = None
    category: Optional[str] = None
    source: Optional[str] = None
    is_top_5000: bool = False
    tranco_rank: Optional[int] = None
    scan_count: int = 1
    last_analyzed_at: Optional[str] = None

class WebsiteListResponse(BaseModel):
    items: List[WebsiteListItem]
    total: int
    page: int
    page_size: int

class WebsiteDetail(BaseModel):
    id: Optional[int] = None
    domain: str
    name: Optional[str] = None
    category: Optional[str] = None
    overall_score: Optional[float] = None
    grade: Optional[str] = None
    grade_color: Optional[str] = None
    pillar_scores: Optional[Dict[str, Any]] = None
    compliance: Optional[Dict[str, Any]] = None
    findings: Optional[Dict[str, Any]] = None
    key_concerns: Optional[List[str]] = None
    key_clauses: Optional[List[Dict[str, str]]] = None
    policy_url: Optional[str] = None
    cookie_data: Optional[List[Dict[str, Any]]] = None
    tracker_data: Optional[List[Dict[str, Any]]] = None
    dark_pattern_data: Optional[List[Dict[str, Any]]] = None
    breach_history: Optional[List[Dict[str, Any]]] = None
    is_top_5000: bool = False
    tranco_rank: Optional[int] = None
    source: Optional[str] = None
    scan_count: int = 1
    first_analyzed_at: Optional[str] = None
    last_analyzed_at: Optional[str] = None

class AdminAddWebsiteRequest(BaseModel):
    domain: str
    name: Optional[str] = None
    category: Optional[str] = None

class AdminBulkRescanRequest(BaseModel):
    domains: List[str]

class AdminDashboardStats(BaseModel):
    total_websites: int = 0
    avg_score: float = 0.0
    grade_distribution: Dict[str, int] = {}
    top_10: List[Dict[str, Any]] = []
    bottom_10: List[Dict[str, Any]] = []
    recent_scans: List[Dict[str, Any]] = []
    source_distribution: Dict[str, int] = {}
    total_top_5000: int = 0


# ===== Cookie Management Schemas =====

class CookiePreferenceItem(BaseModel):
    cookie_name: str
    action: str  # 'block' | 'allow' | 'ignore'
    cookie_category: Optional[str] = None

class CookiePreferencesRequest(BaseModel):
    preferences: List[CookiePreferenceItem]

class CookieRulesResponse(BaseModel):
    domain: str
    block: List[str] = []
    allow: List[str] = []
    ignore: List[str] = []
    total_cookies: int = 0

class GlobalCookieRuleRequest(BaseModel):
    cookie_pattern: str
    cookie_category: Optional[str] = None
    default_action: str = "block"
    description: Optional[str] = None

class GlobalCookieRuleResponse(BaseModel):
    id: int
    cookie_pattern: str
    cookie_category: Optional[str] = None
    default_action: str
    description: Optional[str] = None
    created_at: Optional[str] = None


# ===== Extension Scan Schemas =====

class ExtensionCookieData(BaseModel):
    name: str
    value: Optional[str] = None
    isTracking: bool = False
    category: Optional[str] = None

class ExtensionTrackerData(BaseModel):
    name: str
    domain: Optional[str] = None
    category: Optional[str] = None

class ExtensionDarkPattern(BaseModel):
    type: str
    description: Optional[str] = None

class ExtensionScanPayload(BaseModel):
    domain: str
    cookies: List[ExtensionCookieData] = []
    trackers: List[ExtensionTrackerData] = []
    dark_patterns: List[ExtensionDarkPattern] = []
    policy_url: Optional[str] = None


# ===== Top 5000 Pipeline Schemas =====

class Top5000StatusResponse(BaseModel):
    status: str = "idle"
    total: int = 0
    scanned: int = 0
    errors: int = 0
    skipped: int = 0
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    current_domain: Optional[str] = None
