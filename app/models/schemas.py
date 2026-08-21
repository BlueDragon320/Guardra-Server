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
