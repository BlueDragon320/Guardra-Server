import os
import secrets
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Header, BackgroundTasks, status, Query
from pydantic import BaseModel
from app.services.policy_analyzer import load_cached_policies, clean_domain
from app.services.crawler_service import (
    save_cached_policies,
    crawl_and_rescore_domain,
    run_bulk_rescore_job,
    run_top_1000_crawler_job,
    get_crawler_status,
    load_top_1000_domains
)
from app.database import get_recent_pings, get_ping_stats

router = APIRouter(prefix="/api/admin", tags=["Admin Portal & Crawler"])

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "guardra_admin_secret_2026")
ACTIVE_SESSIONS = set()

# Request Models
class AdminLoginRequest(BaseModel):
    admin_key: str

class SiteUpdateRequest(BaseModel):
    domain: str
    name: str
    grade: str
    score: int
    summary: str
    category: Optional[str] = "Web Platform"
    rubric: Optional[Dict[str, Any]] = None
    compliance: Optional[Dict[str, Any]] = None
    key_clauses: Optional[List[Dict[str, Any]]] = None

class AddSiteRequest(BaseModel):
    domain: str
    auto_scrape: bool = True
    manual_data: Optional[SiteUpdateRequest] = None

class RescoreSiteRequest(BaseModel):
    domain: str

import hmac
import hashlib

def get_master_session_token() -> str:
    return hmac.new(ADMIN_SECRET_KEY.encode('utf-8'), b"guardra_persistent_admin_session", hashlib.sha256).hexdigest()

# Dependency for Admin Authentication
async def verify_admin(
    x_admin_key: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None)
):
    token = x_admin_key
    if not token and authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ")[1].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required (Provide X-Admin-Key or Bearer token)"
        )

    if token == ADMIN_SECRET_KEY or token == get_master_session_token() or token in ACTIVE_SESSIONS:
        return True

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid admin credentials"
    )

@router.post("/login")
async def admin_login(payload: AdminLoginRequest):
    if payload.admin_key == ADMIN_SECRET_KEY:
        session_token = get_master_session_token()
        ACTIVE_SESSIONS.add(session_token)
        return {
            "status": "authenticated",
            "token": session_token,
            "message": "Admin session authenticated successfully."
        }
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect admin key."
    )

@router.get("/sites")
async def list_all_sites(
    search: Optional[str] = None,
    grade: Optional[str] = None,
    limit: int = 1000,
    auth: bool = Depends(verify_admin)
):
    policies = load_cached_policies()
    filtered = policies

    if search:
        s = search.lower().strip()
        filtered = [
            p for p in filtered
            if s in p.get("domain", "").lower() or s in p.get("name", "").lower()
        ]

    if grade:
        g = grade.upper().strip()
        filtered = [p for p in filtered if p.get("grade", "").startswith(g)]

    return {
        "total": len(policies),
        "count": len(filtered),
        "sites": filtered[:limit]
    }

@router.get("/sites/{domain}")
async def get_site_details(domain: str, auth: bool = Depends(verify_admin)):
    clean = clean_domain(domain)
    policies = load_cached_policies()
    for p in policies:
        if clean_domain(p.get("domain", "")) == clean:
            return p
    raise HTTPException(status_code=404, detail=f"Site {domain} not found in database.")

@router.post("/sites")
async def add_new_site(payload: AddSiteRequest, auth: bool = Depends(verify_admin)):
    clean = clean_domain(payload.domain)
    policies = load_cached_policies()

    for p in policies:
        if clean_domain(p.get("domain", "")) == clean:
            raise HTTPException(status_code=400, detail=f"Site {clean} is already in the database.")

    if payload.auto_scrape:
        res = await crawl_and_rescore_domain(clean)
        if res.get("status") == "success":
            return {"status": "created", "method": "auto_scraped", "site": res.get("rating")}
        else:
            new_entry = {
                "domain": clean,
                "name": clean.split(".")[0].title(),
                "grade": "C",
                "score": 55,
                "color": "amber",
                "summary": f"Initial baseline for {clean}.",
                "rubric": {
                    "data_sharing": { "score": 50, "max": 100, "label": "Standard Vendor Sharing", "risk": "medium" },
                    "retention": { "score": 50, "max": 100, "label": "Standard Retention Window", "risk": "medium" },
                    "tracking_cookies": { "score": 50, "max": 100, "label": "Standard Tracking Pixels", "risk": "medium" },
                    "user_rights": { "score": 60, "max": 100, "label": "Standard Erasure Request Flow", "risk": "medium" },
                    "breach_history": { "score": 60, "max": 100, "label": "No Known Major Breaches", "risk": "low" },
                    "readability": { "score": 60, "max": 100, "label": "Standard Readability", "risk": "medium" }
                },
                "compliance": {
                    "dpdp": { "compliant": True, "grievance_officer": f"Grievance Officer ({clean})", "grievance_email": f"privacy@{clean}", "redressal_period_days": 30, "erasure_right_disclosed": True },
                    "gdpr": { "compliant": True, "dpo_contact": f"dpo@{clean}", "lawful_basis_stated": True, "erasure_art17_disclosed": True },
                    "ccpa": { "compliant": False, "opt_out_link": None, "do_not_sell": False }
                },
                "category": "Web Platform",
                "source": "manual_admin"
            }
            policies.insert(0, new_entry)
            save_cached_policies(policies)
            return {"status": "created", "method": "manual_fallback", "site": new_entry}
    else:
        if not payload.manual_data:
            raise HTTPException(status_code=400, detail="Manual site data must be provided when auto_scrape is False.")
        new_entry = payload.manual_data.dict()
        policies.insert(0, new_entry)
        save_cached_policies(policies)
        return {"status": "created", "method": "manual", "site": new_entry}

@router.put("/sites/{domain}")
async def update_site(
    domain: str,
    payload: SiteUpdateRequest,
    auth: bool = Depends(verify_admin)
):
    clean = clean_domain(domain)
    policies = load_cached_policies()
    index_to_update = -1

    for i, p in enumerate(policies):
        if clean_domain(p.get("domain", "")) == clean:
            index_to_update = i
            break

    if index_to_update == -1:
        raise HTTPException(status_code=404, detail=f"Site {domain} not found.")

    existing = policies[index_to_update]
    updated_site = {
        **existing,
        "domain": clean,
        "name": payload.name,
        "grade": payload.grade.upper(),
        "score": payload.score,
        "color": "green" if payload.score >= 70 else ("amber" if payload.score >= 35 else "red"),
        "summary": payload.summary,
        "category": payload.category or existing.get("category", "Web Platform"),
        "rubric": payload.rubric or existing.get("rubric", {}),
        "compliance": payload.compliance or existing.get("compliance", {}),
        "key_clauses": payload.key_clauses or existing.get("key_clauses", []),
        "last_edited_by": "admin",
        "last_edited_at": "now"
    }

    policies[index_to_update] = updated_site
    save_cached_policies(policies)

    return {
        "status": "updated",
        "domain": clean,
        "site": updated_site
    }

@router.delete("/sites/{domain}")
async def delete_site(domain: str, auth: bool = Depends(verify_admin)):
    clean = clean_domain(domain)
    policies = load_cached_policies()
    new_list = [p for p in policies if clean_domain(p.get("domain", "")) != clean]

    if len(new_list) == len(policies):
        raise HTTPException(status_code=404, detail=f"Site {domain} not found in database.")

    save_cached_policies(new_list)
    return {
        "status": "deleted",
        "domain": clean,
        "remaining_count": len(new_list)
    }

# Crawler Control
@router.post("/crawler/rescore-site")
async def rescore_single_site(payload: RescoreSiteRequest, auth: bool = Depends(verify_admin)):
    res = await crawl_and_rescore_domain(payload.domain)
    return res

@router.post("/crawler/rescore-all")
async def trigger_bulk_rescore(background_tasks: BackgroundTasks, auth: bool = Depends(verify_admin)):
    status = get_crawler_status()
    if status["is_running"]:
        return {"status": "already_running", "message": "Bulk crawling is currently in progress."}

    background_tasks.add_task(run_bulk_rescore_job)
    return {
        "status": "started",
        "message": "Bulk policy crawling and re-scoring initiated in background."
    }

@router.post("/crawler/scan-top-1000")
async def trigger_top_1000_crawler(background_tasks: BackgroundTasks, auth: bool = Depends(verify_admin)):
    status = get_crawler_status()
    if status["is_running"]:
        return {"status": "already_running", "message": "Crawler is currently running."}

    background_tasks.add_task(run_top_1000_crawler_job)
    return {
        "status": "started",
        "message": "Top 1000 sites automated crawler initiated in background."
    }

@router.get("/crawler/status")
async def crawler_status(auth: bool = Depends(verify_admin)):
    return get_crawler_status()

# Extension Ping Audit Endpoints
@router.get("/pings")
async def list_extension_pings(
    limit: int = Query(100, ge=1, le=500),
    search: Optional[str] = None,
    auth: bool = Depends(verify_admin)
):
    pings = get_recent_pings(limit=limit, search=search)
    return {
        "count": len(pings),
        "limit": limit,
        "pings": pings
    }

@router.get("/pings/stats")
async def ping_statistics(auth: bool = Depends(verify_admin)):
    return get_ping_stats()
