from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.models.schemas import PasswordCheckRequest, EmailCheckRequest
from app.services.breach_service import check_password_pwned, check_email_exposure

router = APIRouter(prefix="/api/breach", tags=["Breach & Exposure"])

@router.post("/check-password")
async def verify_password(req: PasswordCheckRequest):
    res = await check_password_pwned(
        password=req.password,
        sha1_prefix=req.sha1_prefix,
        sha1_suffix=req.sha1_suffix
    )
    return res

@router.post("/check-email")
async def verify_email(req: EmailCheckRequest):
    if not req.email or "@" not in req.email:
        raise HTTPException(status_code=400, detail="Valid email is required")
    res = await check_email_exposure(req.email)
    return res

@router.get("/search")
async def search_domain_breach(domain: str):
    """Real-time OSINT security radar search for any domain or enterprise."""
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter required")
    from app.services.breach_service import search_live_domain_breaches
    breaches = await search_live_domain_breaches(domain)
    return {
        "domain": domain,
        "breaches_found": len(breaches),
        "breaches": breaches
    }
