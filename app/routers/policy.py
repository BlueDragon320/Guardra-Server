import time
from fastapi import APIRouter, Query, HTTPException, Request
from typing import List, Dict, Any
from app.services.policy_analyzer import get_site_rating, load_cached_policies
from app.models.schemas import AnalyzeUrlRequest
from app.database import log_extension_ping

router = APIRouter(prefix="/api/policy", tags=["Policy Rating"])

@router.get("/rating")
async def get_rating(
    request: Request,
    domain: str = Query(..., description="Target site domain, e.g. google.com or swiggy.com")
):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")

    start_time = time.time()
    result = await get_site_rating(domain)
    duration_ms = (time.time() - start_time) * 1000

    # Extract client metadata for audit logging
    client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()
    
    user_agent = request.headers.get("user-agent", "GuardraExtension/1.0")
    client_type = request.headers.get("x-guardra-client", "extension")

    # Record ping to SQLite audit log
    log_extension_ping(
        domain=domain,
        client_ip=client_ip,
        user_agent=user_agent,
        client_type=client_type,
        grade=result.get("grade", "N/A"),
        score=result.get("score", 0),
        response_time_ms=duration_ms
    )

    return result

@router.post("/analyze")
async def analyze_url(req: AnalyzeUrlRequest, request: Request):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL is required")
    start_time = time.time()
    result = await get_site_rating(req.url)
    duration_ms = (time.time() - start_time) * 1000

    client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else "127.0.0.1")
    log_extension_ping(
        domain=req.url,
        client_ip=client_ip,
        user_agent=request.headers.get("user-agent", "Dashboard/1.0"),
        client_type="dashboard",
        grade=result.get("grade", "N/A"),
        score=result.get("score", 0),
        response_time_ms=duration_ms
    )
    return result

@router.get("/cached")
async def get_cached_sites():
    return load_cached_policies()
