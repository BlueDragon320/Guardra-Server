from fastapi import APIRouter, Query, HTTPException
from typing import List, Dict, Any
from app.services.policy_analyzer import get_site_rating, load_cached_policies
from app.models.schemas import AnalyzeUrlRequest

router = APIRouter(prefix="/api/policy", tags=["Policy Rating"])

@router.get("/rating")
async def get_rating(domain: str = Query(..., description="Target site domain, e.g. google.com or swiggy.com")):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")
    result = await get_site_rating(domain)
    return result

@router.post("/analyze")
async def analyze_url(req: AnalyzeUrlRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL is required")
    result = await get_site_rating(req.url)
    return result

@router.get("/cached")
async def get_cached_sites():
    return load_cached_policies()
