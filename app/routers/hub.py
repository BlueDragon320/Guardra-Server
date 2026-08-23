import os
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.services.footprint_service import get_footprint_data, toggle_action
from app.models.schemas import ActionToggleRequest
from app.database import get_db_connection

router = APIRouter(prefix="/api/hub", tags=["Privacy Hub & Footprint"])

PLATFORMS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "privacy_hub.json")

# In-memory store of recent live browser activity from extension
RECENT_ACTIVITIES = [
    {
        "id": "act_init",
        "domain": "guardra.local",
        "url": "http://localhost:5173",
        "action": "Shield Activated",
        "details": "Guardra extension connected to active session.",
        "trackers_blocked": 0,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
]

class TelemetryPayload(BaseModel):
    domain: str
    url: str
    action_type: str = "scan"  # scan, auto_reject_cookies, opt_out_toggled, dark_pattern_cleared
    details: str = ""
    trackers_detected: List[Dict[str, Any]] = []
    auto_actions_taken: List[str] = []

@router.get("/platforms")
async def get_platforms():
    if os.path.exists(PLATFORMS_PATH):
        with open(PLATFORMS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@router.get("/footprint")
async def get_footprint():
    return get_footprint_data()

@router.post("/footprint/toggle")
async def toggle_footprint_action(req: ActionToggleRequest):
    return toggle_action(req.action_id)

@router.post("/telemetry/active-session")
async def record_telemetry(payload: TelemetryPayload):
    new_entry = {
        "id": f"act_{len(RECENT_ACTIVITIES) + 1}",
        "domain": payload.domain,
        "url": payload.url,
        "action": payload.action_type,
        "details": payload.details or f"Analyzed {payload.domain}",
        "trackers_blocked": len(payload.trackers_detected),
        "auto_actions": payload.auto_actions_taken,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
    RECENT_ACTIVITIES.insert(0, new_entry)
    if len(RECENT_ACTIVITIES) > 25:
        RECENT_ACTIVITIES.pop()
    return {"status": "recorded", "activity": new_entry}

@router.get("/telemetry/live-feed")
async def get_live_feed():
    return RECENT_ACTIVITIES


# ===== Extension Scan Persistence & Cookie Rules =====

class ScanPayload(BaseModel):
    domain: str
    cookies: List[Dict[str, Any]] = []
    trackers: List[Dict[str, Any]] = []
    dark_patterns: List[Dict[str, Any]] = []
    policy_url: Optional[str] = None

@router.post("/scan-result")
async def receive_scan_result(payload: ScanPayload):
    """Receive and persist scan data from the browser extension.
    
    If domain exists in DB: updates cookie/tracker/dark pattern data.
    If domain is new: runs full analysis and stores it.
    Returns computed cookie block rules for the domain.
    """
    from app.services.policy_analyzer import get_site_rating, clean_domain
    from app.services.cookie_service import compute_rules_for_domain
    
    clean = clean_domain(payload.domain)
    now = datetime.utcnow().isoformat()
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM websites WHERE domain = ?", (clean,))
        existing = cursor.fetchone()
        
        cookie_json = json.dumps([c if isinstance(c, dict) else c for c in payload.cookies])
        tracker_json = json.dumps([t if isinstance(t, dict) else t for t in payload.trackers])
        dark_pattern_json = json.dumps([d if isinstance(d, dict) else d for d in payload.dark_patterns])
        
        if existing:
            # Update existing record with latest scan data
            cursor.execute("""
                UPDATE websites 
                SET cookie_data = ?, tracker_data = ?, dark_pattern_data = ?,
                    scan_count = scan_count + 1, last_analyzed_at = ?, updated_at = ?
                WHERE domain = ?
            """, (cookie_json, tracker_json, dark_pattern_json, now, now, clean))
            conn.commit()
        else:
            # New domain — run full analysis and store
            rating = await get_site_rating(clean, 
                                            tracker_data=payload.trackers,
                                            cookie_data=payload.cookies,
                                            dark_patterns=payload.dark_patterns)
            
            cursor.execute("""
                INSERT INTO websites (
                    domain, name, category, overall_score, grade, grade_color,
                    pillar_scores, compliance, findings, key_concerns, key_clauses,
                    breach_history, cookie_data, tracker_data, dark_pattern_data,
                    source, scan_count, first_analyzed_at, last_analyzed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'auto_scan', 1, ?, ?, ?)
            """, (
                clean, rating.get("name", clean), rating.get("category", "Web Service"),
                rating.get("score", 0), rating.get("grade", "N/A"), rating.get("color", "gray"),
                json.dumps(rating.get("rubric", {})), json.dumps(rating.get("compliance", {})),
                json.dumps(rating.get("findings", {})), json.dumps(rating.get("key_concerns", [])),
                json.dumps(rating.get("key_clauses", [])), json.dumps(rating.get("breaches", [])),
                cookie_json, tracker_json, dark_pattern_json, now, now, now
            ))
            conn.commit()
        
        # Compute and return cookie rules for the extension
        cookie_rules = compute_rules_for_domain(clean, payload.cookies)
        
        # Get the current score for the domain
        cursor.execute("SELECT overall_score, grade FROM websites WHERE domain = ?", (clean,))
        row = cursor.fetchone()
        
        return {
            "domain": clean,
            "grade": row["grade"] if row else "N/A",
            "score": row["overall_score"] if row else 0,
            "cookie_rules": cookie_rules
        }
    finally:
        conn.close()
