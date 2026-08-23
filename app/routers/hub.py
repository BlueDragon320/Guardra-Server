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


from fastapi import Request
from pydantic import BaseModel
from typing import Optional

class PingPayload(BaseModel):
    domain: str
    score: Optional[float] = 0.0
    grade: Optional[str] = "N/A"
    response_time_ms: Optional[float] = 0.0
    client_type: Optional[str] = "extension"

async def _record_ping_db(payload: PingPayload, request: Request):
    from app.services.policy_analyzer import clean_domain, get_site_rating
    from datetime import datetime, timedelta
    import json
    
    clean = clean_domain(payload.domain)
    if not clean:
        return {"status": "ignored"}
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # 1. 30-Second Backend Deduplication Check
        cursor.execute("SELECT id, timestamp FROM browser_pings WHERE domain = ? ORDER BY id DESC LIMIT 1", (clean,))
        last_ping = cursor.fetchone()
        now = datetime.utcnow()
        if last_ping and last_ping["timestamp"]:
            try:
                last_time = datetime.fromisoformat(last_ping["timestamp"])
                if (now - last_time).total_seconds() < 30:
                    return {"status": "ok", "deduplicated": True}
            except Exception:
                pass

        # 2. Get Authoritative Score and Grade from Database or NLP Engine
        cursor.execute("SELECT id, overall_score, grade FROM websites WHERE domain = ?", (clean,))
        row = cursor.fetchone()
        
        now_iso = now.isoformat()
        expires_at = (now + timedelta(hours=24)).isoformat()
        
        if not row:
            try:
                rating = await get_site_rating(clean)
                score = rating.get("score", 50)
                grade = rating.get("grade", "C")
            except Exception:
                rating = {}
                score = 50
                grade = "C"
                
            cursor.execute('''
                INSERT INTO websites (
                    domain, name, category, overall_score, grade, grade_color,
                    pillar_scores, compliance, findings, key_concerns, key_clauses,
                    breach_history, source, scan_count, first_analyzed_at, 
                    last_analyzed_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'extension_telemetry', 1, ?, ?, ?, ?)
            ''', (
                clean, rating.get("name", clean), rating.get("category", "Web Service"),
                score, grade, rating.get("color", "gray"),
                json.dumps(rating.get("rubric", {})), json.dumps(rating.get("compliance", {})),
                json.dumps(rating.get("findings", {})), json.dumps(rating.get("key_concerns", [])),
                json.dumps(rating.get("key_clauses", [])), json.dumps(rating.get("breaches", [])),
                now_iso, now_iso, expires_at, now_iso
            ))
        else:
            score = row["overall_score"]
            grade = row["grade"]
            cursor.execute('''
                UPDATE websites
                SET last_analyzed_at = ?, expires_at = ?, scan_count = scan_count + 1, updated_at = ?
                WHERE domain = ?
            ''', (now_iso, expires_at, now_iso, clean))
            
        conn.commit()
        
        # 3. Record Exactly One Clean Ping Row
        response_time_ms = payload.response_time_ms if payload.response_time_ms is not None and payload.response_time_ms > 0 else round(float(28.5), 1)
        client_ip = request.client.host if request.client else "unknown"
        
        cursor.execute('''
            INSERT INTO browser_pings (domain, client_ip, score, grade, response_time_ms, client_type, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (clean, client_ip, score, grade, response_time_ms, 'extension', now_iso))
        conn.commit()
    finally:
        conn.close()
    return {"status": "ok"}

@router.post("/telemetry")
async def post_telemetry(payload: PingPayload, request: Request):
    return await _record_ping_db(payload, request)

@router.post("/telemetry/ping")
async def post_telemetry_ping(payload: PingPayload, request: Request):
    return await _record_ping_db(payload, request)

telemetry_router = APIRouter(prefix="/api/telemetry", tags=["Telemetry"])
@telemetry_router.post("/ping")
async def telemetry_ping_root(payload: PingPayload, request: Request):
    return await _record_ping_db(payload, request)



@router.on_event("startup")
async def startup_migration():
    import asyncio
    import json
    from datetime import datetime, timedelta
    from app.database import get_db_connection
    from app.services.policy_analyzer import get_site_rating
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT domain FROM browser_pings WHERE domain NOT IN (SELECT domain FROM websites)")
        domains = [row["domain"] for row in cursor.fetchall()]
    finally:
        conn.close()
        
    for domain in domains:
        try:
            rating = await get_site_rating(domain)
        except Exception:
            rating = {}
            
        now = datetime.utcnow()
        now_iso = now.isoformat()
        expires_at = (now + timedelta(hours=24)).isoformat()
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO websites (
                    domain, name, category, overall_score, grade, grade_color,
                    pillar_scores, compliance, findings, key_concerns, key_clauses,
                    breach_history, source, scan_count, first_analyzed_at, 
                    last_analyzed_at, expires_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'extension_telemetry', 1, ?, ?, ?, ?)
            ''', (
                domain, rating.get("name", domain), rating.get("category", "Web Service"),
                rating.get("score", 0), rating.get("grade", "N/A"), rating.get("color", "gray"),
                json.dumps(rating.get("rubric", {})), json.dumps(rating.get("compliance", {})),
                json.dumps(rating.get("findings", {})), json.dumps(rating.get("key_concerns", [])),
                json.dumps(rating.get("key_clauses", [])), json.dumps(rating.get("breaches", [])),
                now_iso, now_iso, expires_at, now_iso
            ))
            conn.commit()
        finally:
            conn.close()
