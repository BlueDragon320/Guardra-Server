
from fastapi import APIRouter, Query, HTTPException, Request
from fastapi.responses import RedirectResponse
from typing import List, Dict, Any, Optional
import json
import time
from datetime import datetime, timedelta
from app.services.policy_analyzer import get_site_rating, load_cached_policies, clean_domain
from app.models.schemas import AnalyzeUrlRequest
from app.database import get_db_connection

router = APIRouter(prefix="/api/policy", tags=["Policy Rating"])

@router.get("/rating")
async def get_rating(
    request: Request,
    domain: str = Query(..., description="Target site domain, e.g. google.com or swiggy.com"),
    format: Optional[str] = Query(None, description="Response format: json or html")
):
    if not domain:
        raise HTTPException(status_code=400, detail="Domain parameter is required")
        
    start_time = time.time()
    clean = clean_domain(domain)

    # If opened directly in a browser without explicit JSON accept, redirect to the visual Audit UI
    accept_header = request.headers.get("accept", "")
    if format == "html" or ("text/html" in accept_header and "application/json" not in accept_header):
        return RedirectResponse(url=f"/?domain={clean}#scanner", status_code=302)
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.utcnow()
    now_iso = now.isoformat()
    
    try:
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM websites WHERE domain = ?", (clean,))
            raw_row = cursor.fetchone()
            
            is_valid = False
            row = dict(raw_row) if raw_row else None
            if row and row.get("expires_at"):
                try:
                    expires_at = datetime.fromisoformat(row["expires_at"])
                    if expires_at > now:
                        is_valid = True
                except (ValueError, TypeError):
                    pass
                    
            if is_valid and row:
                new_expires = now + timedelta(hours=24)
                try:
                    cursor.execute('''
                        UPDATE websites 
                        SET last_analyzed_at = ?, expires_at = ?, scan_count = scan_count + 1 
                        WHERE domain = ?
                    ''', (now_iso, new_expires.isoformat(), clean))
                    conn.commit()
                except Exception:
                    pass
                
                result = dict(row)
                for field in ["pillar_scores", "compliance", "findings", "key_concerns", "key_clauses", "cookie_data", "tracker_data", "dark_pattern_data", "breach_history"]:
                    if result.get(field):
                        try:
                            result[field] = json.loads(result[field])
                        except Exception:
                            pass
                
                result["score"] = result.pop("overall_score", 0)
                result["color"] = result.pop("grade_color", "gray")
                result["rubric"] = result.pop("pillar_scores", {})
                result["breaches"] = result.pop("breach_history", [])
                result["source"] = "db_cache"
                
                # Record website visit in browser_pings table (with 15s deduplication)
                try:
                    latency_ms = round((time.time() - start_time) * 1000, 1)
                    cursor.execute("SELECT id, timestamp FROM browser_pings WHERE domain = ? ORDER BY id DESC LIMIT 1", (clean,))
                    last_p = cursor.fetchone()
                    should_insert = True
                    if last_p and last_p["timestamp"]:
                        try:
                            if (now - datetime.fromisoformat(last_p["timestamp"])).total_seconds() < 15:
                                should_insert = False
                        except Exception:
                            pass
                    if should_insert:
                        cursor.execute('''
                            INSERT INTO browser_pings (domain, client_ip, score, grade, response_time_ms, client_type, timestamp)
                            VALUES (?, ?, ?, ?, ?, 'extension', ?)
                        ''', (clean, client_ip, result.get("score", 50), result.get("grade", "C"), latency_ms, now_iso))
                        conn.commit()
                except Exception:
                    pass

                return result
            else:
                result = await get_site_rating(clean)
                expires_at_iso = (now + timedelta(hours=24)).isoformat()
                
                cookie_json = json.dumps(result.get("cookie_data", []))
                tracker_json = json.dumps(result.get("tracker_data", []))
                dark_pattern_json = json.dumps(result.get("dark_pattern_data", []))
                
                try:
                    if row:
                        cursor.execute('''
                            UPDATE websites 
                            SET overall_score = ?, grade = ?, grade_color = ?, pillar_scores = ?, compliance = ?,
                                findings = ?, key_concerns = ?, key_clauses = ?, breach_history = ?,
                                last_analyzed_at = ?, expires_at = ?, updated_at = ?, scan_count = scan_count + 1
                            WHERE domain = ?
                        ''', (
                            result.get("score", 0), result.get("grade", "N/A"), result.get("color", "gray"),
                            json.dumps(result.get("rubric", {})), json.dumps(result.get("compliance", {})),
                            json.dumps(result.get("findings", {})), json.dumps(result.get("key_concerns", [])),
                            json.dumps(result.get("key_clauses", [])), json.dumps(result.get("breaches", [])),
                            now_iso, expires_at_iso, now_iso, clean
                        ))
                    else:
                        cursor.execute('''
                            INSERT INTO websites (
                                domain, name, category, overall_score, grade, grade_color,
                                pillar_scores, compliance, findings, key_concerns, key_clauses,
                                breach_history, cookie_data, tracker_data, dark_pattern_data,
                                source, scan_count, first_analyzed_at, last_analyzed_at, expires_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                        ''', (
                            clean, result.get("name", clean), result.get("category", "Web Service"),
                            result.get("score", 0), result.get("grade", "N/A"), result.get("color", "gray"),
                            json.dumps(result.get("rubric", {})), json.dumps(result.get("compliance", {})),
                            json.dumps(result.get("findings", {})), json.dumps(result.get("key_concerns", [])),
                            json.dumps(result.get("key_clauses", [])), json.dumps(result.get("breaches", [])),
                            cookie_json, tracker_json, dark_pattern_json,
                            'live_scan', now_iso, now_iso, expires_at_iso, now_iso
                        ))
                    
                    # Record visit in browser_pings table
                    latency_ms = round((time.time() - start_time) * 1000, 1)
                    cursor.execute('''
                        INSERT INTO browser_pings (domain, client_ip, score, grade, response_time_ms, client_type, timestamp)
                        VALUES (?, ?, ?, ?, ?, 'extension', ?)
                    ''', (clean, client_ip, result.get("score", 50), result.get("grade", "C"), latency_ms, now_iso))
                    conn.commit()
                except Exception:
                    pass
                
                return result
        finally:
            conn.close()
    except Exception:
        return await get_site_rating(clean)

@router.post("/analyze")
async def analyze_url(req: AnalyzeUrlRequest):
    if not req.url:
        raise HTTPException(status_code=400, detail="URL is required")
    result = await get_site_rating(req.url)
    return result

@router.get("/cached")
async def get_cached_sites():
    return load_cached_policies()
