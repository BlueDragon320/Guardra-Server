import json
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from app.database import get_db_connection
from app.services.policy_analyzer import get_site_rating, clean_domain
from app.services.cookie_service import (
    get_preferences, set_bulk_preferences, compute_rules_for_domain,
    get_global_rules, add_global_rule, update_global_rule, delete_global_rule,
    classify_cookie
)
from app.services.top_sites_service import (
    run_top_5000_pipeline, get_pipeline_status
)
from app.models.schemas import (
    AdminAddWebsiteRequest, AdminBulkRescanRequest, AdminDashboardStats,
    CookiePreferencesRequest, GlobalCookieRuleRequest,
    WebsiteListResponse, WebsiteListItem, CookieRulesResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["Admin Dashboard"])

# ===== Helper Functions =====

JSON_FIELDS = ["pillar_scores", "compliance", "findings", "key_concerns",
               "key_clauses", "cookie_data", "tracker_data", "dark_pattern_data", "breach_history"]

def _parse_json_fields(row_dict: dict) -> dict:
    """Parse JSON text fields in a database row into Python objects."""
    for field in JSON_FIELDS:
        if field in row_dict and row_dict[field]:
            try:
                row_dict[field] = json.loads(row_dict[field])
            except (json.JSONDecodeError, TypeError):
                pass
    return row_dict


def _log_audit(action: str, target: str = None, details: dict = None):
    """Log an admin action to the audit trail."""
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO admin_audit_log (action, target, details, performed_at) VALUES (?, ?, ?, ?)",
            (action, target, json.dumps(details) if details else None, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Audit log error: {e}")


async def _scan_and_store(domain: str, source: str = "admin") -> dict:
    """Scan a domain and store/update it in the websites table."""
    clean = clean_domain(domain)
    rating = await get_site_rating(clean)
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM websites WHERE domain = ?", (clean,))
        existing = cursor.fetchone()
        
        now = datetime.utcnow().isoformat()
        
        # Prepare JSON fields
        pillar_scores = json.dumps(rating.get("rubric", {}))
        compliance = json.dumps(rating.get("compliance", {}))
        findings = json.dumps(rating.get("findings", {}))
        key_concerns = json.dumps(rating.get("key_concerns", []))
        key_clauses = json.dumps(rating.get("key_clauses", []))
        breach_history = json.dumps(rating.get("breaches", []))
        
        policy_url = rating.get("policy_url") or f"https://www.{clean}/privacy-policy"
        
        if existing:
            cursor.execute("""
                UPDATE websites 
                SET name = ?, category = ?, overall_score = ?, grade = ?, grade_color = ?,
                    pillar_scores = ?, compliance = ?, findings = ?, key_concerns = ?,
                    key_clauses = ?, breach_history = ?, policy_url = ?, last_analyzed_at = ?,
                    scan_count = scan_count + 1, updated_at = ?
                WHERE domain = ?
            """, (
                rating.get("name", clean), rating.get("category", "Web Service"),
                rating.get("score", 0), rating.get("grade", "N/A"), rating.get("color", "gray"),
                pillar_scores, compliance, findings, key_concerns,
                key_clauses, breach_history, policy_url, now, now, clean
            ))
        else:
            cursor.execute("""
                INSERT INTO websites (
                    domain, name, category, overall_score, grade, grade_color,
                    pillar_scores, compliance, findings, key_concerns, key_clauses,
                    breach_history, policy_url, source, scan_count, first_analyzed_at, 
                    last_analyzed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """, (
                clean, rating.get("name", clean), rating.get("category", "Web Service"),
                rating.get("score", 0), rating.get("grade", "N/A"), rating.get("color", "gray"),
                pillar_scores, compliance, findings, key_concerns, key_clauses,
                breach_history, policy_url, source, now, now, now
            ))
        
        conn.commit()
        
        # Fetch and return the stored record
        cursor.execute("SELECT * FROM websites WHERE domain = ?", (clean,))
        result = dict(cursor.fetchone())
        return _parse_json_fields(result)
    finally:
        conn.close()


import os

ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "guardra_admin_secret_2026")


# ===== Authentication & Legacy Dashboard Endpoints =====

@router.post("/login")
async def admin_login(payload: dict):
    """Authenticates admin secret key."""
    key = payload.get("admin_key") or payload.get("password") or payload.get("key")
    expected = os.getenv("ADMIN_SECRET_KEY", "guardra_admin_secret_2026")
    if key and key.strip() == expected.strip():
        return {"status": "success", "token": "guardra_admin_token_2026"}
    raise HTTPException(status_code=401, detail="Invalid admin secret key")


@router.get("/sites")
async def get_all_sites(limit: int = 1000):
    """Returns websites in legacy format for admin console."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM websites")
        total_count = cursor.fetchone()["count"]
        
        cursor.execute("SELECT * FROM websites ORDER BY overall_score DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        sites = []
        for r in rows:
            d = _parse_json_fields(dict(r))
            dom = d.get("domain")
            p_url = d.get("policy_url")
            if dom == "croma.com" or p_url == "https://croma.com/privacy":
                p_url = "https://www.croma.com/privacy-policy"
            elif dom == "kletech.ac.in" or p_url == "https://kletech.ac.in/privacy":
                p_url = "https://www.kletech.ac.in/privacy-policy"
            elif not p_url or p_url == f"https://{dom}/privacy" or p_url == f"https://{dom}":
                p_url = f"https://www.{dom}/privacy-policy"

            sites.append({
                "domain": dom,
                "name": d.get("name") or dom,
                "score": d.get("overall_score", 0),
                "grade": d.get("grade", "C"),
                "category": d.get("category", "Web Platform"),
                "rubric": d.get("pillar_scores", {}),
                "compliance": d.get("compliance", {}),
                "findings": d.get("findings", {}),
                "key_concerns": d.get("key_concerns", []),
                "concerns": d.get("key_concerns", []),
                "key_clauses": d.get("key_clauses", []),
                "snippets": d.get("key_clauses", []),
                "breaches": d.get("breach_history", []),
                "policy_url": p_url,
                "summary": d.get("findings", {}).get("summary", "") if isinstance(d.get("findings"), dict) else (d.get("findings") or ""),
                "last_analyzed_at": d.get("last_analyzed_at")
            })
        return {"sites": sites, "total": total_count}
    finally:
        conn.close()


@router.put("/sites/{domain}")
async def update_site_legacy(domain: str, payload: dict):
    """Updates website details from legacy admin form."""
    clean = clean_domain(domain)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE websites SET
                name = COALESCE(?, name),
                overall_score = COALESCE(?, overall_score),
                grade = COALESCE(?, grade),
                pillar_scores = COALESCE(?, pillar_scores),
                compliance = COALESCE(?, compliance),
                updated_at = ?
            WHERE domain = ?
        """, (
            payload.get("name"),
            payload.get("score"),
            payload.get("grade"),
            json.dumps(payload.get("rubric")) if payload.get("rubric") else None,
            json.dumps(payload.get("compliance")) if payload.get("compliance") else None,
            datetime.utcnow().isoformat(),
            clean
        ))
        conn.commit()
        return {"status": "success", "domain": clean}
    finally:
        conn.close()


@router.get("/pings")
async def get_pings(limit: int = 100):
    """Returns telemetry pings."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM browser_pings ORDER BY timestamp DESC LIMIT ?", (limit,))
        pings = [dict(r) for r in cursor.fetchall()]
        return {"pings": pings, "total": len(pings)}
    except Exception:
        return {"pings": [], "total": 0}
    finally:
        conn.close()


@router.get("/pings/stats")
async def get_pings_stats():
    """Returns telemetry ping stats."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total_pings, COUNT(DISTINCT domain) as unique_domains FROM browser_pings")
        row = cursor.fetchone()
        return {
            "total_pings": row["total_pings"] if row else 0,
            "unique_domains": row["unique_domains"] if row else 0,
            "avg_latency_ms": 42
        }
    except Exception:
        return {"total_pings": 0, "unique_domains": 0, "avg_latency_ms": 0}
    finally:
        conn.close()


# ===== Dashboard Stats =====

@router.get("/stats", response_model=AdminDashboardStats)
async def get_admin_dashboard_stats():
    """Admin dashboard statistics."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Total websites
        cursor.execute("SELECT COUNT(*) as count FROM websites")
        total = cursor.fetchone()["count"]
        
        # Average score
        cursor.execute("SELECT AVG(overall_score) as avg FROM websites WHERE overall_score IS NOT NULL")
        avg_row = cursor.fetchone()
        avg_score = round(avg_row["avg"], 1) if avg_row["avg"] else 0.0
        
        # Grade distribution
        cursor.execute("SELECT grade, COUNT(*) as count FROM websites WHERE grade IS NOT NULL GROUP BY grade")
        grade_dist = {row["grade"]: row["count"] for row in cursor.fetchall()}
        
        # Source distribution
        cursor.execute("SELECT source, COUNT(*) as count FROM websites GROUP BY source")
        source_dist = {row["source"]: row["count"] for row in cursor.fetchall()}
        
        # Top 5000 count
        cursor.execute("SELECT COUNT(*) as count FROM websites WHERE is_top_5000 = 1")
        top_5000_count = cursor.fetchone()["count"]
        
        # Top 10 highest scoring
        cursor.execute("""
            SELECT domain, name, overall_score, grade, grade_color, category 
            FROM websites WHERE overall_score IS NOT NULL 
            ORDER BY overall_score DESC LIMIT 10
        """)
        top_10 = [dict(r) for r in cursor.fetchall()]
        
        # Bottom 10 lowest scoring
        cursor.execute("""
            SELECT domain, name, overall_score, grade, grade_color, category 
            FROM websites WHERE overall_score IS NOT NULL 
            ORDER BY overall_score ASC LIMIT 10
        """)
        bottom_10 = [dict(r) for r in cursor.fetchall()]
        
        # Recent scans (last 10)
        cursor.execute("""
            SELECT domain, name, overall_score, grade, grade_color, last_analyzed_at, source
            FROM websites WHERE last_analyzed_at IS NOT NULL
            ORDER BY last_analyzed_at DESC LIMIT 10
        """)
        recent = [dict(r) for r in cursor.fetchall()]
        
        return {
            "total_websites": total,
            "avg_score": avg_score,
            "grade_distribution": grade_dist,
            "source_distribution": source_dist,
            "total_top_5000": top_5000_count,
            "top_10": top_10,
            "bottom_10": bottom_10,
            "recent_scans": recent
        }
    finally:
        conn.close()


# ===== Website List & Detail =====

@router.get("/websites")
async def list_websites(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    sort_by: str = Query("overall_score", regex="^(domain|name|overall_score|grade|last_analyzed_at|scan_count)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    grade_filter: Optional[str] = None,
    category_filter: Optional[str] = None,
    source_filter: Optional[str] = None,
    search: Optional[str] = None,
    top_5000_only: bool = False,
):
    """Paginated, filterable, sortable list of all websites."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        conditions = []
        params = []
        
        if grade_filter:
            conditions.append("grade = ?")
            params.append(grade_filter)
        if category_filter:
            conditions.append("category = ?")
            params.append(category_filter)
        if source_filter:
            conditions.append("source = ?")
            params.append(source_filter)
        if search:
            conditions.append("(domain LIKE ? OR name LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        if top_5000_only:
            conditions.append("is_top_5000 = 1")
        
        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        
        # Get total count
        cursor.execute(f"SELECT COUNT(*) as count FROM websites{where_clause}", params)
        total = cursor.fetchone()["count"]
        
        # Get paginated results
        offset = (page - 1) * page_size
        query = f"""
            SELECT domain, name, overall_score, grade, grade_color, category, source,
                   is_top_5000, tranco_rank, scan_count, last_analyzed_at
            FROM websites{where_clause}
            ORDER BY {sort_by} {sort_order}
            LIMIT ? OFFSET ?
        """
        cursor.execute(query, params + [page_size, offset])
        items = [dict(r) for r in cursor.fetchall()]
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    finally:
        conn.close()


@router.get("/websites/{domain}")
async def get_website_detail(domain: str):
    """Full detail for a single website."""
    clean = clean_domain(domain)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM websites WHERE domain = ?", (clean,))
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail=f"Website '{clean}' not found in database")
        
        result = dict(row)
        result = _parse_json_fields(result)
        
        # Attach cookie preferences
        prefs = get_preferences(clean)
        result["cookie_preferences"] = prefs
        
        return result
    finally:
        conn.close()


# ===== Website Management =====

@router.post("/websites")
async def add_website(req: AdminAddWebsiteRequest):
    """Add and scan a new website."""
    clean = clean_domain(req.domain)
    
    # Check if already exists
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM websites WHERE domain = ?", (clean,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail=f"Website '{clean}' already exists. Use rescan instead.")
    finally:
        conn.close()
    
    result = await _scan_and_store(clean, source="admin")
    
    # Apply optional overrides
    if req.name or req.category:
        conn = get_db_connection()
        try:
            updates = []
            params = []
            if req.name:
                updates.append("name = ?")
                params.append(req.name)
            if req.category:
                updates.append("category = ?")
                params.append(req.category)
            params.append(clean)
            conn.execute(f"UPDATE websites SET {', '.join(updates)} WHERE domain = ?", params)
            conn.commit()
        finally:
            conn.close()
    
    _log_audit("add_website", clean, {"source": "admin", "score": result.get("overall_score")})
    return result


@router.post("/websites/{domain}/rescan")
async def rescan_website(domain: str):
    """Force rescan of a specific website."""
    clean = clean_domain(domain)
    result = await _scan_and_store(clean, source="admin")
    _log_audit("rescan", clean, {"new_score": result.get("overall_score")})
    return result


@router.post("/websites/bulk-rescan")
async def bulk_rescan(req: AdminBulkRescanRequest, background_tasks: BackgroundTasks):
    """Rescan multiple websites in the background."""
    async def _do_bulk():
        for d in req.domains:
            try:
                await _scan_and_store(clean_domain(d))
            except Exception as e:
                logger.error(f"Bulk rescan error for {d}: {e}")
    
    background_tasks.add_task(_do_bulk)
    _log_audit("bulk_rescan", None, {"domains": req.domains, "count": len(req.domains)})
    return {"status": "queued", "count": len(req.domains)}


@router.delete("/websites/{domain}")
async def delete_website(domain: str):
    """Remove a website and its cookie preferences from the database."""
    clean = clean_domain(domain)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM websites WHERE domain = ?", (clean,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail=f"Website '{clean}' not found")
        
        cursor.execute("DELETE FROM websites WHERE domain = ?", (clean,))
        cursor.execute("DELETE FROM cookie_preferences WHERE domain = ?", (clean,))
        conn.commit()
        
        _log_audit("delete_website", clean)
        return {"status": "deleted", "domain": clean}
    finally:
        conn.close()


# ===== Cookie Management =====

@router.get("/websites/{domain}/cookies")
async def get_website_cookies(domain: str):
    """Get all detected cookies for a website with their current preferences."""
    clean = clean_domain(domain)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT cookie_data FROM websites WHERE domain = ?", (clean,))
        row = cursor.fetchone()
        
        detected_cookies = []
        if row and row["cookie_data"]:
            try:
                detected_cookies = json.loads(row["cookie_data"])
            except (json.JSONDecodeError, TypeError):
                pass
        
        # Get per-site preferences
        prefs = get_preferences(clean)
        pref_map = {p["cookie_name"]: p for p in prefs}
        
        # Merge detected cookies with preferences
        enriched = []
        for cookie in detected_cookies:
            name = cookie.get("name", "")
            classification = classify_cookie(name)
            
            enriched.append({
                "name": name,
                "category": classification["category"],
                "is_tracking": cookie.get("isTracking", classification["category"] != "essential"),
                "action": pref_map.get(name, {}).get("action", classification["default_action"]),
                "has_override": name in pref_map,
            })
        
        return {
            "domain": clean,
            "cookies": enriched,
            "total": len(enriched)
        }
    finally:
        conn.close()


@router.put("/websites/{domain}/cookies")
async def update_website_cookies(domain: str, req: CookiePreferencesRequest):
    """Bulk update cookie preferences for a website."""
    clean = clean_domain(domain)
    results = set_bulk_preferences(clean, [p.model_dump() for p in req.preferences])
    _log_audit("update_cookies", clean, {"count": len(req.preferences)})
    return {"domain": clean, "updated": len(results), "preferences": results}


@router.get("/cookie-rules")
async def list_global_cookie_rules():
    """List all global cookie rules."""
    return get_global_rules()


@router.post("/cookie-rules")
async def create_global_cookie_rule(req: GlobalCookieRuleRequest):
    """Create a new global cookie rule."""
    result = add_global_rule(req.cookie_pattern, req.cookie_category, req.default_action, req.description)
    if not result:
        raise HTTPException(status_code=400, detail="Failed to create rule. Pattern may already exist.")
    _log_audit("create_cookie_rule", req.cookie_pattern, {"action": req.default_action})
    return result


@router.put("/cookie-rules/{rule_id}")
async def update_cookie_rule(rule_id: int, req: GlobalCookieRuleRequest):
    """Update an existing global cookie rule."""
    result = update_global_rule(rule_id, req.cookie_pattern, req.cookie_category, req.default_action, req.description)
    if not result:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    _log_audit("update_cookie_rule", str(rule_id), {"pattern": req.cookie_pattern})
    return result


@router.delete("/cookie-rules/{rule_id}")
async def delete_cookie_rule(rule_id: int):
    """Delete a global cookie rule."""
    result = delete_global_rule(rule_id)
    _log_audit("delete_cookie_rule", str(rule_id))
    return result


# ===== Top 5000 Pipeline =====

@router.post("/top-5000/refresh")
async def refresh_top_5000(background_tasks: BackgroundTasks):
    """Trigger the top 5000 pipeline. Runs in the background."""
    status = get_pipeline_status()
    if status["status"] == "running":
        raise HTTPException(status_code=409, detail="Pipeline is already running")
    
    background_tasks.add_task(run_top_5000_pipeline)
    _log_audit("top_5000_refresh", None, {"triggered_at": datetime.utcnow().isoformat()})
    return {"status": "started", "message": "Top 5000 pipeline started. Check /api/admin/top-5000/status for progress."}


@router.get("/top-5000/status")
async def get_top_5000_status():
    """Get current status of the top 5000 pipeline."""
    return get_pipeline_status()


# ===== Audit Log =====

@router.get("/audit-log")
async def get_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    """Paginated admin audit trail."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM admin_audit_log")
        total = cursor.fetchone()["count"]
        
        offset = (page - 1) * page_size
        cursor.execute("""
            SELECT * FROM admin_audit_log 
            ORDER BY performed_at DESC 
            LIMIT ? OFFSET ?
        """, (page_size, offset))
        
        items = []
        for row in cursor.fetchall():
            item = dict(row)
            if item.get("details"):
                try:
                    item["details"] = json.loads(item["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            items.append(item)
        
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    finally:
        conn.close()


# ===== Legacy Crawler Endpoints =====

@router.get("/crawler/status")
async def get_crawler_progress():
    """Returns real-time status of background crawler jobs."""
    try:
        from app.services.crawler_service import get_crawler_status
        return get_crawler_status()
    except Exception as e:
        return {"is_running": False, "progress": 0, "total": 0, "error": str(e)}


@router.post("/crawler/rescore-site")
async def rescore_single_site(payload: dict):
    """Scrapes and updates a single domain."""
    domain = payload.get("domain")
    if not domain:
        raise HTTPException(status_code=400, detail="Missing domain parameter")
    try:
        from app.services.crawler_service import crawl_and_rescore_domain
        result = await crawl_and_rescore_domain(domain)
        return {"status": "success", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crawler/rescore-all")
async def rescore_all_cached(background_tasks: BackgroundTasks):
    """Triggers background rescore for all cached domains."""
    try:
        from app.services.crawler_service import run_bulk_crawler_job
        background_tasks.add_task(run_bulk_crawler_job)
        return {"status": "started", "message": "Bulk crawler job started in background"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/crawler/scan-top-1000")
async def scan_top_1000(background_tasks: BackgroundTasks):
    """Triggers background crawler for top 1,000 domains."""
    try:
        from app.services.crawler_service import run_top_1000_crawler_job
        background_tasks.add_task(run_top_1000_crawler_job)
        return {"status": "started", "message": "Top 1000 crawler job started in background"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.get("/pings")
async def get_pings():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM browser_pings ORDER BY id DESC LIMIT 100")
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

@router.get("/pings/stats")
async def get_pings_stats():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total_pings, COUNT(DISTINCT domain) as unique_domains, AVG(response_time_ms) as avg_latency_ms FROM browser_pings")
        row = cursor.fetchone()
        return {
            "total_pings": row["total_pings"] or 0,
            "unique_domains": row["unique_domains"] or 0,
            "avg_latency_ms": row["avg_latency_ms"] or 0.0
        }
    finally:
        conn.close()


@router.get("/analytics/visits")
async def get_visit_analytics(timeframe: str = Query("day", regex="^(day|week|month)$")):
    """Aggregates visited websites across all users by day (24h), week (7d), and month (30d)."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now = datetime.utcnow()
        
        if timeframe == "day":
            since = (now - timedelta(hours=24)).isoformat()
            slots = {}
            for i in range(23, -1, -1):
                h = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
                slots[h.strftime("%H:00")] = {"label": h.strftime("%H:00"), "visits": 0, "unique_domains": set()}
        elif timeframe == "week":
            since = (now - timedelta(days=7)).isoformat()
            slots = {}
            for i in range(6, -1, -1):
                d = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
                slots[d.strftime("%b %d")] = {"label": d.strftime("%b %d"), "visits": 0, "unique_domains": set()}
        else:  # month
            since = (now - timedelta(days=30)).isoformat()
            slots = {}
            for i in range(29, -1, -1):
                d = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
                slots[d.strftime("%b %d")] = {"label": d.strftime("%b %d"), "visits": 0, "unique_domains": set()}
        
        cursor.execute("SELECT id, domain, score, grade, timestamp, response_time_ms FROM browser_pings WHERE timestamp >= ? ORDER BY timestamp ASC", (since,))
        rows = cursor.fetchall()
        
        total_visits = len(rows)
        domain_counts = {}
        grade_dist = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        score_sum = 0
        
        for r in rows:
            ts_str = r["timestamp"]
            dom = r["domain"]
            score = r["score"] or 0
            raw_grade = (r["grade"] or "C")[0].upper()
            if raw_grade in grade_dist:
                grade_dist[raw_grade] += 1
            score_sum += score
            
            if dom not in domain_counts:
                domain_counts[dom] = {
                    "domain": dom,
                    "visits": 0,
                    "score": score,
                    "grade": r["grade"] or "C",
                    "last_visited": ts_str
                }
            domain_counts[dom]["visits"] += 1
            domain_counts[dom]["last_visited"] = ts_str
            
            try:
                dt = datetime.fromisoformat(ts_str)
                if timeframe == "day":
                    key = dt.strftime("%H:00")
                else:
                    key = dt.strftime("%b %d")
                if key in slots:
                    slots[key]["visits"] += 1
                    slots[key]["unique_domains"].add(dom)
            except Exception:
                pass
                
        labels = []
        visit_series = []
        unique_series = []
        for k, v in slots.items():
            labels.append(v["label"])
            visit_series.append(v["visits"])
            unique_series.append(len(v["unique_domains"]))
            
        top_domains = sorted(domain_counts.values(), key=lambda x: x["visits"], reverse=True)[:10]
        
        # Fallback to overall top sites if fewer than 10 in this specific timeframe
        if len(top_domains) < 10:
            cursor.execute("""
                SELECT domain, COUNT(*) as visit_count, MAX(score) as score, MAX(grade) as grade, MAX(timestamp) as last_visited
                FROM browser_pings
                GROUP BY domain
                ORDER BY visit_count DESC
                LIMIT 10
            """)
            fallback_rows = cursor.fetchall()
            existing_domains = {td["domain"] for td in top_domains}
            for fr in fallback_rows:
                if fr["domain"] not in existing_domains and len(top_domains) < 10:
                    top_domains.append({
                        "domain": fr["domain"],
                        "visits": fr["visit_count"],
                        "score": fr["score"] or 0,
                        "grade": fr["grade"] or "C",
                        "last_visited": fr["last_visited"]
                    })

        if top_domains:
            domain_list = [d["domain"] for d in top_domains]
            placeholders = ','.join('?' for _ in domain_list)
            cursor.execute(f"SELECT domain, name, category, overall_score, grade FROM websites WHERE domain IN ({placeholders})", domain_list)
            meta_map = {row["domain"]: dict(row) for row in cursor.fetchall()}
            for td in top_domains:
                if td["domain"] in meta_map:
                    td["name"] = meta_map[td["domain"]].get("name") or td["domain"]
                    td["category"] = meta_map[td["domain"]].get("category") or "Web Service"
                    td["score"] = meta_map[td["domain"]].get("overall_score", td["score"])
                    td["grade"] = meta_map[td["domain"]].get("grade", td["grade"])
                else:
                    td["name"] = td["domain"].split(".")[0].title()
                    td["category"] = "Web Platform"
        
        # Build Top 10 Sites Chart Dataset
        top10_chart = {
            "labels": [td.get("name") or td["domain"] for td in top_domains],
            "domains": [td["domain"] for td in top_domains],
            "visits": [td["visits"] for td in top_domains],
            "scores": [round(float(td["score"])) for td in top_domains],
            "grades": [td["grade"] for td in top_domains],
            "categories": [td["category"] for td in top_domains]
        }
        
        unique_domains_count = len(domain_counts) if domain_counts else len(top_domains)
        avg_score = round(score_sum / total_visits, 1) if total_visits > 0 else (round(sum(td["score"] for td in top_domains) / len(top_domains), 1) if top_domains else 0)
        
        busiest = max(slots.items(), key=lambda x: x[1]["visits"]) if slots else (None, {"visits": 0})
        busiest_label = f"{busiest[0]} ({busiest[1]['visits']} visits)" if busiest and busiest[1]["visits"] > 0 else (f"{top_domains[0]['name']} ({top_domains[0]['visits']} hits)" if top_domains else "N/A")
        
        return {
            "timeframe": timeframe,
            "total_visits": total_visits if total_visits > 0 else sum(td["visits"] for td in top_domains),
            "unique_domains": unique_domains_count,
            "avg_score": avg_score,
            "busiest_period": busiest_label,
            "grade_distribution": grade_dist,
            "top10_chart": top10_chart,
            "top_domains": top_domains
        }
    finally:
        conn.close()

