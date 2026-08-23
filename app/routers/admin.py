import json
import logging
from datetime import datetime
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
        
        if existing:
            cursor.execute("""
                UPDATE websites 
                SET name = ?, category = ?, overall_score = ?, grade = ?, grade_color = ?,
                    pillar_scores = ?, compliance = ?, findings = ?, key_concerns = ?,
                    key_clauses = ?, breach_history = ?, last_analyzed_at = ?,
                    scan_count = scan_count + 1, updated_at = ?
                WHERE domain = ?
            """, (
                rating.get("name", clean), rating.get("category", "Web Service"),
                rating.get("score", 0), rating.get("grade", "N/A"), rating.get("color", "gray"),
                pillar_scores, compliance, findings, key_concerns,
                key_clauses, breach_history, now, now, clean
            ))
        else:
            cursor.execute("""
                INSERT INTO websites (
                    domain, name, category, overall_score, grade, grade_color,
                    pillar_scores, compliance, findings, key_concerns, key_clauses,
                    breach_history, source, scan_count, first_analyzed_at, 
                    last_analyzed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            """, (
                clean, rating.get("name", clean), rating.get("category", "Web Service"),
                rating.get("score", 0), rating.get("grade", "N/A"), rating.get("color", "gray"),
                pillar_scores, compliance, findings, key_concerns, key_clauses,
                breach_history, source, now, now, now
            ))
        
        conn.commit()
        
        # Fetch and return the stored record
        cursor.execute("SELECT * FROM websites WHERE domain = ?", (clean,))
        result = dict(cursor.fetchone())
        return _parse_json_fields(result)
    finally:
        conn.close()


# ===== Dashboard & Stats =====

@router.get("/stats")
async def get_admin_stats():
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
