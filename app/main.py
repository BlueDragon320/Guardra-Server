import os
import io
import json
import zipfile
import logging
from datetime import datetime
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from app.database import get_db_connection, init_db
from app.routers import policy, deletion, breach, hub
from app.routers import admin
from app.services.cookie_service import seed_default_rules, compute_rules_for_domain

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Guardra Privacy Suite API",
    description="Backend engine for privacy policy scoring (DPDP/GDPR/CCPA), automated deletion requests, k-anonymity breach monitoring, and privacy hub.",
    version="2.0.0"
)

# Enable CORS for frontend and browser extensions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(policy.router)
app.include_router(deletion.router)
app.include_router(breach.router)
app.include_router(hub.router)
app.include_router(hub.telemetry_router)
app.include_router(admin.router)


@app.on_event("startup")
async def startup_event():
    """Initialize database, seed data, and migrate cached policies."""
    init_db()
    seed_default_rules()
    _seed_cached_policies()
    _sync_visited_pings_to_websites()
    _migrate_and_fix_policy_urls()


def _migrate_and_fix_policy_urls():
    """Fixes any legacy policy URLs stored in the SQLite database to proper working endpoints."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        known = {
            "croma.com": "https://www.croma.com/privacy-policy",
            "kletech.ac.in": "https://www.kletech.ac.in/privacy-policy",
            "swiggy.com": "https://www.swiggy.com/privacy-policy",
            "zomato.com": "https://www.zomato.com/privacy",
            "flipkart.com": "https://www.flipkart.com/pages/privacypolicy",
            "apple.com": "https://www.apple.com/legal/privacy/en-ww/",
            "boat-lifestyle.com": "https://www.boat-lifestyle.com/pages/privacy-policy",
            "zerodha.com": "https://zerodha.com/privacy",
            "google.com": "https://policies.google.com/privacy",
            "meta.com": "https://www.facebook.com/privacy/policy/",
            "amazon.in": "https://www.amazon.in/gp/help/customer/display.html?nodeId=200534380",
            "paytm.com": "https://paytm.com/privacy-policy",
            "netflix.com": "https://help.netflix.com/legal/privacy"
        }
        for d, u in known.items():
            cursor.execute("UPDATE websites SET policy_url = ? WHERE domain = ?", (u, d))
        
        # General cleanup for any remaining rows
        cursor.execute("SELECT domain, policy_url FROM websites")
        rows = cursor.fetchall()
        for r in rows:
            dom = r["domain"]
            p_url = r["policy_url"] or ""
            if not p_url or p_url.endswith(f"{dom}/privacy") or not p_url.startswith("http"):
                new_url = f"https://www.{dom}/privacy-policy"
                cursor.execute("UPDATE websites SET policy_url = ? WHERE domain = ?", (new_url, dom))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _sync_visited_pings_to_websites():
    """Ensures all user-visited domains logged in browser_pings are stored in websites table."""
    from datetime import timedelta
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT domain FROM browser_pings")
        ping_domains = [r["domain"].replace("www.", "") for r in cursor.fetchall() if r["domain"]]
        
        now_iso = datetime.utcnow().isoformat()
        expires_iso = (datetime.utcnow() + timedelta(hours=24)).isoformat()
        
        for dom in ping_domains:
            cursor.execute("SELECT id FROM websites WHERE domain = ?", (dom,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO websites (
                        domain, name, category, policy_url, overall_score, grade, grade_color,
                        pillar_scores, compliance, source, scan_count, first_analyzed_at, last_analyzed_at, expires_at, updated_at
                    ) VALUES (?, ?, 'Visited Site', 60, 'C', 'amber', '{}', '{}', 'extension_visited', 1, ?, ?, ?, ?)
                """, (dom, dom.split(".")[0].upper(), now_iso, now_iso, expires_iso, now_iso))
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()


def _seed_cached_policies():
    """One-time migration: load cached_policies.json into the websites table."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM websites")
        count = cursor.fetchone()["count"]
        
        data_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "data", "cached_policies.json"
        )
        
        if not os.path.exists(data_path):
            logger.warning("cached_policies.json not found, skipping seed")
            return
        
        with open(data_path, "r", encoding="utf-8") as f:
            cached = json.load(f)
        
        now = datetime.utcnow().isoformat()
        
        for site in cached:
            try:
                cursor.execute("""
                    INSERT INTO websites (
                        domain, name, category, policy_url, overall_score, grade, grade_color,
                        pillar_scores, compliance, findings, key_concerns, key_clauses,
                        breach_history, source, scan_count, first_analyzed_at,
                        last_analyzed_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'cached', 1, ?, ?, ?)
                    ON CONFLICT(domain) DO UPDATE SET policy_url=excluded.policy_url, key_clauses=excluded.key_clauses, compliance=excluded.compliance, pillar_scores=excluded.pillar_scores, overall_score=excluded.overall_score, grade=excluded.grade, findings=excluded.findings
                """, (
                    site.get("domain", ""),
                    site.get("name", ""),
                    site.get("category", "Web Service"),
                    site.get("policy_url", ""),
                    site.get("score", 0),
                    site.get("grade", "N/A"),
                    site.get("color", "gray"),
                    json.dumps(site.get("rubric", {})),
                    json.dumps(site.get("compliance", {})),
                    json.dumps({}),  # findings not in cached format
                    json.dumps(site.get("key_concerns", [])),
                    json.dumps(site.get("key_clauses", [])),
                    json.dumps(site.get("breaches", [])),
                    now, now, now
                ))
            except Exception as e:
                logger.error(f"Error seeding {site.get('domain')}: {e}")
        
        conn.commit()
        logger.info(f"Seeded {len(cached)} cached policies into websites table")
    except Exception as e:
        logger.error(f"Error during seed migration: {e}")
    finally:
        conn.close()


from fastapi import FastAPI, Response, Request

@app.get("/")
async def root(request: Request):
    static_landing = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "landing.html")
    accept = request.headers.get("accept", "")
    if "text/html" in accept and os.path.exists(static_landing):
        from fastapi.responses import FileResponse
        return FileResponse(static_landing)
    return {
        "service": "Guardra Privacy Suite API",
        "version": "2.0.0",
        "status": "online",
        "portal": "/admin",
        "documentation": "/docs",
        "admin_endpoints": "/api/admin/stats",
        "health": "/api/health"
    }


@app.get("/admin")
async def admin_root():
    static_admin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "admin.html")
    if os.path.exists(static_admin):
        from fastapi.responses import FileResponse
        return FileResponse(static_admin)
    from app.routers.admin import get_admin_dashboard_stats
    return await get_admin_dashboard_stats()


@app.get("/api/admin")
async def admin_api_root():
    from app.routers.admin import get_admin_dashboard_stats
    return await get_admin_dashboard_stats()


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Guardra Privacy Suite Backend",
        "version": "2.0.0",
        "features": [
            "DPDP Act 2023 / GDPR Compliance Scorer",
            "Real-time Policy NLP Rubric Analyzer",
            "K-Anonymity HIBP Breach Checker",
            "Statutory Deletion Request Generator & PDF Builder",
            "One-Place Privacy Control Hub",
            "Admin Dashboard & Website Management",
            "Cookie Management & Blocking Rules",
            "Top 5000 Websites Pipeline"
        ]
    }

@app.get("/api/extension/download")
async def download_extension_zip():
    """Package the /extension directory into a zip file and stream it for direct installation"""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ext_dir = os.path.join(base_dir, "extension")
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(ext_dir):
            for file in files:
                abs_file = os.path.join(root, file)
                rel_file = os.path.relpath(abs_file, ext_dir)
                zf.write(abs_file, rel_file)
                
    zip_buffer.seek(0)
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": "attachment; filename=guardra-extension.zip"
        }
    )


@app.get("/api/websites/{domain}/cookie-rules")
async def get_cookie_rules_for_domain(domain: str):
    """Public endpoint for the extension to fetch computed cookie block/allow/ignore rules for a domain."""
    from app.services.policy_analyzer import clean_domain
    clean = clean_domain(domain)
    
    # Get detected cookies from DB if available
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
        
        rules = compute_rules_for_domain(clean, detected_cookies)
        rules["domain"] = clean
        rules["total_cookies"] = len(detected_cookies)
        return rules
    finally:
        conn.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
