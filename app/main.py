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
app.include_router(admin.router)


@app.on_event("startup")
async def startup_event():
    """Initialize database, seed data, and migrate cached policies."""
    # Ensure all tables exist (init_db is also called on module import, but this is explicit)
    init_db()
    
    # Seed default global cookie rules
    seed_default_rules()
    
    # Migrate cached_policies.json into the websites table if empty
    _seed_cached_policies()


def _seed_cached_policies():
    """One-time migration: load cached_policies.json into the websites table."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM websites")
        count = cursor.fetchone()["count"]
        
        if count > 0:
            return  # Already seeded
        
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
                    INSERT OR IGNORE INTO websites (
                        domain, name, category, overall_score, grade, grade_color,
                        pillar_scores, compliance, findings, key_concerns, key_clauses,
                        breach_history, source, scan_count, first_analyzed_at,
                        last_analyzed_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'cached', 1, ?, ?, ?)
                """, (
                    site.get("domain", ""),
                    site.get("name", ""),
                    site.get("category", "Web Service"),
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


@app.get("/")
async def root():
    return {
        "service": "Guardra Privacy Suite API",
        "version": "2.0.0",
        "status": "online",
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
