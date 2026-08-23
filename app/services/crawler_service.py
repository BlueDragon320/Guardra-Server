import os
import json
import hashlib
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional
import httpx
from bs4 import BeautifulSoup
from app.services.policy_analyzer import analyze_live_policy, clean_domain, load_cached_policies, DATA_PATH

TOP_DOMAINS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "top_1000_domains.json")
CRAWLER_LOGS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "crawler_history.json")

# In-memory crawler status
CRAWLER_STATUS = {
    "is_running": False,
    "current_site": None,
    "progress": 0,
    "total": 0,
    "scanned_count": 0,
    "updated_count": 0,
    "last_run": None,
    "last_results": []
}

def load_top_1000_domains() -> List[Dict[str, str]]:
    if os.path.exists(TOP_DOMAINS_PATH):
        try:
            with open(TOP_DOMAINS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_cached_policies(policies: List[Dict[str, Any]]) -> bool:
    try:
        with open(DATA_PATH, "w", encoding="utf-8") as f:
            json.dump(policies, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving policies to {DATA_PATH}: {e}")
        return False

async def crawl_and_rescore_domain(domain: str) -> Dict[str, Any]:
    """Scrapes a single domain's live policy endpoints, computes fresh rubric scores with breach intelligence, and updates database."""
    from app.services.policy_analyzer import discover_and_fetch_policy, analyze_live_policy, _get_grade
    from app.services.breach_service import get_domain_breaches
    from app.database import get_db_connection
    clean = clean_domain(domain)

    domain_breaches = get_domain_breaches(clean)
    policy_url, scraped_html = await discover_and_fetch_policy(clean)

    if not scraped_html:
        name = clean.split(".")[0].title()
        fallback_score = 0
        grade, color = _get_grade(fallback_score)
        fresh_rating = {
            "domain": clean,
            "name": name,
            "policy_url": None,
            "grade": grade,
            "score": fallback_score,
            "color": color,
            "summary": f"🚨 Critical Privacy Alert: No valid privacy policy exists or could be found for {name} ({clean}).",
            "breaches": domain_breaches,
            "rubric": {
                "data_sharing": { "score": 0, "max": 100, "label": "🚨 Undisclosed Data Sharing", "risk": "high" },
                "retention": { "score": 0, "max": 100, "label": "🚨 Undisclosed Retention Limits", "risk": "high" },
                "tracking_cookies": { "score": 0, "max": 100, "label": "🚨 Unregulated Telemetry", "risk": "high" },
                "user_rights": { "score": 0, "max": 100, "label": "🚨 No Erasure Rights", "risk": "high" },
                "breach_history": { "score": (0 if domain_breaches else 10), "max": 100, "label": ("🚨 Recorded Data Breach" if domain_breaches else "No Disclosed Security Safeguards"), "risk": "high" },
                "readability": { "score": 0, "max": 100, "label": "No Policy Found", "risk": "high" }
            },
            "compliance": {
                "dpdp": { "compliant": False, "grievance_officer": None, "grievance_email": None, "redressal_period_days": None, "erasure_right_disclosed": False },
                "gdpr": { "compliant": False, "dpo_contact": None, "erasure_art17_disclosed": False },
                "ccpa": { "compliant": False, "do_not_sell": False }
            },
            "key_clauses": [
                {"type": "negative", "text": "No public privacy policy could be located for this domain."}
            ],
            "findings": {
                "data_sharing": ["No privacy policy was located to verify data sharing safeguards."],
                "retention": ["No privacy policy was located to verify data retention limits."],
                "user_rights": ["No mechanism disclosed for users to exercise data erasure or deletion rights."]
            },
            "key_concerns": [f"No privacy policy exists for {clean}. All data handling is completely undisclosed and unverified."],
            "category": "Web Service",
            "last_crawled": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "missing_policy_zero_score"
        }
    else:
        content_hash = hashlib.sha256(scraped_html.encode('utf-8')).hexdigest()[:16]
        fresh_rating = analyze_live_policy(policy_url or clean, scraped_html, domain_breaches=domain_breaches)
        fresh_rating["last_crawled"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fresh_rating["policy_hash"] = content_hash
        fresh_rating["policy_url"] = policy_url or f"https://www.{clean}/privacy-policy"
        fresh_rating["breaches"] = domain_breaches
        fresh_rating["source"] = "automated_crawler"

    # 1. Update SQLite database
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        now_iso = datetime.utcnow().isoformat()
        cursor.execute("SELECT id FROM websites WHERE domain = ?", (clean,))
        existing = cursor.fetchone()
        
        pillar_json = json.dumps(fresh_rating.get("rubric", {}))
        comp_json = json.dumps(fresh_rating.get("compliance", {}))
        find_json = json.dumps(fresh_rating.get("findings", {}))
        concerns_json = json.dumps(fresh_rating.get("key_concerns", []))
        clauses_json = json.dumps(fresh_rating.get("key_clauses", []))
        breaches_json = json.dumps(fresh_rating.get("breaches", []))
        
        if existing:
            cursor.execute("""
                UPDATE websites SET
                    name = ?, category = ?, overall_score = ?, grade = ?, grade_color = ?,
                    pillar_scores = ?, compliance = ?, findings = ?, key_concerns = ?,
                    key_clauses = ?, breach_history = ?, policy_url = ?, last_analyzed_at = ?,
                    scan_count = scan_count + 1, updated_at = ?
                WHERE domain = ?
            """, (
                fresh_rating.get("name", clean), fresh_rating.get("category", "Web Service"),
                fresh_rating.get("score", 50), fresh_rating.get("grade", "C"), fresh_rating.get("color", "gray"),
                pillar_json, comp_json, find_json, concerns_json,
                clauses_json, breaches_json, fresh_rating.get("policy_url"), now_iso, now_iso, clean
            ))
        else:
            cursor.execute("""
                INSERT INTO websites (
                    domain, name, category, overall_score, grade, grade_color,
                    pillar_scores, compliance, findings, key_concerns, key_clauses,
                    breach_history, policy_url, source, scan_count, first_analyzed_at,
                    last_analyzed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'automated_crawler', 1, ?, ?, ?)
            """, (
                clean, fresh_rating.get("name", clean), fresh_rating.get("category", "Web Service"),
                fresh_rating.get("score", 50), fresh_rating.get("grade", "C"), fresh_rating.get("color", "gray"),
                pillar_json, comp_json, find_json, concerns_json,
                clauses_json, breaches_json, fresh_rating.get("policy_url"), now_iso, now_iso, now_iso
            ))
        conn.commit()
    finally:
        conn.close()

    # 2. Update cached_policies.json
    all_policies = load_cached_policies()
    updated = False
    old_grade = None
    old_score = None

    for i, site in enumerate(all_policies):
        if clean_domain(site.get("domain", "")) == clean:
            old_grade = site.get("grade")
            old_score = site.get("score")
            fresh_rating["category"] = site.get("category", fresh_rating.get("category", "Web Platform"))
            all_policies[i] = fresh_rating
            updated = True
            break

    if not updated:
        all_policies.append(fresh_rating)

    save_cached_policies(all_policies)

    return {
        "domain": clean,
        "status": "success",
        "old_grade": old_grade,
        "new_grade": fresh_rating["grade"],
        "old_score": old_score,
        "new_score": fresh_rating["score"],
        "last_crawled": fresh_rating["last_crawled"],
        "rating": fresh_rating
    }

async def run_top_1000_crawler_job() -> Dict[str, Any]:
    """Scans the top 1000 sites in background batches."""
    global CRAWLER_STATUS
    if CRAWLER_STATUS["is_running"]:
        return {"status": "already_running"}

    top_domains = load_top_1000_domains()
    if not top_domains:
        return {"status": "error", "message": "No top domains configured."}

    CRAWLER_STATUS["is_running"] = True
    CRAWLER_STATUS["total"] = len(top_domains)
    CRAWLER_STATUS["progress"] = 0
    CRAWLER_STATUS["scanned_count"] = 0
    CRAWLER_STATUS["last_results"] = []

    results = []

    # Process in concurrent chunks of 5
    chunk_size = 5
    for i in range(0, len(top_domains), chunk_size):
        chunk = top_domains[i:i+chunk_size]
        tasks = [crawl_and_rescore_domain(d["domain"]) for d in chunk]
        chunk_results = await asyncio.gather(*tasks, return_exceptions=True)

        for cr in chunk_results:
            if isinstance(cr, dict):
                results.append(cr)
            else:
                results.append({"status": "error", "message": str(cr)})

        CRAWLER_STATUS["progress"] = min(i + chunk_size, len(top_domains))
        CRAWLER_STATUS["current_site"] = chunk[-1]["domain"] if chunk else None
        CRAWLER_STATUS["scanned_count"] = len(results)

        # Brief rest between chunks
        await asyncio.sleep(0.5)

    CRAWLER_STATUS["is_running"] = False
    CRAWLER_STATUS["current_site"] = None
    CRAWLER_STATUS["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    CRAWLER_STATUS["last_results"] = results[:50] # Store recent 50 in memory

    # Save summary to crawler history file
    try:
        with open(CRAWLER_LOGS_PATH, "w", encoding="utf-8") as f:
            json.dump({
                "last_run": CRAWLER_STATUS["last_run"],
                "total_scanned": len(results),
                "successful": len([r for r in results if r.get("status") == "success"])
            }, f, indent=2)
    except Exception:
        pass

    return {
        "status": "completed",
        "total_scanned": len(results),
        "last_run": CRAWLER_STATUS["last_run"]
    }

async def run_bulk_rescore_job() -> Dict[str, Any]:
    """Rescores all domains currently present in the database and cached policies."""
    global CRAWLER_STATUS
    if CRAWLER_STATUS["is_running"]:
        return {"status": "already_running"}

    from app.database import get_db_connection
    domains_to_rescore = []
    
    # 1. Fetch domains from database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM websites")
        rows = cursor.fetchall()
        for r in rows:
            d = clean_domain(r["domain"] if isinstance(r, dict) else r[0])
            if d and d not in domains_to_rescore:
                domains_to_rescore.append(d)
        conn.close()
    except Exception:
        pass
        
    # 2. Fetch cached policies
    cached = load_cached_policies()
    for p in cached:
        d = clean_domain(p.get("domain", ""))
        if d and d not in domains_to_rescore:
            domains_to_rescore.append(d)
            
    if not domains_to_rescore:
        return {"status": "error", "message": "No websites in database to rescore."}

    CRAWLER_STATUS["is_running"] = True
    CRAWLER_STATUS["total"] = len(domains_to_rescore)
    CRAWLER_STATUS["progress"] = 0
    CRAWLER_STATUS["scanned_count"] = 0
    CRAWLER_STATUS["last_results"] = []

    results = []
    chunk_size = 5
    for i in range(0, len(domains_to_rescore), chunk_size):
        chunk = domains_to_rescore[i:i+chunk_size]
        tasks = [crawl_and_rescore_domain(d) for d in chunk]
        chunk_results = await asyncio.gather(*tasks, return_exceptions=True)

        for cr in chunk_results:
            if isinstance(cr, dict):
                results.append(cr)
            else:
                results.append({"status": "error", "message": str(cr)})

        CRAWLER_STATUS["progress"] = min(i + chunk_size, len(domains_to_rescore))
        CRAWLER_STATUS["current_site"] = chunk[-1] if chunk else None
        CRAWLER_STATUS["scanned_count"] = len(results)

        await asyncio.sleep(0.3)

    CRAWLER_STATUS["is_running"] = False
    CRAWLER_STATUS["current_site"] = None
    CRAWLER_STATUS["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    CRAWLER_STATUS["last_results"] = results[:50]

    return {
        "status": "completed",
        "total_scanned": len(results),
        "last_run": CRAWLER_STATUS["last_run"]
    }

def get_crawler_status() -> Dict[str, Any]:
    return CRAWLER_STATUS
