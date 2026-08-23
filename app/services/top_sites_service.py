import asyncio
import json
import io
import zipfile
import csv
import logging
from datetime import datetime, timedelta
import httpx

from app.database import get_db_connection
from app.services.policy_analyzer import get_site_rating

logger = logging.getLogger(__name__)

_pipeline_status = {
    "status": "idle",  # idle | running | completed | error
    "total": 0,
    "scanned": 0,
    "errors": 0,
    "skipped": 0,
    "started_at": None,
    "completed_at": None,
    "error_message": None,
    "current_domain": None
}

def get_pipeline_status() -> dict:
    """Returns a copy of the current pipeline status."""
    return _pipeline_status.copy()

async def fetch_tranco_list(limit: int = 5000) -> list[tuple[int, str]]:
    """
    Downloads the Tranco top-1m list, extracts the CSV, and takes the first `limit` entries.
    Returns a list of (rank, domain) tuples.
    """
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                content = f.read().decode('utf-8')
                
        reader = csv.reader(io.StringIO(content))
        results = []
        for i, row in enumerate(reader):
            if i >= limit:
                break
            if len(row) >= 2:
                results.append((int(row[0]), row[1]))
        return results
    except Exception as e:
        logger.error(f"Error fetching Tranco list: {e}")
        return []

def filter_scannable_domains(domains: list[tuple[int, str]], max_age_days: int = 30) -> list[tuple[int, str]]:
    """
    Filters out domains that were already scanned within `max_age_days`.
    Returns only domains that need scanning.
    """
    conn = get_db_connection()
    try:
        cutoff_date = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat()
        cursor = conn.cursor()
        
        domain_names = [d[1] for d in domains]
        if not domain_names:
            return []
            
        # SQLite maximum number of host parameters is usually 999 or 32766, 
        # so chunking might be needed for 5000 parameters.
        recent_domains = set()
        chunk_size = 900
        for i in range(0, len(domain_names), chunk_size):
            chunk = domain_names[i:i + chunk_size]
            placeholders = ",".join("?" * len(chunk))
            query = f"SELECT domain, last_analyzed_at FROM websites WHERE domain IN ({placeholders})"
            cursor.execute(query, chunk)
            
            for row in cursor.fetchall():
                if row["last_analyzed_at"] and row["last_analyzed_at"] >= cutoff_date:
                    recent_domains.add(row["domain"])
                
        return [d for d in domains if d[1] not in recent_domains]
    except Exception as e:
        logger.error(f"Error filtering domains: {e}")
        return domains
    finally:
        conn.close()

async def scan_single_domain(domain: str, rank: int = None) -> dict:
    """
    Scans a single domain, gets its rating, and stores/updates it in the database.
    """
    try:
        rating_result = await get_site_rating(domain)
        
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM websites WHERE domain = ?", (domain,))
            row = cursor.fetchone()
            
            now = datetime.utcnow().isoformat()
            
            # Prepare JSON fields - map from policy_analyzer output field names to DB column names
            pillar_scores = json.dumps(rating_result.get("rubric", {}))
            compliance = json.dumps(rating_result.get("compliance", {}))
            findings = json.dumps(rating_result.get("findings", {}))
            key_concerns = json.dumps(rating_result.get("key_concerns", []))
            key_clauses = json.dumps(rating_result.get("key_clauses", []))
            breach_history = json.dumps(rating_result.get("breaches", []))
            
            overall_score = rating_result.get("score", 0)
            grade = rating_result.get("grade", "N/A")
            grade_color = rating_result.get("color", "gray")
            name = rating_result.get("name", domain)
            category = rating_result.get("category", "Web Service")
            
            if row:
                # Update existing
                query = """
                    UPDATE websites 
                    SET name = ?, category = ?, overall_score = ?, grade = ?, grade_color = ?, 
                        pillar_scores = ?, compliance = ?, findings = ?, key_concerns = ?, 
                        key_clauses = ?, breach_history = ?, last_analyzed_at = ?, 
                        scan_count = scan_count + 1, is_top_5000 = ?, tranco_rank = ?, updated_at = ?
                    WHERE domain = ?
                """
                cursor.execute(query, (
                    name, category, overall_score, grade, grade_color, pillar_scores, compliance,
                    findings, key_concerns, key_clauses, breach_history, now,
                    1 if rank is not None else 0, rank, now, domain
                ))
            else:
                # Insert new
                query = """
                    INSERT INTO websites (
                        domain, name, category, overall_score, grade, grade_color, pillar_scores, 
                        compliance, findings, key_concerns, key_clauses, breach_history,
                        is_top_5000, tranco_rank, source, scan_count, first_analyzed_at, 
                        last_analyzed_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """
                source = 'top_list' if rank is not None else 'manual'
                cursor.execute(query, (
                    domain, name, category, overall_score, grade, grade_color, pillar_scores,
                    compliance, findings, key_concerns, key_clauses, breach_history,
                    1 if rank is not None else 0, rank, source, now, now, now
                ))
            
            conn.commit()
            
            # Fetch the updated/inserted row to return
            cursor.execute("SELECT * FROM websites WHERE domain = ?", (domain,))
            return dict(cursor.fetchone())
        finally:
            conn.close()
    except Exception as e:
        logger.error(f"Error scanning domain {domain}: {e}")
        raise

async def _process_batch_with_semaphore(batch: list[tuple[int, str]], sem: asyncio.Semaphore):
    async def _scan(rank, domain):
        async with sem:
            _pipeline_status["current_domain"] = domain
            try:
                await scan_single_domain(domain, rank)
                _pipeline_status["scanned"] += 1
            except Exception:
                _pipeline_status["errors"] += 1
                
    await asyncio.gather(*[_scan(r, d) for r, d in batch])

async def run_top_5000_pipeline(limit: int = 5000, batch_size: int = 50, max_concurrent: int = 5) -> dict:
    """
    Main pipeline to fetch the top list, filter scannable domains, and process them in batches.
    """
    global _pipeline_status
    _pipeline_status.update({
        "status": "running",
        "total": 0,
        "scanned": 0,
        "errors": 0,
        "skipped": 0,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "error_message": None,
        "current_domain": None
    })
    
    try:
        domains = await fetch_tranco_list(limit)
        if not domains:
            raise Exception("Failed to fetch Tranco list or list is empty")
            
        _pipeline_status["total"] = len(domains)
        
        scannable = filter_scannable_domains(domains)
        _pipeline_status["skipped"] = len(domains) - len(scannable)
        
        # Unmark existing is_top_5000 = 1
        conn = get_db_connection()
        try:
            conn.execute("UPDATE websites SET is_top_5000 = 0")
            conn.commit()
        finally:
            conn.close()
            
        sem = asyncio.Semaphore(max_concurrent)
        
        for i in range(0, len(scannable), batch_size):
            batch = scannable[i:i + batch_size]
            await _process_batch_with_semaphore(batch, sem)
            await asyncio.sleep(1)
            
        _pipeline_status["status"] = "completed"
        
    except Exception as e:
        _pipeline_status["status"] = "error"
        _pipeline_status["error_message"] = str(e)
        logger.error(f"Pipeline fatal error: {e}")
    finally:
        _pipeline_status["completed_at"] = datetime.utcnow().isoformat()
        _pipeline_status["current_domain"] = None
        
    return _pipeline_status.copy()

def get_top_5000_websites(page: int = 1, page_size: int = 50) -> dict:
    """
    Queries the websites table for is_top_5000 = 1 ordered by tranco_rank.
    Returns paginated results.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM websites WHERE is_top_5000 = 1")
        total = cursor.fetchone()["count"]
        
        offset = (page - 1) * page_size
        
        cursor.execute(
            "SELECT * FROM websites WHERE is_top_5000 = 1 ORDER BY tranco_rank ASC LIMIT ? OFFSET ?",
            (page_size, offset)
        )
        
        items = [dict(row) for row in cursor.fetchall()]
        
        # parse json fields
        json_fields = ["pillar_scores", "compliance", "findings", "key_concerns", "key_clauses"]
        for item in items:
            for field in json_fields:
                if item.get(field):
                    try:
                        item[field] = json.loads(item[field])
                    except json.JSONDecodeError:
                        pass
                        
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size
        }
    finally:
        conn.close()
