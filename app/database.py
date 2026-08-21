import sqlite3
import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "guardra.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Deletion requests table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS deletion_requests (
        id TEXT PRIMARY KEY,
        site_domain TEXT NOT NULL,
        site_name TEXT NOT NULL,
        legal_basis TEXT NOT NULL,
        user_name TEXT NOT NULL,
        user_email TEXT NOT NULL,
        user_phone TEXT,
        account_identifier TEXT,
        grievance_email TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Sent',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        notes TEXT,
        tracking_history TEXT
    )
    """)

    # Privacy footprint and onboarding state
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_profile (
        id TEXT PRIMARY KEY,
        name TEXT DEFAULT 'Privacy Advocate',
        email TEXT DEFAULT 'user@guardra.local',
        footprint_score INTEGER DEFAULT 45,
        completed_actions TEXT DEFAULT '[]',
        created_at TEXT NOT NULL
    )
    """)

    # Extension ping audit logs table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ping_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        domain TEXT NOT NULL,
        client_ip TEXT,
        user_agent TEXT,
        client_type TEXT DEFAULT 'extension',
        grade TEXT,
        score INTEGER,
        response_time_ms REAL DEFAULT 0.0,
        status_code INTEGER DEFAULT 200
    )
    """)

    # Index for fast domain and timestamp queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ping_logs_timestamp ON ping_logs(timestamp DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ping_logs_domain ON ping_logs(domain)")

    # Check if default user profile exists
    cursor.execute("SELECT id FROM user_profile WHERE id = 'default'")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO user_profile (id, name, email, footprint_score, completed_actions, created_at)
        VALUES ('default', 'Privacy Advocate', 'user@guardra.local', 52, '["enable_2fa", "install_extension"]', ?)
        """, (datetime.utcnow().isoformat(),))
        
    conn.commit()
    conn.close()

def log_extension_ping(
    domain: str,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    client_type: str = "extension",
    grade: Optional[str] = None,
    score: Optional[int] = None,
    response_time_ms: float = 0.0
):
    """Records an incoming extension rating request to SQLite."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO ping_logs (timestamp, domain, client_ip, user_agent, client_type, grade, score, response_time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            domain.lower().strip(),
            client_ip or "127.0.0.1",
            user_agent or "GuardraExtension/1.0",
            client_type,
            grade or "N/A",
            score if score is not None else 0,
            round(response_time_ms, 2)
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error logging ping for {domain}: {e}")

def get_recent_pings(limit: int = 100, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent extension ping logs."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if search:
            s = f"%{search.lower().strip()}%"
            cursor.execute("""
            SELECT id, timestamp, domain, client_ip, user_agent, client_type, grade, score, response_time_ms
            FROM ping_logs
            WHERE domain LIKE ? OR client_ip LIKE ?
            ORDER BY id DESC
            LIMIT ?
            """, (s, s, limit))
        else:
            cursor.execute("""
            SELECT id, timestamp, domain, client_ip, user_agent, client_type, grade, score, response_time_ms
            FROM ping_logs
            ORDER BY id DESC
            LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"Error fetching ping logs: {e}")
        return []

def get_ping_stats() -> Dict[str, Any]:
    """Computes aggregated ping metrics."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Total pings count
        cursor.execute("SELECT COUNT(*) FROM ping_logs")
        total_pings = cursor.fetchone()[0]

        # Unique domains pinged
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM ping_logs")
        unique_domains = cursor.fetchone()[0]

        # Top 10 most queried domains
        cursor.execute("""
        SELECT domain, COUNT(*) as count, grade, AVG(score) as avg_score
        FROM ping_logs
        GROUP BY domain
        ORDER BY count DESC
        LIMIT 10
        """)
        top_domains = [dict(r) for r in cursor.fetchall()]

        # Average response latency
        cursor.execute("SELECT AVG(response_time_ms) FROM ping_logs")
        avg_latency = cursor.fetchone()[0] or 0.0

        conn.close()
        return {
            "total_pings": total_pings,
            "unique_domains": unique_domains,
            "avg_latency_ms": round(avg_latency, 2),
            "top_domains": top_domains
        }
    except Exception as e:
        print(f"Error computing ping stats: {e}")
        return {
            "total_pings": 0,
            "unique_domains": 0,
            "avg_latency_ms": 0.0,
            "top_domains": []
        }

# Initialize DB on module import
init_db()
