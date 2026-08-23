import sqlite3
import os
import json
from datetime import datetime

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

    # Persists all analyzed website data
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS websites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        name TEXT,
        category TEXT,
        overall_score REAL,
        grade TEXT,
        grade_color TEXT,
        pillar_scores TEXT,
        compliance TEXT,
        findings TEXT,
        key_concerns TEXT,
        key_clauses TEXT,
        policy_text TEXT,
        policy_url TEXT,
        cookie_data TEXT,
        tracker_data TEXT,
        dark_pattern_data TEXT,
        breach_history TEXT,
        is_top_5000 INTEGER DEFAULT 0,
        tranco_rank INTEGER,
        source TEXT DEFAULT 'manual',
        scan_count INTEGER DEFAULT 1,
        first_analyzed_at TEXT,
        last_analyzed_at TEXT,
        updated_at TEXT
    )
    """)

    # Per-site cookie preferences (block/allow/ignore overrides)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cookie_preferences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        cookie_name TEXT NOT NULL,
        cookie_category TEXT,
        action TEXT DEFAULT 'block',
        created_at TEXT,
        updated_at TEXT,
        UNIQUE(domain, cookie_name)
    )
    """)

    # Global cookie rules (applied across ALL websites unless overridden)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS global_cookie_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cookie_pattern TEXT NOT NULL UNIQUE,
        cookie_category TEXT,
        default_action TEXT DEFAULT 'block',
        description TEXT,
        created_at TEXT
    )
    """)

    # Admin action audit trail
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        target TEXT,
        details TEXT,
        performed_at TEXT
    )
    """)

    # Check if default user profile exists
    cursor.execute("SELECT id FROM user_profile WHERE id = 'default'")
    if not cursor.fetchone():
        cursor.execute("""
        INSERT INTO user_profile (id, name, email, footprint_score, completed_actions, created_at)
        VALUES ('default', 'Privacy Advocate', 'user@guardra.local', 52, '["enable_2fa", "install_extension"]', ?)
        """, (datetime.utcnow().isoformat(),))
        
    conn.commit()
    conn.close()

# Initialize DB on module import
init_db()
