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
