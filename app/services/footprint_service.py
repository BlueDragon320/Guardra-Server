import json
from typing import Dict, Any, List
from app.database import get_db_connection

ALL_ACTIONS = [
    {
        "id": "install_extension",
        "title": "Install Guardra Extension",
        "category": "Protection",
        "points": 15,
        "description": "Active real-time DPDP & GDPR site rating badge and tracker detection in browser."
    },
    {
        "id": "enable_2fa",
        "title": "Enable Hardware or TOTP 2FA",
        "category": "Account Security",
        "points": 10,
        "description": "Protect Core Banking and Primary email accounts with authenticator apps or security keys."
    },
    {
        "id": "setup_email_alias",
        "title": "Setup Email Compartmentalization",
        "category": "Identity",
        "points": 15,
        "description": "Use Firefox Relay, SimpleLogin, or DuckDuckGo aliases for shopping & newsletter signups."
    },
    {
        "id": "optout_google",
        "title": "Disable Google Ad & Location Profiling",
        "category": "Ad Tracking",
        "points": 12,
        "description": "Turn off Web & App Activity, voice recordings, and personalized ad center profiling."
    },
    {
        "id": "optout_meta",
        "title": "Disconnect Meta Off-Facebook Tracking",
        "category": "Ad Tracking",
        "points": 12,
        "description": "Sever third-party website tracking pixels linked to your Instagram & Facebook account."
    },
    {
        "id": "optout_data_brokers",
        "title": "Suppress Records at 3+ Data Brokers",
        "category": "OSINT Suppression",
        "points": 15,
        "description": "Submit opt-out and suppression requests to Acxiom, LexisNexis, Whitepages, or Spokeo."
    },
    {
        "id": "passwords_secured",
        "title": "Audit Credentials via K-Anonymity",
        "category": "Account Security",
        "points": 11,
        "description": "Verify passwords have 0 breach occurrences using zero-knowledge SHA-1 prefix checks."
    },
    {
        "id": "resolved_deletion",
        "title": "Exercise Statutory Erasure Request",
        "category": "Legal Rights",
        "points": 10,
        "description": "Dispatched and tracked a formal deletion request under DPDP Act 2023 or GDPR Art. 17."
    }
]

def get_footprint_data() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT completed_actions FROM user_profile WHERE id = 'default'")
    row = cursor.fetchone()
    
    completed_ids = []
    if row and row["completed_actions"]:
        try:
            completed_ids = json.loads(row["completed_actions"])
        except Exception:
            completed_ids = []
            
    # Check if there are active or resolved deletion requests
    cursor.execute("SELECT COUNT(*) as cnt FROM deletion_requests WHERE status IN ('Resolved', 'Sent', 'Acknowledged')")
    del_count = cursor.fetchone()["cnt"]
    if del_count > 0 and "resolved_deletion" not in completed_ids:
        completed_ids.append("resolved_deletion")
        
    conn.close()

    total_points = 0
    actions_with_status = []
    
    for action in ALL_ACTIONS:
        is_completed = action["id"] in completed_ids
        if is_completed:
            total_points += action["points"]
        actions_with_status.append({
            **action,
            "completed": is_completed
        })
        
    score = min(100, total_points)
    
    if score >= 80:
        level = "Fortress (Excellent)"
        badge_color = "green"
        recommendation = "Outstanding privacy hygiene! Your digital footprint is well-compartmentalized and minimized."
    elif score >= 55:
        level = "Shielded (Good)"
        badge_color = "blue"
        recommendation = "Strong baseline. Complete remaining data broker opt-outs and platform tracking toggles to reach Fortress level."
    elif score >= 30:
        level = "Vulnerable (Moderate)"
        badge_color = "amber"
        recommendation = "Significant tracking surface. Start by setting up email aliases and opting out of Google & Meta tracking."
    else:
        level = "Exposed (High Risk)"
        badge_color = "red"
        recommendation = "Critical personal data exposure. Complete the onboarding wizard and audit compromised credentials immediately."

    return {
        "score": score,
        "level": level,
        "badge_color": badge_color,
        "recommendation": recommendation,
        "actions": actions_with_status,
        "completed_count": len(completed_ids),
        "total_actions": len(ALL_ACTIONS)
    }

def toggle_action(action_id: str) -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT completed_actions FROM user_profile WHERE id = 'default'")
    row = cursor.fetchone()
    
    completed_ids = []
    if row and row["completed_actions"]:
        try:
            completed_ids = json.loads(row["completed_actions"])
        except Exception:
            completed_ids = []
            
    if action_id in completed_ids:
        completed_ids.remove(action_id)
    else:
        completed_ids.append(action_id)
        
    cursor.execute("UPDATE user_profile SET completed_actions = ? WHERE id = 'default'", (json.dumps(completed_ids),))
    conn.commit()
    conn.close()
    
    return get_footprint_data()
