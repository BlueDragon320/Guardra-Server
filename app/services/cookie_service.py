import sqlite3
from datetime import datetime
from app.database import get_db_connection
import logging

logger = logging.getLogger(__name__)

COOKIE_CATEGORIES = {
    'essential': {
        'patterns': ['session', 'csrf', '__cf_bm', 'cart', 'basket', 'auth', 'login',
                     'jwt', 'token', 'cookieconsent', 'optanon', 'PHPSESSID', '__cfduid',
                     'XSRF-TOKEN', 'laravel_session', 'connect.sid', 'rack.session'],
        'default_action': 'allow',
    },
    'analytics': {
        'patterns': ['_ga', '_gid', '_gat', 'amplitude', 'mixpanel', '_hjSession',
                     '_hjid', 'mp_', 'ajs_', '__hstc', 'hubspot', '_clck', '_clsk',
                     '__utma', '__utmb', '__utmc', '__utmz', 'plausible'],
        'default_action': 'block',
    },
    'advertising': {
        'patterns': ['_fbp', '_fbc', 'fr', '_gcl', 'IDE', 'test_cookie', 'cto_',
                     '_ttp', '_tt_', '1P_JAR', 'MUID', 'NID', 'APISID', 'SSID',
                     'HSID', 'SAPISID', 'SID', 'SIDCC', 'OGPC', '__gads',
                     'pagead', 'ads_prefs', 'DSID'],
        'default_action': 'block',
    },
    'social_media': {
        'patterns': ['datr', 'li_sugr', 'bcookie', 'lidc', 'snap_', 'sc_at',
                     'sb', 'wd', 'c_user', 'xs', 'presence', 'act', 'spin'],
        'default_action': 'block',
    },
}

def classify_cookie(cookie_name: str) -> dict:
    """Classify a cookie name into a category and return default action."""
    cookie_name_lower = cookie_name.lower()
    for category, data in COOKIE_CATEGORIES.items():
        for pattern in data['patterns']:
            if cookie_name_lower.startswith(pattern.lower()) or cookie_name_lower == pattern.lower():
                return {"category": category, "default_action": data['default_action']}
    return {"category": "unknown", "default_action": "block"}

def get_preferences(domain: str) -> list[dict]:
    """Fetch all per-site cookie preferences for a domain."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, domain, cookie_name, cookie_category, action, created_at, updated_at
                FROM cookie_preferences
                WHERE domain = ?
            ''', (domain,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as e:
        logger.error(f"Error fetching preferences: {e}")
        return []

def set_preference(domain: str, cookie_name: str, action: str, cookie_category: str = None) -> dict:
    """Insert or update a single cookie preference."""
    if action not in ('block', 'allow', 'ignore'):
        raise ValueError("Invalid action")
    
    if not cookie_category:
        classification = classify_cookie(cookie_name)
        cookie_category = classification['category']

    now = datetime.utcnow().isoformat()
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO cookie_preferences
                (domain, cookie_name, cookie_category, action, created_at, updated_at)
                VALUES (?, ?, ?, ?, COALESCE((SELECT created_at FROM cookie_preferences WHERE domain=? AND cookie_name=?), ?), ?)
            ''', (domain, cookie_name, cookie_category, action, domain, cookie_name, now, now))
            conn.commit()
            
            cursor.execute('SELECT * FROM cookie_preferences WHERE domain = ? AND cookie_name = ?', (domain, cookie_name))
            return dict(cursor.fetchone())
    except sqlite3.Error as e:
        logger.error(f"Error setting preference: {e}")
        return {}

def set_bulk_preferences(domain: str, preferences: list[dict]) -> list[dict]:
    """Batch update per-site preferences."""
    results = []
    for pref in preferences:
        res = set_preference(
            domain,
            pref['cookie_name'],
            pref['action'],
            pref.get('cookie_category')
        )
        if res:
            results.append(res)
    return results

def ignore_cookie(domain: str, cookie_name: str) -> dict:
    """Sets action='ignore' for this cookie on this domain."""
    return set_preference(domain, cookie_name, 'ignore')

def unignore_cookie(domain: str, cookie_name: str) -> dict:
    """Deletes the per-site override."""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM cookie_preferences WHERE domain = ? AND cookie_name = ?', (domain, cookie_name))
            conn.commit()
        return {"status": "removed"}
    except sqlite3.Error as e:
        logger.error(f"Error unignoring cookie: {e}")
        return {"status": "error"}

def compute_rules_for_domain(domain: str, detected_cookies: list[dict] = None) -> dict:
    """Computes the final block/allow/ignore lists."""
    result = {"block": [], "allow": [], "ignore": []}
    
    if detected_cookies is None:
        detected_cookies = []

    # Get per-site overrides
    preferences = get_preferences(domain)
    pref_map = {p['cookie_name']: p['action'] for p in preferences}
    
    # Process detected cookies
    for cookie in detected_cookies:
        name = cookie.get('name', '')
        if not name:
            continue
            
        # 1. Classify cookie
        classification = classify_cookie(name)
        category = classification['category']
        
        # 2. Apply rules and overrides
        if name in pref_map:
            action = pref_map[name]
        else:
            action = classification['default_action']
            if category == 'essential':
                action = 'allow'
                
        # Essential overrides logic as per instructions
        if action == 'ignore':
            result['ignore'].append(name)
        elif action == 'allow':
            result['allow'].append(name)
        else:
            result['block'].append(name)
        
    return result

def get_global_rules() -> list[dict]:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM global_cookie_rules')
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    except sqlite3.Error as e:
        logger.error(f"Error fetching global rules: {e}")
        return []

def add_global_rule(cookie_pattern: str, cookie_category: str, default_action: str, description: str) -> dict:
    now = datetime.utcnow().isoformat()
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO global_cookie_rules 
                (cookie_pattern, cookie_category, default_action, description, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (cookie_pattern, cookie_category, default_action, description, now))
            conn.commit()
            
            rule_id = cursor.lastrowid
            cursor.execute('SELECT * FROM global_cookie_rules WHERE id = ?', (rule_id,))
            return dict(cursor.fetchone())
    except sqlite3.Error as e:
        logger.error(f"Error adding global rule: {e}")
        return {}

def update_global_rule(rule_id: int, cookie_pattern: str = None, cookie_category: str = None, default_action: str = None, description: str = None) -> dict:
    updates = []
    params = []
    
    if cookie_pattern is not None:
        updates.append("cookie_pattern = ?")
        params.append(cookie_pattern)
    if cookie_category is not None:
        updates.append("cookie_category = ?")
        params.append(cookie_category)
    if default_action is not None:
        updates.append("default_action = ?")
        params.append(default_action)
    if description is not None:
        updates.append("description = ?")
        params.append(description)
        
    if not updates:
        return {}

    params.append(rule_id)
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = f"UPDATE global_cookie_rules SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, tuple(params))
            conn.commit()
            
            cursor.execute('SELECT * FROM global_cookie_rules WHERE id = ?', (rule_id,))
            return dict(cursor.fetchone())
    except sqlite3.Error as e:
        logger.error(f"Error updating global rule: {e}")
        return {}

def delete_global_rule(rule_id: int) -> dict:
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM global_cookie_rules WHERE id = ?', (rule_id,))
            conn.commit()
            return {"status": "deleted"}
    except sqlite3.Error as e:
        logger.error(f"Error deleting global rule: {e}")
        return {"status": "error"}

def seed_default_rules() -> None:
    defaults = [
        ('_ga', 'analytics', 'block', 'Google Analytics'),
        ('_fbp', 'advertising', 'block', 'Facebook Pixel'),
        ('_gcl', 'advertising', 'block', 'Google Ads Conversion'),
        ('cto_', 'advertising', 'block', 'Criteo'),
        ('_hjSession', 'analytics', 'block', 'Hotjar'),
        ('_ttp', 'advertising', 'block', 'TikTok Pixel'),
        ('IDE', 'advertising', 'block', 'Doubleclick'),
        ('MUID', 'advertising', 'block', 'Bing Ads')
    ]
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) as count FROM global_cookie_rules')
            count = cursor.fetchone()['count']
            
            if count == 0:
                now = datetime.utcnow().isoformat()
                for pattern, cat, action, desc in defaults:
                    cursor.execute('''
                        INSERT INTO global_cookie_rules 
                        (cookie_pattern, cookie_category, default_action, description, created_at)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (pattern, cat, action, desc, now))
                conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Error seeding default rules: {e}")
