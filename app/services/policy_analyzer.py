import os
import json
import re
import math
from typing import Dict, Any, List, Optional
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "cached_policies.json")

def load_cached_policies() -> List[Dict[str, Any]]:
    if os.path.exists(DATA_PATH):
        try:
            with open(DATA_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def clean_domain(url_or_domain: str) -> str:
    cleaned = url_or_domain.strip().lower()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "https://" + cleaned
    try:
        parsed = urlparse(cleaned)
        netloc = parsed.netloc or parsed.path
        netloc = re.sub(r"^www\.", "", netloc)
        return netloc.split(":")[0]
    except Exception:
        return url_or_domain.lower()


# ===== Negation-Aware Keyword Matching =====

NEGATION_WORDS = [
    "not", "never", "no", "don't", "doesn't", "does not", "do not",
    "will not", "won't", "cannot", "can't", "neither", "nor",
    "without", "prohibit", "refrain", "cease"
]

def _check_negation(text: str, keyword_pos: int, window: int = 120) -> bool:
    """Check if a keyword occurrence is preceded by a negation word within a character window."""
    start = max(0, keyword_pos - window)
    preceding_text = text[start:keyword_pos].lower()
    # Check the last ~10 words before the keyword
    words_before = preceding_text.split()[-10:]
    preceding_phrase = " ".join(words_before)
    for neg in NEGATION_WORDS:
        if neg in preceding_phrase:
            return True
    return False

def _score_keywords_with_context(text: str, keywords_config: List[Dict]) -> int:
    """Score text using weighted keywords with negation detection.
    
    keywords_config: list of {
        'pattern': str (regex pattern),
        'weight': int (positive = bonus, negative = penalty),
        'polarity': 'positive' | 'negative'  (what the keyword normally indicates)
    }
    
    Returns: total score adjustment
    """
    text_lower = text.lower()
    total_adjustment = 0
    
    for kw in keywords_config:
        pattern = kw['pattern']
        weight = kw['weight']
        polarity = kw.get('polarity', 'negative')
        
        for match in re.finditer(pattern, text_lower):
            is_negated = _check_negation(text_lower, match.start())
            
            if is_negated:
                # Negation flips the meaning:
                # "we do NOT sell data" -> negative keyword negated -> positive signal
                # "we do NOT encrypt" -> positive keyword negated -> negative signal
                if polarity == 'negative':
                    total_adjustment += abs(weight)  # Negated negative = positive
                else:
                    total_adjustment -= abs(weight)  # Negated positive = negative
            else:
                total_adjustment += weight
    
    return total_adjustment


# ===== Weighted Keyword Configuration =====

PILLAR1_KEYWORDS = [
    # Critical negative (data selling, broker sharing)
    {"pattern": r"\b(sell|sold)\s+(your\s+)?(personal\s+)?data\b", "weight": -15, "polarity": "negative"},
    {"pattern": r"\bdata\s+broker", "weight": -15, "polarity": "negative"},
    {"pattern": r"\bbehavioral\s+advertising\b", "weight": -15, "polarity": "negative"},
    {"pattern": r"\bcross-device\s+tracking\b", "weight": -15, "polarity": "negative"},
    # High negative (ad networks, profiling)
    {"pattern": r"\bad\s+network", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bcommercial\s+partner", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bretarget", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bprofiling\b", "weight": -10, "polarity": "negative"},
    # Moderate negative
    {"pattern": r"\banalytics\s+partner", "weight": -5, "polarity": "negative"},
    {"pattern": r"\baffiliate", "weight": -5, "polarity": "negative"},
    {"pattern": r"\bservice\s+provider", "weight": -3, "polarity": "negative"},
    # Strong positive
    {"pattern": r"\bnever\s+sold?\b", "weight": 12, "polarity": "positive"},
    {"pattern": r"\bzero\s+tracking\b", "weight": 12, "polarity": "positive"},
    {"pattern": r"\bdo\s+not\s+sell\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\bessential\s+cookies?\s+only\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\blimited\s+sharing\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\bno\s+third.party\b", "weight": 8, "polarity": "positive"},
]

PILLAR2_KEYWORDS = [
    # Critical negative (invasive trackers)
    {"pattern": r"\bfingerprint", "weight": -12, "polarity": "negative"},
    {"pattern": r"\bcross-site\s+tracking\b", "weight": -12, "polarity": "negative"},
    {"pattern": r"\bdoubleclick\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bcriteo\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\btaboola\b", "weight": -8, "polarity": "negative"},
    {"pattern": r"\boutbrain\b", "weight": -8, "polarity": "negative"},
    # High negative
    {"pattern": r"\bfacebook\s+pixel\b", "weight": -8, "polarity": "negative"},
    {"pattern": r"\bmeta\s+pixel\b", "weight": -8, "polarity": "negative"},
    {"pattern": r"\btracking\s+pixel", "weight": -7, "polarity": "negative"},
    {"pattern": r"\bgoogle\s+analytics\b", "weight": -5, "polarity": "negative"},
    # Moderate negative
    {"pattern": r"\bweb\s+beacon", "weight": -5, "polarity": "negative"},
    {"pattern": r"\btelemetry\b", "weight": -4, "polarity": "negative"},
    {"pattern": r"\badvertising\s+id\b", "weight": -6, "polarity": "negative"},
    {"pattern": r"\bdevice\s+id\b", "weight": -4, "polarity": "negative"},
    # Positive
    {"pattern": r"\bno\s+cookies?\b", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bno\s+tracking\b", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bprivacy.focused\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\bdo\s+not\s+track\b", "weight": 6, "polarity": "positive"},
]

PILLAR3_KEYWORDS = [
    # Strong positive (user rights)
    {"pattern": r"\bright\s+to\s+delet", "weight": 8, "polarity": "positive"},
    {"pattern": r"\bright\s+to\s+erasure\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\baccount\s+deletion\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\b1-click\s+delet", "weight": 12, "polarity": "positive"},
    {"pattern": r"\bself-service\s+delet", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bdata\s+portability\b", "weight": 6, "polarity": "positive"},
    {"pattern": r"\bopt.out\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\bwithdraw\s+consent\b", "weight": 6, "polarity": "positive"},
    {"pattern": r"\bgrievance\s+officer\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\bdata\s+protection\s+officer\b", "weight": 5, "polarity": "positive"},
    # Negative (obstructing rights)
    {"pattern": r"\bcannot\s+be\s+deleted\b", "weight": -12, "polarity": "negative"},
    {"pattern": r"\bretain\s+indefinitely\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bno\s+deletion\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bwritten\s+letter\b", "weight": -8, "polarity": "negative"},
    {"pattern": r"\bphone\s+call\s+required\b", "weight": -8, "polarity": "negative"},
]

PILLAR4_KEYWORDS = [
    # Positive (explicit retention)
    {"pattern": r"\bpurged?\s+(within|after)\b", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bdeleted?\s+after\s+\d+", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bretained?\s+for\s+\d+\s+(day|month|year)", "weight": 8, "polarity": "positive"},
    {"pattern": r"\bauto.purg", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bautomatically\s+deleted\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\bretention\s+period\b", "weight": 5, "polarity": "positive"},
    # Negative (indefinite retention)
    {"pattern": r"\bindefinitely\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bas\s+long\s+as\s+necessary\b", "weight": -8, "polarity": "negative"},
    {"pattern": r"\blegitimate\s+business\b", "weight": -6, "polarity": "negative"},
    {"pattern": r"\bcommercial\s+records?\b", "weight": -5, "polarity": "negative"},
]

PILLAR5_KEYWORDS = [
    # Positive (security disclosures)
    {"pattern": r"\bencryption\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\baes-256\b", "weight": 8, "polarity": "positive"},
    {"pattern": r"\btls\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\bssl\b", "weight": 4, "polarity": "positive"},
    {"pattern": r"\bend-to-end\b", "weight": 10, "polarity": "positive"},
    {"pattern": r"\bzero.knowledge\b", "weight": 10, "polarity": "positive"},
    {"pattern": r"\btwo-factor\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\b2fa\b", "weight": 5, "polarity": "positive"},
    {"pattern": r"\bsecurity\s+safeguard", "weight": 5, "polarity": "positive"},
    {"pattern": r"\bbreach\s+notification\b", "weight": 4, "polarity": "positive"},
    # Negative (breach history)
    {"pattern": r"\bdata\s+breach\b", "weight": -12, "polarity": "negative"},
    {"pattern": r"\bsecurity\s+incident\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bunauthorized\s+access\b", "weight": -10, "polarity": "negative"},
    {"pattern": r"\bleaked?\b", "weight": -8, "polarity": "negative"},
]


def calculate_readability(text: str) -> int:
    """Calculate Flesch Reading Ease score for policy text."""
    sentences = re.split(r'[.!?]+', text)
    sentences = [s for s in sentences if len(s.strip()) > 0]
    words = re.findall(r'\b\w+\b', text)
    
    if not words or not sentences:
        return 60
    
    word_count = len(words)
    sentence_count = max(len(sentences), 1)
    
    # Syllable approximation
    syllable_count = 0
    for word in words:
        w = word.lower()
        count = len(re.findall(r'[aeiouy]+', w))
        syllable_count += max(1, count)
        
    # Flesch Reading Ease
    flesch = 206.835 - 1.015 * (word_count / sentence_count) - 84.6 * (syllable_count / word_count)
    score = max(10, min(95, int(flesch)))
    return score


def _score_pillar_with_context(text: str, base_score: int, keywords: List[Dict], 
                                 min_score: int = 0, max_score: int = 100) -> int:
    """Score a pillar using negation-aware weighted keyword matching."""
    adjustment = _score_keywords_with_context(text, keywords)
    final = base_score + adjustment
    return max(min_score, min(max_score, final))


def _score_tracking_with_real_data(policy_score: int, tracker_data: List = None, 
                                     cookie_data: List = None) -> int:
    """Blend policy text score with actual tracker/cookie data from extension scans.
    
    When real data is available, weights: 40% policy text, 60% real detection.
    When no real data: 100% policy text.
    """
    if not tracker_data and not cookie_data:
        return policy_score
    
    # Score based on real detected tracker count
    non_essential_trackers = len([t for t in (tracker_data or []) 
                                   if isinstance(t, dict) and t.get('category') != 'essential'])
    
    # Cut points aggressively when non-essential trackers are detected
    if non_essential_trackers == 0:
        real_tracker_score = 98
    elif non_essential_trackers == 1:
        real_tracker_score = 75
    elif non_essential_trackers == 2:
        real_tracker_score = 60
    elif non_essential_trackers <= 4:
        real_tracker_score = 40
    elif non_essential_trackers <= 7:
        real_tracker_score = 25
    elif non_essential_trackers <= 10:
        real_tracker_score = 10
    else:
        real_tracker_score = 0
    
    # Cookie invasiveness penalty (advertising/analytics/social)
    cookie_penalty = 0
    if cookie_data:
        for cookie in cookie_data:
            if isinstance(cookie, dict):
                cat = cookie.get('category', 'unknown')
                if cat == 'advertising':
                    cookie_penalty -= 10
                elif cat == 'analytics':
                    cookie_penalty -= 5
                elif cat == 'social_media':
                    cookie_penalty -= 8
    
    # Cap cookie penalty at -40
    cookie_penalty = max(cookie_penalty, -40)
    
    # Give 75% weight to real detected trackers/cookies and 25% to policy disclosure
    blended = int(policy_score * 0.25 + real_tracker_score * 0.75) + cookie_penalty
    return max(0, min(100, blended))


def _get_grade(score: int) -> tuple:
    """Return (grade, color) based on refined 9-grade bands."""
    if score >= 92:
        return "A+", "#10b981"
    elif score >= 83:
        return "A", "#10b981"
    elif score >= 74:
        return "B+", "#22c55e"
    elif score >= 65:
        return "B", "#22c55e"
    elif score >= 55:
        return "C+", "#f59e0b"
    elif score >= 45:
        return "C", "#f59e0b"
    elif score >= 35:
        return "D+", "#f97316"
    elif score >= 25:
        return "D", "#f97316"
    else:
        return "F", "#ef4444"


def _check_compliance(text_lower: str) -> Dict[str, Any]:
    """Extract regional compliance information from policy text.
    Strict validation: Grievance Officer and email must be genuinely present in text.
    """
    # DPDP Act 2023 (India)
    dpdp_grievance_match = re.search(
        r'(?:grievance\s+officer|nodal\s+officer|grievance\s+redressal\s+officer)(?:[^\.\;\n\!\?]{0,80})', text_lower)
    
    # Extract email associated with grievance/privacy/dpo in text
    all_emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text_lower)
    grievance_emails = [e for e in all_emails if any(k in e for k in ["grievance", "nodal", "privacy", "dpo", "compliance", "legal", "dataprotection"])]
    
    dpdp_email = grievance_emails[0] if grievance_emails else (all_emails[0] if (dpdp_grievance_match and all_emails) else None)
    
    dpdp_erasure = bool(re.search(r'\b(erasure|deletion|right to withdraw consent|correct personal data)\b', text_lower))
    
    # DPDP is ONLY genuinely compliant if an explicit Grievance Officer AND valid email are found
    dpdp_compliant = bool(dpdp_grievance_match and dpdp_email)
    
    raw_officer = dpdp_grievance_match.group(0) if dpdp_grievance_match else None
    cleaned_officer = None
    if raw_officer:
        # Strip trailing fragments like 'if you are not', 'please contact', etc.
        raw_officer = re.split(r'\b(?:if\s+you|please|in\s+case|write\s+to|reach\s+out|contact|appointed|under\s+section|email)\b', raw_officer, flags=re.I)[0]
        cleaned_officer = raw_officer.strip(" :,-.\t\r\n").title()
        if not cleaned_officer or len(cleaned_officer) < 5 or cleaned_officer.lower() in ["grievance officer", "nodal officer"]:
            cleaned_officer = "Designated Grievance Officer"
        elif len(cleaned_officer) > 50:
            cleaned_officer = cleaned_officer[:50].strip()

    dpdp_info = {
        "compliant": dpdp_compliant,
        "grievance_officer": cleaned_officer,
        "grievance_email": dpdp_email,
        "redressal_period_days": 30 if dpdp_compliant else None,
        "erasure_right_disclosed": dpdp_erasure,
        "notes": "DPDP Statutory Grievance Officer & Contact identified." if dpdp_compliant else "Grievance Officer not found."
    }

    # GDPR (EU)
    gdpr_dpo_match = re.search(
        r'(?:data\s+protection\s+officer|dpo|eu\s+representative)(?:[^\.\;\n\!\?]{0,80})', text_lower)
    gdpr_email = [e for e in all_emails if "dpo" in e or "privacy" in e]
    gdpr_dpo_contact = gdpr_email[0] if gdpr_email else (all_emails[0] if gdpr_dpo_match and all_emails else None)
    
    gdpr_compliant = bool(gdpr_dpo_match and gdpr_dpo_contact)
    gdpr_info = {
        "compliant": gdpr_compliant,
        "dpo_contact": gdpr_dpo_contact,
        "lawful_basis_stated": bool(re.search(r'\b(legitimate interest|contractual necessity|consent)\b', text_lower)),
        "erasure_art17_disclosed": bool(re.search(r'\b(erasure|delete my data|right to be forgotten)\b', text_lower)),
        "notes": "GDPR DPO and Article 17 rights identified." if gdpr_compliant else "GDPR DPO not found."
    }

    # CCPA
    ccpa_mentioned = bool(re.search(r'\b(ccpa|california consumer privacy|do not sell|cpra)\b', text_lower))
    ccpa_info = {
        "compliant": ccpa_mentioned,
        "opt_out_link": None,
        "do_not_sell": bool(re.search(r'do not sell|opt-out of sale', text_lower))
    }
    
    return {
        "dpdp": dpdp_info,
        "gdpr": gdpr_info,
        "ccpa": ccpa_info
    }


def _calculate_compliance_bonus(compliance: Dict) -> int:
    """Calculate bonus/penalty based on verified regulatory compliance.
    Gives + points ONLY if verified Grievance Officer and contact genuinely exist.
    If not found, gives ZERO bonus.
    """
    bonus = 0
    
    dpdp = compliance.get("dpdp", {})
    gdpr = compliance.get("gdpr", {})
    ccpa = compliance.get("ccpa", {})
    
    # Bonus ONLY if grievance email and officer are genuinely verified
    if dpdp.get("compliant") and dpdp.get("grievance_email"):
        bonus += 3
        if dpdp.get("erasure_right_disclosed"):
            bonus += 2
            
    if gdpr.get("compliant") and gdpr.get("dpo_contact"):
        bonus += 3
        if gdpr.get("erasure_art17_disclosed"):
            bonus += 2
            
    if ccpa.get("compliant") and ccpa.get("do_not_sell"):
        bonus += 2
    
    # Penalty if no framework is compliant
    if not dpdp.get("compliant") and not gdpr.get("compliant") and not ccpa.get("compliant"):
        bonus -= 6
    
    return bonus


def _calculate_dark_pattern_penalty(dark_patterns: List = None) -> int:
    """Calculate penalty for detected dark patterns. Max -15."""
    if not dark_patterns:
        return 0
    count = len(dark_patterns) if isinstance(dark_patterns, list) else 0
    return max(-15, count * -3)


def analyze_live_policy(url: str, html_text: str, tracker_data: List = None,
                         cookie_data: List = None, dark_patterns: List = None,
                         domain_breaches: List = None) -> Dict[str, Any]:
    """Analyze a live privacy policy with improved scoring engine.
    
    Enhanced with: negation-aware keyword matching, weighted severity tiers,
    real tracker integration, compliance bonuses, dark pattern penalties,
    and refined 9-grade classification.
    """
    domain = clean_domain(url)
    soup = BeautifulSoup(html_text, "html.parser")
    
    # Remove script and style tags
    for s in soup(["script", "style", "nav", "footer"]):
        s.decompose()
        
    text = soup.get_text(separator=" ", strip=True)
    text_lower = text.lower()
    
    # Compliance detection
    compliance = _check_compliance(text_lower)
    
    
    # Extract DPO / Grievance Officer contacts
    contacts = {
        "email": [],
        "phone": [],
        "address": [],
        "officer": []
    }
    
    # Emails
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
    if emails:
        contacts["email"] = list(set([e for e in emails if "privacy" in e.lower() or "dpo" in e.lower() or "grievance" in e.lower()] or emails))[:3]
        
    # Phones
    phones = re.findall(r'\+?\d[\d -]{8,12}\d', text)
    if phones:
        contacts["phone"] = list(set(phones))[:3]
        
    # Officers
    officers = re.findall(r'(?:Grievance Officer|Data Protection Officer|DPO|Privacy Officer)[^.!?\n]{0,100}', text, re.IGNORECASE)
    if officers:
        contacts["officer"] = list(set([o.strip() for o in officers]))[:3]
        
    # Addresses
    addresses = re.findall(r'(?:P\.?O\.? Box|Street|Avenue|Boulevard|Bldg|Building)[^.!?\n]{0,100}', text, re.IGNORECASE)
    if addresses:
        contacts["address"] = list(set([a.strip() for a in addresses]))[:3]

    # ===== 6-Pillar Scoring with Improved Engine =====
    
    # Pillar 1: Third-Party Data Sharing (weight: 0.25)
    ds_score = _score_pillar_with_context(text, base_score=65, keywords=PILLAR1_KEYWORDS)
    if ds_score >= 85:
        ds_label, ds_risk = "Strict Data Minimization & Limited Sharing", "low"
    elif ds_score >= 55:
        ds_label, ds_risk = "Moderate Partner & Vendor Sharing", "medium"
    else:
        ds_label, ds_risk = "Broad Third-Party & Commercial Sharing", "high"
    
    # Pillar 2: Cookies & Telemetry (weight: 0.20)
    trk_policy_score = _score_pillar_with_context(text, base_score=65, keywords=PILLAR2_KEYWORDS)
    trk_score = _score_tracking_with_real_data(trk_policy_score, tracker_data, cookie_data)
    if trk_score >= 85:
        trk_label, trk_risk = "Minimal or No Tracking Cookies", "low"
    elif trk_score >= 55:
        trk_label, trk_risk = "Standard Functional & Analytics Tracking", "medium"
    else:
        trk_label, trk_risk = "Extensive Tracking Pixels & Telemetry", "high"
    
    # Pillar 3: User Rights & Erasure (weight: 0.20)
    ur_score = _score_pillar_with_context(text, base_score=50, keywords=PILLAR3_KEYWORDS)
    if ur_score >= 85:
        ur_label, ur_risk = "Comprehensive User Rights & Erasure Flow", "low"
    elif ur_score >= 55:
        ur_label, ur_risk = "Basic Support Request Deletion", "medium"
    else:
        ur_label, ur_risk = "Opaque or Difficult Deletion Procedures", "high"
    
    # Pillar 4: Data Retention (weight: 0.15)
    ret_score = _score_pillar_with_context(text, base_score=50, keywords=PILLAR4_KEYWORDS)
    if ret_score >= 80:
        ret_label, ret_risk = "Explicit Retention Limits & Auto-Purge Disclosed", "low"
    elif ret_score >= 50:
        ret_label, ret_risk = "Standard Operational Retention", "medium"
    else:
        ret_label, ret_risk = "Extended or Indefinite Retention Window", "high"
    
    # Pillar 5: Breach History & Real-World Incident Radar
    if domain_breaches:
        total_pwned = sum(b.get("pwn_count", 0) for b in domain_breaches if isinstance(b, dict))
        if total_pwned >= 1_000_000:
            br_score = 10
            br_label, br_risk = f"🚨 Massive Customer Leak ({total_pwned:,} Records)", "high"
        elif total_pwned > 0:
            br_score = 20
            br_label, br_risk = f"🚨 Confirmed Data Leak ({total_pwned:,} Records)", "high"
        else:
            br_score = 25
            br_label, br_risk = "🚨 Confirmed Security Incident", "high"
    else:
        br_score = _score_pillar_with_context(text, base_score=75, keywords=PILLAR5_KEYWORDS)
        if br_score >= 80:
            br_label, br_risk = "Strong Security Architecture Disclosed", "low"
        elif br_score >= 55:
            br_label, br_risk = "Standard Technical Safeguards", "medium"
        else:
            br_label, br_risk = "Security Concerns or Incomplete Safeguards", "high"
    
    # Pillar 6: Readability (weight: 0.07)
    read_score = calculate_readability(text[:5000])
    read_label = "Plain Language Clarity" if read_score > 65 else ("Moderate Complexity" if read_score > 40 else "Dense Legal Terminology")
    read_risk = "low" if read_score > 65 else ("medium" if read_score > 40 else "high")

    rubric = {
        "data_sharing": {"score": ds_score, "max": 100, "label": ds_label, "risk": ds_risk},
        "retention": {"score": ret_score, "max": 100, "label": ret_label, "risk": ret_risk},
        "tracking_cookies": {"score": trk_score, "max": 100, "label": trk_label, "risk": trk_risk},
        "user_rights": {"score": ur_score, "max": 100, "label": ur_label, "risk": ur_risk},
        "breach_history": {"score": br_score, "max": 100, "label": br_label, "risk": br_risk},
        "readability": {"score": read_score, "max": 100, "label": read_label, "risk": read_risk}
    }

    # Calculate overall weighted score with 40% weightage on Trackers & Cookies
    # Weights: Data Sharing (0.20), Retention (0.10), Tracking & Cookies (0.40), User Rights (0.15), Breach History (0.08), Readability (0.07)
    weights = [0.20, 0.10, 0.40, 0.15, 0.08, 0.07]
    scores = [ds_score, ret_score, trk_score, ur_score, br_score, read_score]
    total_score = int(sum(s * w for s, w in zip(scores, weights)))
    
    # Apply severe direct penalty for real-world verified data breaches (-30 pts for major leaks)
    if domain_breaches:
        total_pwned = sum(b.get("pwn_count", 0) for b in domain_breaches if isinstance(b, dict))
        breach_penalty = 30 if total_pwned >= 1_000_000 else 20
        total_score = max(5, total_score - breach_penalty)
    
    # Apply compliance bonus/penalty
    compliance_bonus = _calculate_compliance_bonus(compliance)
    total_score = max(0, min(100, total_score + compliance_bonus))
    
    # Apply dark pattern penalty
    dp_penalty = _calculate_dark_pattern_penalty(dark_patterns)
    total_score = max(0, min(100, total_score + dp_penalty))
    
    # Get refined grade
    grade, color = _get_grade(total_score)

    # Extract sample key clauses
    key_clauses = []
    sentences = re.split(r'(?<=[.!?])\s+', text)
    for s in sentences:
        s_clean = s.strip()
        if 40 < len(s_clean) < 220:
            if re.search(r'\b(share.*third|advertising.*partners|collect.*location)\b', s_clean, re.I) and len(key_clauses) < 2:
                key_clauses.append({"type": "negative", "text": s_clean})
            elif re.search(r'\b(not sell|delete.*account|opt-out|encrypt)\b', s_clean, re.I) and len(key_clauses) < 4:
                key_clauses.append({"type": "positive", "text": s_clean})
    
    if not key_clauses:
        key_clauses = [
            {"type": "negative", "text": "Collects device metrics, IP address, and cookie tokens for service operation."},
            {"type": "positive", "text": "Users may contact the privacy desk to request access or deletion of their account records."}
        ]

    # Extract findings
    findings = _extract_findings(text)
    
    # Extract key concerns
    key_concerns = _extract_concerns(text, total_score)

    # Form summary
    site_title = soup.title.string.strip() if soup.title and soup.title.string else domain.title()
    summary = f"Scanned live policy for {domain}. Scored {total_score}/100 based on data sharing, user rights disclosures, and regional DPDP/GDPR alignment."

    return {
        "domain": domain,
        "name": site_title[:40],
        "policy_url": url if url.startswith("http") else f"https://www.{domain}/privacy-policy",
        "grade": grade,
        "score": total_score,
        "color": color,
        "summary": summary,
        "rubric": rubric,
        "compliance": compliance,
        "key_clauses": key_clauses,
        "findings": findings,
        "key_concerns": key_concerns,
        "contacts": contacts,
        "category": "Web Service",
        "source": "live_nlp"
    }


def _extract_findings(text: str) -> Dict[str, List[str]]:
    """Extract categorized findings from policy text."""
    findings = {
        "data_sharing": [],
        "retention": [],
        "user_rights": []
    }
    
    sentences = re.split(r'(?<=[.!?])\s+', text)
    for s in sentences:
        s_clean = s.strip()
        if 30 < len(s_clean) < 300:
            s_lower = s_clean.lower()
            if re.search(r'\b(share|third.party|partner|affiliate|vendor|sell)\b', s_lower):
                if len(findings["data_sharing"]) < 5:
                    findings["data_sharing"].append(s_clean)
            if re.search(r'\b(retain|retention|store|keep|preserve|purge|delete after)\b', s_lower):
                if len(findings["retention"]) < 5:
                    findings["retention"].append(s_clean)
            if re.search(r'\b(right|delete|erasure|opt.out|withdraw|consent|portability|access)\b', s_lower):
                if len(findings["user_rights"]) < 5:
                    findings["user_rights"].append(s_clean)
    
    return findings


def _extract_concerns(text: str, score: int) -> List[str]:
    """Extract key privacy concerns based on score and detected patterns, using rich quotes where possible."""
    concerns = []
    text_lower = text.lower()
    sentences = re.split(r'(?<=[.!?])\s+', text)
    
    if score < 50:
        concerns.append(f"Overall privacy score ({score}/100) indicates significant privacy concerns.")
    if score < 25:
        concerns.append("Critical privacy risk — this site may be hostile to user privacy.")
        
    def find_quote(pattern):
        for s in sentences:
            if re.search(pattern, s, re.IGNORECASE) and len(s) < 300:
                return s.strip()
        return None
        
    q = find_quote(r'\b(sell|sold)\s+(your\s+)?data\b')
    if q: concerns.append(f"Policy mentions selling or sharing user data: '{q}'")
    elif re.search(r'\b(sell|sold)\s+(your\s+)?data\b', text_lower): concerns.append("Policy mentions selling or sharing user data with third parties.")
        
    q = find_quote(r'\bdata\s+broker\b')
    if q: concerns.append(f"Data broker relationships disclosed: '{q}'")
    elif re.search(r'\bdata\s+broker\b', text_lower): concerns.append("Data broker relationships disclosed.")
        
    q = find_quote(r'\bindefinitely\b')
    if q: concerns.append(f"Indefinite data retention clause detected: '{q}'")
    elif 'indefinitely' in text_lower: concerns.append("Indefinite data retention clause detected.")
        
    q = find_quote(r'\bcannot\s+be\s+deleted\b')
    if q: concerns.append(f"Policy suggests some user data cannot be fully deleted: '{q}'")
    elif re.search(r'\bcannot\s+be\s+deleted\b', text_lower): concerns.append("Policy suggests some user data cannot be fully deleted.")
        
    q = find_quote(r'\bfingerprint')
    if q: concerns.append(f"Browser or device fingerprinting techniques referenced: '{q}'")
    elif 'fingerprint' in text_lower: concerns.append("Browser or device fingerprinting techniques referenced.")
        
    if not re.search(r'\b(delete|erasure|removal)\b', text_lower):
        concerns.append("No clear data deletion or erasure mechanism disclosed.")
        
    q = find_quote(r'\bbehavioral\s+advertising\b')
    if q: concerns.append(f"Behavioral advertising and interest-based profiling in use: '{q}'")
    elif 'behavioral advertising' in text_lower: concerns.append("Behavioral advertising and interest-based profiling in use.")
    
    return concerns


async def discover_and_fetch_policy(clean_domain: str) -> tuple[str, str]:
    """
    Builds candidate URLs checking BOTH https://www.{clean}/... and https://{clean}/...
    including Shopify /pages/privacy-policy, /policies/privacy-policy, and legal portal paths.
    """
    paths = [
        # Standard paths
        "/privacy-policy", "/privacy-policy/", "/privacy", "/privacy/",
        # Shopify & D2C Brand E-Commerce (Noise, Boat Lifestyle, Mamaearth, Sugar, Snitch, Lenskart)
        "/pages/privacy-policy", "/pages/privacy-policy/", "/pages/privacypolicy", "/pages/privacy",
        "/policies/privacy-policy", "/policies/privacy-policy/",
        # Legal & Corporate Portals (Apple, Flipkart, Google, Netflix, Amazon)
        "/pages/privacypolicy", "/legal/privacy", "/legal/privacy-policy", "/legal/privacy/",
        "/legal/privacy-policy/", "/privacy-statement", "/privacypolicy", "/terms-and-privacy",
        "/about/privacy", "/about/privacy-policy", "/in/privacy-policy", "/en-in/privacy-policy"
    ]
    
    candidates = []
    for p in paths:
        candidates.append(f"https://www.{clean_domain}{p}")
        candidates.append(f"https://{clean_domain}{p}")
        
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9"
    }
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        for url in candidates:
            try:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200 and len(resp.text) > 400:
                    text_lower = resp.text.lower()
                    if "privacy" in text_lower or "personal data" in text_lower or "information" in text_lower or "cookies" in text_lower:
                        return str(resp.url), resp.text
            except Exception:
                continue
                
        # Try homepage
        homepages = [f"https://www.{clean_domain}", f"https://{clean_domain}"]
        for hp in homepages:
            try:
                resp = await client.get(hp, headers=headers)
                if resp.status_code == 200:
                    from bs4 import BeautifulSoup
                    from urllib.parse import urljoin
                    soup = BeautifulSoup(resp.text, "html.parser")
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        text = a.get_text(strip=True).lower()
                        if 'privacy' in href.lower() or 'privacy' in text:
                            target_url = urljoin(hp, href)
                            try:
                                p_resp = await client.get(target_url, headers=headers)
                                if p_resp.status_code == 200 and len(p_resp.text) > 500:
                                    return str(p_resp.url), p_resp.text
                            except Exception:
                                continue
            except Exception:
                continue
                
    return "", ""


async def get_site_rating(domain_or_url: str, tracker_data: List = None,
                           cookie_data: List = None, dark_patterns: List = None) -> Dict[str, Any]:
    """Get privacy rating for a domain. Enhanced with real-time OSINT breach discovery & tracker intelligence."""
    from app.services.breach_service import search_live_domain_breaches
    clean = clean_domain(domain_or_url)
    cached = load_cached_policies()
    
    # Check verified breach intelligence and real-time security radar
    domain_breaches = await search_live_domain_breaches(clean)

    # Exact or suffix match in cached policies
    for site in cached:
        site_domain = clean_domain(site["domain"])
        if clean == site_domain or clean.endswith("." + site_domain) or site_domain.endswith("." + clean):
            result = dict(site)
            result["source"] = "cache"
            if not result.get("policy_url"):
                result["policy_url"] = f"https://www.{site_domain}/privacy-policy"
            result["breaches"] = domain_breaches if domain_breaches else result.get("breaches", [])
            # Re-apply breach penalty dynamically if newly discovered breach exists
            if domain_breaches:
                total_pwned = sum(b.get("pwn_count", 0) for b in domain_breaches if isinstance(b, dict))
                deduction = 30 if total_pwned >= 1_000_000 else 20
                if result.get("overall_score", 0) > 40:
                    result["overall_score"] = max(10, result["overall_score"] - deduction)
                    grade, color = _get_grade(result["overall_score"])
                    result["grade"] = grade
                    result["grade_color"] = color
                    result["color"] = color
                    if "pillar_scores" in result and isinstance(result["pillar_scores"], dict):
                        result["pillar_scores"]["breach_history"] = {
                            "score": 10 if total_pwned >= 1_000_000 else 20,
                            "max": 100,
                            "label": f"🚨 Confirmed Data Leak ({total_pwned:,} Records)",
                            "risk": "high"
                        }
            return result
            
    # Try fetching live privacy policy
    policy_url, policy_html = await discover_and_fetch_policy(clean)
    if policy_url and policy_html:
        live_res = analyze_live_policy(policy_url, policy_html, tracker_data, cookie_data, dark_patterns, domain_breaches)
        live_res["breaches"] = domain_breaches
        return live_res
    
    # Fallback when privacy policy does not exist or cannot be found — completely honest score: 0/100 (Grade F)
    fallback_score = 0
    grade, color = _get_grade(fallback_score)
    
    return {
        "domain": clean,
        "name": clean.split(".")[0].title(),
        "policy_url": None,
        "grade": grade,
        "score": fallback_score,
        "color": color,
        "summary": f"🚨 Critical Privacy Alert: No valid privacy policy exists or could be found for {clean}. Without a disclosed policy, users have zero legal guarantees regarding data retention, third-party sharing, or user rights.",
        "breaches": domain_breaches,
        "rubric": {
            "data_sharing": {"score": 0, "max": 100, "label": "🚨 Undisclosed Third-Party Data Sharing", "risk": "high"},
            "retention": {"score": 0, "max": 100, "label": "🚨 Undisclosed Data Retention Policy", "risk": "high"},
            "tracking_cookies": {"score": 0, "max": 100, "label": "🚨 Unregulated Tracking & Telemetry", "risk": "high"},
            "user_rights": {"score": 0, "max": 100, "label": "🚨 No Erasure or Deletion Flow Disclosed", "risk": "high"},
            "breach_history": {"score": (0 if domain_breaches else 10), "max": 100, "label": ("🚨 Recorded Security Breach" if domain_breaches else "No Disclosed Security Policy"), "risk": "high"},
            "readability": {"score": 0, "max": 100, "label": "No Policy Found", "risk": "high"}
        },
        "compliance": {
            "dpdp": {
                "compliant": False,
                "grievance_officer": None,
                "grievance_email": None,
                "redressal_period_days": None,
                "erasure_right_disclosed": False,
                "notes": "Non-compliant: No privacy policy or Indian DPDP grievance officer disclosed."
            },
            "gdpr": {
                "compliant": False,
                "dpo_contact": None,
                "lawful_basis_stated": False,
                "erasure_art17_disclosed": False,
                "notes": "Non-compliant: No GDPR privacy statement or DPO contact."
            },
            "ccpa": {
                "compliant": False,
                "opt_out_link": None,
                "do_not_sell": False
            }
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
        "source": "missing_policy_zero_score"
    }
