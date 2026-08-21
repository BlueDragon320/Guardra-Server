import os
import uuid
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import io

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

from app.database import get_db_connection

def generate_notice_text(
    site_domain: str,
    site_name: str,
    legal_basis: str,
    user_name: str,
    user_email: str,
    user_phone: Optional[str] = None,
    account_identifier: Optional[str] = None,
    grievance_email: str = ""
) -> Dict[str, str]:
    today_str = datetime.now().strftime("%B %d, %Y")
    phone_line = f"Phone Number Associated: {user_phone}\n" if user_phone else ""
    account_line = f"Account Username / Identifier: {account_identifier}\n" if account_identifier else ""
    
    if legal_basis.lower() == "dpdp":
        subject = f"FORMAL NOTICE: Request for Erasure of Personal Data under Section 12, DPDP Act 2023 — {user_name}"
        body = f"""Date: {today_str}

To:
The Grievance Redressal Officer / Data Protection Team
{site_name} ({site_domain})
Email: {grievance_email}

From:
{user_name}
Email: {user_email}
{phone_line}{account_line}

Subject: Formal Request for Erasure and Cessation of Processing of Personal Data under Section 12 & Section 13 of the Digital Personal Data Protection Act, 2023 (DPDP Act)

Dear Grievance Officer,

I am writing to you in my capacity as a Data Principal under the Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023).

1. Statutory Right to Erasure (Section 12):
Pursuant to Section 12(1)(b) and Section 12(3) of the DPDP Act, 2023, I hereby formally request the complete erasure of all my personal data held, stored, or processed by {site_name}, including but not limited to:
  a) Registration and profile details (name, email, contact numbers, device identifiers);
  b) Transaction records, telemetry, location data, and behavioral interaction histories;
  c) Any profiling or psychographic segment data derived from my interactions;
  d) Personal data shared with any Third-Party Data Processors or marketing partners under Section 8(2).

2. Withdrawal of Consent (Section 6(4)):
To the extent that processing of my personal data was predicated upon consent previously granted, please treat this letter as formal withdrawal of all such consent in accordance with Section 6(4) of the DPDP Act.

3. Obligation of Data Fiduciary:
Under the DPDP Rules, as a Data Fiduciary, {site_name} is required to:
  a) Erase personal data unless retention is mandatory under an express statutory provision of Indian law;
  b) Instruct all downstream Data Processors to whom my personal data was transferred to erase the same;
  c) Provide written confirmation of erasure within thirty (30) days from the receipt of this notice.

4. Escalation to Data Protection Board of India:
Please take notice that in the event of failure to respond, unjustified refusal, or non-redressal within thirty (30) days, I shall exercise my statutory right under Section 13(3) to file a formal complaint before the Data Protection Board of India (DPBI).

Kindly acknowledge receipt of this notice and confirm compliance in writing to {user_email}.

Yours sincerely,

{user_name}
Contact: {user_email}
Generated via Guardra Privacy Suite (Open Source)
"""
    elif legal_basis.lower() == "gdpr":
        subject = f"GDPR Article 17 Erasure Request — {user_name} ({user_email})"
        body = f"""Date: {today_str}

To:
Data Protection Officer / Privacy Team
{site_name} ({site_domain})
Email: {grievance_email}

From:
{user_name}
Email: {user_email}
{phone_line}{account_line}

Subject: Request for Erasure of Personal Data pursuant to Article 17 of the General Data Protection Regulation (GDPR)

Dear Data Protection Officer,

I am submitting this request under Article 17 of the General Data Protection Regulation (EU) 2016/679 ("Right to erasure" / "Right to be forgotten").

1. Scope of Erasure:
I request the immediate and permanent deletion of all personal data concerning me held by {site_name} and any third-party processors acting on your behalf, including:
  a) User account credentials, contact information, and identifiers;
  b) Browsing, tracking, and analytics logs;
  c) Customer preference profiles, ad categories, and behavioral metadata.

2. Legal Grounds (Article 17(1)):
  - The personal data are no longer necessary in relation to the purposes for which they were collected;
  - I hereby withdraw any consent on which the processing is based (Article 17(1)(b));
  - I object to processing pursuant to Article 21(1) and there are no overriding legitimate grounds.

3. Obligation to Inform Downstream Processors (Article 17(2)):
Please ensure that reasonable steps are taken to inform third-party data processors to erase any links to, or copies of, my personal data.

4. Response Timeframe:
Under GDPR Article 12(3), you are required to provide information on actions taken on this request without undue delay and at the latest within one month of receipt.

If you do not comply with this request, I reserve the right to lodge a complaint with the relevant Data Protection Supervisory Authority (e.g. CNIL, DPC, ICO, BfDI).

Sincerely,

{user_name}
Email: {user_email}
Generated via Guardra Privacy Suite
"""
    else: # CCPA
        subject = f"CCPA Personal Information Deletion Request — {user_name}"
        body = f"""Date: {today_str}

To:
Privacy Team / Legal Department
{site_name} ({site_domain})
Email: {grievance_email}

From:
{user_name}
Email: {user_email}
{phone_line}{account_line}

Subject: Verified Consumer Request to Delete Personal Information under the California Consumer Privacy Act (CCPA / CPRA, Cal. Civ. Code § 1798.105)

Dear Privacy Officer,

I am submitting this verified consumer request under the California Consumer Privacy Act of 2018 (CCPA) as amended by the California Privacy Rights Act (CPRA).

1. Right to Delete (Cal. Civ. Code § 1798.105):
I hereby request that {site_name} permanently delete all personal information collected about me, and direct all service providers, contractors, and third parties to delete my personal information from their records.

2. Do Not Sell or Share My Personal Information (Cal. Civ. Code § 1798.120):
I further instruct you not to sell, share, or disclose any of my personal information for cross-context behavioral advertising.

3. Response Timeframe:
Under Cal. Civ. Code § 1798.130, you must confirm receipt within 10 business days and fulfill this deletion request within 45 calendar days.

Thank you for your prompt attention.

Sincerely,

{user_name}
Email: {user_email}
Generated via Guardra Privacy Suite
"""

    mailto_url = f"mailto:{grievance_email}?subject={requests_quote(subject)}&body={requests_quote(body)}"
    return {
        "subject": subject,
        "body": body,
        "mailto_url": mailto_url,
        "legal_basis_name": "Digital Personal Data Protection Act 2023 (India)" if legal_basis == "dpdp" else ("GDPR Article 17 (EU)" if legal_basis == "gdpr" else "CCPA / CPRA (California)")
    }

def requests_quote(string: str) -> str:
    import urllib.parse
    return urllib.parse.quote(string)

def generate_pdf_notice(
    site_domain: str,
    site_name: str,
    legal_basis: str,
    user_name: str,
    user_email: str,
    user_phone: Optional[str] = None,
    account_identifier: Optional[str] = None,
    grievance_email: str = ""
) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0f172a"),
        fontName='Helvetica-Bold'
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569")
    )
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1e293b")
    )
    bold_style = ParagraphStyle(
        'DocBold',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#0f172a")
    )
    
    elements = []
    
    # Header badge
    elements.append(Paragraph("GUARDRA PRIVACY SUITE — FORMAL STATUTORY NOTICE", title_style))
    elements.append(Paragraph(f"Generated on {datetime.now().strftime('%B %d, %Y')} | Verified Legal Deletion Notice", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceAfter=15))
    
    # Address Block
    data_table = [
        [Paragraph("<b>TO:</b>", bold_style), Paragraph(f"Grievance Officer / Privacy Desk<br/><b>{site_name}</b> ({site_domain})<br/>Email: {grievance_email}", body_style)],
        [Paragraph("<b>FROM:</b>", bold_style), Paragraph(f"<b>{user_name}</b><br/>Email: {user_email}" + (f"<br/>Phone: {user_phone}" if user_phone else "") + (f"<br/>Account ID: {account_identifier}" if account_identifier else ""), body_style)],
        [Paragraph("<b>LEGAL BASIS:</b>", bold_style), Paragraph(f"<b>{'Digital Personal Data Protection Act, 2023 (Section 12 & 13)' if legal_basis == 'dpdp' else ('GDPR Article 17 Right to Erasure' if legal_basis == 'gdpr' else 'CCPA / CPRA § 1798.105')}</b>", body_style)]
    ]
    
    t = Table(data_table, colWidths=[100, 430])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15))
    
    notice_data = generate_notice_text(
        site_domain, site_name, legal_basis, user_name, user_email, user_phone, account_identifier, grievance_email
    )
    
    # Paragraphs for body
    for line in notice_data["body"].split("\n"):
        line_s = line.strip()
        if not line_s:
            elements.append(Spacer(1, 6))
        elif line_s.startswith("Subject:"):
            elements.append(Paragraph(f"<b>{line_s}</b>", bold_style))
            elements.append(Spacer(1, 6))
        elif line_s.startswith(("1.", "2.", "3.", "4.")):
            elements.append(Paragraph(f"<b>{line_s}</b>", bold_style))
        else:
            elements.append(Paragraph(line_s, body_style))
            
    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=10))
    elements.append(Paragraph("This legal notice was generated by Guardra Privacy Guardian. Under applicable laws, deliberate failure to adhere to statutory erasure requests is subject to regulatory complaints before the Data Protection Board of India, European DPAs, or California CPPA.", subtitle_style))
    
    doc.build(elements)
    pdf = buffer.getvalue()
    buffer.close()
    return pdf

def save_deletion_request(
    site_domain: str,
    site_name: str,
    legal_basis: str,
    user_name: str,
    user_email: str,
    user_phone: Optional[str],
    account_identifier: Optional[str],
    grievance_email: str,
    notes: Optional[str] = None
) -> Dict[str, Any]:
    req_id = f"del_{uuid.uuid4().hex[:8]}"
    now = datetime.utcnow().isoformat()
    
    initial_history = json.dumps([{
        "status": "Sent",
        "timestamp": now,
        "note": f"Initial formal notice sent to {grievance_email} under {legal_basis.upper()} framework."
    }])
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO deletion_requests (
        id, site_domain, site_name, legal_basis, user_name, user_email,
        user_phone, account_identifier, grievance_email, status, created_at,
        updated_at, notes, tracking_history
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Sent', ?, ?, ?, ?)
    """, (
        req_id, site_domain, site_name, legal_basis, user_name, user_email,
        user_phone, account_identifier, grievance_email, now, now, notes or "Request dispatched via email.", initial_history
    ))
    conn.commit()
    conn.close()
    
    return {
        "id": req_id,
        "site_domain": site_domain,
        "site_name": site_name,
        "legal_basis": legal_basis,
        "user_name": user_name,
        "user_email": user_email,
        "user_phone": user_phone,
        "account_identifier": account_identifier,
        "grievance_email": grievance_email,
        "status": "Sent",
        "created_at": now,
        "updated_at": now,
        "notes": notes or "Request dispatched via email."
    }

def get_all_deletion_requests() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM deletion_requests ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        history = []
        try:
            history = json.loads(r["tracking_history"]) if r["tracking_history"] else []
        except Exception:
            history = []
            
        results.append({
            "id": r["id"],
            "site_domain": r["site_domain"],
            "site_name": r["site_name"],
            "legal_basis": r["legal_basis"],
            "user_name": r["user_name"],
            "user_email": r["user_email"],
            "user_phone": r["user_phone"],
            "account_identifier": r["account_identifier"],
            "grievance_email": r["grievance_email"],
            "status": r["status"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
            "notes": r["notes"],
            "history": history
        })
    return results

def update_request_status(req_id: str, new_status: str, note: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM deletion_requests WHERE id = ?", (req_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
        
    now = datetime.utcnow().isoformat()
    history = []
    try:
        history = json.loads(row["tracking_history"]) if row["tracking_history"] else []
    except Exception:
        history = []
        
    history.append({
        "status": new_status,
        "timestamp": now,
        "note": note or f"Status updated to {new_status}"
    })
    
    cursor.execute("""
    UPDATE deletion_requests
    SET status = ?, updated_at = ?, notes = ?, tracking_history = ?
    WHERE id = ?
    """, (new_status, now, note or row["notes"], json.dumps(history), req_id))
    
    conn.commit()
    conn.close()
    
    return {
        "id": req_id,
        "status": new_status,
        "updated_at": now,
        "note": note
    }
