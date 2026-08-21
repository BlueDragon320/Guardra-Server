import os
import json
from fastapi import APIRouter, HTTPException, Response
from typing import List, Dict, Any
from app.models.schemas import DeletionNoticeRequest, StatusUpdateRequest
from app.services.deletion_service import (
    generate_notice_text,
    generate_pdf_notice,
    save_deletion_request,
    get_all_deletion_requests,
    update_request_status
)

router = APIRouter(prefix="/api/deletion", tags=["Data Rights & Deletion"])

BROKERS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "data_brokers.json")
REGULATORS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "regulators.json")

@router.post("/generate-notice")
async def create_notice(req: DeletionNoticeRequest):
    data = generate_notice_text(
        site_domain=req.site_domain,
        site_name=req.site_name,
        legal_basis=req.legal_basis,
        user_name=req.user_name,
        user_email=req.user_email,
        user_phone=req.user_phone,
        account_identifier=req.account_identifier,
        grievance_email=req.grievance_email
    )
    return data

@router.post("/generate-pdf")
async def create_pdf(req: DeletionNoticeRequest):
    pdf_bytes = generate_pdf_notice(
        site_domain=req.site_domain,
        site_name=req.site_name,
        legal_basis=req.legal_basis,
        user_name=req.user_name,
        user_email=req.user_email,
        user_phone=req.user_phone,
        account_identifier=req.account_identifier,
        grievance_email=req.grievance_email
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=Guardra_Erasure_Notice_{req.site_domain}.pdf"
        }
    )

@router.post("/submit")
async def submit_request(req: DeletionNoticeRequest):
    saved = save_deletion_request(
        site_domain=req.site_domain,
        site_name=req.site_name,
        legal_basis=req.legal_basis,
        user_name=req.user_name,
        user_email=req.user_email,
        user_phone=req.user_phone,
        account_identifier=req.account_identifier,
        grievance_email=req.grievance_email
    )
    return saved

@router.get("/requests")
async def list_requests():
    return get_all_deletion_requests()

@router.patch("/requests/{req_id}/status")
async def change_status(req_id: str, payload: StatusUpdateRequest):
    updated = update_request_status(req_id, payload.status, payload.notes)
    if not updated:
        raise HTTPException(status_code=404, detail="Request ID not found")
    return updated

@router.get("/directory")
async def get_brokers_directory():
    if os.path.exists(BROKERS_PATH):
        with open(BROKERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@router.get("/regulators")
async def get_regulators():
    if os.path.exists(REGULATORS_PATH):
        with open(REGULATORS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []
