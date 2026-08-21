import os
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
from pydantic import BaseModel
from app.services.footprint_service import get_footprint_data, toggle_action
from app.models.schemas import ActionToggleRequest

router = APIRouter(prefix="/api/hub", tags=["Privacy Hub & Footprint"])

PLATFORMS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "privacy_hub.json")

# In-memory store of recent live browser activity from extension
RECENT_ACTIVITIES = [
    {
        "id": "act_init",
        "domain": "guardra.local",
        "url": "http://localhost:5173",
        "action": "Shield Activated",
        "details": "Guardra extension connected to active session.",
        "trackers_blocked": 0,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
]

class TelemetryPayload(BaseModel):
    domain: str
    url: str
    action_type: str = "scan"  # scan, auto_reject_cookies, opt_out_toggled, dark_pattern_cleared
    details: str = ""
    trackers_detected: List[Dict[str, Any]] = []
    auto_actions_taken: List[str] = []

@router.get("/platforms")
async def get_platforms():
    if os.path.exists(PLATFORMS_PATH):
        with open(PLATFORMS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []

@router.get("/footprint")
async def get_footprint():
    return get_footprint_data()

@router.post("/footprint/toggle")
async def toggle_footprint_action(req: ActionToggleRequest):
    return toggle_action(req.action_id)

@router.post("/telemetry/active-session")
async def record_telemetry(payload: TelemetryPayload):
    new_entry = {
        "id": f"act_{len(RECENT_ACTIVITIES) + 1}",
        "domain": payload.domain,
        "url": payload.url,
        "action": payload.action_type,
        "details": payload.details or f"Analyzed {payload.domain}",
        "trackers_blocked": len(payload.trackers_detected),
        "auto_actions": payload.auto_actions_taken,
        "timestamp": datetime.now().strftime("%H:%M:%S")
    }
    RECENT_ACTIVITIES.insert(0, new_entry)
    if len(RECENT_ACTIVITIES) > 25:
        RECENT_ACTIVITIES.pop()
    return {"status": "recorded", "activity": new_entry}

@router.get("/telemetry/live-feed")
async def get_live_feed():
    return RECENT_ACTIVITIES
