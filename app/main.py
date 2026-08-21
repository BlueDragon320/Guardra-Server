import os
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from app.routers import policy, deletion, breach, hub, admin

app = FastAPI(
    title="Guardra Server API",
    description="Dedicated production API server for real-time website policy rating (DPDP Act 2023 / GDPR / CCPA), statutory data deletion generation, breach audits, and privacy hub telemetry.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration allowing requests from browser extensions and client apps
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(policy.router)
app.include_router(deletion.router)
app.include_router(breach.router)
app.include_router(hub.router)
app.include_router(admin.router)

ADMIN_HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "admin.html")

@app.get("/admin", response_class=HTMLResponse)
async def admin_portal():
    if os.path.exists(ADMIN_HTML_PATH):
        return FileResponse(ADMIN_HTML_PATH)
    return HTMLResponse("<h1>Admin portal file not found</h1>", status_code=404)

@app.get("/")
async def root():
    return {
        "service": "Guardra Server API",
        "status": "online",
        "version": "1.0.0",
        "admin_portal": "/admin",
        "docs": "/docs",
        "health": "/api/health"
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Guardra Server Backend",
        "version": "1.0.0",
        "features": [
            "DPDP Act 2023 / GDPR / CCPA Compliance Scoring",
            "Real-Time Policy NLP Web Scraping & Evaluation",
            "K-Anonymity Zero-Knowledge Breach Audits",
            "Statutory Deletion Request Notice & PDF Generator",
            "Privacy Control Hub Directory",
            "Admin Policy Override & Rating Management",
            "Automated Policy Crawler & Re-scoring Engine"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
