import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routers import policy, deletion, breach, hub

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

@app.get("/")
async def root():
    return {
        "service": "Guardra Server API",
        "status": "online",
        "version": "1.0.0",
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
            "Privacy Control Hub Directory"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
