from datetime import datetime, timedelta, timezone
from fastapi import FastAPI

app = FastAPI(
    title="Secure API Demo",
    description="Demonstrates public and JWT-secured endpoints with FastAPI",
    version="1.0.0"
)

@app.get("/", tags=["Public"])
def root():
    """Health-check - no authentication required"""
    return {"status": "ok", "message": "Secure API Demo is running!"}

@app.get("/public/status", tags=["Public"])
def public_status():
    """Returns basic API status information - publicly accessible"""
    return {
        "api": "Secure API Demo",
        "version" : "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }