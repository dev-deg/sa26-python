from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

#Setup rate limiting
limiter = Limiter(key_func=get_remote_address)

# Pydantic models

class Item(BaseModel):
    id: int
    name: str
    description: str
    owner: str

app = FastAPI(
    title="Secure API Demo",
    description="Demonstrates public and JWT-secured endpoints with FastAPI",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

FAKE_ITEMS_DB: list[dict] = [
    {"id": 1, "name": "Sword of Destiny", "description": "A legendary blade forged in dragon fire.", "owner": "alice"},
    {"id": 2, "name": "Shield of Valor", "description": "An unbreakable shield blessed by the gods.", "owner": "bob"},
    {"id": 3, "name": "Cloak of Shadows", "description": "Renders the wearer invisible in darkness.", "owner": "alice"},
    {"id": 4, "name": "Staff of Wisdom", "description": "Grants its wielder vast arcane knowledge.", "owner": "charlie"},
    {"id": 5, "name": "Boots of Swiftness", "description": "Doubles the speed of whoever wears them.", "owner": "bob"},
]

@app.get("/", tags=["Public"])
@limiter.limit("60/minute")
def root(request: Request):
    """Health-check - no authentication required"""
    return {"status": "ok", "message": "Secure API Demo is running!"}

@app.get("/public/status", tags=["Public"])
@limiter.limit("60/minute")
def public_status(request: Request):
    """Returns basic API status information - publicly accessible"""
    return {
        "api": "Secure API Demo",
        "version" : "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/public/items", tags=["Public"], response_model=list[Item])
def list_public_items(request: Request):
    """Returns a list of public items - publicly accessible"""
    return FAKE_ITEMS_DB

@app.get("/public/items/search", tags=["Public"], response_model=list[Item])
def search_public_items(request: Request, name: str):
    """Search for public items by name - publicly accessible"""
    return [item for item in FAKE_ITEMS_DB if name.lower() in item["name"].lower()]
