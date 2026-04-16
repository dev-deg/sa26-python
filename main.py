import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import JWTError, jwt

from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from passlib.context import CryptContext

from dotenv import load_dotenv
import os

from loguru import logger
from fastapi.middleware.cors import CORSMiddleware

load_dotenv()

# ── Logging setup (must happen before FastAPI / uvicorn touch anything) ───────

# Step 1: silence uvicorn's stdlib-based logger
logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)

# Step 2: remove loguru's default stderr handler (ALWAYS do this first)
logger.remove()

# Step 3: console — INFO and above
logger.add(
    sys.stdout,
    level="INFO",
    colorize=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {name}:{line} | {message}",
)

# Step 4: rolling file — async write so disk never blocks responses
logger.add(
    str(Path(__file__).parent / "logs" / "log-{time:YYYYMMDD}.txt"),
    rotation="1 day",
    level="INFO",
    enqueue=True,
)

# ─────────────────────────────────────────────────────────────────────────────

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM","HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
USERNAME = os.getenv("API_USERNAME")
# Hash the password from .env for demonstration purposes (to simulate a stored hashed password in a database)
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
HASHED_PASSWORD = _pwd_context.hash(os.getenv("PASSWORD"))

#Setup rate limiting
limiter = Limiter(key_func=get_remote_address)

# Pydantic models

class Item(BaseModel):
    id: int
    name: str
    description: str
    owner: str

class ItemCreate(BaseModel):
    name: str
    description: str

app = FastAPI(
    title="Secure API Demo",
    description="Demonstrates public and JWT-secured endpoints with FastAPI",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

FAKE_ITEMS_DB: list[dict] = [
    {"id": 1, "name": "Sword of Destiny", "description": "A legendary blade forged in dragon fire.", "owner": "alice"},
    {"id": 2, "name": "Shield of Valor", "description": "An unbreakable shield blessed by the gods.", "owner": "bob"},
    {"id": 3, "name": "Cloak of Shadows", "description": "Renders the wearer invisible in darkness.", "owner": "alice"},
    {"id": 4, "name": "Staff of Wisdom", "description": "Grants its wielder vast arcane knowledge.", "owner": "charlie"},
    {"id": 5, "name": "Boots of Swiftness", "description": "Doubles the speed of whoever wears them.", "owner": "bob"},
]

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"{request.method} {request.url.path}")
    response = await call_next(request)   # ← route runs here
    logger.info(f"Status: {response.status_code}")
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],                       # ← only this origin - UPDATE for Production!
    allow_credentials=True,
    allow_methods=["GET", "POST"],           # ← only these methods
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Stop browsers guessing the content type
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Block this page being embedded in an iframe
    response.headers["X-Frame-Options"] = "DENY"
    # Restrict where scripts can be loaded from
    # response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app.get("/", tags=["Public"])
@limiter.limit("60/minute")
def root(request: Request):
    """Return a simple index.html page (inside the templates folder)"""
    return templates.TemplateResponse("index.html", {"request": request})

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
@limiter.limit("60/minute")
def list_public_items(request: Request):
    """Returns a list of public items - publicly accessible"""
    return FAKE_ITEMS_DB

@app.get("/public/items/search", tags=["Public"], response_model=list[Item])
@limiter.limit("60/minute")
def search_public_items(request: Request, name: str):
    """Search for public items by name - publicly accessible"""
    return [item for item in FAKE_ITEMS_DB if name.lower() in item["name"].lower()]

@app.post("/auth/token", tags=["Auth"])
@limiter.limit("5/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """Login and return a JWT token"""
    # In a real app, we would need to query the database for the user and verify the password
    username_match = form_data.username == USERNAME
    password_match = _pwd_context.verify(form_data.password, HASHED_PASSWORD) if HASHED_PASSWORD else False
    if not username_match or not password_match:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid credentials (username_match={username_match}, password_match={password_match})",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": form_data.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

@app.get("/secure/items", tags=["Secured"], response_model=list[Item])
@limiter.limit("60/minute")
def list_secure_items(request: Request, token: str = Depends(oauth2_scheme)):
    """Returns a list of secure items - authentication required"""
    return FAKE_ITEMS_DB

@app.post("/secure/items", tags=["Secured"], response_model=dict)
@limiter.limit("60/minute")
def create_secure_item(request: Request, itemCreate: ItemCreate, token: str = Depends(oauth2_scheme)):
    """Creates a new secure item - authentication required"""
    new_id = max(item["id"] for item in FAKE_ITEMS_DB) + 1 if FAKE_ITEMS_DB else 1
    item = Item(id=new_id, name=itemCreate.name, description=itemCreate.description, owner=USERNAME)
    FAKE_ITEMS_DB.append(item.dict())
    return {"message": "Secure item created", "item": item}