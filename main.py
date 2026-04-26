import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import JWTError, jwt

from lxml import etree
import defusedxml.ElementTree as safe_xml

from pydantic import BaseModel, field_validator
import bleach
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
# SECURITY NOTE: Proper logging is crucial for incident response and auditing.
# We use loguru for structured, asynchronous logging.

# Step 1: silence uvicorn's stdlib-based logger to avoid duplicate/messy logs
logging.getLogger("uvicorn").setLevel(logging.CRITICAL)
logging.getLogger("uvicorn.access").setLevel(logging.CRITICAL)

# Step 2: remove loguru's default stderr handler
logger.remove()

# Step 3: console — INFO and above
logger.add(
    sys.stdout,
    level="INFO",
    colorize=True,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {name}:{line} | {message}",
)

# Step 4: rolling file — async write so disk never blocks responses
# Keeping persistent logs helps in identifying attack patterns over time.
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

# SECURITY NOTE: Never store passwords in plain text. Use strong hashing like bcrypt.
# The CryptContext here handles salts and secure comparison for us.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
HASHED_PASSWORD = _pwd_context.hash(os.getenv("PASSWORD"))

# SECURITY NOTE: Rate limiting prevents Brute Force and DoS attacks by restricting 
# how many requests a client can make in a given timeframe.
limiter = Limiter(key_func=get_remote_address)

# ── Pydantic models with Input Sanitization ───────────────────────────────────
# SECURITY NOTE: Input Sanitization is the first line of defense against Injection.
# We use bleach.clean() to strip out dangerous HTML tags/attributes that could 
# lead to XSS (Cross-Site Scripting).

class Item(BaseModel):
    id: int
    name: str
    description: str
    owner: str

    @field_validator("name", "description", "owner")
    @classmethod
    def sanitize_strings(cls, v: str) -> str:
        """Strip dangerous HTML to prevent reflected or stored XSS."""
        return bleach.clean(v)

class ItemCreate(BaseModel):
    name: str
    description: str

    @field_validator("name", "description")
    @classmethod
    def sanitize_strings(cls, v: str) -> str:
        return bleach.clean(v)

class User(BaseModel):
    id: int
    username: str
    email: str
    full_name: str | None = None

    @field_validator("username", "email", "full_name")
    @classmethod
    def sanitize_strings(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return bleach.clean(v)

class UserCreate(BaseModel):
    username: str
    email: str
    password: str 
    # NOTE: We do NOT sanitize the password with bleach. 
    # Sanitizing might change the actual character sequence (e.g., converting "<" to "&lt;").
    # Passwords should be hashed immediately, making injection in HTML contexts irrelevant.

    @field_validator("username", "email")
    @classmethod
    def sanitize_strings(cls, v: str) -> str:
        return bleach.clean(v)

class Feedback(BaseModel):
    content: str
    rating: int

    @field_validator("content")
    @classmethod
    def sanitize_content(cls, v: str) -> str:
        """Stored XSS often happens via feedback/comments displayed to admins later."""
        return bleach.clean(v)

class Comment(BaseModel):
    item_id: int
    user_id: int
    text: str

    @field_validator("text")
    @classmethod
    def sanitize_text(cls, v: str) -> str:
        return bleach.clean(v)

class SearchQuery(BaseModel):
    query: str
    category: str | None = None

    @field_validator("query", "category")
    @classmethod
    def sanitize_search(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return bleach.clean(v)

# ─────────────────────────────────────────────────────────────────────────────

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
    """Audit log for every incoming request."""
    logger.info(f"{request.method} {request.url.path}")
    response = await call_next(request)
    logger.info(f"Status: {response.status_code}")
    return response

# SECURITY NOTE: CORS (Cross-Origin Resource Sharing) should be restrictive.
# Allow-Origins should be a specific list of trusted domains, not "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],                       # ← UPDATE for Production!
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Security Headers instruct the browser to enable built-in protections."""
    response = await call_next(request)
    # X-Content-Type-Options: nosniff -> Prevents Mime-Sniffing attacks.
    response.headers["X-Content-Type-Options"] = "nosniff"
    # X-Frame-Options: DENY -> Prevents Clickjacking by forbidding the site from being framed.
    response.headers["X-Frame-Options"] = "DENY"
    # Content-Security-Policy (CSP) -> Extremely powerful against XSS.
    # response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Generates a secure JWT token for authenticated sessions."""
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
    """Login and return a JWT token. Rate limited to 5 tries/min to slow brute force."""
    username_match = form_data.username == USERNAME
    password_match = _pwd_context.verify(form_data.password, HASHED_PASSWORD) if HASHED_PASSWORD else False
    if not username_match or not password_match:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
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
    """Creates a new secure item. Pydantic's field_validator cleans the input."""
    new_id = max(item["id"] for item in FAKE_ITEMS_DB) + 1 if FAKE_ITEMS_DB else 1
    item = Item(id=new_id, name=itemCreate.name, description=itemCreate.description, owner=USERNAME)
    FAKE_ITEMS_DB.append(item.dict())
    return {"message": "Secure item created", "item": item}


# ── XSS (Cross-Site Scripting) Demo ───────────────────────────────────────────
# XSS occurs when an application includes untrusted data in a web page without 
# proper validation or escaping. This allows an attacker to execute malicious 
# scripts in the victim's browser.

@app.get("/vuln/xss", tags=["Vulnerable"])
@limiter.limit("60/minute")
def vulnerable_xss(request: Request, name: str = "World"):
    """
    VULNERABLE: This endpoint reflects the 'name' parameter directly into HTML.
    Try passing: <script>alert('XSS!')</script> as the name.
    """
    response = templates.TemplateResponse(
        "xss.html", {"request": request, "name": name, "vulnerable": True}
        )
    
    # SECURITY NOTE: Cookies should ALWAYS be 'HttpOnly' and 'Secure'.
    # If a cookie is NOT HttpOnly, an attacker's script can steal it via document.cookie.
    response.set_cookie("session_id", "a688b9898ef7ca683b1bdac9c8d9a5c39536977d70a2895a7fc9352df0997dfa")
    response.set_cookie("user_role", "admin") 

    return response

@app.get("/secure/xss", tags=["Vulnerable"])
@limiter.limit("60/minute")
def secure_xss_endpoint(request: Request, name: str = "World"):
    """
    SECURE: Uses Jinja2's auto-escaping, which converts characters like '<' to '&lt;'.
    This prevents the browser from interpreting the input as a script tag.
    """
    response = templates.TemplateResponse(
        "xss.html", {"request": request, "name": name, "vulnerable": False}
        )
    
    # In a real secure app, these would be: httponly=True, secure=True
    response.set_cookie("session_id", "...", httponly=True)
    return response

# ── XXE (XML External Entity) Demo ───────────────────────────────────────────
# XXE is a vulnerability where an XML parser improperly handles external entities.
# Attackers can use entities to read local files, perform SSRF (Server-Side Request 
# Forgery), or cause Denial of Service (Billion Laughs attack).

def _extract_xml_text(root) -> dict:
    """Walk an XML element tree and collect tag → text pairs."""
    result = {}
    for elem in root.iter():
        if elem.text and elem.text.strip():
            result[elem.tag] = elem.text.strip()
    return result

_DEMO_TARGETS = {
    "secrets": Path(__file__).parent / "demo_files" / "fake_secrets.env",
    "billion_laughs": Path(__file__).parent / "attack_files" / "xxe_billion_laughs.xml",
}

def _build_demo_payload(target: Path) -> bytes:
    """Generate an XXE payload that defines a SYSTEM entity pointing to a file."""
    uri = target.as_uri()
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE item [<!ENTITY secret SYSTEM "{uri}">]>'
        f"<item><name>Demo Attack</name><description>&secret;</description></item>"
    ).encode()


@app.post("/vuln/xxe", tags=["Vulnerable - Educational"])
@limiter.limit("20/minute")
async def vulnerable_xxe(request: Request, demo: str | None = None):
    """
    VULNERABLE: Uses a parser with 'resolve_entities=True'.
    The parser will actually fetch the file path defined in the XML entity.
    """
    if demo:
        target = _DEMO_TARGETS.get(demo)
        if not target: return {"error": "Invalid demo"}
        body = target.read_bytes() if demo == "billion_laughs" else _build_demo_payload(target)
    else:
        body = await request.body()

    try:
        # Resolve entities allows fetching local files or internal URLs
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
        root = etree.fromstring(body, parser)
        return {
            "warning": "VULNERABLE: entities were resolved",
            "parsed": _extract_xml_text(root),
        }
    except etree.XMLSyntaxError as exc:
        return {"error": str(exc)}


@app.post("/secure/xxe", tags=["Secure - Educational"])
@limiter.limit("20/minute")
async def secure_xxe(request: Request, demo: str | None = None):
    """
    SECURE: Uses 'defusedxml', which explicitly disables entity resolution.
    It blocks SYSTEM entities and recursive entity expansion by default.
    """
    if demo:
        target = _DEMO_TARGETS.get(demo)
        if not target: return {"error": "Invalid demo"}
        body = target.read_bytes() if demo == "billion_laughs" else _build_demo_payload(target)
    else:
        body = await request.body()
    try:
        # defusedxml is a safe wrapper around standard XML libraries
        root = safe_xml.fromstring(body.decode())
        result = _extract_xml_text(root)
        return {
            "note": "SECURE: parsed safely with defusedxml",
            "parsed": result,
        }
    except Exception as exc:
        return {
            "blocked": True,
            "reason": type(exc).__name__,
            "detail": str(exc),
        }