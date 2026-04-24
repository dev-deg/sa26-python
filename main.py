import logging
import sys
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import JWTError, jwt

from lxml import etree
import defusedxml.ElementTree as safe_xml

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


# -- XSS DEMO ENDPOINT (for testing only, do not use in production)

@app.get("/vuln/xss", tags=["Vulnerable"])
@limiter.limit("60/minute")
def vulnerable_xss(request: Request, name: str = "World"):
    """A vulnerable endpoint that reflects user input without sanitization (for testing only)"""
    response = templates.TemplateResponse(
        "xss.html", {"request": request, "name": name, "vulnerable": True}
        )
    
    # Fake session cookie - to test XSS
    response.set_cookie("session_id", "a688b9898ef7ca683b1bdac9c8d9a5c39536977d70a2895a7fc9352df0997dfa") # ← this cookie is not HttpOnly, so it can be stolen by XSS
    response.set_cookie("user_role", "admin")  # ← this cookie is not HttpOnly, so it can be stolen by XSS

    return response

@app.get("/secure/xss", tags=["Vulnerable"])
@limiter.limit("60/minute")
def vulnerable_xss(request: Request, name: str = "World"):
    """A vulnerable endpoint that reflects user input without sanitization (for testing only)"""
    response = templates.TemplateResponse(
        "xss.html", {"request": request, "name": name, "vulnerable": False}
        )
    
    # Fake session cookie - to test XSS
    response.set_cookie("session_id", "a688b9898ef7ca683b1bdac9c8d9a5c39536977d70a2895a7fc9352df0997dfa") # ← this cookie is not HttpOnly, so it can be stolen by XSS
    response.set_cookie("user_role", "admin")  # ← this cookie is not HttpOnly, so it can be stolen by XSS
    return response

# ── XXE Demo Endpoints ────────────────────────────────────────────────────────

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

# ── SQLite Demo Setup ─────────────────────────────────────────────────────────

_DB_PATH = Path(__file__).parent / "demo_users.db"

def _init_demo_db():
    """Create and seed an in-memory-style SQLite DB for the SQL injection demos."""
    con = sqlite3.connect(_DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email    TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'user'
        )
    """)
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            [
                ("alice", "alice@example.com", "admin"),
                ("bob",   "bob@example.com",   "user"),
                ("charlie", "charlie@example.com", "user"),
            ],
        )
    con.commit()
    con.close()

_init_demo_db()

def _build_demo_payload(target: Path) -> bytes:
    """Generate an XXE payload that reads target using the correct absolute URI for this OS."""
    uri = target.as_uri()   # file:///absolute/path — works on Windows and Unix
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE item [<!ENTITY secret SYSTEM "{uri}">]>'
        f"<item><name>Demo Attack</name><description>&secret;</description></item>"
    ).encode()


@app.post("/vuln/xxe", tags=["Vulnerable - Educational"])
@limiter.limit("20/minute")
async def vulnerable_xxe(request: Request, demo: str | None = None):
    """
    VULNERABLE: Parses XML using lxml with external entity resolution enabled.

    Pass ?demo=secrets to auto-generate a cross-platform payload that reads
    demo_files/fake_secrets.env (contains fake credentials — no real secrets).

    curl -X POST "http://localhost:8000/vuln/xxe?demo=secrets"
    """
    if demo:
        target = _DEMO_TARGETS.get(demo)
        if not target:
            return {"error": f"Unknown demo target '{demo}'. Available: {list(_DEMO_TARGETS)}"}
        if demo == "billion_laughs":
            body = target.read_bytes()          # send the raw XML bomb as-is
        else:
            body = _build_demo_payload(target)  # wrap file path in an entity
    else:
        body = await request.body()

    try:
        # VULNERABLE: resolve_entities=True + load_dtd=True allows XXE file reads
        parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=True)
        root = etree.fromstring(body, parser)
        return {
            "warning": "VULNERABLE endpoint — external entities were resolved",
            "parsed": _extract_xml_text(root),
        }
    except etree.XMLSyntaxError as exc:
        if "amplification" in str(exc).lower():
            return {
                "blocked_by": "lxml / libxml2 (not defusedxml)",
                "reason": "Maximum entity amplification factor exceeded",
                "finding": (
                    "lxml's underlying C library (libxml2) has a built-in amplification "
                    "limit that stops billion-laughs expansion before it consumes memory. "
                    "This is defence-in-depth at the C library level — but it is NOT "
                    "something every XML parser provides. Older parsers (Python's stdlib "
                    "xml.etree before 3.8, PHP's SimpleXML, Java's DocumentBuilder with "
                    "default settings) have no such limit and will exhaust RAM. "
                    "defusedxml blocks it earlier and more explicitly, at the Python layer."
                ),
            }
        return {"error": f"XML parse error: {exc}"}


@app.post("/secure/xxe", tags=["Secure - Educational"])
@limiter.limit("20/minute")
async def secure_xxe(request: Request, demo: str | None = None):
    """
    SECURE: Parses XML using defusedxml, which forbids external entities, DTDs,
    and recursive entity expansion (billion laughs).

    Supports the same ?demo= targets as /vuln/xxe so you can compare results
    side-by-side without changing the payload.

    curl -X POST "http://localhost:8000/secure/xxe?demo=secrets"
    curl -X POST "http://localhost:8000/secure/xxe?demo=billion_laughs"
    """
    if demo:
        target = _DEMO_TARGETS.get(demo)
        if not target:
            return {"error": f"Unknown demo target '{demo}'. Available: {list(_DEMO_TARGETS)}"}
        body = target.read_bytes() if demo == "billion_laughs" else _build_demo_payload(target)
    else:
        body = await request.body()
    try:
        # SECURE: defusedxml raises DefusedXmlException for any dangerous construct
        root = safe_xml.fromstring(body.decode())
        result = {}
        for elem in root.iter():
            if elem.text and elem.text.strip():
                result[elem.tag] = elem.text.strip()
        return {
            "note": "SECURE endpoint — parsed safely with defusedxml",
            "parsed": result,
        }
    except Exception as exc:
        return {
            "blocked": True,
            "reason": type(exc).__name__,
            "detail": str(exc),
            "note": "defusedxml blocked a dangerous XML construct",
        }

# ── SQL Injection Demo Endpoints ─────────────────────────────────────────────

def _get_db():
    con = sqlite3.connect(_DB_PATH)
    con.row_factory = sqlite3.Row
    return con


@app.get("/vuln/sqli", tags=["Vulnerable - Educational"])
@limiter.limit("60/minute")
def vulnerable_sqli(request: Request, username: str = "alice"):
    """
    VULNERABLE: Looks up a user by username using **string interpolation**,
    which allows SQL injection.

    Safe example  → /vuln/sqli?username=alice
    Inject all    → /vuln/sqli?username=' OR '1'='1
    Dump schema   → /vuln/sqli?username=' UNION SELECT 1,sql,3,4 FROM sqlite_master--
    """
    query = f"SELECT id, username, email, role FROM users WHERE username = '{username}'"
    logger.warning(f"[VULN SQLi] Executing: {query}")
    try:
        con = _get_db()
        # VULNERABLE: raw string interpolation allows injected SQL to run -> con.execute(query)
        rows = con.execute(query).fetchall()
        con.close()
        return {
            "warning": "VULNERABLE endpoint — raw string interpolation used in SQL query",
            "query_executed": query,
            "results": [dict(r) for r in rows],
        }
    except Exception as exc:
        return {"error": str(exc), "query_attempted": query}


@app.get("/secure/sqli", tags=["Secure - Educational"])
@limiter.limit("60/minute")
def secure_sqli(request: Request, username: str = "alice"):
    """
    SECURE: Looks up a user by username using a **parameterised query**,
    which prevents SQL injection — the injected string is treated as data,
    not as SQL code.

    Safe example  → /secure/sqli?username=alice
    Inject attempt → /secure/sqli?username=' OR '1'='1   (returns no rows)
    """
    query = "SELECT id, username, email, role FROM users WHERE username = ?"
    logger.info(f"[SECURE SQLi] Executing parameterised query for username={username!r}")
    con = _get_db()
    # SECURE: parameterised query prevents injection — the ? placeholder is replaced safely by the value in the tuple (username,) -> con.execute(query, (username,))
    rows = con.execute(query, (username,)).fetchall()
    con.close()
    return {
        "note": "SECURE endpoint — parameterised query used, injection not possible",
        "results": [dict(r) for r in rows],
    }


# ── Log Injection Demo Endpoints ──────────────────────────────────────────────

@app.get("/vuln/log-injection", tags=["Vulnerable - Educational"])
@limiter.limit("60/minute")
def vulnerable_log_injection(request: Request, username: str = "alice"):
    """
    VULNERABLE: Logs user-supplied input directly without any sanitisation.

    An attacker can inject fake log entries by embedding newline characters,
    which causes the logger to write additional, spoofed lines.

    Safe example    → /vuln/log-injection?username=alice
    Inject example  → /vuln/log-injection?username=alice%0A2026-04-24+12:00:00+|+INFO+|+Fake+log+entry+injected+by+attacker
    """
    # VULNERABLE: user-controlled value interpolated directly into the log message
    # A newline in `username` will break the log into multiple lines, letting an
    # attacker forge entries that look like genuine log records.
    logger.warning(f"[VULN LOG] Login attempt for username: {username}")
    return {
        "warning": "VULNERABLE endpoint — user input logged without sanitisation",
        "username_received": username,
        "tip": (
            "Try passing a newline in the username parameter, e.g. "
            "?username=alice%0A2026-04-24+12:00:00+|+INFO+|+Fake+entry"
        ),
    }


@app.get("/secure/log-injection/v1", tags=["Secure - Educational"])
@limiter.limit("60/minute")
def secure_log_injection(request: Request, username: str = "alice"):
    """
    SECURE: Sanitises user-supplied input before logging by stripping (or
    replacing) newline and carriage-return characters, which eliminates the
    ability to inject forged log lines.

    Safe example    → /secure/log-injection?username=alice
    Inject attempt  → /secure/log-injection?username=alice%0AFake+log+entry  (newline stripped)
    """
    # SECURE: remove CR / LF characters so injected newlines cannot forge new log lines
    sanitised_username = username.replace("\n", " ").replace("\r", " ")
    logger.info(f"[SECURE LOG] Login attempt for username: {sanitised_username!r}")
    return {
        "note": "SECURE endpoint — newline characters stripped before logging",
        "username_received": username,
        "username_logged": sanitised_username,
    }

@app.get("/secure/log-injection/v2", tags=["Secure - Educational"])
@limiter.limit("60/minute")
def secure_log_injection(request: Request, username: str = "alice"):
    """
    SECURE: Sanitises user-supplied input before logging by stripping (or
    replacing) newline and carriage-return characters, which eliminates the
    ability to inject forged log lines.

    Safe example    → /secure/log-injection?username=alice
    Inject attempt  → /secure/log-injection?username=alice%0AFake+log+entry  (newline stripped)
    """
    # SECURE: pass the untrusted value as a positional argument to the logger,
    # using a {} placeholder in the format string — equivalent to printf's "%s"
    # parameterised approach.  Loguru (like Python's stdlib logging with "%s")
    # keeps the format string and the value separate; the value is never
    # concatenated into the template, so a newline inside `username` cannot
    # break the record into multiple lines or forge new log entries.
    # This is analogous to: logger.info("Login attempt for username: %s", username)
    # in stdlib logging, but loguru uses {} placeholders instead of %s.
    logger.info("[SECURE LOG] Login attempt for username: {}", username)
    return {
        "note": "SECURE endpoint — value passed as positional argument (parameterised), not interpolated into the format string",
        "username_received": username,
    }