import os
import json
from fastapi import FastAPI, HTTPException, Query, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import requests
import time
import datetime
import asyncio
from contextlib import asynccontextmanager
import ssl
import socket
import re
import ipaddress
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sqlite3
import secrets
import datetime as dt
from typing import Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
import models
from database import get_db
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)

# --- Enterprise Configuration ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "multi_static")
DB_PATH = os.path.join(BASE_DIR, "domains.json")
MAX_DOMAINS = 999999  # No domain limit
PING_INTERVAL = 120  # 2 minutes

# Local runs use an ephemeral signing key unless configured. Live deployments
# must set JWT_SECRET_KEY to a stable random secret (32+ characters).
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or secrets.token_urlsafe(48)
JWT_ALGORITHM = "HS256"
JWT_TTL_HOURS = 12
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)
password_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
VALID_ROLES = {"Admin", "Operator", "Viewer", "Guest"}

if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)

# --- Email Alert Configuration ---
ACTIVE_ALERTS = {}
SYSTEM_EVENT_LOGS = []

def log_event(service, level, message, source="Internal"):
    """Adds an event to the global log list for Central Diagnostics."""
    global SYSTEM_EVENT_LOGS
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "time": timestamp,
        "service": service,
        "level": level,
        "message": message,
        "source": source
    }
    SYSTEM_EVENT_LOGS.append(entry)
    if len(SYSTEM_EVENT_LOGS) > 100:
        SYSTEM_EVENT_LOGS.pop(0)
    print(f"[{timestamp}] [{level}] {service}: {message}")

def get_email_settings():
    db_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitoring.db")
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute("SELECT smtp_server, smtp_port, smtp_user, smtp_pass, recipient FROM email_settings LIMIT 1")
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "server": row[0],
                "port": row[1],
                "user": row[2],
                "pass": row[3],
                "recipient": row[4]
            }
    except Exception as e:
        print(f"Error fetching email settings: {e}")
    return None

def dispatch_email_sync(domain: str, status: str, details: str):
    settings = get_email_settings()
    if not settings:
        print(f"Skipping email for {domain} ({status}): No settings in database")
        return
        
    try:
        msg = MIMEMultipart()
        msg['From'] = f"uptrix-monitor@{socket.gethostname()}"
        msg['To'] = settings['recipient']
        
        if status == "DOWN":
            msg['Subject'] = f"CRITICAL: {domain} is Offline"
            color = "#ef4444"
            status_text = "OFFLINE"
        else:
            msg['Subject'] = f"RESOLVED: {domain} is Back Online"
            color = "#22c55e"
            status_text = "ONLINE & RECOVERED"
            
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; background-color: #f8fafc; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);">
                    <div style="background-color: {color}; padding: 20px; text-align: center; color: white;">
                        <h2 style="margin: 0;">UPTRIX System Alert</h2>
                    </div>
                    <div style="padding: 30px;">
                        <p style="font-size: 16px; color: #334155;">Automated System Alert: {domain} is {status_text}.</p>
                        <div style="background-color: #f1f5f9; padding: 15px; border-radius: 6px; margin: 20px 0;">
                            <p style="margin: 5px 0;"><strong>Domain:</strong> {domain}</p>
                            <p style="margin: 5px 0;"><strong>Status:</strong> <span style="color: {color}; font-weight: bold;">{status_text}</span></p>
                            <p style="margin: 5px 0;"><strong>Details:</strong> {details}</p>
                            <p style="margin: 5px 0;"><strong>Time:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                        <p style="font-size: 12px; color: #94a3b8; text-align: center;">This is an automated notification from your monitoring system.</p>
                    </div>
                </div>
            </body>
        </html>
        """
        msg.attach(MIMEText(html, 'html'))
        
        server = smtplib.SMTP(settings['server'], settings['port'], timeout=10)
        
        # Only use TLS and Login if not using Local MTA (Port 25)
        if settings['port'] != 25 and settings['user'] and settings['pass']:
            server.starttls()
            server.login(settings['user'], settings['pass'])
            msg['From'] = settings['user'] # Override from for authenticated SMTP
        
        server.send_message(msg)
        server.quit()
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Email Alert Sent to {settings['recipient']}: {domain} -> {status}")
    except Exception as e:
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Failed to send email alert for {domain}: {e}")

async def send_email_alert(domain: str, status: str, details: str):
    await asyncio.to_thread(dispatch_email_sync, domain, status, details)

async def is_internal_ip(domain: str) -> bool:
    def _check():
        try:
            internal_patterns = [
                r'^127\.', r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.', r'^192\.168\.',
                r'^169\.254\.', r'^localhost'
            ]
            if any(re.match(p, domain) for p in internal_patterns):
                if domain.startswith("192.168.101."):
                    return False
                return True

            try:
                ip = socket.gethostbyname(domain)
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback or addr.is_link_local:
                    if ip.startswith("192.168.101.") or ip == "192.168.101.135" or ip == "192.168.101.111":
                        return False
                    return True
                return False
            except socket.gaierror:
                return False
        except Exception:
            return False
    return await asyncio.to_thread(_check)

# --- Persistence Layer ---
def clean_domain_name(domain: str) -> str:
    if not domain: return ""
    # Deep clean: remove protocols, whitespace, and consecutive dots
    clean = domain.strip().lower()
    clean = clean.replace("https://", "").replace("http://", "").split('/')[0].strip('/')
    domain_only = re.sub(r'\.+', '.', clean).strip('.')
    return domain_only

# --- Persistence Layer ---
def load_domains():
    if os.path.exists(DB_PATH):
        try:
            with open(DB_PATH, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Migration: Clean all existing domains on load
                    return sorted(list(set(clean_domain_name(d) for d in data if d)))
                return []
        except Exception as e:
            print(f"ERROR loading domains: {e}")
            return None # Return None to indicate load failure
    return []

def save_domains(domains):
    if domains is None: return # Crucial: don't save if load failed
    with open(DB_PATH, "w") as f:
        json.dump(sorted(list(set(domains))), f, indent=4)

# --- State Management ---
initial_load = load_domains()
if initial_load is None:
    MONITORED_DOMAINS = []
else:
    MONITORED_DOMAINS = initial_load

cached_results = []
# Persistent history mapping
HISTORY_PATH = os.path.join(BASE_DIR, "history.json")

def load_history():
    if os.path.exists(HISTORY_PATH):
        try:
            with open(HISTORY_PATH, "r") as f: return json.load(f)
        except: return {}
    return {}

def save_history(h_cache):
    with open(HISTORY_PATH, "w") as f: json.dump(h_cache, f)

history_cache = load_history()
MAX_HISTORY_POINTS = 720 # 24 Hours (30 points/hour * 24 hours)
LAST_PING_TIMESTAMP = "Never"

# --- Monitoring Engine ---
async def get_ssl_info(hostname):
    def _fetch_ssl():
        try:
            host = hostname.replace("https://", "").replace("http://", "").split('/')[0].split(':')[0]
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    expiry_date = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                    days_left = (expiry_date.replace(tzinfo=None) - datetime.datetime.now()).days
                    return f"{days_left} Days"
        except Exception:
            return "N/A"
    return await asyncio.to_thread(_fetch_ssl)

DB_FAILURE_MARKERS = (
    "database",
    "db connection",
    "sqlalchemy",
    "sqlite",
    "postgres",
    "mysql",
    "mariadb",
    "redis",
    "connection pool",
    "could not connect to server",
    "connection refused",
)

RESOURCE_FAILURE_MARKERS = (
    "no space left",
    "disk full",
    "insufficient storage",
    "out of memory",
    "memory exhausted",
    "cannot allocate memory",
)

HIGH_LATENCY_MS = 2500

def root_cause(code: str, label: str, detail: str, confidence: str = "high") -> dict:
    return {
        "code": code,
        "label": label,
        "detail": detail,
        "confidence": confidence,
    }

def append_root_cause(result: dict, cause: dict) -> None:
    if not any(existing["code"] == cause["code"] for existing in result["root_causes"]):
        result["root_causes"].append(cause)

def set_failure_analysis(result: dict) -> None:
    status = str(result.get("status", "")).upper()
    latency = result.get("latency") or 0
    causes = result.get("root_causes") or []

    if status == "UP" and latency >= HIGH_LATENCY_MS:
        result["failure_analysis"] = f"Website is reachable but slow because response latency is {round(latency)}ms."
        return
    if status == "UP":
        result["failure_analysis"] = "Healthy."
        return
    if causes:
        primary = causes[0]
        detail = primary.get("detail") or primary.get("label") or "root cause detected"
        result["failure_analysis"] = f"Website down because {detail}"
        return
    reason = result.get("reason") or "the monitor could not reach the service"
    result["failure_analysis"] = f"Website down because {reason}."

async def get_dns_diagnostic(hostname: str) -> dict:
    def _resolve():
        try:
            addresses = sorted({
                item[4][0]
                for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            })
            return {"ok": True, "addresses": addresses[:4], "detail": ", ".join(addresses[:4])}
        except Exception as exc:
            return {"ok": False, "addresses": [], "detail": str(exc)}
    return await asyncio.to_thread(_resolve)

async def get_ssl_diagnostic(hostname: str) -> dict:
    def _inspect():
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    expiry = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
                    expiry_naive = expiry.replace(tzinfo=None)
                    days_left = (expiry_naive - datetime.datetime.now()).days
                    return {
                        "expired": days_left < 0,
                        "days_left": days_left,
                        "detail": f"certificate expired on {expiry_naive.strftime('%Y-%m-%d')}" if days_left < 0 else f"{days_left} days remaining",
                    }
        except Exception as exc:
            return {"expired": False, "days_left": None, "detail": str(exc)}
    return await asyncio.to_thread(_inspect)

def get_http_root_causes(resp: requests.Response) -> list:
    status_code = resp.status_code
    server_header = str(resp.headers.get("server", "")).lower()
    body_sample = str(resp.text or "")[:4000].lower() if status_code >= 500 else ""
    causes = []

    if status_code in (502, 503, 504) and ("nginx" in server_header or not server_header):
        causes.append(root_cause(
            "nginx_down",
            "nginx down",
            f"Gateway returned HTTP {status_code}; the reverse proxy could not serve the origin.",
            "medium",
        ))
    if status_code == 504:
        causes.append(root_cause(
            "origin_timeout",
            "origin server timeout",
            "Gateway timed out while waiting for the upstream origin.",
        ))
    if status_code >= 500 and any(marker in body_sample for marker in DB_FAILURE_MARKERS):
        causes.append(root_cause(
            "db_unreachable",
            "database connection failed",
            "database connection failed in the upstream application.",
            "medium",
        ))
    if status_code >= 500 and any(marker in body_sample for marker in RESOURCE_FAILURE_MARKERS):
        causes.append(root_cause(
            "server_resource_full",
            "server resource full",
            "server memory or storage appears full in the upstream error response.",
            "medium",
        ))
    return causes

async def perform_health_check(domain: str):
    domain_only = clean_domain_name(domain)
    if not domain_only: return None
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    
    result = {
        "url": domain_only,
        "status": "DOWN",
        "status_code": "---",
        "latency": 0,
        "ssl_expiry": "N/A",
        "timestamp": datetime.datetime.now().isoformat(),
        "reason": "Checking...",
        "root_causes": [],
    }

    # Latency check logic continues below

    # SSRF Protection: Block internal IP ranges
    if await is_internal_ip(domain_only):
        result["reason"] = "Restricted Internal Address (SSRF Block)"
        append_root_cause(result, root_cause(
            "restricted_internal_address",
            "restricted internal address",
            "monitoring blocked this internal address for SSRF protection.",
        ))
        set_failure_analysis(result)
        return result

    dns = await get_dns_diagnostic(domain_only)
    if not dns["ok"]:
        result["reason"] = "DNS failed"
        append_root_cause(result, root_cause(
            "dns_failed",
            "DNS failed",
            dns["detail"] or f"{domain_only} did not resolve.",
        ))
        set_failure_analysis(result)
        return result

    ssl_diagnostic = await get_ssl_diagnostic(domain_only)
    if ssl_diagnostic["expired"]:
        result["ssl_expiry"] = f"{ssl_diagnostic['days_left']} Days"
        result["reason"] = "SSL expired"
        append_root_cause(result, root_cause(
            "ssl_expired",
            "SSL expired",
            ssl_diagnostic["detail"],
        ))
        set_failure_analysis(result)
        return result
    # 2. HTTP Status Check & SSRF Protection
    # Consistently uses is_internal_ip which now allows the 192.168.101.0/24 subnet
    protocols = ["https://", "http://"]
    last_error = "DNS / Name Error"

    for proto in protocols:
        target = f"{proto}{domain_only}"
        start_time = time.time()
        try:
            # TLS Validation Enabled (verify=True is default, but explicitly setting it)
            # Send the host header explicitly to correctly route to the resolved IP
            def fetch_with_fallback():
                try:
                    return requests.get(target, headers=headers, timeout=30, verify=True, allow_redirects=True)
                except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
                    # Fallback for self-signed certs (e.g. xevhire)
                    return requests.get(target, headers=headers, timeout=30, verify=False, allow_redirects=True)

            resp = await asyncio.to_thread(fetch_with_fallback)
            latency = round((time.time() - start_time) * 1000, 2)
            
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] PING {domain_only} | Status: {resp.status_code} | Latency: {latency}ms")
            # Status refinement
            is_serious_err = resp.status_code >= 500
            result.update({
                "status": "UP" if not is_serious_err else "ERR",
                "status_code": resp.status_code,
                "latency": latency,
                "ssl_expiry": await get_ssl_info(domain_only) if proto == "https://" else "HTTP Only",
                "reason": "OK" if 200 <= resp.status_code < 400 else f"HTTP {resp.status_code}"
            })
            if result["status"] == "UP" and latency >= HIGH_LATENCY_MS:
                append_root_cause(result, root_cause(
                    "high_latency",
                    "high latency",
                    f"response latency is {round(latency)}ms.",
                    "medium",
                ))
                result["reason"] = "High latency"
            if not is_serious_err:
                # HTTP fallback can recover after a failed HTTPS transport attempt.
                result["root_causes"] = [
                    cause for cause in result["root_causes"]
                    if cause.get("code") == "high_latency"
                ]
            for cause in get_http_root_causes(resp):
                append_root_cause(result, cause)
            if result["root_causes"]:
                result["reason"] = result["root_causes"][0]["label"]
            set_failure_analysis(result)
            return result
        except requests.exceptions.SSLError as se:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] PING {domain_only} | SSL Error")
            last_error = "SSL certificate issue"
            append_root_cause(result, root_cause(
                "ssl_issue",
                "SSL issue",
                f"SSL certificate validation failed: {str(se)[:160]}",
            ))
        except requests.exceptions.ConnectionError as ce:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] PING {domain_only} | Connection Error")
            last_error = "DNS / Connection Failed"
            append_root_cause(result, root_cause(
                "web_listener_unreachable",
                "web listener unreachable",
                f"{proto.rstrip(':/').upper()} connection could not reach the web listener: {str(ce)[:160]}",
                "medium",
            ))
        except requests.exceptions.Timeout:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] PING {domain_only} | Timeout")
            last_error = "Request Timeout"
            append_root_cause(result, root_cause(
                "origin_timeout",
                "origin server timeout",
                f"{target} did not respond within 30 seconds.",
            ))
        except Exception as e:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] PING {domain_only} | Error: {e}")
            last_error = str(e)[:50]
            
    result["reason"] = last_error
    set_failure_analysis(result)
    return result

async def update_monitoring_task():
    while True:
        try:
            await load_immediate_check()
        except Exception as e:
            print(f"Monitoring loop error: {e}")
        await asyncio.sleep(PING_INTERVAL)

# --- API Layer ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(update_monitoring_task())
    log_event("Core-System", "INFO", "UPTRIX monitor service gracefully initialized and monitoring established.")
    yield
    task.cancel()

app = FastAPI(title="Enterprise Monitor v2", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

async def get_current_user(token: Optional[str] = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get("sub")
    except JWTError:
        username = None
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired session", headers={"WWW-Authenticate": "Bearer"})
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid or inactive account", headers={"WWW-Authenticate": "Bearer"})
    if user.role not in VALID_ROLES:
        raise HTTPException(status_code=403, detail="Account has an unsupported role")
    return user

def require_roles(*roles):
    def check_role(user=Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return check_role

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=256)

class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=256)
    role: str

class UserRoleUpdate(BaseModel):
    role: str

class UserPasswordReset(BaseModel):
    password: str = Field(min_length=12, max_length=256)

class UserActiveUpdate(BaseModel):
    is_active: bool

@app.post("/api/auth/login")
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    if len(payload.password) < 12:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    try:
        valid_password = bool(user and user.hashed_password and password_context.verify(payload.password, user.hashed_password))
    except (TypeError, ValueError):
        valid_password = False
    if not user or not user.is_active or not valid_password:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    expire = dt.datetime.utcnow() + dt.timedelta(hours=JWT_TTL_HOURS)
    token = jwt.encode({"sub": user.username, "exp": expire}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "username": user.username, "role": user.role}

@app.get("/api/auth/me")
def who_am_i(user=Depends(get_current_user)):
    return {"username": user.username, "role": user.role}

@app.get("/api/admin/users")
def list_users(db: Session = Depends(get_db), _admin=Depends(require_roles("Admin"))):
    return [{"id": u.id, "username": u.username, "role": u.role, "is_active": bool(u.is_active)} for u in db.query(models.User).order_by(models.User.id).all()]

@app.post("/api/admin/users", status_code=201)
def create_user(payload: UserCreate, db: Session = Depends(get_db), _admin=Depends(require_roles("Admin"))):
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail="Role must be Admin, Operator, Viewer, or Guest")
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")
    user = models.User(username=payload.username, hashed_password=password_context.hash(payload.password), role=payload.role,
                       permissions={"Admin": "admin", "Operator": "write", "Viewer": "read", "Guest": "demo"}[payload.role], is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": True}

@app.patch("/api/admin/users/{user_id}/role")
def update_user_role(user_id: int, payload: UserRoleUpdate, db: Session = Depends(get_db), admin=Depends(require_roles("Admin"))):
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail="Role must be Admin, Operator, Viewer, or Guest")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and payload.role != "Admin":
        raise HTTPException(status_code=400, detail="Administrators cannot remove their own Admin role")
    if user.role == "Admin" and payload.role != "Admin" and db.query(models.User).filter_by(role="Admin", is_active=True).count() <= 1:
        raise HTTPException(status_code=400, detail="The last active administrator cannot be demoted")
    user.role = payload.role
    user.permissions = {"Admin": "admin", "Operator": "write", "Viewer": "read", "Guest": "demo"}[payload.role]
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role}

@app.patch("/api/admin/users/{user_id}/password")
def reset_user_password(user_id: int, payload: UserPasswordReset, db: Session = Depends(get_db), _admin=Depends(require_roles("Admin"))):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = password_context.hash(payload.password)
    db.commit()
    return {"id": user.id, "username": user.username, "password_reset": True}

@app.patch("/api/admin/users/{user_id}/active")
def set_user_active(user_id: int, payload: UserActiveUpdate, db: Session = Depends(get_db), admin=Depends(require_roles("Admin"))):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id and not payload.is_active:
        raise HTTPException(status_code=400, detail="Administrators cannot deactivate their own account")
    if user.role == "Admin" and user.is_active and not payload.is_active and db.query(models.User).filter_by(role="Admin", is_active=True).count() <= 1:
        raise HTTPException(status_code=400, detail="The last active administrator cannot be deactivated")
    user.is_active = payload.is_active
    db.commit()
    return {"id": user.id, "username": user.username, "role": user.role, "is_active": bool(user.is_active)}

@app.delete("/api/admin/users/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), admin=Depends(require_roles("Admin"))):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Administrators cannot delete their own account")
    if user.role == "Admin" and user.is_active and db.query(models.User).filter_by(role="Admin", is_active=True).count() <= 1:
        raise HTTPException(status_code=400, detail="The last active administrator cannot be deleted")
    db.delete(user)
    db.commit()

@app.get("/")
def read_root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/report")
def get_report_page():
    return FileResponse(os.path.join(STATIC_DIR, "report.html"))

DEMO_SITES = [
    {"url": "status.example.com", "status": "UP", "status_code": "200", "latency": 84, "ssl_expiry": "2027-08-14", "reason": "Demo: site responding normally", "failure_analysis": "Demo data only; no live request was made."},
    {"url": "shop.example.org", "status": "UP", "status_code": "200", "latency": 142, "ssl_expiry": "2027-05-22", "reason": "Demo: site responding normally", "failure_analysis": "Demo data only; no live request was made."},
    {"url": "api.example.net", "status": "DOWN", "status_code": "503", "latency": 0, "ssl_expiry": "2027-06-03", "reason": "Demo: simulated service unavailable", "failure_analysis": "This is a simulated outage for demonstration."},
]

def demo_history(range_name="1h"):
    now = datetime.datetime.now()
    count = {"5m": 5, "30m": 6, "1h": 6, "24h": 8}.get(range_name, 6)
    result = {}
    for site in DEMO_SITES:
        values = [84, 91, 88, 102, 79, 84] if site["status"] == "UP" else [78, 81, 0, 0, 0, 0]
        result[site["url"]] = [{"time": (now - datetime.timedelta(minutes=(count-i)*5)).strftime("%H:%M"),
                                 "latency": values[i % len(values)], "status": "UP" if values[i % len(values)] else "DOWN"}
                                for i in range(count)]
    return result

@app.get("/api/demo/status")
def get_demo_status():
    results = [dict(site) for site in DEMO_SITES]
    online = sum(site["status"] == "UP" for site in results)
    latencies = [site["latency"] for site in results if site["latency"]]
    return {"demo": True, "results": results, "summary": {"total": len(results), "online": online,
            "offline": len(results)-online, "avg_latency": round(sum(latencies)/len(latencies), 2),
            "last_ping": "Sample data"}}

@app.get("/api/demo/history")
def get_demo_history(range: str = "1h"):
    return demo_history(range)

@app.get("/api/demo/collection")
def get_demo_collection():
    return {site["url"]: [{"time": point["time"], "latency": point["latency"], "status": point["status"],
                           "ssl_expiry": site["ssl_expiry"], "failure_analysis": site["failure_analysis"]}
                          for point in points] for site, (domain, points) in zip(DEMO_SITES, demo_history().items())}

@app.get("/api/demo/report")
def get_demo_report():
    return {"report_type": "UPTRIX public demo sample", "data_notice": "All entries are fixed demonstration data; no customer monitoring records are included.",
            "sites": DEMO_SITES, "history": demo_history()}

@app.get("/api/demo/report/pdf")
def get_demo_pdf_report():
    import io
    def pdf_escape(value):
        return str(value).encode("ascii", "replace").decode("ascii").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    lines = ["UPTRIX - Public Demo Sample Report", "Fixed example data only; no customer records are included.", ""]
    lines.extend(f'{s["url"]} | {s["status"]} | {s["latency"]} ms | SSL {s["ssl_expiry"]}' for s in DEMO_SITES)
    commands = ["BT", "/F1 16 Tf", "48 760 Td"]
    for index, line in enumerate(lines):
        if index == 1:
            commands.append("/F1 10 Tf")
        elif index == 2:
            commands.append("/F1 12 Tf")
        elif index > 2:
            commands.append("/F1 10 Tf")
        commands.extend([f"({pdf_escape(line)}) Tj", "0 -24 Td"])
    commands.append("ET")
    stream = "\n".join(commands).encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = io.BytesIO(); output.write(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(output.tell()); output.write(f"{number} 0 obj\n".encode("ascii")); output.write(obj); output.write(b"\nendobj\n")
    xref_offset = output.tell()
    output.write(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    for offset in offsets[1:]: output.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.write(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode("ascii"))
    output.seek(0)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(output, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=uptrix-demo-report.pdf"})

@app.get("/api/report/model")
async def get_report_model(_user=Depends(require_roles("Admin", "Operator", "Viewer"))):
    return {
        "model_name": "Infrastructure Analytical Report v2.0",
        "fields": [
            {"name": "Domain", "type": "String", "description": "Target monitored endpoint"},
            {"name": "Timestamp", "type": "DateTime", "description": "Time of collection (Local)"},
            {"name": "Latency", "type": "Float", "description": "Responsiveness in ms"},
            {"name": "Status", "type": "String", "description": "UP/DOWN status of the website"}
        ],
        "export_format": "CSV, JSON",
        "persistence_limit": "100 entries per domain"
    }

@app.get("/api/collection")
async def get_collection(_user=Depends(require_roles("Admin", "Operator", "Viewer"))):
    path = os.path.join(BASE_DIR, "trace_collection.json")
    if os.path.exists(path):
        return FileResponse(path)
    return {"detail": "No collection detected yet."}

@app.get("/api/report")
async def get_report(date: str = Query(None), _user=Depends(require_roles("Admin", "Operator", "Viewer"))):
    import openpyxl
    from openpyxl.styles import Font, Alignment, PatternFill, Border, Side
    from openpyxl.drawing.image import Image as XLImage
    import io
    from fastapi.responses import StreamingResponse
    
    # Load collection
    TRACE_PATH = os.path.join(BASE_DIR, "trace_collection.json")
    LOGO_PATH = os.path.join(STATIC_DIR, "logo_new.png")
    
    if not os.path.exists(TRACE_PATH):
        return {"detail": "No data available"}
    
    try:
        with open(TRACE_PATH, "r") as f:
            data = json.load(f)
        
        # Create Workbook
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Infrastructure Report"
        
        # 1. Branding Header
        try:
            from openpyxl.drawing.image import Image as XLImage
            if os.path.exists(LOGO_PATH):
                img = XLImage(LOGO_PATH)
                img.height = 60
                img.width = 60
                ws.add_image(img, 'B2')
        except Exception as img_err:
            print(f"Header Image Error: {img_err}")

        ws.merge_cells('C2:E3')
        title_cell = ws['C2']
        title_cell.value = "UPTRIX - Infrastructure Analytical Report"
        title_cell.font = Font(name='Segoe UI', size=14, bold=True, color="0F172A")
        title_cell.alignment = Alignment(horizontal='center', vertical='center')
        
        # Add Generation Timestamp & Filter info
        ws.merge_cells('C4:E4')
        gen_cell = ws['C4']
        gen_time = datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
        filter_display = f"FOR DATE: {date}" if date else "FULL SNAPSHOT"
        gen_cell.value = f"Report Type: {filter_display} | Generated On: {gen_time}"
        gen_cell.font = Font(name='Segoe UI', size=10, italic=True, color="64748B")
        gen_cell.alignment = Alignment(horizontal='center')
        
        # 2. Table Headers
        headers = ["Domain", "Timestamp", "Status", "Latency (ms)", "SLA / SSL Expiry", "Failure Analysis"]
        header_fill = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
        header_font = Font(name='Segoe UI', color="FFFFFF", bold=True)
        thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))
        
        start_row = 6
        for col_num, header_title in enumerate(headers, 1):
            cell = ws.cell(row=start_row, column=col_num)
            cell.value = header_title
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal='center')
            cell.border = thin_border
            
        # 3. Data Population
        current_row = start_row + 1
        found_data = False
        for domain, entries in data.items():
            for entry in entries:
                entry_time = entry.get("time", "")
                if date and not entry_time.startswith(date):
                    continue
                
                found_data = True
                lat = entry.get("latency", 0)
                status_val = entry.get("status", "UP" if lat > 0 else "DOWN")
                reason = entry.get("failure_analysis", entry.get("reason", "OK"))
                ssl_val = entry.get("ssl_expiry", "N/A")
                
                ws.cell(row=current_row, column=1).value = str(domain)
                ws.cell(row=current_row, column=2).value = str(entry_time)
                ws.cell(row=current_row, column=3).value = status_val
                ws.cell(row=current_row, column=4).value = lat
                ws.cell(row=current_row, column=5).value = ssl_val
                ws.cell(row=current_row, column=6).value = reason if status_val != "UP" else "Healthy"
                
                for c in range(1, 7):
                    ws.cell(row=current_row, column=c).border = thin_border
                    ws.cell(row=current_row, column=c).alignment = Alignment(horizontal='left')
                    if c == 3 and status_val == "DOWN":
                        ws.cell(row=current_row, column=c).font = Font(color="ef4444", bold=True)
                    elif c == 3 and status_val == "UP":
                        ws.cell(row=current_row, column=c).font = Font(color="10b981", bold=True)
                
                current_row += 1
        
        if not found_data:
            ws.cell(row=current_row, column=1).value = "No records found for the selected filter."
            ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=4)

        # 4. Column Sizing
        ws.column_dimensions['A'].width = 25
        ws.column_dimensions['B'].width = 22
        ws.column_dimensions['C'].width = 12
        ws.column_dimensions['D'].width = 15
        ws.column_dimensions['E'].width = 20
        ws.column_dimensions['F'].width = 35
        
        # Save to memory stream
        output = io.BytesIO()
        wb.save(output)
        output.seek(0)
        
        filename = f"UPTRIX_Report_{date if date else 'Full'}.xlsx"
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Cache-Control": "no-cache"
            }
        )
    except Exception as e:
        import traceback
        return {"error": str(e), "trace": traceback.format_exc()}

@app.get("/api/report/pdf")
async def get_report_pdf(date: str = Query(None), _user=Depends(require_roles("Admin", "Operator", "Viewer"))):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    import io
    from fastapi.responses import StreamingResponse
    
    # Load collection
    TRACE_PATH = os.path.join(BASE_DIR, "trace_collection.json")
    LOGO_PATH = os.path.join(STATIC_DIR, "logo_new.png")
    
    if not os.path.exists(TRACE_PATH):
        return {"detail": "No data available"}
    
    try:
        with open(TRACE_PATH, "r") as f:
            data = json.load(f)
        
        output = io.BytesIO()
        doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
        elements = []
        styles = getSampleStyleSheet()
        
        # Header Style
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=16,
            textColor=colors.HexColor("#0F172A"),
            alignment=1, # Center
            spaceAfter=10
        )
        
        sub_title_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor("#64748B"),
            alignment=1, # Center
            spaceAfter=20
        )
        
        # 1. Branding Header (Logo if exists)
        if os.path.exists(LOGO_PATH):
            try:
                logo = Image(LOGO_PATH, width=50, height=50)
                logo.hAlign = 'CENTER'
                elements.append(logo)
                elements.append(Spacer(1, 12))
            except:
                pass
                
        # 2. Titles
        elements.append(Paragraph("UPTRIX - Infrastructure Analytical Report", title_style))
        gen_time = datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
        filter_display = f"FOR DATE: {date}" if date else "FULL SNAPSHOT"
        elements.append(Paragraph(f"Report Type: {filter_display} | Generated On: {gen_time}", sub_title_style))
        
        # 3. Aggregation for Pie Chart
        up_count = 0
        down_count = 0
        table_data = [["Domain", "Timestamp", "Status", "Lat", "SSL", "Reason"]]
        
        for domain, entries in data.items():
            for entry in entries:
                entry_time = entry.get("time", "")
                if date and not entry_time.startswith(date): continue
                
                lat = entry.get("latency", 0)
                status_val = entry.get("status", "UP" if lat > 0 else "DOWN")
                ssl_val = entry.get("ssl_expiry", "N/A")
                reason = entry.get("failure_analysis", entry.get("reason", "OK"))
                
                if status_val == "UP": up_count += 1
                else: down_count += 1
                
                table_data.append([
                    str(domain)[:20], # Truncate for PDF width
                    str(entry_time)[11:], # Time only for space
                    status_val, 
                    str(lat),
                    str(ssl_val),
                    str(reason)[:20]
                ])

        # 4. Add Summary Pie Chart
        if (up_count + down_count) > 0:
            from reportlab.graphics.shapes import Drawing
            from reportlab.graphics.charts.piecharts import Pie
            from reportlab.lib.colors import HexColor
            
            d = Drawing(200, 100)
            pc = Pie()
            pc.x = 65
            pc.y = 0
            pc.width = 90
            pc.height = 90
            pc.data = [up_count, down_count]
            pc.labels = [f'Online ({up_count})', f'Offline ({down_count})']
            pc.slices.strokeWidth = 0.5
            pc.slices[0].fillColor = HexColor("#10b981")
            pc.slices[1].fillColor = HexColor("#ef4444")
            d.add(pc)
            elements.append(d)
            elements.append(Paragraph("System Availability Distribution", sub_title_style))
            elements.append(Spacer(1, 20))

        # 5. Table Styling
        t = Table(table_data, colWidths=[120, 80, 50, 40, 80, 140])
        t_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
        ]
        
        # Conditional formatting for Status column (Index 2)
        for i in range(1, len(table_data)):
            status = table_data[i][2]
            if status == "DOWN":
                t_style.append(('TEXTCOLOR', (2, i), (2, i), colors.red))
            elif status == "UP":
                t_style.append(('TEXTCOLOR', (2, i), (2, i), colors.green))

        t.setStyle(TableStyle(t_style))
        elements.append(t)
        doc.build(elements)
        output.seek(0)
        
        filename = f"UPTRIX_Report_{date if date else 'Full'}.pdf"
        return StreamingResponse(
            output,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Cache-Control": "no-cache"
            }
        )
    except Exception as e:
        import traceback
        return {"error": str(e), "trace": traceback.format_exc()}

@app.get("/api/status")
async def get_status(_user=Depends(require_roles("Admin", "Operator", "Viewer"))):
    summary = {
        "total": len(MONITORED_DOMAINS),
        "online": len([r for r in cached_results if r["status"] == "UP"]),
        "offline": len([r for r in cached_results if r["status"] != "UP"]),
        "avg_latency": round(sum([r["latency"] for r in cached_results]) / len(cached_results), 2) if cached_results else 0,
        "last_ping": LAST_PING_TIMESTAMP
    }
    return {"results": cached_results, "summary": summary}

@app.get("/api/history")
async def get_history(range: str = "1h", _user=Depends(require_roles("Admin", "Operator", "Viewer"))):
    filtered = {}
    now = datetime.datetime.now()

    ranges = {"5m": 300, "30m": 1800, "1h": 3600, "24h": 86400}
    max_seconds = ranges.get(range, 3600)

    for domain, points in history_cache.items():
        if domain not in MONITORED_DOMAINS:
            continue
        domain_points = []
        for p in points:
            try:
                p_time = datetime.datetime.strptime(p["time"], "%Y-%m-%d %H:%M:%S")
                if (now - p_time).total_seconds() <= max_seconds:
                    display_time = p_time.strftime("%H:%M")
                    domain_points.append({
                        "time": display_time, 
                        "latency": p["latency"],
                        "status": p.get("status", "UP")
                    })
            except: continue
        filtered[domain] = domain_points
    return filtered

@app.get("/api/logs/realtime")
async def get_realtime_logs(user=Depends(require_roles("Admin", "Operator"))):
    """Serves the live logs for the Central Diagnostics section."""
    if user.role == "Admin":
        return SYSTEM_EVENT_LOGS
    return [event for event in SYSTEM_EVENT_LOGS if event.get("service") in {"Website-Monitor", "Website Checks"}]

@app.post("/api/domains")
# @limiter.limit("200/minute")
async def add_domains(urls: str = Query(...), _user=Depends(require_roles("Admin", "Operator"))):
    global MONITORED_DOMAINS, history_cache, cached_results
    
    # Validation & Extraction
    new_raw = [clean_domain_name(u) for u in urls.split(",") if u.strip()]
    unique_new = []
    for u in new_raw:
        if u and u not in MONITORED_DOMAINS and u not in unique_new:
            unique_new.append(u)
            
    MONITORED_DOMAINS.extend(unique_new)
    save_domains(MONITORED_DOMAINS)
    
    # Publish new targets immediately so the dashboard can show them while
    # their first health check runs in the background.
    for u in unique_new:
        if u not in history_cache:
            history_cache[u] = []
        cached_results = [row for row in cached_results if row.get("url") != u]
        cached_results.append({
            "url": u,
            "status": "PENDING",
            "status_code": "---",
            "latency": 0,
            "ssl_expiry": "Checking...",
            "timestamp": datetime.datetime.now().isoformat(),
            "reason": "Initial check in progress",
            "failure_analysis": "The first website check is in progress.",
            "root_causes": [],
        })
        
    asyncio.create_task(load_immediate_check())
    return {"message": f"Added {len(unique_new)} domains.", "current_list": MONITORED_DOMAINS}

@app.post("/api/domains/remove")
# @limiter.limit("10/minute")
async def remove_domain(url: str = Query(...), _user=Depends(require_roles("Admin"))):
    global MONITORED_DOMAINS, history_cache, cached_results
    
    target = clean_domain_name(url)
    if not target: raise HTTPException(status_code=400, detail="Invalid domain")
    
    if target in MONITORED_DOMAINS:
        MONITORED_DOMAINS.remove(target)
        save_domains(MONITORED_DOMAINS)
        
        # Cleanup in-memory structures
        if target in history_cache: del history_cache[target]
        cached_results = [r for r in cached_results if r["url"] != target]

        save_history(history_cache)

        # Cleanup persistent trace collection
        TRACE_PATH = os.path.join(BASE_DIR, "trace_collection.json")
        if os.path.exists(TRACE_PATH):
            try:
                with open(TRACE_PATH, "r") as f:
                    collection = json.load(f)
                if target in collection:
                    del collection[target]
                with open(TRACE_PATH, "w") as f:
                    json.dump(collection, f, indent=4)
            except Exception as e:
                print(f"Cleanup collection error: {e}")

        return {"message": "Domain removed successfully"}
        
    raise HTTPException(status_code=404, detail=f"Domain {url} not found in monitored list")

async def load_immediate_check():
    global cached_results, history_cache, LAST_PING_TIMESTAMP
    
    # Pre-populate with PENDING state if empty to prevent zero-domain UI flicker
    if not cached_results and MONITORED_DOMAINS:
        initial_results = []
        for d in MONITORED_DOMAINS:
            initial_results.append({
                "url": d, "status": "PENDING", "status_code": "---", "latency": 0,
                "ssl_expiry": "...", "timestamp": datetime.datetime.now().isoformat(),
                "reason": "Initializing...", "failure_analysis": "Website check is initializing.", "root_causes": []
            })
        cached_results = initial_results

    if MONITORED_DOMAINS:
        tasks = [perform_health_check(d) for d in MONITORED_DOMAINS]
        results = await asyncio.gather(*tasks)
        cached_results = [r for r in results if r]
        LAST_PING_TIMESTAMP = datetime.datetime.now().strftime("%I:%M:%S %p")
        
        # Immediate Collection Update
        TRACE_PATH = os.path.join(BASE_DIR, "trace_collection.json")
        collection = {}
        if os.path.exists(TRACE_PATH):
            try:
                with open(TRACE_PATH, "r") as f:
                    collection = json.load(f)
            except: collection = {}
            
        for r in cached_results:
            dom = r["url"]
            hist_entry = {
                "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "latency": r["latency"],
                "status": r["status"],
                "ssl_expiry": r.get("ssl_expiry", "N/A"),
                "reason": r.get("reason", "OK"),
                "failure_analysis": r.get("failure_analysis", r.get("reason", "OK"))
            }
            if dom not in history_cache: history_cache[dom] = []
            history_cache[dom].append(hist_entry)
            
            if dom not in collection: collection[dom] = []
            collection[dom].append(hist_entry)
            
            # Real-time Log Injection
            log_level = "INFO" if r["status"] == "UP" else "ERROR"
            log_msg = f"Monitoring heartbeat: {dom} is {r['status']} ({r['latency']}ms)"
            log_event("Monitor-Service", log_level, log_msg, dom)

            # --- 7-Day Retention Logic ---
            # Keeps data only if it was recorded within the last 7 days.
            try:
                seven_days_ago = datetime.datetime.now() - datetime.timedelta(days=7)
                collection[dom] = [
                    e for e in collection[dom]
                    if datetime.datetime.strptime(e['time'], "%Y-%m-%d %H:%M:%S") > seven_days_ago
                ]
            except Exception as e:
                print(f"Retention error for {dom}: {e}")
            
            # Additional safety cap (max 6000 entries ~ 8.3 days at 2-min intervals)
            if len(collection[dom]) > 6000:
                collection[dom] = collection[dom][-6000:]

            # --- Email Notification Hook ---
            is_up = (r.get("status") == "UP")
            if not is_up and dom not in ACTIVE_ALERTS:
                ACTIVE_ALERTS[dom] = True
                asyncio.create_task(send_email_alert(dom, "DOWN", r.get("reason", "Connection Error")))
            elif is_up and dom in ACTIVE_ALERTS:
                del ACTIVE_ALERTS[dom]
                asyncio.create_task(send_email_alert(dom, "UP", f"Latency normalized at {r.get('latency')}ms"))

        with open(TRACE_PATH, "w") as f:
            json.dump(collection, f, indent=4)
        save_history(history_cache)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5174)
