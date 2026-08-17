"""
Discord OAuth2 Backend Server with Web Interface
Flask application for handling OAuth2 callbacks and token validation
Includes a simple web interface for role verification
"""

import os
import secrets
import logging
import hmac
import hashlib
import json
import base64
from functools import wraps
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, session, redirect, render_template_string
from dotenv import load_dotenv
import requests
import traceback
from discord_auth import DiscordAuth

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

# Session storage for /auth-status endpoint
active_sessions_auth = {}
user_machines_auth = {}
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Discord OAuth2 handler
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")
REQUIRED_GUILD_ID = os.getenv("DISCORD_SERVER_ID")
def _parse_roles(env_name):
    return [r.strip() for r in os.getenv(env_name, "").split(",") if r.strip()]

# Per-app required roles. Each client says which app it is via /login?app=...
# "titan" (default) keeps using the original DISCORD_REQUIRED_ROLES env var so
# existing clients that send no ?app= keep working unchanged. "remote" uses a
# new DISCORD_REQUIRED_ROLES_REMOTE env var.
#
# "zero" is Enchanted Zero. Its role is hardcoded as a fallback so the app works
# before DISCORD_REQUIRED_ROLES_ZERO is set on the service; the env var wins when
# present, so the role can be rotated without a redeploy. Role IDs are not
# secrets - they are visible to anyone in the Discord server.
ZERO_ROLE_FALLBACK = ["1533536305064185927"]

ROLE_SETS = {
    "titan":  _parse_roles("DISCORD_REQUIRED_ROLES"),
    "remote": _parse_roles("DISCORD_REQUIRED_ROLES_REMOTE"),
    "zero":   _parse_roles("DISCORD_REQUIRED_ROLES_ZERO") or ZERO_ROLE_FALLBACK,
}
DEFAULT_APP = "titan"
# Backward-compat alias: the generic /check-* endpoints still use REQUIRED_ROLES.
REQUIRED_ROLES = ROLE_SETS[DEFAULT_APP]

logger.info(f"=== DISCORD AUTH CONFIG ===")
logger.info(f"CLIENT_ID: {DISCORD_CLIENT_ID}")
logger.info(f"CLIENT_SECRET: {DISCORD_CLIENT_SECRET[:20] if DISCORD_CLIENT_SECRET else 'NONE'}...")
logger.info(f"REDIRECT_URI: {DISCORD_REDIRECT_URI}")
logger.info(f"REQUIRED_GUILD_ID: {REQUIRED_GUILD_ID}")
logger.info(f"REQUIRED_ROLES (raw): {os.getenv('DISCORD_REQUIRED_ROLES')}")
logger.info(f"REQUIRED_ROLES (parsed): {REQUIRED_ROLES}")
for _app_name, _app_roles in ROLE_SETS.items():
    logger.info(f"ROLE_SET '{_app_name}': {_app_roles or '(none configured)'}")
logger.info(f"DEFAULT_APP: {DEFAULT_APP}")
logger.info(f"=== END CONFIG ===")

if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
    raise ValueError("Missing required Discord credentials in environment")

discord_auth = DiscordAuth(DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI)

# OAuth2 scopes
DEFAULT_SCOPES = ["identify", "guilds", "guilds.members.read"]

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Discord Verification</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 400px;
            text-align: center;
        }
        h1 {
            color: #333;
            margin: 0 0 10px 0;
            font-size: 28px;
        }
        p {
            color: #666;
            margin: 0 0 30px 0;
            font-size: 16px;
        }
        .btn {
            display: inline-block;
            padding: 12px 32px;
            background: #5865F2;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            font-size: 16px;
            cursor: pointer;
            border: none;
            transition: background 0.2s;
        }
        .btn:hover {
            background: #4752C4;
        }
        .discord-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="discord-icon">🔐</div>
        <h1>Discord Verification</h1>
        <p>Click below to verify your Discord account and role</p>
        <a href="/login" class="btn">Login with Discord</a>
    </div>
</body>
</html>
"""

SUCCESS_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Access Granted ✓</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #00b894 0%, #00cec9 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 400px;
            text-align: center;
        }
        h1 {
            color: #00b894;
            margin: 0 0 10px 0;
            font-size: 28px;
        }
        p {
            color: #666;
            margin: 10px 0;
            font-size: 16px;
        }
        .checkmark {
            font-size: 64px;
            margin-bottom: 20px;
        }
        .user-info {
            background: #f0f0f0;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            text-align: left;
        }
        .user-info p {
            margin: 5px 0;
            font-size: 14px;
        }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #00b894;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            border: none;
        }
        .btn:hover {
            background: #009473;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="checkmark">✓</div>
        <h1>Access Granted!</h1>
        <p>You have been verified successfully.</p>
        <div class="user-info">
            <p>Username: {{ username }}</p>
            <p>User ID: {{ user_id }}</p>
        </div>
        <p style="color: #888; font-size: 14px;">You have access to this application.</p>
        <a href="/logout" class="btn">Logout</a>
    </div>
</body>
</html>
"""

DENIED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied ✗</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #ee5a6f 0%, #f79f1f 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 400px;
            text-align: center;
        }
        h1 {
            color: #ee5a6f;
            margin: 0 0 10px 0;
            font-size: 28px;
        }
        p {
            color: #666;
            margin: 10px 0;
            font-size: 16px;
        }
        .icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        .reason {
            background: #ffe0e0;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
            text-align: left;
            border-left: 4px solid #ee5a6f;
        }
        .reason p {
            margin: 5px 0;
            font-size: 14px;
            color: #c0392b;
        }
        .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            background: #ee5a6f;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            border: none;
        }
        .btn:hover {
            background: #d63447;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">✗</div>
        <h1>Access Denied</h1>
        <p>You don't have permission to access this application.</p>
        <div class="reason">
            <p><strong>Reason:</strong></p>
            <p>{{ reason }}</p>
        </div>
        <p style="color: #888; font-size: 14px;">If you believe this is an error, please contact the administrator.</p>
        <a href="/" class="btn">Try Again</a>
    </div>
</body>
</html>
"""


def validate_token(f):
    """Decorator to validate auth token from request"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header[7:]  # Remove "Bearer " prefix
        request.user_token = token
        return f(*args, **kwargs)

    return decorated_function


# In-memory auth status cache
auth_status_cache = {}
recent_authentications = {}  # Store recent auth results by user IP

def get_client_ip():
    """Get real client IP, handling Render's reverse proxy (X-Forwarded-For)"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # X-Forwarded-For can be "client, proxy1, proxy2" — first is the real IP
        return forwarded.split(",")[0].strip()
    return request.remote_addr


# ── Device bind / one session / security log (app=zero and any client sending mid)
_DATA_DIR = os.getenv("DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
_BINDS_PATH = os.path.join(_DATA_DIR, "device_binds.json")
_EVENTS_PATH = os.path.join(_DATA_DIR, "auth_events.jsonl")
_LIVE_TTL = 90  # seconds; heartbeat is ~40s so a crash can relogin after this
_device_binds = {}
_live_sessions = {}
_role_denied = {}
DISCORD_BOT_TOKEN = (os.getenv("DISCORD_BOT_TOKEN") or "").strip()
_ROLE_CACHE = {}

try:
    import threading as _threading
    _DEV_LOCK = _threading.Lock()
except Exception:
    _DEV_LOCK = None


def _dev_lock():
    if _DEV_LOCK:
        return _DEV_LOCK
    class _N:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return _N()


def _load_binds():
    global _device_binds
    try:
        with open(_BINDS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            _device_binds = data
    except Exception:
        _device_binds = {}


def _save_binds():
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        tmp = _BINDS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_device_binds, f, indent=2)
        os.replace(tmp, _BINDS_PATH)
    except Exception as exc:
        logger.warning("Could not save device binds: %s", exc)


def _log_event(kind, **fields):
    rec = {"ts": datetime.utcnow().isoformat(), "event": kind}
    rec.update(fields)
    logger.info("[SEC] %s", rec)
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        with open(_EVENTS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def _req_mid():
    return (request.headers.get("X-Machine-Id") or request.args.get("mid") or "").strip()[:64]


def _req_uid():
    return (request.headers.get("X-User-Id") or request.args.get("user_id") or "").strip()[:80]


def _req_session():
    return (request.headers.get("X-Session") or request.args.get("session") or "").strip()[:80]


def _bind_key(app_key, user_id):
    return "%s:%s" % (app_key, user_id)


_load_binds()


def _drop_live(app_key, user_id):
    key = _bind_key(app_key, user_id)
    with _dev_lock():
        _live_sessions.pop(key, None)


def _fetch_live_roles(user_id):
    """Return role ids on a successful Discord read, or None if the lookup failed."""
    uid = str(user_id or "")
    guild = REQUIRED_GUILD_ID
    if not uid or not guild:
        return None

    token = None
    try:
        token = discord_auth.get_cached_token(uid)
    except Exception:
        token = None
    if token:
        try:
            r = requests.get(
                "https://discord.com/api/v10/users/@me/guilds/%s/member" % guild,
                headers={"Authorization": "Bearer %s" % token},
                timeout=5,
            )
            logger.info("oauth role re-check user=%s status=%s", uid, r.status_code)
            if r.status_code == 200:
                return [str(x) for x in (r.json().get("roles") or [])]
            # 401/403/429/5xx: token or Discord issue — not proof they lost the role
        except Exception as exc:
            logger.warning("oauth role re-check: %s", exc)

    bot = DISCORD_BOT_TOKEN
    if bot:
        try:
            r = requests.get(
                "https://discord.com/api/v10/guilds/%s/members/%s" % (guild, uid),
                headers={"Authorization": "Bot %s" % bot},
                timeout=5,
            )
            logger.info("bot role re-check user=%s status=%s", uid, r.status_code)
            if r.status_code == 200:
                return [str(x) for x in (r.json().get("roles") or [])]
            if r.status_code == 404:
                return []
        except Exception as exc:
            logger.warning("bot role re-check: %s", exc)
    return None


def _user_still_has_role(user_id, app_key):
    """Re-check Discord roles. Only deny when Discord clearly shows the role is gone."""
    required = [str(r) for r in (ROLE_SETS.get(app_key) or [])]
    uid = str(user_id or "")
    if not required or not uid or uid in ("authenticated", "None"):
        return True, ""
    cache_key = "%s:%s" % (app_key, uid)
    now = datetime.utcnow().timestamp()
    hit = _ROLE_CACHE.get(cache_key)
    if hit and hit[0] > now:
        return hit[1], hit[2]
    roles = _fetch_live_roles(uid)
    if roles is None:
        # Could not read Discord — keep the session.
        return True, ""
    ok = any(r in roles for r in required)
    reason = "" if ok else "You don't have the required role(s)"
    _ROLE_CACHE[cache_key] = (now + 20, ok, reason)
    if not ok:
        logger.warning("role lost user=%s app=%s have=%s need=%s", uid, app_key, roles, required)
    return ok, reason


def _claim_device(app_key, user_id, mid, username, ip):
    """First machine wins. Other PCs are denied. Same PC refreshes the live session."""
    if not user_id or not mid:
        return False, "Missing device id", None
    key = _bind_key(app_key, user_id)
    now = datetime.utcnow()
    with _dev_lock():
        bound = _device_binds.get(key)
        if bound and bound.get("mid") and bound.get("mid") != mid:
            _log_event(
                "deny_bind",
                app=app_key, user_id=user_id, username=username,
                mid=mid, bound_mid=bound.get("mid"), ip=ip,
            )
            return False, "This account is locked to another PC", None
        if not bound:
            _device_binds[key] = {
                "mid": mid,
                "username": username or "",
                "bound_at": now.isoformat(),
                "app": app_key,
            }
            _save_binds()
            _log_event("bind", app=app_key, user_id=user_id, username=username, mid=mid, ip=ip)

        live = _live_sessions.get(key)
        if live:
            age = (now - datetime.fromisoformat(live["last_seen"])).total_seconds()
            if live.get("mid") != mid and age < _LIVE_TTL:
                _log_event(
                    "deny_session",
                    app=app_key, user_id=user_id, username=username,
                    mid=mid, other_mid=live.get("mid"), ip=ip,
                )
                return False, "Already signed in on another session", None
            if live.get("mid") == mid and live.get("sid"):
                live["last_seen"] = now.isoformat()
                live["ip"] = ip
                _log_event("login", app=app_key, user_id=user_id, username=username, mid=mid, ip=ip)
                return True, "", live["sid"]

        sid = secrets.token_urlsafe(24)
        _live_sessions[key] = {
            "sid": sid,
            "mid": mid,
            "last_seen": now.isoformat(),
            "ip": ip,
        }
        _log_event("login", app=app_key, user_id=user_id, username=username, mid=mid, ip=ip)
        return True, "", sid


def _heartbeat_device(app_key, user_id, mid, sid, ip):
    key = _bind_key(app_key, user_id)
    now = datetime.utcnow()
    with _dev_lock():
        bound = _device_binds.get(key)
        if not bound or not bound.get("mid"):
            return False, "Sign in again", None
        if bound.get("mid") != mid:
            _log_event(
                "deny_bind",
                app=app_key, user_id=user_id, mid=mid,
                bound_mid=bound.get("mid"), ip=ip, via="heartbeat",
            )
            return False, "This account is locked to another PC", None

        live = _live_sessions.get(key)
        if live and live.get("mid") == mid:
            keep = sid if sid and sid == live.get("sid") else (live.get("sid") or sid)
            if not keep:
                keep = secrets.token_urlsafe(24)
            live["sid"] = keep
            live["last_seen"] = now.isoformat()
            live["ip"] = ip
            return True, "", keep
        if live and live.get("sid") and sid and live.get("sid") != sid:
            age = (now - datetime.fromisoformat(live["last_seen"])).total_seconds()
            if age < _LIVE_TTL:
                _log_event(
                    "deny_session",
                    app=app_key, user_id=user_id, mid=mid, ip=ip, via="heartbeat",
                )
                return False, "Already signed in on another session", None
        keep = sid or secrets.token_urlsafe(24)
        _live_sessions[key] = {
            "sid": keep,
            "mid": mid,
            "last_seen": now.isoformat(),
            "ip": ip,
        }
        return True, "", keep

def create_signed_auth_token(user_id: str, username: str, secret_key: str) -> str:
    """Create an HMAC-signed token that proves authentication"""
    # Create a payload with timestamp
    payload = {
        "user_id": user_id,
        "username": username,
        "timestamp": datetime.utcnow().isoformat()
    }
    payload_json = json.dumps(payload)
    payload_b64 = base64.b64encode(payload_json.encode()).decode()
    
    # Create HMAC signature
    signature = hmac.new(
        secret_key.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Combine payload and signature
    token = f"{payload_b64}.{signature}"
    return token

def verify_signed_auth_token(token: str, secret_key: str) -> Optional[Dict]:
    """Verify and decode a signed token"""
    try:
        if '.' not in token:
            return None
        
        payload_b64, signature = token.rsplit('.', 1)
        
        # Verify signature
        expected_signature = hmac.new(
            secret_key.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            return None
        
        # Decode payload
        payload_json = base64.b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
        
        # Check timestamp (valid for 60 seconds)
        token_time = datetime.fromisoformat(payload["timestamp"])
        time_diff = (datetime.utcnow() - token_time).total_seconds()
        
        if time_diff > 60:
            return None
        
        logger.info(f"[AUTH] Token verified for {payload['user_id']}")
        return payload
    except Exception as e:
        logger.error(f"[AUTH] Token verification failed: {e}")
        return None

def create_signed_auth_token(user_id: str, username: str, secret_key: str) -> str:
    """Create an HMAC-signed token that proves authentication"""
    # Create a payload with timestamp
    payload = {
        "user_id": user_id,
        "username": username,
        "timestamp": datetime.utcnow().isoformat()
    }
    payload_json = json.dumps(payload)
    payload_b64 = base64.b64encode(payload_json.encode()).decode()
    
    # Create HMAC signature
    signature = hmac.new(
        secret_key.encode(),
        payload_b64.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # Combine payload and signature
    token = f"{payload_b64}.{signature}"
    logger.info(f"[AUTH] Created signed token for {user_id}")
    return token

def verify_signed_auth_token(token: str, secret_key: str) -> Optional[Dict]:
    """Verify and decode a signed token"""
    try:
        if '.' not in token:
            logger.warning("[AUTH] Invalid token format - no dot")
            return None
        
        payload_b64, signature = token.rsplit('.', 1)
        
        # Verify signature
        expected_signature = hmac.new(
            secret_key.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.warning("[AUTH] Invalid token signature")
            return None
        
        # Decode payload
        payload_json = base64.b64decode(payload_b64).decode()
        payload = json.loads(payload_json)
        
        # Check timestamp (valid for 60 seconds)
        token_time = datetime.fromisoformat(payload["timestamp"])
        time_diff = (datetime.utcnow() - token_time).total_seconds()
        
        if time_diff > 60:
            logger.warning(f"[AUTH] Token expired ({time_diff}s old)")
            return None
        
        logger.info(f"[AUTH] Token verified for {payload['user_id']}")
        return payload
    except Exception as e:
        logger.error(f"[AUTH] Token verification failed: {e}")
        return None

@app.route("/", methods=["GET"])
def index():
    """Home page - show login or access granted"""
    client_ip = get_client_ip()
    user_id = session.get("user_id")
    auth_token = request.args.get("auth_token")
    
    print(f"[INDEX] Request from {client_ip}, has token: {bool(auth_token)}")
    
    # Check if signed auth_token is provided
    if auth_token:
        print(f"[INDEX] Verifying signed token...")
        token_data = verify_signed_auth_token(auth_token, app.secret_key)
        
        if token_data:
            print(f"[INDEX] ✓ Token verified for {token_data['user_id']}")
            return render_template_string(
                SUCCESS_TEMPLATE,
                username=token_data.get("username", "User"),
                user_id=token_data.get("user_id", "unknown")
            )
        else:
            print(f"[INDEX] ✗ Token verification failed")
    
    # First check if user has active session
    if user_id:
        user_info = session.get("user_info", {})
        print(f"[INDEX] User {user_id} authenticated via session")
        return render_template_string(
            SUCCESS_TEMPLATE,
            username=user_info.get("username", "User"),
            user_id=user_id
        )
    
    # Not authenticated - show login page
    print(f"[INDEX] No auth, showing login page")
    return render_template_string(LOGIN_TEMPLATE)



def get_auth_status():
    """Get authentication status - always check current session and recent auth"""
    user_id = session.get("user_id")
    user_info = session.get("user_info", {})
    client_ip = get_client_ip()
    
    # First check if user has active session
    if user_id and user_info:
        # User has active session
        return jsonify({
            "authenticated": True,
            "user_id": user_id,
            "username": user_info.get("username", "User"),
            "source": "session",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    
    # Check if there's a recent auth from this IP (within 30 seconds)
    if client_ip in recent_authentications:
        auth = recent_authentications[client_ip]
        auth_time = datetime.fromisoformat(auth["timestamp"])
        if (datetime.utcnow() - auth_time).total_seconds() < 30:
            return jsonify({
                "authenticated": True,
                "user_id": auth.get("user_id", "unknown"),
                "username": auth.get("username", "User"),
                "source": "recent",
                "timestamp": auth.get("timestamp")
            }), 200
    
    # No active session and no recent auth
    return jsonify({"error": "Not authenticated", "authenticated": False}), 401


@app.route("/auth-status", methods=["GET"])
def auth_status():
    """Check auth status - returns granted/denied/pending based on recent_authentications"""
    client_ip = get_client_ip()

    requested_app = (request.args.get("app") or DEFAULT_APP).strip().lower()
    if requested_app not in ROLE_SETS:
        requested_app = DEFAULT_APP

    mid = _req_mid()
    uid_hdr = _req_uid()
    sess = _req_session()

    # Heartbeat from a compiled client that already has a user id + machine id.
    if uid_hdr and mid:
        ok_role, role_reason = _user_still_has_role(uid_hdr, requested_app)
        if not ok_role:
            _drop_live(requested_app, uid_hdr)
            return jsonify({
                "authenticated": False,
                "denied": True,
                "reason": role_reason or "You don't have the required role(s)",
            }), 403
        ok, reason, sid = _heartbeat_device(requested_app, uid_hdr, mid, sess, client_ip)
        if not ok:
            return jsonify({
                "authenticated": False,
                "denied": True,
                "reason": reason,
            }), 403
        return jsonify({
            "authenticated": True,
            "user_id": uid_hdr,
            "session": sid,
        }), 200

    if client_ip in recent_authentications:
        auth = recent_authentications[client_ip]

        if auth.get("app", DEFAULT_APP) != requested_app:
            return jsonify({"authenticated": False, "denied": False}), 401

        auth_time = datetime.fromisoformat(auth["timestamp"])
        # Valid for 5 minutes
        if (datetime.utcnow() - auth_time).total_seconds() < 300:
            if auth.get("authenticated"):
                uid = str(auth.get("user_id") or "")
                ok_role, role_reason = _user_still_has_role(uid, requested_app)
                if not ok_role:
                    _drop_live(requested_app, uid)
                    return jsonify({
                        "authenticated": False,
                        "denied": True,
                        "reason": role_reason or "You don't have the required role(s)",
                        "username": auth.get("username", ""),
                    }), 403
                payload = {
                    "authenticated": True,
                    "username": auth.get("username"),
                    "user_id": auth.get("user_id"),
                }
                if mid:
                    ok, reason, sid = _claim_device(
                        requested_app,
                        str(auth.get("user_id") or ""),
                        mid,
                        auth.get("username") or "",
                        client_ip,
                    )
                    if not ok:
                        return jsonify({
                            "authenticated": False,
                            "denied": True,
                            "reason": reason,
                            "username": auth.get("username", ""),
                        }), 403
                    payload["session"] = sid
                return jsonify(payload), 200
            else:
                # Access was denied
                return jsonify({
                    "authenticated": False,
                    "denied": True,
                    "reason": auth.get("reason", "Access denied"),
                    "username": auth.get("username", "")
                }), 403
    
    # No auth attempt yet (still pending)
    return jsonify({"authenticated": False, "denied": False}), 401


@app.route("/admin/security", methods=["GET"])
def admin_security():
    key = os.getenv("DEVICE_ADMIN_KEY", "")
    if not key or request.args.get("key") != key:
        return jsonify({"error": "not found"}), 404
    events = []
    try:
        with open(_EVENTS_PATH, encoding="utf-8") as f:
            lines = f.readlines()[-80:]
        for line in lines:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    except Exception:
        pass
    return jsonify({
        "binds": _device_binds,
        "live": {
            k: {"mid": v.get("mid"), "last_seen": v.get("last_seen"), "ip": v.get("ip")}
            for k, v in _live_sessions.items()
        },
        "events": events,
    }), 200


@app.route("/admin/unbind", methods=["GET", "POST"])
def admin_unbind():
    key = os.getenv("DEVICE_ADMIN_KEY", "")
    if not key or request.args.get("key") != key:
        return jsonify({"error": "not found"}), 404
    user_id = (request.args.get("user_id") or "").strip()
    app_key = (request.args.get("app") or "zero").strip().lower()
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    bk = _bind_key(app_key, user_id)
    with _dev_lock():
        gone = _device_binds.pop(bk, None)
        _live_sessions.pop(bk, None)
        _save_binds()
    _log_event("unbind", app=app_key, user_id=user_id, had=bool(gone))
    return jsonify({"ok": True, "removed": gone}), 200


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})


@app.route("/test-discord", methods=["GET"])
def test_discord():
    """Test if we can reach Discord API"""
    try:
        response = requests.get("https://discord.com/api/v10/oauth2/applications/@me", timeout=10)
        return jsonify({
            "can_reach_discord": True,
            "status_code": response.status_code,
            "response": response.text[:200]
        })
    except Exception as e:
        return jsonify({
            "can_reach_discord": False,
            "error": str(e)
        }), 500


@app.route("/login", methods=["GET"])
def login():
    """Initiate OAuth2 login flow"""
    # Which app is logging in? Determines which role(s) we require in /callback.
    app_key = (request.args.get("app") or DEFAULT_APP).strip().lower()
    if app_key not in ROLE_SETS:
        app_key = DEFAULT_APP
    session["app"] = app_key

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    auth_url = discord_auth.get_authorization_url(DEFAULT_SCOPES, state)
    return redirect(auth_url)


@app.route("/callback", methods=["GET"])
def callback():
    """OAuth2 callback endpoint"""
    # Validate state for CSRF protection
    state = request.args.get("state")
    if not state or state != session.get("oauth_state"):
        logger.warning("Invalid state in OAuth callback")
        return render_template_string(
            DENIED_TEMPLATE,
            reason="Invalid state parameter - possible CSRF attack"
        ), 403

    # Check for errors from Discord
    error = request.args.get("error")
    if error:
        error_description = request.args.get("error_description", "Unknown error")
        logger.error(f"Discord OAuth error: {error} - {error_description}")
        return render_template_string(
            DENIED_TEMPLATE,
            reason=f"Discord error: {error}"
        ), 400

    # Get authorization code
    code = request.args.get("code")
    if not code:
        logger.warning("No authorization code in callback")
        return render_template_string(
            DENIED_TEMPLATE,
            reason="No authorization code received"
        ), 400

    # Exchange code for token and get user info
    success, user_id, user_info = discord_auth.authenticate_user(code)
    if not success:
        logger.error("Failed to authenticate user")
        return render_template_string(
            DENIED_TEMPLATE,
            reason="Failed to authenticate with Discord"
        ), 401

    # Get the access token from the cache for API calls
    access_token = discord_auth.get_cached_token(user_id)
    if not access_token:
        logger.error(f"Failed to retrieve cached token for user {user_id}")
        return render_template_string(
            DENIED_TEMPLATE,
            reason="Failed to retrieve authentication token"
        ), 500

    # Which app this login was started for, set by /login?app=. Resolved before
    # any result is recorded, so every record below is tagged with it and
    # /auth-status only reports it back to that app's client.
    app_key = session.get("app", DEFAULT_APP)

    # Check guild membership if required guild is configured
    if REQUIRED_GUILD_ID:
        guilds = discord_auth.get_user_guilds(access_token)
        if not guilds or not any(g["id"] == REQUIRED_GUILD_ID for g in guilds):
            logger.warning(f"User {user_id} not in required guild {REQUIRED_GUILD_ID}")
            # Store denial by IP so GUI can detect it
            recent_authentications[get_client_ip()] = {
                "authenticated": False,
                "reason": "You are not a member of the required Discord server",
                "username": user_info.get("username", "User"),
                "user_id": user_id,
                "app": app_key,
                "timestamp": datetime.utcnow().isoformat()
            }
            return render_template_string(
                DENIED_TEMPLATE,
                reason=f"You are not a member of the required Discord server"
            ), 403

        # Per-app required roles — determined by ?app= at /login time.
        required_roles = ROLE_SETS.get(app_key, ROLE_SETS[DEFAULT_APP])

        # Check required roles if any
        if required_roles:
            logger.info(f"[CALLBACK] app={app_key} checking required roles: {required_roles}")
            user_roles = discord_auth.get_user_roles_in_guild(
                access_token, REQUIRED_GUILD_ID, user_id
            )
            logger.info(f"[CALLBACK] User {user_id} roles from API: {user_roles}")
            if not user_roles or not any(r in user_roles for r in required_roles):
                logger.warning(f"User {user_id} missing required roles. User roles: {user_roles}, Required: {required_roles}")
                # Store denial by IP so GUI can detect it
                recent_authentications[get_client_ip()] = {
                    "authenticated": False,
                    "reason": "You don't have the required role(s)",
                    "username": user_info.get("username", "User"),
                    "user_id": user_id,
                    "app": app_key,
                    "timestamp": datetime.utcnow().isoformat()
                }
                _role_denied[str(user_id)] = True
                _ROLE_CACHE.pop("%s:%s" % (app_key, user_id), None)
                _drop_live(app_key, user_id)
                return render_template_string(
                    DENIED_TEMPLATE,
                    reason=f"You don't have the required role(s)"
                ), 403
            logger.info(f"[CALLBACK] User {user_id} has all required roles")
        else:
            logger.warning(f"[CALLBACK] No required roles configured for app={app_key} - skipping role check")

    # Store user in session
    session["user_id"] = user_id
    session["user_info"] = user_info

    logger.info(f"User {user_id} ({user_info.get('username')}) successfully authenticated for app={app_key}")

    _role_denied.pop(str(user_id), None)
    _ROLE_CACHE.pop("%s:%s" % (app_key, user_id), None)

    # Store by IP so GUI can detect auth result
    recent_authentications[get_client_ip()] = {
        "authenticated": True,
        "user_id": user_id,
        "username": user_info.get("username", "User"),
        "app": app_key,
        "timestamp": datetime.utcnow().isoformat()
    }

    # Redirect to home page
    return redirect("/")


@app.route("/logout", methods=["GET"])
def logout():
    """Logout user and clear cache"""
    user_id = session.get("user_id")
    if user_id:
        discord_auth.clear_user_cache(user_id)
        logger.info(f"Logged out user {user_id}")

    session.clear()
    return redirect("/")


@app.route("/verify-token", methods=["GET"])
def verify_token_get():
    """Verify a signed auth token - for GUI dialog"""
    token = request.args.get("token")
    
    if not token:
        return jsonify({"error": "No token provided"}), 400
    
    token_data = verify_signed_auth_token(token, app.secret_key)
    
    if token_data:
        logger.info(f"[VERIFY] Token verified for {token_data.get('user_id')}")
        return jsonify({
            "verified": True,
            "user_id": token_data.get("user_id"),
            "username": token_data.get("username")
        }), 200
    else:
        logger.warning("[VERIFY] Token verification failed")
        return jsonify({"verified": False, "error": "Invalid or expired token"}), 401


# Keep existing API endpoints for backward compatibility
@app.route("/user", methods=["GET"])
@validate_token
def get_user():
    """Get current user information"""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Not authenticated"}), 401

    user_info = session.get("user_info")
    return jsonify(
        {
            "user_id": user_id,
            "username": user_info.get("username"),
            "email": user_info.get("email"),
            "avatar": user_info.get("avatar"),
        }
    )


@app.route("/validate-token", methods=["POST"])
def validate_token_endpoint():
    """Validate Discord access token"""
    data = request.get_json()
    if not data or "access_token" not in data:
        return jsonify({"error": "Missing access_token"}), 400

    access_token = data["access_token"]

    # Get user info to validate token
    user_info = discord_auth.get_user_info(access_token)
    if not user_info:
        return jsonify({"valid": False}), 401

    return jsonify({"valid": True, "user_id": user_info.get("id")})


@app.route("/check-membership", methods=["POST"])
def check_membership():
    """Check if user is in required guild"""
    data = request.get_json()
    if not data or "access_token" not in data:
        return jsonify({"error": "Missing access_token"}), 400

    access_token = data["access_token"]
    guild_id = data.get("guild_id", REQUIRED_GUILD_ID)

    if not guild_id:
        return jsonify({"error": "guild_id required"}), 400

    guilds = discord_auth.get_user_guilds(access_token)
    if guilds is None:
        return jsonify({"error": "Failed to fetch user guilds"}), 500

    is_member = any(g["id"] == guild_id for g in guilds)

    if not is_member:
        return jsonify(
            {
                "is_member": False,
                "reason": f"User is not a member of guild {guild_id}",
            }
        ), 403

    return jsonify({"is_member": True, "reason": "User is a member of the guild"})


@app.route("/check-roles", methods=["POST"])
def check_roles():
    """Check if user has required roles in guild"""
    data = request.get_json()
    if not data or "access_token" not in data:
        return jsonify({"error": "Missing access_token"}), 400

    access_token = data["access_token"]
    guild_id = data.get("guild_id", REQUIRED_GUILD_ID)
    required_roles = data.get("required_roles", REQUIRED_ROLES)

    if not guild_id:
        return jsonify({"error": "guild_id required"}), 400

    guilds = discord_auth.get_user_guilds(access_token)
    if guilds is None:
        return jsonify({"error": "Failed to fetch user guilds"}), 500

    is_member = any(g["id"] == guild_id for g in guilds)
    if not is_member:
        return (
            jsonify(
                {
                    "has_required_roles": False,
                    "reason": "User is not a member of the guild",
                }
            ),
            403,
        )

    user_info = discord_auth.get_user_info(access_token)
    if not user_info:
        return jsonify({"error": "Failed to fetch user info"}), 500

    user_id = user_info.get("id")

    user_roles = discord_auth.get_user_roles_in_guild(access_token, guild_id, user_id)
    if user_roles is None:
        return jsonify({"error": "Failed to fetch user roles"}), 500

    if required_roles:
        missing_roles = [r for r in required_roles if r not in user_roles]
        has_required_roles = len(missing_roles) == 0

        return jsonify(
            {
                "has_required_roles": has_required_roles,
                "user_roles": user_roles,
                "required_roles": required_roles,
                "missing_roles": missing_roles,
                "reason": "User has all required roles"
                if has_required_roles
                else f"User missing roles: {', '.join(missing_roles)}",
            }
        )

    return jsonify(
        {
            "has_required_roles": True,
            "user_roles": user_roles,
            "reason": "User membership verified (no specific roles required)",
        }
    )


@app.route("/check-auth", methods=["POST"])
def check_auth():
    """Complete authentication check"""
    data = request.get_json()
    if not data or "access_token" not in data:
        return jsonify({"error": "Missing access_token"}), 400

    access_token = data["access_token"]
    guild_id = data.get("guild_id", REQUIRED_GUILD_ID)
    required_roles = data.get("required_roles", REQUIRED_ROLES)

    result = {
        "authenticated": False,
        "checks": {
            "token_valid": False,
            "is_member": False,
            "has_required_roles": False,
        },
        "user_info": None,
        "user_roles": [],
        "errors": [],
    }

    user_info = discord_auth.get_user_info(access_token)
    if not user_info:
        result["errors"].append("Invalid or expired access token")
        return jsonify(result), 401

    result["checks"]["token_valid"] = True
    result["user_info"] = {
        "id": user_info.get("id"),
        "username": user_info.get("username"),
        "email": user_info.get("email"),
    }
    user_id = user_info.get("id")

    if guild_id:
        guilds = discord_auth.get_user_guilds(access_token)
        if guilds is None:
            result["errors"].append("Failed to fetch user guilds")
            return jsonify(result), 500

        is_member = any(g["id"] == guild_id for g in guilds)
        result["checks"]["is_member"] = is_member

        if not is_member:
            result["errors"].append(f"User not a member of guild {guild_id}")
            return jsonify(result), 403

        if required_roles:
            user_roles = discord_auth.get_user_roles_in_guild(
                access_token, guild_id, user_id
            )
            if user_roles is None:
                result["errors"].append("Failed to fetch user roles")
                return jsonify(result), 500

            result["user_roles"] = user_roles
            missing_roles = [r for r in required_roles if r not in user_roles]
            result["checks"]["has_required_roles"] = len(missing_roles) == 0

            if missing_roles:
                result["errors"].append(f"User missing roles: {', '.join(missing_roles)}")
                return jsonify(result), 403

    result["authenticated"] = all(
        result["checks"][k] for k in ["token_valid", "is_member"]
    )
    if required_roles:
        result["authenticated"] = result["authenticated"] and result["checks"][
            "has_required_roles"
        ]

    return jsonify(result), 200 if result["authenticated"] else 401


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    port = int(os.getenv("PORT", 10000))
    host = os.getenv("HOST", "0.0.0.0")

    logger.info(f"Starting Discord OAuth2 server on {host}:{port}")
    app.run(host=host, port=port, debug=debug_mode)
# ==========================================
# SERVER-SIDE ACTION VERIFICATION
# ==========================================

user_sessions_verify = {}
rate_limits_verify = {}
action_logs_verify = {}

@app.route("/api/verify-action", methods=["POST"])
def api_verify_action():
    try:
        session_token = request.headers.get("X-Session", "")
        machine_id = request.headers.get("X-Machine-Id", "")
        user_id_hdr = request.headers.get("X-User-Id", "")
        body = request.get_json() or {}
        action = body.get("action", "unknown")
        
        if not all([session_token, machine_id, user_id_hdr]):
            return jsonify({"allowed": False, "reason": "Missing authentication headers"}), 400
        
        session_data = user_sessions_verify.get(session_token)
        if not session_data:
            return jsonify({"allowed": False, "reason": "Invalid or expired session"}), 401
        
        if session_data.get("machine_id") != machine_id:
            return jsonify({"allowed": False, "reason": "Machine ID mismatch"}), 403
        
        if session_data.get("user_id") != user_id_hdr:
            return jsonify({"allowed": False, "reason": "User ID mismatch"}), 403
        
        return jsonify({"allowed": True}), 200
    except Exception as e:
        logger.error(f"[verify-action] Error: {e}")
        return jsonify({"allowed": False, "reason": "Server error"}), 500

@app.route("/api/session/create", methods=["POST"])
def api_create_session():
    body = request.get_json() or {}
    session_id = body.get("session_id")
    user_sessions_verify[session_id] = {
        "user_id": body.get("user_id"),
        "discord_id": body.get("discord_id"),
        "username": body.get("username"),
        "machine_id": body.get("machine_id")
    }
    return jsonify({"success": True}), 200

@app.route("/api/admin/logs/<user_id>", methods=["GET"])
def api_get_user_logs(user_id):
    return jsonify({"user_id": user_id, "logs": action_logs_verify.get(user_id, [])}), 200
