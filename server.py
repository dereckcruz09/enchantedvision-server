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

from discord_auth import DiscordAuth

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Discord OAuth2 handler
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")
REQUIRED_GUILD_ID = os.getenv("DISCORD_SERVER_ID")
REQUIRED_ROLES = os.getenv("DISCORD_REQUIRED_ROLES", "").split(",")
REQUIRED_ROLES = [r.strip() for r in REQUIRED_ROLES if r.strip()]

logger.info(f"=== DISCORD AUTH CONFIG ===")
logger.info(f"CLIENT_ID: {DISCORD_CLIENT_ID}")
logger.info(f"CLIENT_SECRET: {DISCORD_CLIENT_SECRET[:20] if DISCORD_CLIENT_SECRET else 'NONE'}...")
logger.info(f"REDIRECT_URI: {DISCORD_REDIRECT_URI}")
logger.info(f"REQUIRED_GUILD_ID: {REQUIRED_GUILD_ID}")
logger.info(f"REQUIRED_ROLES (raw): {os.getenv('DISCORD_REQUIRED_ROLES')}")
logger.info(f"REQUIRED_ROLES (parsed): {REQUIRED_ROLES}")
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
    client_ip = request.remote_addr
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
    client_ip = request.remote_addr
    
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

    # Check guild membership if required guild is configured
    if REQUIRED_GUILD_ID:
        guilds = discord_auth.get_user_guilds(access_token)
        if not guilds or not any(g["id"] == REQUIRED_GUILD_ID for g in guilds):
            logger.warning(f"User {user_id} not in required guild {REQUIRED_GUILD_ID}")
            return render_template_string(
                DENIED_TEMPLATE,
                reason=f"You are not a member of the required Discord server"
            ), 403

        # Check required roles if any
        if REQUIRED_ROLES:
            logger.info(f"[CALLBACK] Checking required roles: {REQUIRED_ROLES}")
            user_roles = discord_auth.get_user_roles_in_guild(
                access_token, REQUIRED_GUILD_ID, user_id
            )
            logger.info(f"[CALLBACK] User {user_id} roles from API: {user_roles}")
            if not user_roles or not any(r in user_roles for r in REQUIRED_ROLES):
                logger.warning(f"User {user_id} missing required roles. User roles: {user_roles}, Required: {REQUIRED_ROLES}")
                return render_template_string(
                    DENIED_TEMPLATE,
                    reason=f"You don't have the required role(s)"
                ), 403
            logger.info(f"[CALLBACK] User {user_id} has all required roles")
        else:
            logger.warning("[CALLBACK] REQUIRED_ROLES is empty - skipping role check")

    # Store user in session
    session["user_id"] = user_id
    session["user_info"] = user_info

    logger.info(f"User {user_id} ({user_info.get('username')}) successfully authenticated")

    # Store by IP for 30 seconds as fallback
    recent_authentications[request.remote_addr] = {
        "authenticated": True,
        "user_id": user_id,
        "username": user_info.get("username", "User"),
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
