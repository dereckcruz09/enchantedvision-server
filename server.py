"""
Discord OAuth2 Backend Server
Flask application for handling OAuth2 callbacks and token validation
"""

import os
import secrets
import logging
from functools import wraps
from typing import Optional, Dict, Tuple
from datetime import datetime

from flask import Flask, request, jsonify, session, redirect
from dotenv import load_dotenv
import requests

from discord_auth import DiscordAuth

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(32))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Discord OAuth2 handler
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/callback")
REQUIRED_GUILD_ID = os.getenv("DISCORD_SERVER_ID")
REQUIRED_ROLES = os.getenv("REQUIRED_ROLES", "").split(",")
REQUIRED_ROLES = [r.strip() for r in REQUIRED_ROLES if r.strip()]

if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
    raise ValueError("Missing required Discord credentials in environment")

discord_auth = DiscordAuth(DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_REDIRECT_URI)

# OAuth2 scopes
DEFAULT_SCOPES = ["identify", "guilds", "guilds.members.read"]


def validate_token(f):
    """Decorator to validate auth token from request"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header[7:]  # Remove "Bearer " prefix
        # In a real app, validate the token against your session/database
        # For now, we'll pass it through
        request.user_token = token
        return f(*args, **kwargs)

    return decorated_function


@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})


@app.route("/login", methods=["GET"])
def login():
    """
    Initiate OAuth2 login flow
    Returns authorization URL for client to redirect to
    """
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    auth_url = discord_auth.get_authorization_url(DEFAULT_SCOPES, state)
    return jsonify({"auth_url": auth_url, "state": state})


@app.route("/callback", methods=["GET"])
def callback():
    """
    OAuth2 callback endpoint
    Discord redirects here with authorization code
    """
    # Validate state for CSRF protection
    state = request.args.get("state")
    if not state or state != session.get("oauth_state"):
        logger.warning("Invalid state in OAuth callback")
        return (
            jsonify({"error": "Invalid state parameter - possible CSRF attack"}),
            403,
        )

    # Check for errors from Discord
    error = request.args.get("error")
    if error:
        error_description = request.args.get("error_description", "Unknown error")
        logger.error(f"Discord OAuth error: {error} - {error_description}")
        return jsonify({"error": f"Discord error: {error}"}), 400

    # Get authorization code
    code = request.args.get("code")
    if not code:
        logger.warning("No authorization code in callback")
        return jsonify({"error": "No authorization code received"}), 400

    # Exchange code for token and get user info
    success, user_id, user_info = discord_auth.authenticate_user(code)
    if not success:
        logger.error("Failed to authenticate user")
        return jsonify({"error": "Failed to authenticate with Discord"}), 401

    # Store user in session
    session["user_id"] = user_id
    session["user_info"] = user_info

    # Redirect to client success page (you can customize this)
    return redirect(f"/?auth_success=true&user_id={user_id}")


@app.route("/user", methods=["GET"])
@validate_token
def get_user():
    """
    Get current user information
    Requires valid session
    """
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
    """
    Validate Discord access token
    Accepts: {"access_token": "..."}
    """
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
    """
    Check if user is in required guild
    Accepts: {"access_token": "...", "guild_id": "..."}
    Returns: {"is_member": bool, "reason": str}
    """
    data = request.get_json()
    if not data or "access_token" not in data:
        return jsonify({"error": "Missing access_token"}), 400

    access_token = data["access_token"]
    guild_id = data.get("guild_id", REQUIRED_GUILD_ID)

    if not guild_id:
        return jsonify({"error": "guild_id required"}), 400

    # Get user guilds
    guilds = discord_auth.get_user_guilds(access_token)
    if guilds is None:
        return jsonify({"error": "Failed to fetch user guilds"}), 500

    # Check if user is in the required guild
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
    """
    Check if user has required roles in guild
    Accepts: {"access_token": "...", "guild_id": "...", "required_roles": [...]}
    Returns: {"has_required_roles": bool, "user_roles": [...], "missing_roles": [...]}
    """
    data = request.get_json()
    if not data or "access_token" not in data:
        return jsonify({"error": "Missing access_token"}), 400

    access_token = data["access_token"]
    guild_id = data.get("guild_id", REQUIRED_GUILD_ID)
    required_roles = data.get("required_roles", REQUIRED_ROLES)

    if not guild_id:
        return jsonify({"error": "guild_id required"}), 400

    # First check membership
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

    # Get user info
    user_info = discord_auth.get_user_info(access_token)
    if not user_info:
        return jsonify({"error": "Failed to fetch user info"}), 500

    user_id = user_info.get("id")

    # Get user roles
    user_roles = discord_auth.get_user_roles_in_guild(access_token, guild_id, user_id)
    if user_roles is None:
        return jsonify({"error": "Failed to fetch user roles"}), 500

    # Check for required roles (if configured)
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

    # If no specific roles required, return user's roles
    return jsonify(
        {
            "has_required_roles": True,
            "user_roles": user_roles,
            "reason": "User membership verified (no specific roles required)",
        }
    )


@app.route("/check-auth", methods=["POST"])
def check_auth():
    """
    Complete authentication check
    Verifies: token validity, server membership, required roles
    Accepts: {"access_token": "...", "guild_id": "...", "required_roles": [...]}
    Returns: comprehensive auth status
    """
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

    # Check 1: Token validity
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

    # Check 2: Guild membership
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

        # Check 3: Required roles (only if member and roles are specified)
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


@app.route("/logout", methods=["POST"])
def logout():
    """
    Logout user and clear cache
    """
    user_id = session.get("user_id")
    if user_id:
        discord_auth.clear_user_cache(user_id)
        logger.info(f"Logged out user {user_id}")

    session.clear()
    return jsonify({"message": "Logged out successfully"})


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
