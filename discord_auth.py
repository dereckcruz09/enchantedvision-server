"""
Discord OAuth2 Authentication Module
Handles OAuth2 flow, token management, and Discord API interactions
"""

import os
import json
import time
import requests
from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Discord OAuth2 endpoints
DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_OAUTH_BASE = "https://discord.com/api/oauth2"
AUTHORIZE_URL = f"{DISCORD_OAUTH_BASE}/authorize"
TOKEN_URL = f"{DISCORD_OAUTH_BASE}/token"


class DiscordAuth:
    """Handles Discord OAuth2 authentication and token management"""

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        """
        Initialize Discord OAuth2 handler

        Args:
            client_id: Discord app client ID
            client_secret: Discord app client secret
            redirect_uri: OAuth2 callback URL
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

        # Token cache: {user_id: {"access_token": str, "refresh_token": str, "expires_at": float}}
        self.token_cache: Dict[str, Dict] = {}
        self.cache_file = ".discord_token_cache.json"
        self._load_cache()

    def _load_cache(self) -> None:
        """Load token cache from file if it exists"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, "r") as f:
                    self.token_cache = json.load(f)
                logger.info("Loaded token cache from file")
            except Exception as e:
                logger.warning(f"Failed to load cache: {e}")
                self.token_cache = {}

    def _save_cache(self) -> None:
        """Save token cache to file"""
        try:
            with open(self.cache_file, "w") as f:
                json.dump(self.token_cache, f)
        except Exception as e:
            logger.error(f"Failed to save cache: {e}")

    def get_authorization_url(self, scopes: List[str], state: str) -> str:
        """
        Generate Discord OAuth2 authorization URL

        Args:
            scopes: List of OAuth2 scopes (e.g., ['identify', 'guilds', 'guilds.members.read'])
            state: Random state string for CSRF protection

        Returns:
            Authorization URL
        """
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "state": state,
        }
        query_string = "&".join(f"{k}={v}" for k, v in params.items())
        return f"{AUTHORIZE_URL}?{query_string}"

    def exchange_code_for_token(self, code: str) -> Optional[Dict]:
        """
        Exchange authorization code for access token

        Args:
            code: Authorization code from OAuth2 callback

        Returns:
            Token dict with access_token, refresh_token, expires_in, or None if failed
        """
        print("=== EXCHANGE_CODE_FOR_TOKEN CALLED ===", flush=True)
        print(f"=== CODE: {code[:20]} ===", flush=True)
        print(f"=== CLIENT_ID: {self.client_id} ===", flush=True)
        print(f"=== CLIENT_SECRET: {self.client_secret[:10]}... ===", flush=True)
        print(f"=== REDIRECT_URI: {self.redirect_uri} ===", flush=True)
        print(f"=== TOKEN_URL: {TOKEN_URL} ===", flush=True)
        
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
        }

        try:
            print(f"=== PAYLOAD: {payload} ===", flush=True)
            print("=== SENDING POST REQUEST ===", flush=True)
            
            headers = {
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            response = requests.post(TOKEN_URL, data=payload, headers=headers, timeout=10)
            
            print(f"=== RESPONSE STATUS: {response.status_code} ===", flush=True)
            print(f"=== RESPONSE CONTENT_TYPE: {response.headers.get('content-type')} ===", flush=True)
            print(f"=== RESPONSE TEXT (FULL): {response.text} ===", flush=True)
            
            if response.status_code == 200:
                try:
                    token_data = response.json()
                    print(f"=== SUCCESS! Token keys: {list(token_data.keys())} ===", flush=True)
                    return token_data
                except Exception as json_err:
                    print(f"=== JSON PARSE FAILED: {json_err} ===", flush=True)
                    return None
            else:
                print(f"=== ERROR: Status {response.status_code} ===", flush=True)
                return None
        except Exception as e:
            print(f"=== EXCEPTION: {e} ===", flush=True)
            import traceback
            print(traceback.format_exc(), flush=True)
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[Dict]:
        """
        Refresh expired access token

        Args:
            refresh_token: Refresh token from previous authentication

        Returns:
            New token dict, or None if refresh failed
        """
        payload = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }

        try:
            response = requests.post(TOKEN_URL, data=payload, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to refresh token: {e}")
            return None

    def get_user_info(self, access_token: str) -> Optional[Dict]:
        """
        Get Discord user information

        Args:
            access_token: Discord access token

        Returns:
            User info dict or None if request failed
        """
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(
                f"{DISCORD_API_BASE}/users/@me", headers=headers, timeout=10
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user info: {e}")
            return None

    def get_user_guilds(self, access_token: str) -> Optional[List[Dict]]:
        """
        Get Discord servers (guilds) user is in

        Args:
            access_token: Discord access token

        Returns:
            List of guild dicts or None if request failed
        """
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(
                f"{DISCORD_API_BASE}/users/@me/guilds",
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user guilds: {e}")
            return None

    def get_user_roles_in_guild(
        self, access_token: str, guild_id: str, user_id: str
    ) -> Optional[List[str]]:
        """
        Get user's roles in a specific guild

        Args:
            access_token: Discord access token
            guild_id: Discord guild (server) ID
            user_id: Discord user ID

        Returns:
            List of role IDs or None if request failed
        """
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(
                f"{DISCORD_API_BASE}/users/@me/guilds/{guild_id}/member",
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            member_data = response.json()
            return member_data.get("roles", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get user roles in guild: {e}")
            return None

    def cache_token(
        self,
        user_id: str,
        access_token: str,
        refresh_token: str,
        expires_in: int,
    ) -> None:
        """
        Cache authentication token

        Args:
            user_id: Discord user ID
            access_token: Access token
            refresh_token: Refresh token
            expires_in: Token expiration in seconds
        """
        expires_at = time.time() + expires_in - 60
        self.token_cache[user_id] = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
        }
        self._save_cache()
        logger.info(f"Cached token for user {user_id}")

    def get_cached_token(self, user_id: str) -> Optional[str]:
        """
        Get cached access token, refreshing if necessary

        Args:
            user_id: Discord user ID

        Returns:
            Valid access token or None
        """
        if user_id not in self.token_cache:
            return None

        token_data = self.token_cache[user_id]
        expires_at = token_data.get("expires_at", 0)

        if time.time() < expires_at:
            return token_data["access_token"]

        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            return None

        new_token_data = self.refresh_access_token(refresh_token)
        if not new_token_data:
            return None

        self.cache_token(
            user_id,
            new_token_data["access_token"],
            new_token_data["refresh_token"],
            new_token_data["expires_in"],
        )
        return new_token_data["access_token"]

    def authenticate_user(
        self, code: str
    ) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Complete OAuth2 flow: exchange code for token and get user info

        Args:
            code: Authorization code from OAuth2 callback

        Returns:
            Tuple of (success: bool, user_id: Optional[str], user_info: Optional[Dict])
        """
        print("=== AUTHENTICATE_USER CALLED ===", flush=True)
        print(f"=== CODE: {code[:20]} ===", flush=True)
        
        logger.info(f"[AUTHENTICATE] Starting authentication with code: {code[:20]}...")
        
        logger.info("[AUTHENTICATE] Exchanging code for token...")
        token_data = self.exchange_code_for_token(code)
        if not token_data:
            logger.error("[AUTHENTICATE] Token exchange failed - no token data returned")
            print("=== TOKEN_DATA IS NONE ===", flush=True)
            return False, None, None

        logger.info(f"[AUTHENTICATE] Token exchange successful. Token keys: {list(token_data.keys())}")
        
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)

        if not access_token:
            logger.error("[AUTHENTICATE] No access_token in token response")
            logger.error(f"[AUTHENTICATE] Token data: {token_data}")
            return False, None, None

        logger.info("[AUTHENTICATE] Getting user info...")
        user_info = self.get_user_info(access_token)
        if not user_info:
            logger.error("[AUTHENTICATE] Failed to get user info")
            return False, None, None

        logger.info(f"[AUTHENTICATE] Got user info: {user_info.get('username', 'unknown')}")
        user_id = user_info.get("id")

        if user_id:
            logger.info(f"[AUTHENTICATE] Caching token for user {user_id}")
            self.cache_token(user_id, access_token, refresh_token, expires_in)
        else:
            logger.warning("[AUTHENTICATE] No user_id in user_info")

        logger.info("[AUTHENTICATE] Authentication successful")
        return True, user_id, user_info

    def clear_user_cache(self, user_id: str) -> None:
        """Clear cached token for user"""
        if user_id in self.token_cache:
            del self.token_cache[user_id]
            self._save_cache()
            logger.info(f"Cleared cache for user {user_id}")
