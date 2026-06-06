"""
Simple Discord Auth - Web-based authentication
User authenticates at Render URL, GUI waits for session
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QMessageBox, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
import webbrowser
import requests
import time
import os


class AuthWaitThread(QThread):
    """Thread that waits for authentication to complete"""
    auth_complete = pyqtSignal(bool, dict)
    
    def __init__(self, server_url: str, timeout: int = 300):
        super().__init__()
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.running = True
    
    def run(self):
        """Wait for user to authenticate at Render"""
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < self.timeout:
            try:
                # Check if there's an active session with user info
                response = requests.get(
                    f"{self.server_url}/",
                    timeout=5,
                    allow_redirects=False
                )
                
                # If we get user info in response, they're authenticated
                if response.status_code == 200 and "Access Granted" in response.text:
                    # Extract user info from the page
                    import re
                    # Try multiple regex patterns for extraction
                    username_match = re.search(r'Username:</strong> ([^<]+)', response.text)
                    user_id_match = re.search(r'User ID:</strong> ([^<]+)', response.text)
                    
                    if username_match and user_id_match:
                        user_info = {
                            "username": username_match.group(1).strip(),
                            "id": user_id_match.group(1).strip()
                        }
                        self.auth_complete.emit(True, user_info)
                        return
                
                time.sleep(1)  # Check every second
            except Exception as e:
                print(f"[AuthWait] Error: {e}")
                time.sleep(1)
        
        # Timeout
        self.auth_complete.emit(False, {})
    
    def stop(self):
        """Stop waiting"""
        self.running = False


class DiscordAuthSimple(QDialog):
    """Simple Discord Auth dialog - opens browser and waits"""
    
    auth_success = pyqtSignal(dict)  # Emits user_info on success
    auth_failed = pyqtSignal(str)  # Emits error message on failure
    
    def __init__(self, server_url: str, parent=None, guild_id: str = None, 
                 required_roles: list = None, client_id: str = None):
        super().__init__(parent)
        self.server_url = server_url.rstrip("/")
        self.user_authenticated = False
        self.authenticated_user = {}
        # Use a session to preserve cookies
        self.session = requests.Session()
        self.setWindowTitle("Discord Authentication")
        self.setFixedSize(400, 200)
        self.setModal(True)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a2e;
                color: #fff;
            }
            QPushButton {
                background-color: #5865F2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #4752C4;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title = QLabel("Discord Authentication")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Instructions
        instructions = QLabel(
            "Click 'Open Discord Login' to authorize with Discord.\n"
            "You will see either:\n"
            "  ✓ 'Access Granted!' - Click 'Waiting for Auth...'\n"
            "  ✗ 'Access Denied' - You don't have the required role\n\n"
            "Only click 'Waiting for Auth...' if you see 'Access Granted!'"
        )
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #ccc; line-height: 1.5;")
        layout.addWidget(instructions)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)  # Indeterminate
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        # Buttons layout
        button_layout = QHBoxLayout()
        
        self.btn_login = QPushButton("Open Discord Login")
        self.btn_login.clicked.connect(self._open_login)
        button_layout.addWidget(self.btn_login)
        
        self.btn_wait = QPushButton("Waiting for Auth...")
        self.btn_wait.clicked.connect(self._start_waiting)
        self.btn_wait.setVisible(False)
        button_layout.addWidget(self.btn_wait)
        
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.clicked.connect(self.reject)
        button_layout.addWidget(self.btn_cancel)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.auth_thread = None
    
    def _open_login(self):
        """Open Discord login in browser"""
        login_url = f"{self.server_url}/login"
        webbrowser.open(login_url)
        
        self.btn_login.setVisible(False)
        self.btn_wait.setVisible(True)
        self.progress.setVisible(True)
    
    def _start_waiting(self):
        """Check if user authenticated via the auth-status endpoint"""
        try:
            print("[AuthDialog] Checking authentication status...")
            
            response = self.session.get(
                f"{self.server_url}/auth-status",
                timeout=5,
                allow_redirects=False
            )
            
            print(f"[AuthDialog] Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                if data.get("authenticated"):
                    print(f"[AuthDialog] ✓ Authenticated: {data.get('username')}")
                    self.authenticated_user = {
                        "username": data.get("username", "User"),
                        "id": data.get("user_id", "authenticated")
                    }
                    self.user_authenticated = True
                    self.done(1)  # Open GUI
                    return
            
            # Not authenticated
            print("[AuthDialog] ✗ Not authenticated")
            QMessageBox.warning(
                self,
                "Not Authenticated",
                "Please log in via Discord in the browser first."
            )
        except Exception as e:
            print(f"[AuthDialog] Error: {e}")
            QMessageBox.critical(self, "Error", f"Error: {e}")
    
    def _on_auth_complete(self, success: bool, user_info: dict):
        """Handle authentication result"""
        self.progress.setVisible(False)
        
        if success:
            QMessageBox.information(
                self,
                "Success",
                f"Authenticated as {user_info.get('username', 'User')}!"
            )
            self.auth_success.emit(user_info)
            self.accept()
        else:
            QMessageBox.warning(
                self,
                "Authentication Failed",
                "Authentication timed out or was denied.\nPlease try again."
            )
            self.auth_failed.emit("Authentication failed or timed out")
            self.btn_wait.setEnabled(True)
            self.btn_wait.setText("Waiting for Auth...")
    
    def closeEvent(self, event):
        """Clean up when dialog closes"""
        if self.auth_thread and self.auth_thread.isRunning():
            self.auth_thread.stop()
            self.auth_thread.wait()
        event.accept()
