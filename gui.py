"""
gui.py — Enchanted Vision Titan V.3 Control Panel
PyQt6-based GUI with modern dark theme and live settings management
"""

import json
import os
import sys
import threading
import time
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QPushButton,
    QLabel, QSpinBox, QGroupBox, QMessageBox, QLineEdit, QCheckBox, QTabWidget,
    QScrollArea, QFrame, QSizePolicy, QSlider, QDoubleSpinBox, QPlainTextEdit, QDialog
)
from PyQt6.QtGui import QColor, QPixmap, QFont
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, QPoint
from PyQt6.QtWidgets import QApplication

from gcv_worker import GCVWorker
from discord_auth_simple import DiscordAuthSimple
from discord_auth_client import DiscordAuthClient

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "settings.json")

# ── Discord Auth Configuration ───────────────────────────────────────────────
DISCORD_SERVER_URL = "https://enchantedvision-server-1.onrender.com"
DISCORD_GUILD_ID = "1474000340448968928"  # Your Discord server ID
DISCORD_REQUIRED_ROLES = ["1512282657554432000"]  # Required role ID for access
REQUIRE_DISCORD_AUTH = True  # Set to False to disable Discord auth requirement

# ── Dark Theme Stylesheet ─────────────────────────────────────────────────────
DARK_STYLESHEET = """
QWidget {
    background-color: #000000;
    color: #d0d0d0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 11px;
}
QTabWidget::pane {
    border: none;
    border-top: 1px solid #1a1a1a;
}
QTabBar {
    background-color: #000000;
}
QTabBar::tab {
    background-color: transparent;
    color: #666;
    padding: 10px 24px;
    border: none;
    font-size: 12px;
}
QTabBar::tab:selected {
    color: #fff;
    background-color: #000000;
    border-top: 2px solid #8b30d0;
}
QTabBar::tab:hover:!selected {
    color: #bbb;
    background-color: #111;
}
QGroupBox {
    border: 1px solid #1a1a1a;
    border-radius: 4px;
    margin-top: 14px;
    padding: 10px 8px 8px 8px;
    color: #bbb;
    font-weight: bold;
    background-color: #0a0a0a;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 8px;
    padding: 0 4px;
    color: #ccc;
}
QSpinBox, QDoubleSpinBox, QLineEdit {
    background-color: #0f0f0f;
    border: 1px solid #1a1a1a;
    border-radius: 3px;
    padding: 3px 6px;
    color: #ddd;
    min-height: 22px;
    selection-background-color: #5520a0;
}
QSpinBox:focus, QDoubleSpinBox:focus, QLineEdit:focus {
    border-color: #7030b0;
}
QCheckBox {
    color: #ccc;
    spacing: 6px;
}
QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #333;
    border-radius: 2px;
    background-color: #0f0f0f;
}
QCheckBox::indicator:checked {
    background-color: #6020a0;
    border-color: #8b30d0;
}
QPushButton {
    background-color: #0f0f0f;
    color: #ccc;
    border: 1px solid #1a1a1a;
    border-radius: 3px;
    padding: 5px 12px;
    min-height: 26px;
}
QPushButton:hover {
    background-color: #1a1a1a;
    border-color: #6020a0;
    color: #fff;
}
QPushButton:pressed {
    background-color: #000000;
}
QSlider::groove:horizontal {
    background-color: #0f0f0f;
    height: 6px;
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background-color: #8b30d0;
    width: 14px;
    margin: -4px 0;
    border-radius: 7px;
}
QSlider::handle:horizontal:hover {
    background-color: #a050d0;
}
QScrollBar:vertical {
    background-color: #000000;
    width: 6px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #1a1a1a;
    border-radius: 3px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background-color: #2a2a2a;
}
"""


# ── Settings Management ──────────────────────────────────────────────────────
def load_settings():
    """Load settings from JSON file or return defaults."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            settings = json.load(f)
            # Ensure all required keys exist
            defaults = {
                "target_height": 26.0,
                "min_area": 100,
                "meter_enabled": False,
                "skele_enabled": False,
                "tempo_ms": 45,
            }
            for key, value in defaults.items():
                if key not in settings:
                    settings[key] = value
            return settings
    except FileNotFoundError:
        return {
            "target_height": 26.0,
            "min_area": 100,
            "meter_enabled": False,
            "skele_enabled": False,
            "tempo_ms": 45,
        }


def save_settings(data):
    """Save settings to JSON file."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(CONFIG_PATH)), exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"[settings] write failed: {e}")
        return False


# ── Main Application ────────────────────────────────────────────────────────
class EnchantedVisionApp(QWidget):
    """Main application window for Enchanted Vision Titan V.3"""

    def __init__(self):
        super().__init__()
        
        # Discord auth setup
        self.discord_client = DiscordAuthClient(DISCORD_SERVER_URL)
        self.user_authenticated = False
        self.current_user_id = None
        self.current_user_info = {}
        
        self.setWindowTitle("Enchanted Vision Titan V.3")
        self.resize(350, 500)
        self.setMinimumSize(350, 500)
        self.setMaximumWidth(350)

        # Make window frameless
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)

        self.cfg = load_settings()
        # Ensure meter detection is off by default
        self.cfg["meter_enabled"] = False
        save_settings(self.cfg)
        
        self._writing = False
        self._debounce_timer = None
        self.worker = None
        self.worker_thread = None
        self.running = False
        self.drag_pos = None

        # Initialize skeleton checkbox early to prevent AttributeError in _on_meter_toggle
        self.chk_skele = QCheckBox("Enable Skeleton Detection")
        self.chk_skele.setChecked(bool(self.cfg.get("skele_enabled", False)))
        self.chk_skele.stateChanged.connect(self._on_skele_toggle)

        self.setStyleSheet(DARK_STYLESHEET)

        # ── Main layout ──────────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Custom Title Bar ──────────────────────────────────────────────────
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #d946ef;")
        title_bar.setFixedHeight(35)
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(15, 0, 15, 0)
        title_layout.setSpacing(10)

        title_label = QLabel("⚙ ENCHANTED VISION TITAN V.3")
        title_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        title_label.setStyleSheet("color: #000000;")
        title_layout.addWidget(title_label)
        title_layout.addStretch()

        # Window control buttons
        btn_minimize = QPushButton("−")
        btn_minimize.setFixedSize(35, 35)
        btn_minimize.setStyleSheet(
            "background-color: #d946ef; color: #000000; border: none; font-size: 18px; font-weight: bold;"
        )
        btn_minimize.clicked.connect(self.showMinimized)
        title_layout.addWidget(btn_minimize)

        btn_maximize = QPushButton("□")
        btn_maximize.setFixedSize(35, 35)
        btn_maximize.setStyleSheet(
            "background-color: #d946ef; color: #000000; border: none; font-size: 16px; font-weight: bold;"
        )
        btn_maximize.clicked.connect(self._toggle_maximize)
        title_layout.addWidget(btn_maximize)
        self.btn_maximize = btn_maximize

        btn_close = QPushButton("✕")
        btn_close.setFixedSize(35, 35)
        btn_close.setStyleSheet(
            "background-color: #d946ef; color: #000000; border: none; font-size: 18px; font-weight: bold;"
        )
        btn_close.clicked.connect(self.close)
        title_layout.addWidget(btn_close)

        title_bar.setLayout(title_layout)
        root.addWidget(title_bar)

        # ── Tabs ─────────────────────────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_general_tab(), "  ⚙  General  ")
        self.tabs.addTab(self._build_meter_tab(), "  ⏱  Meter  ")
                
        root.addWidget(self.tabs, 1)

        # ── Bottom action bar ────────────────────────────────────────────────
        root.addWidget(self._build_bottom_bar())

        # ── Debounce timer for autosave ──────────────────────────────────────
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(150)
        self._debounce_timer.timeout.connect(self._do_autosave)

    # ── Tab builders ─────────────────────────────────────────────────────────

    def _build_general_tab(self) -> QWidget:
        """General settings tab with logo."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo
        img_lbl = QLabel()
        img_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        img_path = os.path.join(BASE_DIR, "banner_top.png")
        if os.path.exists(img_path):
            pix = QPixmap(img_path)
            if not pix.isNull():
                pix = pix.scaledToWidth(330, Qt.TransformationMode.SmoothTransformation)
            img_lbl.setPixmap(pix)
        else:
            img_lbl.setText("[ banner_top.png not found ]")
            img_lbl.setStyleSheet("color: #555; font-size: 10px;")
        layout.addWidget(img_lbl, alignment=Qt.AlignmentFlag.AlignCenter)

        scroll.setWidget(content)
        return scroll

    def _build_meter_tab(self) -> QWidget:
        """Meter configuration tab."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)


        # Meter settings
        meter_box = QGroupBox("Meter Configuration")
        meter_form = QFormLayout(meter_box)
        meter_form.setVerticalSpacing(8)
        meter_form.setHorizontalSpacing(12)

        self.spin_height = QDoubleSpinBox()
        self.spin_height.setRange(0, 480)
        self.spin_height.setDecimals(1)
        self.spin_height.setSingleStep(0.1)
        self.spin_height.setValue(float(self.cfg.get("target_height", 26.0)))
        self.spin_height.valueChanged.connect(self._autosave_debounced)

        self.slider_height = QSlider(Qt.Orientation.Horizontal)
        self.slider_height.setRange(0, 4800)  # 0-480 with 0.1 precision
        self.slider_height.setValue(int(float(self.cfg.get("target_height", 26.0)) * 10))
        self.slider_height.sliderMoved.connect(lambda v: self.spin_height.setValue(v / 10.0))
        self.spin_height.valueChanged.connect(lambda v: self.slider_height.setValue(int(v * 10)))

        self.spin_area = QSpinBox()
        self.spin_area.setRange(10, 10000)
        self.spin_area.setValue(int(self.cfg.get("min_area", 100)))
        self.spin_area.valueChanged.connect(self._autosave_debounced)

        # ── EV 4.2 Exact Tempo UI ──────────────────────────────────────────
        # Create tempo control container with up/down buttons (EV 4.2 style)
        self.tempo_container = QWidget()
        tempo_layout = QHBoxLayout(self.tempo_container)
        tempo_layout.setContentsMargins(0, 0, 0, 0)
        tempo_layout.setSpacing(4)
        
        self.tempo_lbl = QLabel(f"{int(self.cfg.get('tempo_ms', 80))} ms")
        self.tempo_lbl.setMinimumWidth(60)
        self.tempo_lbl.setStyleSheet("font-weight: bold; color: #d0d0d0;")
        
        self.tempo_inc_btn = QPushButton("▲")
        self.tempo_inc_btn.setMaximumWidth(35)
        self.tempo_inc_btn.setMaximumHeight(24)
        self.tempo_inc_btn.setStyleSheet(
            "background-color: #8b30d0; color: white; border: 1px solid #6020a0; "
            "border-radius: 3px; font-weight: bold; padding: 2px;"
        )
        self.tempo_inc_btn.clicked.connect(self._tempo_inc)
        
        self.tempo_dec_btn = QPushButton("▼")
        self.tempo_dec_btn.setMaximumWidth(35)
        self.tempo_dec_btn.setMaximumHeight(24)
        self.tempo_dec_btn.setStyleSheet(
            "background-color: #8b30d0; color: white; border: 1px solid #6020a0; "
            "border-radius: 3px; font-weight: bold; padding: 2px;"
        )
        self.tempo_dec_btn.clicked.connect(self._tempo_dec)
        
        tempo_layout.addWidget(self.tempo_lbl)
        tempo_layout.addWidget(self.tempo_inc_btn)
        tempo_layout.addWidget(self.tempo_dec_btn)
        tempo_layout.addStretch()

        self.chk_meter = QCheckBox("Enable Meter Detection")
        self.chk_meter.setChecked(bool(self.cfg.get("meter_enabled", False)))
        self.chk_meter.stateChanged.connect(self._on_meter_toggle)

        meter_form.addRow("Target Height (px):", self.spin_height)
        meter_form.addRow("Height Slider:", self.slider_height)
        meter_form.addRow("Min Detection Area (px²):", self.spin_area)
        meter_form.addRow("Tempo (ms):", self.tempo_container)
        meter_form.addRow("", self.chk_meter)

        layout.addWidget(meter_box)

        # Fine tune buttons
        tune_box = QGroupBox("Fine Tune")
        tune_layout = QHBoxLayout(tune_box)
        tune_layout.setSpacing(8)

        adjustments = [(-5.0, "-5.0"), (-0.1, "-0.1"), (0.1, "+0.1"), (5.0, "+5.0")]
        for adj_value, adj_label in adjustments:
            btn = QPushButton(adj_label)
            btn.setStyleSheet(
                "background-color: #8b30d0; color: white; border: 1px solid #6020a0; "
                "border-radius: 3px; padding: 5px 12px; min-height: 26px; font-weight: bold;"
            )
            btn.clicked.connect(lambda checked, a=adj_value: self._adjust_height(a))
            tune_layout.addWidget(btn)

        layout.addWidget(tune_box)
        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _build_skele_tab(self) -> QWidget:
        """Skeleton detection tab."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        skele_box = QGroupBox("Skeleton Configuration")
        skele_layout = QVBoxLayout(skele_box)

        # Use the checkbox that was initialized in __init__
        skele_layout.addWidget(self.chk_skele)
        skele_layout.addWidget(QLabel("More options coming soon..."))

        layout.addWidget(skele_box)
        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _build_creative_tab(self) -> QWidget:
        """Creative settings tab (blank for now)."""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        layout.addStretch()
        scroll.setWidget(content)
        return scroll

    def _build_bottom_bar(self) -> QWidget:
        """Bottom action bar."""
        bar = QWidget()
        bar.setStyleSheet("background-color: #000000; border-top: 1px solid #1a1a1a;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #444; font-size: 10px;")
        layout.addWidget(self.status_label)

        layout.addStretch()

        btn_save = QPushButton("💾 Save Settings")
        btn_save.clicked.connect(self._save_only)
        layout.addWidget(btn_save)

        btn_apply = QPushButton("✓ Apply & Send")
        btn_apply.setStyleSheet(
            "background-color: #0a0a0a; color: #bb77ff; border: 1px solid #5020a0;"
        )
        btn_apply.clicked.connect(self._apply_live)
        layout.addWidget(btn_apply)

        return bar

    # ── Event handlers ───────────────────────────────────────────────────────

    def mousePressEvent(self, event):
        """Handle mouse press on title bar for dragging."""
        if event.pos().y() < 35:  # Title bar height
            self.drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()

    def mouseMoveEvent(self, event):
        """Handle mouse move for dragging window."""
        if self.drag_pos is not None and event.buttons() == Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self.drag_pos)

    def mouseReleaseEvent(self, event):
        """Handle mouse release."""
        self.drag_pos = None

    def _toggle_maximize(self):
        """Toggle between maximized and normal window."""
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()

    def _autosave_debounced(self):
        """Debounce autosave on value changes."""
        self._debounce_timer.stop()
        self._debounce_timer.start()

    def _do_autosave(self):
        """Perform autosave."""
        self._save_only()

    def _adjust_height(self, amount):
        """Adjust height by amount."""
        current = self.spin_height.value()
        self.spin_height.setValue(current + amount)

    def _tempo_inc(self):
        """Increment tempo (EV 4.2 exact logic: min(200, tempo + 1))."""
        current = int(self.tempo_lbl.text().split()[0])
        new_val = min(200, current + 1)
        self.tempo_lbl.setText(f"{new_val} ms")
        self.cfg["tempo_ms"] = new_val
        self._autosave_debounced()

    def _tempo_dec(self):
        """Decrement tempo (EV 4.2 exact logic: max(1, tempo - 1))."""
        current = int(self.tempo_lbl.text().split()[0])
        new_val = max(1, current - 1)
        self.tempo_lbl.setText(f"{new_val} ms")
        self.cfg["tempo_ms"] = new_val
        self._autosave_debounced()

    def _on_meter_toggle(self):
        """Handle meter toggle."""
        if self.chk_meter.isChecked():
            self.chk_skele.setChecked(False)
            self.cfg["meter_enabled"] = True
            self.cfg["skele_enabled"] = False
        else:
            self.cfg["meter_enabled"] = False
        self._autosave_debounced()

    def _on_skele_toggle(self):
        """Handle skeleton toggle."""
        if self.chk_skele.isChecked():
            self.chk_meter.setChecked(False)
            self.cfg["skele_enabled"] = True
            self.cfg["meter_enabled"] = False
        else:
            self.cfg["skele_enabled"] = False
        self._autosave_debounced()

    def _save_only(self):
        """Save settings to disk only."""
        try:
            self.cfg["target_height"] = float(self.spin_height.value())
            self.cfg["min_area"] = self.spin_area.value()
            self.cfg["tempo_ms"] = int(self.tempo_lbl.text().split()[0])
            self.cfg["meter_enabled"] = self.chk_meter.isChecked()
            self.cfg["skele_enabled"] = self.chk_skele.isChecked()

            if save_settings(self.cfg):
                self.status_label.setText("✓ Settings saved")
            else:
                self.status_label.setText("✗ Save failed")
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")

    def _apply_live(self):
        """Save and apply settings live."""
        self._save_only()
        self.status_label.setText("✓ Settings applied")

    def _copy_to_clipboard(self, text, label):
        """Copy text to clipboard and show confirmation."""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", f"{label} copied to clipboard!")

    def closeEvent(self, event):
        """Handle window close event - disable meter detection."""
        # Turn off meter detection
        self.cfg["meter_enabled"] = False
        save_settings(self.cfg)
        
        # Close the window
        event.accept()

    # ── Discord Authentication ───────────────────────────────────────────────

    def _check_discord_auth(self) -> bool:
        """
        Check Discord authentication. Shows login dialog if needed.
        Returns True if authenticated, False otherwise.
        """
        if not REQUIRE_DISCORD_AUTH:
            self.user_authenticated = True
            return True
        
        print("[Auth] Checking Discord authentication...")
        
        try:
            # Try to use cached authentication
            if self._try_cached_auth():
                print("[Auth] Using cached authentication")
                return True
        except Exception as e:
            print(f"[Auth] Cached auth check error: {e}")
        
        print("[Auth] No cached auth, showing dialog...")
        # Show login dialog
        try:
            result = self._show_discord_login_dialog()
            print(f"[Auth] Dialog result: {result}")
            return result
        except Exception as e:
            print(f"[Auth] Dialog error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _try_cached_auth(self) -> bool:
        """Try to authenticate with cached Discord token"""
        try:
            if not self.discord_client or not hasattr(self.discord_client, 'access_token'):
                return False
            
            if not self.discord_client.access_token:
                return False
            
            # For now, just skip the full check - the dialog will handle it
            print("[Auth] Found cached access token")
            return False  # Let the dialog handle verification instead
        except Exception as e:
            print(f"[Auth] Cached auth check error: {e}")
            return False

    def _show_discord_login_dialog(self) -> bool:
        """Show Discord authentication dialog"""
        print("[GUI] Creating auth dialog...")
        dialog = DiscordAuthSimple(
            parent=self,
            guild_id=DISCORD_GUILD_ID,
            required_roles=DISCORD_REQUIRED_ROLES,
            server_url=DISCORD_SERVER_URL,
            client_id="1512267443832361030"
        )
        
        print("[GUI] Showing auth dialog...")
        # Show dialog modally
        result = dialog.exec()
        
        print(f"[GUI] Dialog exec() returned: {result}")
        
        # In PyQt6, QDialog.Accepted = 1
        if result == 1:
            # Get the authenticated user from the dialog
            if hasattr(dialog, 'authenticated_user') and dialog.authenticated_user:
                print(f"[GUI] Got authenticated_user: {dialog.authenticated_user}")
                self.user_authenticated = True
                self.current_user_id = dialog.authenticated_user.get("id", "authenticated")
                self.current_user_info = dialog.authenticated_user
                print(f"[Discord Auth] Successfully authenticated: {self.current_user_id}")
                return True
            else:
                print(f"[GUI] authenticated_user not set. Has attr: {hasattr(dialog, 'authenticated_user')}, Value: {getattr(dialog, 'authenticated_user', 'NOT_SET')}")
        else:
            print(f"[GUI] Dialog returned {result}, not Accepted (1)")
        
        # Authentication cancelled or failed
        print("[Discord Auth] Authentication failed or cancelled")
        return False

    def _discord_check_membership(self) -> bool:
        """Check if current user is member of required guild"""
        if not self.user_authenticated or not self.discord_client.access_token:
            return False
        
        is_member, reason = self.discord_client.check_server_membership(DISCORD_GUILD_ID)
        print(f"[Discord] Membership check: {is_member} - {reason}")
        return is_member

    def _discord_check_roles(self) -> tuple:
        """
        Check user's roles in the server
        Returns: (has_all_required_roles, user_roles, missing_roles)
        """
        if not self.user_authenticated or not self.discord_client.access_token:
            return False, [], DISCORD_REQUIRED_ROLES
        
        has_all, user_roles, missing = self.discord_client.check_user_roles(
            DISCORD_GUILD_ID,
            DISCORD_REQUIRED_ROLES
        )
        print(f"[Discord] Role check: has_all={has_all}, user_roles={user_roles}, missing={missing}")
        return has_all, user_roles, missing

    def _discord_logout(self):
        """Logout current Discord user"""
        if self.discord_client:
            self.discord_client.logout()
        
        self.user_authenticated = False
        self.current_user_id = None
        self.current_user_info = {}
        print("[Discord Auth] User logged out")


# ── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    print("[Main] Creating window...")
    window = EnchantedVisionApp()
    
    print("[Main] Checking discord auth...")
    # Check Discord authentication before showing GUI
    if not window._check_discord_auth():
        print("[Main] Discord authentication failed. Exiting.")
        sys.exit(1)
    
    print("[Main] Showing window...")
    window.show()
    print("[Main] Running app...")
    sys.exit(app.exec())
