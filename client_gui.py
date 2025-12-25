from __future__ import annotations

import sys
import socket
import threading
import cv2
import numpy as np
import pyaudio
import config
import json
import struct
import time
import math
import os
import ssl
import queue
import logging
import re
import html
import platform

from mss import mss

try:
    import sounddevice as sd  # type: ignore
except ImportError:  # System audio capture remains disabled without sounddevice
    sd = None

from PyQt6.QtWidgets import (QApplication, QWidget, QVBoxLayout, QHBoxLayout,

                             QListWidget, QTextEdit, QLineEdit, QPushButton,

                             QSplitter, QDialog, QFormLayout, QDialogButtonBox,

                             QLabel, QMessageBox, QGridLayout, QSizePolicy,

                             QFileDialog, QListWidgetItem, QProgressBar,

                             QInputDialog, QStackedWidget, QSpacerItem,

                             QTabWidget, QFrame, QGraphicsDropShadowEffect,

                             QToolButton, QMenu)

from PyQt6.QtCore import (Qt, pyqtSignal, QObject, QTimer, QSize,

                          QPropertyAnimation, QRect, QParallelAnimationGroup,

                          QEasingCurve)

from PyQt6.QtGui import (QImage, QPixmap, QFont, QIcon, QResizeEvent,
                         QColor, QAction, QActionGroup)



# Setup logging based on config

logging.basicConfig(level=config.LOG_LEVEL, format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s')


# --- UI Color Palette ---
PRIMARY_BG = "#0F172A"
SURFACE_BG = "#111C2E"
PANEL_BG = "#15243A"
CARD_BG = "#1E2D47"
BORDER_COLOR = "#243551"
ACCENT_COLOR = "#3B82F6"
ACCENT_HOVER = "#60A5FA"
ACCENT_PRESSED = "#2563EB"
ACCENT_MUTED = "#1D4ED8"
TEXT_PRIMARY = "#E2E8F0"
TEXT_MUTED = "#94A3B8"
DANGER_COLOR = "#EF4444"
SUCCESS_COLOR = "#22C55E"
WARNING_COLOR = "#F59E0B"


def resource_path(relative: str) -> str:
    """Resolve resource paths for both source and PyInstaller bundles."""
    search_roots = []
    if hasattr(sys, "_MEIPASS"):
        search_roots.append(getattr(sys, "_MEIPASS"))
    module_dir = os.path.dirname(os.path.abspath(__file__))
    search_roots.extend([module_dir, os.getcwd()])
    for root in search_roots:
        candidate = os.path.join(root, relative)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(module_dir, relative)


ICON_DIR = resource_path("icons")


class BadgeButton(QPushButton):
    """Push button with a tiny notification dot."""

    def __init__(self, icon: QIcon, tooltip: str, parent: QWidget | None = None):
        super().__init__(icon, "", parent)
        self.setCheckable(True)
        self.setToolTip(tooltip)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._badge = QLabel(self)
        self._badge.setFixedSize(10, 10)
        self._badge.setStyleSheet(
            f"background-color: {WARNING_COLOR}; border-radius: 5px; border: 1px solid {PRIMARY_BG};"
        )
        self._badge.hide()

    def set_badge_visible(self, visible: bool) -> None:
        self._badge.setVisible(visible)

    def has_badge(self) -> bool:
        return self._badge.isVisible()

    def resizeEvent(self, event: QResizeEvent) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        offset = 6
        self._badge.move(self.width() - self._badge.width() - offset, offset)


class ChatBubbleWidget(QWidget):
    """Simple left/right aligned chat bubble used inside the chat list."""

    def __init__(self, sender: str, message: str, bubble_type: str,
                 message_color: str | None = None, parent: QWidget | None = None):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(0)

        bubble = QFrame()
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(12, 8, 12, 8)
        bubble_layout.setSpacing(4)

        sender_label = QLabel(sender)
        sender_label.setStyleSheet("font-size: 12px; font-weight: 600;")
        sender_label.setVisible(bool(sender))

        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_label.setTextFormat(Qt.TextFormat.PlainText)

        palette = {
            "self": (ACCENT_COLOR, TEXT_PRIMARY),
            "other": (CARD_BG, TEXT_PRIMARY),
            "system": (SURFACE_BG, TEXT_MUTED),
        }
        bg_color, fg_color = palette.get(bubble_type, (CARD_BG, TEXT_PRIMARY))

        if bubble_type == "self":
            # Always keep outgoing messages high-contrast regardless of font tags
            message_color = None

        if message_color:
            fg_color = message_color

        if bubble_type == "self":
            layout.addStretch()
            layout.addWidget(bubble)
        elif bubble_type == "system":
            layout.addStretch()
            layout.addWidget(bubble)
            layout.addStretch()
            sender_label.setVisible(False)
        else:
            layout.addWidget(bubble)
            layout.addStretch()

        if bubble_type == "system":
            bubble.setStyleSheet(
                f"background-color: {bg_color}; border: 1px dashed {BORDER_COLOR}; border-radius: 10px;"
            )
        else:
            bubble.setStyleSheet(
                f"background-color: {bg_color}; border-radius: 12px; color: {fg_color};"
            )

        message_label.setStyleSheet(f"color: {fg_color};")
        sender_label.setStyleSheet(f"color: {fg_color};")

        bubble_layout.addWidget(sender_label)
        bubble_layout.addWidget(message_label)
        bubble_layout.addStretch()

class SessionInfoBar(QWidget):

    """Compact header summarizing the active collaboration session."""

    def __init__(self, username: str, session_id: str, server_ip: str, parent: QWidget | None = None):
        super().__init__(parent)

        self.setObjectName("SessionInfoBar")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(20)

        self.avatar_label = QLabel(self)
        self.avatar_label.setFixedSize(42, 42)
        self.avatar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        initials = (username or "").strip()[:2].upper() or "??"
        self.avatar_label.setText(initials)
        self.avatar_label.setObjectName("SessionAvatar")

        info_column = QVBoxLayout()
        info_column.setSpacing(2)

        self.title_label = QLabel(session_id)
        self.title_label.setObjectName("SessionTitle")

        safe_username = username if username else "Guest"
        safe_server_ip = server_ip if server_ip else "Unknown"
        self.subtitle_label = QLabel(f"Signed in as {safe_username} • {safe_server_ip}")
        self.subtitle_label.setObjectName("SessionSubtitle")

        info_column.addWidget(self.title_label)
        info_column.addWidget(self.subtitle_label)

        layout.addWidget(self.avatar_label)
        layout.addLayout(info_column)
        layout.addStretch()

        self.participant_chip = QLabel("Participants —")
        self.participant_chip.setObjectName("SessionParticipantChip")
        self.participant_chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.participant_chip.setFixedHeight(26)
        self.participant_chip.setMinimumWidth(120)
        layout.addWidget(self.participant_chip)

        self.status_pill = QLabel("Connecting…")
        self.status_pill.setObjectName("SessionStatusPill")
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_pill.setFixedHeight(26)
        self.status_pill.setMinimumWidth(120)
        layout.addWidget(self.status_pill)

        self.setStyleSheet(
            f"""
            QWidget#SessionInfoBar {{
                background-color: {SURFACE_BG};
                border-bottom: 1px solid {BORDER_COLOR};
            }}
            QLabel#SessionAvatar {{
                background-color: {ACCENT_MUTED};
                border-radius: 21px;
                color: {TEXT_PRIMARY};
                font-weight: 600;
                font-size: 16px;
            }}
            QLabel#SessionTitle {{
                color: {TEXT_PRIMARY};
                font-size: 16px;
                font-weight: 600;
            }}
            QLabel#SessionSubtitle {{
                color: {TEXT_MUTED};
                font-size: 12px;
            }}
            QLabel#SessionParticipantChip {{
                background-color: {CARD_BG};
                border-radius: 13px;
                color: {TEXT_PRIMARY};
                font-size: 12px;
                font-weight: 500;
                padding: 0 12px;
            }}
            QLabel#SessionStatusPill {{
                background-color: {ACCENT_COLOR};
                border-radius: 13px;
                color: {TEXT_PRIMARY};
                font-size: 12px;
                font-weight: 600;
                padding: 0 12px;
            }}
            """
        )

    def update_status(self, text: str, accent: str = ACCENT_COLOR) -> None:
        self.status_pill.setText(text)
        self.status_pill.setStyleSheet(
            f"background-color: {accent}; border-radius: 13px; color: {TEXT_PRIMARY}; padding: 0 12px; font-weight: 600;"
        )

    def update_participants(self, count: int) -> None:
        if count <= 0:
            label = "No participants"
        elif count == 1:
            label = "1 participant"
        else:
            label = f"{count} participants"
        self.participant_chip.setText(label)

    def update_identity(self, username: str | None = None, session_id: str | None = None, server_ip: str | None = None) -> None:
        if session_id is not None:
            self.title_label.setText(session_id)

        current_text = self.subtitle_label.text()
        if " • " in current_text:
            current_name, current_ip = current_text.replace("Signed in as ", "").split(" • ", maxsplit=1)
        else:
            current_name, current_ip = current_text, server_ip or "Unknown"

        name = username if username is not None else current_name
        ip = server_ip if server_ip is not None else current_ip
        self.subtitle_label.setText(f"Signed in as {name} • {ip}")
        initials = (name or "??").strip()[:2].upper() or "??"
        self.avatar_label.setText(initials)


def _detect_primary_ipv4() -> str | None:
    """Attempt to detect the machine's primary IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return None


def _list_local_ipv4_addresses() -> list[str]:
    """Return a sorted list of non-loopback IPv4 addresses available on the host."""
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET):
            candidate = info[4][0]
            if candidate and candidate != "127.0.0.1":
                addresses.add(candidate)
    except Exception:
        pass

    primary = _detect_primary_ipv4()
    if primary and primary != "127.0.0.1":
        addresses.add(primary)

    if not addresses:
        return ["127.0.0.1"]
    return sorted(addresses)


def resolve_default_server_ip() -> str:
    """Pick a sensible default server IP for the login dialog."""
    env_override = os.environ.get("LAN_COLLAB_SERVER_IP", "").strip()
    if env_override:
        return env_override

    default_config_ip = getattr(config, "DEFAULT_SERVER_IP", "").strip()
    if default_config_ip:
        return default_config_ip

    return _detect_primary_ipv4() or "127.0.0.1"




# --- Robust TCP Messaging ---

def recv_msg(sock: ssl.SSLSocket) -> bytes | None:

    """Receives a TCP message prefixed with its length."""

    if sock.fileno() == -1:

        logging.warning("recv_msg: Socket is already closed.")

        return None

    try:

        raw_msglen = sock.recv(config.TCP_MSG_HEADER_SIZE)

        if not raw_msglen:

            logging.info("recv_msg: Connection closed by peer (received empty header).")

            return None

        msglen = struct.unpack('>I', raw_msglen)[0]

        if msglen > 10 * 1024 * 1024: # Max 10MB sanity check

             logging.error(f"recv_msg: Excessive message length declared: {msglen}. Closing connection.")

             raise ConnectionError("Excessive message length received.")

        data = b''

        while len(data) < msglen:

            if sock.fileno() == -1:

                logging.warning("recv_msg: Socket closed during message receive.")

                return None

            packet = sock.recv(msglen - len(data))

            if not packet:

                logging.warning("recv_msg: Connection closed unexpectedly mid-message.")

                return None

            data += packet

        return data

    except (OSError, ssl.SSLError, ConnectionError) as e:

        logging.error(f"recv_msg: Socket error during recv: {e}")

        return None

    except struct.error as e:

        logging.error(f"recv_msg: Error unpacking length. Header: {raw_msglen.hex() if 'raw_msglen' in locals() else 'N/A'}. Error: {e}")

        return None

    except Exception as e:

       logging.error(f"recv_msg: Unexpected error: {e}", exc_info=True)

       return None



def send_msg(sock: ssl.SSLSocket, msg: bytes):

    """Prefixes a TCP message with its length and sends it."""

    try:

        if sock.fileno() == -1:

            raise OSError("Socket is closed")

        msg_len_bytes = struct.pack('>I', len(msg))

        sock.sendall(msg_len_bytes + msg)

    except (OSError, ssl.SSLError) as e:

        logging.error(f"send_msg: Socket error during sendall: {e}")

        raise # Re-raise to be caught by safe_send_tcp

    except Exception as e:

        logging.error(f"send_msg: Unexpected error: {e}", exc_info=True)

        raise # Re-raise



# --- Audio Compression ---

def encode_ulaw(audio_data, mu=255):

    """Encodes 16-bit PCM audio data to 8-bit mu-law."""

    audio_float = audio_data.astype(np.float32) / 32768.0

    magnitude = np.log1p(mu * np.abs(audio_float)) / np.log1p(mu)

    compressed = np.sign(audio_float) * magnitude

    return ((compressed + 1) / 2 * mu).astype(np.uint8)



def decode_ulaw(encoded_data, mu=255):

    """Decodes 8-bit mu-law data back to 16-bit PCM."""

    encoded_float = (encoded_data.astype(np.float32) / mu * 2) - 1

    magnitude = (1 / mu) * ((1 + mu)**np.abs(encoded_float) - 1)

    expanded_float = np.sign(encoded_float) * magnitude

    return (expanded_float * 32768.0).astype(np.int16)

class VideoWidget(QWidget):
    """Widget to display a video frame with name and status icons."""
    def __init__(self, name="Participant", parent=None):
        super().__init__(parent)
        self.is_muted = False
        self.is_video_on = True
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        self.widget_name = name
        self.initial = name[0].upper() if name else "?"

        # Base styles
        self.style_video_on = f"background-color: {CARD_BG}; border: 1px solid {BORDER_COLOR}; border-radius: 8px;"
        self.style_video_off_base = f"background-color: {CARD_BG}; color: {TEXT_PRIMARY}; border: 1px solid {BORDER_COLOR}; border-radius: 8px;"
        self.current_font_style = "" # Will be set by update_font_size
        
        self.name_label_font = QFont()
        self.name_label_font.setBold(True)
        
        # Main video/initial label
        self.video_label = QLabel(self.initial)
        self.video_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.video_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.video_label.setScaledContents(False)
        self.video_label.setMinimumSize(180, 120)

        # --- FIX: Make labels children of 'self' (the VideoWidget), NOT 'self.video_label' ---

        # Name label (for bottom-right)
        self.name_label = QLabel(name, self) # <-- FIXED
        self.name_label.setStyleSheet(f"background-color: rgba(15, 23, 42, 185); color: {TEXT_PRIMARY}; padding: 4px 8px; border-radius: 6px; margin: 5px;")
        self.name_label.setFont(self.name_label_font) 
        self.name_label.show() # Always visible

        # Status icon (for bottom-left)
        self.status_icon_label = QLabel(self) # <-- FIXED
        self.status_icon_label.setFixedSize(34, 34)
        self.status_icon_label.setStyleSheet("background-color: transparent; margin: 5px;")
        self.status_icon_label.show() # Always visible

        # Main layout ONLY contains the video_label
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.video_label)

        self.speaking_effect = QGraphicsDropShadowEffect(self)
        self.speaking_effect.setOffset(0, 0)
        self.speaking_effect.setBlurRadius(12)
        self.speaking_effect.setColor(QColor(BORDER_COLOR))
        self.setGraphicsEffect(self.speaking_effect)

        self._glow_anim = QPropertyAnimation(self.speaking_effect, b"blurRadius", self)
        self._glow_anim.setDuration(400)
        self._glow_anim.setStartValue(12)
        self._glow_anim.setEndValue(28)
        self._glow_anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

        self.current_pixmap = None
        self.set_speaking(False)
        self.update_font_size()
        
    def _position_overlays(self):
        """Helper function to move name and status labels to corners."""
        # Use self.width() and self.height() which are the widget's full size
        widget_width = self.width() 
        widget_height = self.height()
        margin = 5 # 5px margin from the edges

        # Position Name Label (Bottom-Right)
        name_size = self.name_label.sizeHint() 
        name_x = widget_width - name_size.width() - margin
        name_y = widget_height - name_size.height() - margin
        self.name_label.move(int(name_x), int(name_y))
        self.name_label.raise_() 

        # Position Status Icon (Bottom-Left)
        icon_size = self.status_icon_label.size()
        icon_x = margin
        icon_y = widget_height - icon_size.height() - margin
        self.status_icon_label.move(int(icon_x), int(icon_y))
        self.status_icon_label.raise_() 

    def update_font_size(self):
        """Calculates and sets the font size for the initial VIA STYLESHEET."""
        if self.current_pixmap:
            self.video_label.setFont(QFont()) 
            return 

        font_size_px = int(min(self.video_label.width(), self.video_label.height()) * 0.3) # 50%
        if font_size_px < 1: return
        
        self.current_font_style = f"font-size: {font_size_px}px; font-weight: bold;"
        
        self.video_label.setStyleSheet(self.style_video_off_base + self.current_font_style)
        
        self.name_label.setFont(self.name_label_font)

    def set_frame(self, frame: np.ndarray):
        """Updates the widget with a new video frame (numpy array)."""
        try:
            if frame is None or frame.size == 0:
                self.clear_frame()
                return

            if self.current_pixmap is None: 
                self.video_label.setText("") 
                self.video_label.setStyleSheet(self.style_video_on) 
                self.video_label.setFont(QFont()) 
            
            h, w, ch = frame.shape
            frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            if not frame_rgb.flags['C_CONTIGUOUS']:
                frame_rgb = np.ascontiguousarray(frame_rgb)
            qt_image = QImage(frame_rgb.data, w, h, ch * w, QImage.Format.Format_RGB888)
            self.current_pixmap = QPixmap.fromImage(qt_image.copy())
            self.update_pixmap() 

        except Exception as e:
            logging.error(f"Error in VideoWidget({self.widget_name}).set_frame: {e}", exc_info=True)
            self.clear_frame()

    def clear_frame(self):
        """Clears the video frame and displays the user's initial."""
        logging.debug(f"VideoWidget '{self.widget_name}': clear_frame called.")
        self.current_pixmap = None
        self.video_label.clear() 
        
        self.video_label.setText(self.initial) 
        self.update_font_size() 
        
        self.video_label.repaint()

    def set_speaking(self, is_speaking: bool):
        """Changes the border color to indicate speaking status."""
        border_color = ACCENT_COLOR if is_speaking else BORDER_COLOR
        border_width = "2px" if is_speaking else "1px"
        
        if hasattr(self, "speaking_effect"):
            self.speaking_effect.setColor(QColor(border_color))
            if is_speaking:
                self._glow_anim.setDirection(QPropertyAnimation.Direction.Forward)
                self._glow_anim.start()
            else:
                self._glow_anim.stop()
                self.speaking_effect.setBlurRadius(12)

        if self.current_pixmap:
            self.style_video_on = f"background-color: {CARD_BG}; border: {border_width} solid {border_color}; border-radius: 8px;"
            self.video_label.setStyleSheet(self.style_video_on)
        else:
            self.style_video_off_base = f"background-color: {CARD_BG}; color: {TEXT_PRIMARY}; border: {border_width} solid {border_color}; border-radius: 8px;"
            self.video_label.setStyleSheet(self.style_video_off_base + self.current_font_style)

    def update_status(self, is_muted=None, is_video_on=None):
        """Updates the status icon (mic/video off) based on state."""
        if is_muted is not None:
            self.is_muted = is_muted
        if is_video_on is not None:
            self.is_video_on = is_video_on
        
        if is_video_on is False and self.current_pixmap is not None:
             self.clear_frame()
             
        icon_path = None
        if self.is_video_on is False:
            icon_path = os.path.join(ICON_DIR, "video-off.svg")
        elif self.is_muted is True:
            icon_path = os.path.join(ICON_DIR, "mic-off.svg")

        if icon_path:
            if os.path.exists(icon_path):
                try:
                    pixmap = QPixmap(icon_path)
                    if not pixmap.isNull():
                        self.status_icon_label.setPixmap(pixmap.scaled(24, 24, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
                    else:
                        logging.warning(f"Failed to load icon (null pixmap): {icon_path}")
                        self.status_icon_label.clear()
                except Exception as e:
                    logging.error(f"Error loading icon {icon_path}: {e}")
                    self.status_icon_label.clear()
            else:
                logging.warning(f"Icon file not found: {icon_path}")
                self.status_icon_label.clear()
        else:
            self.status_icon_label.clear()

    def update_pixmap(self):
        """Scales the current pixmap to fit the label size."""
        if self.current_pixmap and not self.current_pixmap.isNull():
            scaled_pixmap = self.current_pixmap.scaled(
                self.video_label.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation
            )
            self.video_label.setPixmap(scaled_pixmap)

    def resizeEvent(self, event: QResizeEvent):
        """Handles widget resize events to rescale video AND position overlays."""
        super().resizeEvent(event)
        
        # Call the helper function to position labels
        self._position_overlays() 

        # Now, update the main content (video or initial)
        if self.current_pixmap:
            self.update_pixmap()
        else:
            self.update_font_size()

class PresenterWidget(QWidget):

    """Widget for presenter view (main screen share + picture-in-picture self-view)."""

    def __init__(self, self_view_widget, parent=None):

        super().__init__(parent)

        self.self_view = self_view_widget

        self.screen_share_widget = VideoWidget("Screen Share") # Main display area

        layout = QVBoxLayout(self)

        layout.setContentsMargins(0,0,0,0)

        layout.addWidget(self.screen_share_widget)



        # Make self-view a child to overlay it

        self.self_view.setParent(self)

        self.self_view.setFixedSize(180, 120) # Size for picture-in-picture



    def resizeEvent(self, event: QResizeEvent):

        """Moves the self-view to the bottom right on resize."""

        super().resizeEvent(event)

        margin = 10

        new_x = self.width() - self.self_view.width() - margin

        new_y = self.height() - self.self_view.height() - margin

        self.self_view.move(new_x, new_y)



class Communicate(QObject):

    """Signal bridge for inter-thread communication."""

    msg_signal = pyqtSignal(str)

    user_list_signal = pyqtSignal(list)

    self_video_frame_signal = pyqtSignal(np.ndarray)

    video_data_signal = pyqtSignal(bytes, bytes) # (ptype, data)

    audio_data_signal = pyqtSignal(bytes)

    connection_failed_signal = pyqtSignal()

    username_taken_signal = pyqtSignal()

    json_command_signal = pyqtSignal(dict)

    processed_frame_signal = pyqtSignal(bytes, str, np.ndarray) # (ptype, username, frame)



class LoginDialog(QDialog):

    """Simple dialog to get server IP, username, and session ID."""

    def __init__(self, default_server_ip: str, parent=None):

        super().__init__(parent)

        self.setWindowTitle("Connect to Server")

        self.server_ip_input = QLineEdit(default_server_ip)
        self.server_ip_input.setPlaceholderText(default_server_ip or "Server IP")
        self.username_input = QLineEdit("Guest")
        self.session_id_input = QLineEdit("main_room")



        layout = QFormLayout(self)

        layout.addRow("Server IP:", self.server_ip_input)

        layout.addRow("Session ID:", self.session_id_input)

        layout.addRow("Username:", self.username_input)


        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)

        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)



    def get_details(self):

        """Returns the entered details."""

        return self.server_ip_input.text(), self.username_input.text(), self.session_id_input.text()





# --- Main Application Window ---



class ChatWindow(QWidget):

    """The main application window, managing UI, network, and media streams."""



    def __init__(self, server_ip, username, session_id):

        super().__init__()

        self.server_ip = server_ip
        self.username = username
        self.session_id = session_id

        self.is_running = True



        # Network Sockets

        self.tcp_socket : ssl.SSLSocket | None = None

        self.udp_socket : socket.socket | None = None



        # Media Capture/Playback

        self.video_cap = None

        self.p_audio = None

        self.audio_stream_in = None

        self.audio_stream_out = None
        self.audio_send_thread = None
        self.audio_playback_thread = None



        # UI State & Widgets

        self.video_widgets = {} # {username: VideoWidget}

        self.audio_activity_timers = {} # {username: QTimer}

        self.is_video_on, self.is_muted = False, True

        self.is_screen_sharing, self.was_streaming = False, False

        self.selected_monitor = None

        self.current_screen_sharer = None # Username of the current sharer

        self.self_view_widget = VideoWidget(self.username) # Dedicated widget for self-view

        self.speaker_name_timer = QTimer(self); self.speaker_name_timer.setSingleShot(True)

        self.speaker_name_timer.timeout.connect(self.clear_speaker_name)

        self.current_page_index = 0

        self.chat_has_unread = False
        self.files_have_unread = False
        self.known_shared_file_keys = set()

        self.available_output_devices = []
        self.audio_output_device_index = None
        self.audio_output_device_name = ""
        self.share_system_audio = False
        self.system_audio_queue = None
        self.system_audio_stream = None
        self.system_audio_device = None
        self.system_audio_thread = None
        self.system_audio_action = None
        self.audio_device_actions = {}
        self.audio_action_group = None
        self.system_audio_supported = bool(
            sd and platform.system().lower().startswith("win") and hasattr(sd, "WasapiSettings")
        )
        self.username_audio_header = self.username.encode('utf-8').ljust(config.USERNAME_HEADER_LENGTH)

       

        # --- NEW: Side Panel State ---

        self.side_panel_width = 300 # Width of the slide-out panel

        self.side_panel_animation = None

        self.is_side_panel_visible = False

        self.current_side_panel_tab = -1 # -1=hidden, 0=Users, 1=Files, 2=Chat

        # --- End New ---



        # File Sharing State

        self.my_shared_files = [] # List of {"filepath": ..., "filename": ..., "filesize": ...}

        self.incoming_files = {} # {transfer_id: {"filepath": ..., "file_handle": ..., "filesize": ..., "progress": ...}}



        # Threading & Queues

        self.audio_playback_queue = queue.Queue(maxsize=config.AUDIO_JITTER_MAX_CHUNKS * 4) # Bounded jitter buffer

        self.video_processing_queue = queue.Queue() # (ptype, username, raw_frame_data)

        self.tcp_send_lock = threading.Lock() # Lock for safe TCP sends

        self.is_tcp_share = False # Track current screen share mode

        

        # Communication Signals

        self.comm = Communicate()

        self.comm.msg_signal.connect(self.append_message)

        self.comm.user_list_signal.connect(self.update_user_list_and_grid)

        self.comm.self_video_frame_signal.connect(self.update_self_video_frame)

        self.comm.video_data_signal.connect(self.handle_received_video_data)

        self.comm.audio_data_signal.connect(self.handle_received_audio_data)

        self.comm.connection_failed_signal.connect(self.handle_connection_failure)

        self.comm.username_taken_signal.connect(self.handle_username_taken)

        self.comm.json_command_signal.connect(self.handle_json_command)

        self.comm.processed_frame_signal.connect(self.handle_processed_frame)



        # Initialization

        self.init_ui()

        self.init_audio_output()



        # Start background threads

        threading.Thread(target=self.connect_to_server, daemon=True).start()

        threading.Thread(target=self.video_processing_loop, daemon=True).start()

        logging.info("ChatWindow initialized.")



    # --- UI Initialization ---

    def init_ui(self):
        """Sets up the main UI layout and widgets."""
        self.setWindowTitle(f"LAN Collab Suite - {self.username} @ {self.session_id}")
        self.resize(1200, 700)

        # --- MODIFIED: Main layout is now QVBoxLayout (Top Bar + Main Area) ---
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0) # No margins
        main_layout.setSpacing(0) # No spacing between top bar and main area

        # --- NEW: Top Bar ---
        self.top_bar = self.setup_top_bar()
        main_layout.addWidget(self.top_bar)

        # --- MODIFIED: Sliding side panel (created here, managed in resizeEvent) ---
        self.side_panel = self.setup_side_panel()
        self.side_panel_animation = QPropertyAnimation(self.side_panel, b"geometry")
        self.side_panel_animation.setDuration(250) # Animation speed
        # Start panel off-screen
        QTimer.singleShot(0, self.initial_resize) # Position panel after window is shown
        
        # --- MODIFIED: Left Panel is now the Main Panel ---
        # It contains the video grid/presenter view and the bottom control bar
        main_video_panel = QWidget()
        main_video_layout = QVBoxLayout(main_video_panel)
        main_video_layout.setContentsMargins(5, 5, 5, 5) # Add some padding around video
        main_video_layout.setSpacing(5)
        
        # --- CHANGES START HERE ---

        # 1. self.view_stack and self.gallery_widget are REMOVED.
        
        # 2. We now just create the gallery_stack and pagination_layout
        self.gallery_stack = QStackedWidget() # Holds pages of grids
        self.pagination_layout = self.setup_pagination_controls() # 3. Stored as self.pagination_layout

        # Presenter View Setup (still needed for page 0)
        self.presenter_view = PresenterWidget(self.self_view_widget)

        # 4. We add the gallery_stack and pagination_layout directly
        main_video_layout.addWidget(self.gallery_stack, 1) # Video area takes most space
        main_video_layout.addLayout(self.pagination_layout) # Pagination is added *after* the stack

        # --- CHANGES END HERE ---

        # --- MODIFIED: Control Bar is added to the *main video panel* ---
        self.setup_control_bar()
        main_video_layout.addWidget(self.control_bar)

        # Add the main video panel to the main layout
        main_layout.addWidget(main_video_panel, 1)

        # Connect chat send actions (widgets are now in side panel, but still exist)
        self.send_button.clicked.connect(self.send_chat_message)
        self.message_input.returnPressed.connect(self.send_chat_message)

        self.update_view_layout() # Initial layout setup

       

    def setup_top_bar(self) -> QWidget:

        """Creates a modern top bar with session summary and quick toggles."""

        top_bar = QWidget()
        top_bar.setObjectName("TopBar")

        outer_layout = QVBoxLayout(top_bar)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self.session_info_bar = SessionInfoBar(self.username, self.session_id, self.server_ip, top_bar)
        outer_layout.addWidget(self.session_info_bar)
        self.session_info_bar.update_participants(1)

        controls_row = QWidget(top_bar)
        controls_row.setObjectName("TopControlsRow")
        controls_row.setStyleSheet(
            f"background-color: {PANEL_BG}; border-bottom: 1px solid {BORDER_COLOR};"
        )

        controls_layout = QHBoxLayout(controls_row)
        controls_layout.setContentsMargins(16, 6, 16, 6)
        controls_layout.setSpacing(8)
        controls_layout.addStretch()

        STYLE = f"""
            QPushButton {{
                background-color: rgba(255, 255, 255, 0.05); border: none;
                padding: 6px; min-width: 36px; min-height: 36px;
                border-radius: 10px; color: {TEXT_PRIMARY};
            }}
            QPushButton:hover {{ background-color: rgba(59, 130, 246, 0.18); }}
            QPushButton:pressed {{ background-color: rgba(37, 99, 235, 0.25); }}
            QPushButton:checked {{ background-color: {ACCENT_COLOR}; color: {TEXT_PRIMARY}; }}
        """

        icon_folder = ICON_DIR

        self.users_toggle_btn = BadgeButton(QIcon(os.path.join(icon_folder, "users.svg")), "Show Participants")
        self.users_toggle_btn.setIconSize(QSize(22, 22))
        self.users_toggle_btn.setStyleSheet(STYLE)
        self.users_toggle_btn.clicked.connect(lambda: self.toggle_side_panel(0))

        self.files_toggle_btn = BadgeButton(QIcon(os.path.join(icon_folder, "folder.svg")), "Show Shared Files")
        self.files_toggle_btn.setIconSize(QSize(22, 22))
        self.files_toggle_btn.setStyleSheet(STYLE)
        self.files_toggle_btn.clicked.connect(lambda: self.toggle_side_panel(1))

        self.chat_toggle_btn = BadgeButton(QIcon(os.path.join(icon_folder, "message-square.svg")), "Show Chat")
        self.chat_toggle_btn.setIconSize(QSize(22, 22))
        self.chat_toggle_btn.setStyleSheet(STYLE)
        self.chat_toggle_btn.clicked.connect(lambda: self.toggle_side_panel(2))

        self.top_toggle_buttons = [self.users_toggle_btn, self.files_toggle_btn, self.chat_toggle_btn]

        controls_layout.addWidget(self.users_toggle_btn)
        controls_layout.addWidget(self.files_toggle_btn)
        controls_layout.addWidget(self.chat_toggle_btn)

        outer_layout.addWidget(controls_row)
        return top_bar



    def setup_side_panel(self) -> QWidget:
        """Creates the sliding side panel with tabs for Users, Files, and Chat."""

        # Main panel container

        side_panel = QFrame(self) # Use QFrame for styling

        side_panel.setFrameShape(QFrame.Shape.NoFrame)

        side_panel.setStyleSheet(f"""
            QFrame {{ background-color: {PANEL_BG}; border-left: 1px solid {BORDER_COLOR}; color: {TEXT_PRIMARY}; }}
            QTabWidget::pane {{ border: none; padding: 5px; }}
            QTabBar::tab {{
                background-color: {PANEL_BG}; border: 1px solid {BORDER_COLOR};
                border-bottom: none; padding: 8px 16px; color: {TEXT_MUTED};
            }}
            QTabBar::tab:selected {{ background-color: {CARD_BG}; border-bottom: 1px solid {CARD_BG}; color: {TEXT_PRIMARY}; }}
            QTabBar::tab:!selected:hover {{ background-color: {CARD_BG}; color: {TEXT_PRIMARY}; }}
        """)

        panel_layout = QVBoxLayout(side_panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(0)

        self.side_panel_tabs = QTabWidget()
        self.side_panel_tabs.currentChanged.connect(self.handle_side_tab_change)

       

        # --- Tab 1: Users ---

        user_tab = QWidget()

        user_tab_layout = QVBoxLayout(user_tab)

        user_tab_layout.addWidget(QLabel("Connected Users"))

        self.user_list_widget = QListWidget()

        user_tab_layout.addWidget(self.user_list_widget)

        self.side_panel_tabs.addTab(user_tab, "Participants")



        # --- Tab 2: Files ---

        file_tab = QWidget()

        file_tab_layout = QVBoxLayout(file_tab)

        file_tab_layout.addWidget(QLabel("Shared Files"))

        self.file_list_widget = QListWidget()

        self.file_list_widget.itemDoubleClicked.connect(self.download_selected_file) # Double-click to download

        file_tab_layout.addWidget(self.file_list_widget, 1) # Takes available vertical space



        file_buttons_layout = QHBoxLayout()

        self.share_file_btn = QPushButton("Share File(s)")

        self.share_file_btn.clicked.connect(self.select_files_to_share)

        self.download_btn = QPushButton("Download")

        self.download_btn.clicked.connect(self.download_selected_file)

        file_buttons_layout.addWidget(self.share_file_btn)

        file_buttons_layout.addWidget(self.download_btn)

        file_tab_layout.addLayout(file_buttons_layout)



        self.progress_bar = QProgressBar()

        self.progress_bar.setVisible(False)

        self.progress_bar.setTextVisible(True)

        self.progress_bar.setFormat("%p% - Downloading...")

        file_tab_layout.addWidget(self.progress_bar)

        self.side_panel_tabs.addTab(file_tab, "Files")

       

        # --- Tab 3: Chat ---

        chat_tab = QWidget()

        chat_tab_layout = QVBoxLayout(chat_tab)

        self.chat_list = QListWidget()
        self.chat_list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.chat_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.chat_list.setSpacing(6)
        chat_tab_layout.addWidget(self.chat_list, 1)



        message_layout = QHBoxLayout()

        self.message_input = QLineEdit()

        self.message_input.setPlaceholderText("Type a message...")

        self.send_button = QPushButton("Send")

        message_layout.addWidget(self.message_input, 1)

        message_layout.addWidget(self.send_button)

        chat_tab_layout.addLayout(message_layout)

        self.side_panel_tabs.addTab(chat_tab, "Chat")



        panel_layout.addWidget(self.side_panel_tabs)

        return side_panel

       

    def setup_pagination_controls(self) -> QHBoxLayout:

        """Creates the Prev/Next page buttons and label."""

        pagination_controls = QHBoxLayout()

        icon_folder = ICON_DIR

        left_icon_path = os.path.join(icon_folder, "chevron-left.svg")
        right_icon_path = os.path.join(icon_folder, "chevron-right.svg")

        left_icon = QIcon(left_icon_path) if os.path.exists(left_icon_path) else QIcon()
        right_icon = QIcon(right_icon_path) if os.path.exists(right_icon_path) else QIcon()

        self.prev_page_btn = QPushButton(left_icon, "< Prev")
        self.prev_page_btn.clicked.connect(self.prev_page)

        self.next_page_btn = QPushButton(right_icon, "Next >")
        self.next_page_btn.clicked.connect(self.next_page)

        self.page_label = QLabel("Page 1 / 1")
        self.page_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        pagination_controls.addWidget(self.prev_page_btn)
        pagination_controls.addStretch()
        pagination_controls.addWidget(self.page_label)
        pagination_controls.addStretch()
        pagination_controls.addWidget(self.next_page_btn)

        return pagination_controls



    def setup_control_bar(self):
        """Creates the bottom control bar with media/leave buttons."""

        self.control_bar = QWidget()
        self.control_bar.setObjectName("ControlBar")

        control_layout = QHBoxLayout(self.control_bar)
        control_layout.setContentsMargins(32, 18, 32, 18)
        control_layout.setSpacing(24)
        control_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.control_layout = control_layout

        control_style = f"""
            QWidget#ControlBar {{ background-color: {SURFACE_BG}; border-top: 1px solid {BORDER_COLOR}; }}
            QWidget#ControlBar QPushButton {{ background-color: {CARD_BG}; border: none; color: {TEXT_PRIMARY}; border-radius: 32px; }}
            QWidget#ControlBar QPushButton:hover {{ background-color: {ACCENT_MUTED}; }}
            QWidget#ControlBar QPushButton:pressed {{ background-color: {ACCENT_PRESSED}; }}
            QWidget#ControlBar QPushButton:checked {{ background-color: {ACCENT_COLOR}; color: {TEXT_PRIMARY}; }}
            QWidget#ControlBar QPushButton:disabled {{ background-color: {BORDER_COLOR}; color: {TEXT_MUTED}; }}
        """
        self.control_bar.setStyleSheet(control_style)

        icon_folder = ICON_DIR
        mic_off_path = os.path.join(icon_folder, "mic-off.svg")
        video_off_path = os.path.join(icon_folder, "video-off.svg")
        monitor_path = os.path.join(icon_folder, "monitor.svg")
        phone_off_path = os.path.join(icon_folder, "phone-off.svg")

        mic_off_icon = QIcon(mic_off_path) if os.path.exists(mic_off_path) else QIcon()
        video_off_icon = QIcon(video_off_path) if os.path.exists(video_off_path) else QIcon()
        monitor_icon = QIcon(monitor_path) if os.path.exists(monitor_path) else QIcon()
        phone_off_icon = QIcon(phone_off_path) if os.path.exists(phone_off_path) else QIcon()

        self.mic_btn = QPushButton(mic_off_icon, "")
        self.mic_btn.setCheckable(True)
        self.mic_btn.setChecked(True)  # Start muted
        self.mic_btn.setIconSize(QSize(28, 28))
        self.mic_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mic_btn.clicked.connect(self.toggle_mic)

        self.video_btn = QPushButton(video_off_icon, "")
        self.video_btn.setCheckable(True)
        self.video_btn.setChecked(True)  # Start video off
        self.video_btn.setIconSize(QSize(28, 28))
        self.video_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.video_btn.clicked.connect(self.toggle_video)

        self.screen_btn = QPushButton(monitor_icon, "")
        self.screen_btn.setCheckable(True)
        self.screen_btn.setIconSize(QSize(28, 28))
        self.screen_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.screen_btn.clicked.connect(self.toggle_screen_share)

        self.leave_btn = QPushButton(phone_off_icon, "")
        self.leave_btn.setIconSize(QSize(28, 28))
        self.leave_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.leave_btn.clicked.connect(self.close)
        self.leave_btn.setStyleSheet(
            f"QPushButton {{ background-color: {DANGER_COLOR}; color: {TEXT_PRIMARY}; border-radius: 32px; }}"
            f"QPushButton:hover {{ background-color: #f87171; }}"
            f"QPushButton:pressed {{ background-color: #b91c1c; }}"
        )

        control_layout.addStretch()
        control_layout.addWidget(self._wrap_control_button(self.mic_btn, "mic_state_label", "Muted"))
        control_layout.addWidget(self._wrap_control_button(self.video_btn, "video_state_label", "Video Off"))
        control_layout.addWidget(self._wrap_control_button(self.screen_btn, "share_state_label", "Share"))
        control_layout.addSpacing(32)
        control_layout.addWidget(self._wrap_control_button(self.leave_btn, "leave_state_label", "Leave"))
        control_layout.addStretch()

        self.refresh_control_labels()

    def _wrap_control_button(self, button: QPushButton, label_attr: str, initial_text: str) -> QWidget:
        """Creates a vertical stack containing a circular button and its caption."""

        container = QWidget(self.control_bar)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(8)

        button.setFixedSize(64, 64)
        layout.addWidget(button, alignment=Qt.AlignmentFlag.AlignCenter)

        label = QLabel(initial_text, container)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet(f"color: {TEXT_MUTED}; font-size: 12px; font-weight: 600;")
        layout.addWidget(label)

        setattr(self, label_attr, label)
        return container

    def refresh_control_labels(self):
        """Updates the text captions under the control bar buttons."""

        if hasattr(self, "mic_state_label"):
            self.mic_state_label.setText("Muted" if self.is_muted else "Mic On")

        if hasattr(self, "video_state_label"):
            self.video_state_label.setText("Video On" if self.is_video_on else "Video Off")

        if hasattr(self, "share_state_label"):
            if self.is_screen_sharing:
                share_text = "Sharing"
            elif self.current_screen_sharer and self.current_screen_sharer != self.username:
                share_text = "Viewing"
            else:
                share_text = "Share"
            self.share_state_label.setText(share_text)

        if hasattr(self, "leave_state_label"):
            self.leave_state_label.setText("Leave")

   

    # --- REMOVED setup_right_panel ---

    # Its contents are now in setup_side_panel()

   

    # --- NEW: Sizing and Animation Methods ---

    def initial_resize(self):

        """Called once to set the initial off-screen position of the side panel."""

        if not self.top_bar: return

        top_bar_height = self.top_bar.height()

        self.side_panel.setGeometry(self.width(), top_bar_height, self.side_panel_width, self.height() - top_bar_height)

        self.side_panel.hide() # Hide it initially



    def resizeEvent(self, event: QResizeEvent):
        """Handles widget resize events to rescale the video AND reposition the side panel."""
        super().resizeEvent(event)
        
        # Reposition the side panel based on its visibility state
        if not hasattr(self, 'top_bar') or not self.top_bar: return # Avoid errors during init
        
        top_bar_height = self.top_bar.height()
        
        # Stop any running animation to prevent conflicts
        if self.side_panel_animation and self.side_panel_animation.state() == QPropertyAnimation.State.Running:
            self.side_panel_animation.stop()

        if self.is_side_panel_visible:
            self.side_panel.setGeometry(
                self.width() - self.side_panel_width,
                top_bar_height,
                self.side_panel_width,
                self.height() - top_bar_height
            )
            self.side_panel.raise_()
        else:
            self.side_panel.setGeometry(
                self.width(), # Off-screen
                top_bar_height,
                self.side_panel_width,
                self.height() - top_bar_height
            )





    # Inside ChatWindow class

    def toggle_side_panel(self, tab_index: int):
        """Animates the side panel in or out."""
        # --- ADD THIS LOGGING LINE FOR DEBUGGING ---
        logging.debug(f"toggle_side_panel called with tab_index: {tab_index}")
        # --- END ADDITION ---

        # Stop any previous animation
        if self.side_panel_animation.state() == QPropertyAnimation.State.Running:
            self.side_panel_animation.stop()
           
        # Clear 'finished' signals to avoid calling hide() prematurely
        try:
            self.side_panel_animation.finished.disconnect()
        except TypeError:
            pass # No connection to disconnect

        top_bar_height = self.top_bar.height()
        current_geo = self.side_panel.geometry()
       
        # Define target geometries
        target_geo_visible = QRect(self.width() - self.side_panel_width, top_bar_height, self.side_panel_width, self.height() - top_bar_height)
        target_geo_hidden = QRect(self.width(), top_bar_height, self.side_panel_width, self.height() - top_bar_height)

        # Uncheck all buttons
        for i, btn in enumerate(self.top_toggle_buttons):
            if i != tab_index:
                btn.setChecked(False)

        if not self.is_side_panel_visible:
            # --- SHOW PANEL ---
            self.side_panel_tabs.setCurrentIndex(tab_index)
            self.side_panel.show() # Show before animating
           
            # --- THIS IS THE FIX ---
            self.side_panel.raise_()
            # --- END FIX ---
           
            self.side_panel_animation.setStartValue(target_geo_hidden)
            self.side_panel_animation.setEndValue(target_geo_visible)
           
            self.is_side_panel_visible = True
            self.current_side_panel_tab = tab_index
            self.top_toggle_buttons[tab_index].setChecked(True)
           
        else: # Panel is already visible
            if tab_index == self.current_side_panel_tab:
                # --- HIDE PANEL (Clicked same button) ---
                self.side_panel_animation.setStartValue(target_geo_visible)
                self.side_panel_animation.setEndValue(target_geo_hidden)
                # Hide the widget *after* animation finishes
                self.side_panel_animation.finished.connect(self.side_panel.hide)
               
                self.is_side_panel_visible = False
                self.current_side_panel_tab = -1
                self.top_toggle_buttons[tab_index].setChecked(False)

            else:
                # --- SWITCH TAB (Clicked different button) ---
                self.side_panel_tabs.setCurrentIndex(tab_index)
                self.current_side_panel_tab = tab_index
                self.top_toggle_buttons[tab_index].setChecked(True)
                # No animation needed, just return
                return

        self.side_panel_animation.start()


    def handle_side_tab_change(self, index: int) -> None:
        """Keeps toggle buttons and unread badges aligned with the active tab."""
        self.current_side_panel_tab = index

        for i, button in enumerate(self.top_toggle_buttons):
            button.setChecked(self.is_side_panel_visible and i == index)

        if index == 2:
            self.chat_has_unread = False
            self.chat_toggle_btn.set_badge_visible(False)
        elif index == 1:
            self.files_have_unread = False
            self.files_toggle_btn.set_badge_visible(False)


    # --- View & Layout Management ---

    def prev_page(self):

        """Switches to the previous page in the gallery view."""

        if self.current_page_index > 0:

            self.current_page_index -= 1

            self.update_pagination_controls()



    def next_page(self):

        """Switches to the next page in the gallery view."""

        if self.current_page_index < self.gallery_stack.count() - 1:

            self.current_page_index += 1

            self.update_pagination_controls()



    def update_pagination_controls(self):
        """Updates the pagination button states and label."""
        num_pages_total = self.gallery_stack.count()
        has_presenter_page = self.gallery_stack.widget(0) == self.presenter_view

        # Show controls if there's more than one page total
        is_visible = num_pages_total > 1
        self.prev_page_btn.setVisible(is_visible)
        self.next_page_btn.setVisible(is_visible)
        self.page_label.setVisible(is_visible)

        if is_visible:
            # Enable/disable buttons
            self.prev_page_btn.setEnabled(self.current_page_index > 0)
            self.next_page_btn.setEnabled(self.current_page_index < num_pages_total - 1)

            # --- FIX: Smart Page Labels ---
            if has_presenter_page:
                if self.current_page_index == 0:
                    self.page_label.setText("Screen Share")
                else:
                    # Show gallery page numbers (e.g., "Page 1 / 2")
                    gallery_page = self.current_page_index
                    gallery_total = num_pages_total - 1
                    self.page_label.setText(f"Page {gallery_page} / {gallery_total}")
            else:
                # Normal gallery paging
                self.page_label.setText(f"Page {self.current_page_index + 1} / {num_pages_total}")

        self.gallery_stack.setCurrentIndex(self.current_page_index)


    def _build_gallery_grid(self, grid_layout: QGridLayout, participants: list):

        """Populates a QGridLayout with VideoWidgets."""

        num = len(participants)

        if num == 0: return



        # Calculate grid dimensions (prefer wider over taller)

        cols = math.ceil(math.sqrt(num))

        rows = math.ceil(num / cols)



        # Clear existing widgets/spacers from the grid
        while (item := grid_layout.takeAt(0)) is not None:
            widget = item.widget()
            if widget:
                widget.setParent(None)

        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.setHorizontalSpacing(12)
        grid_layout.setVerticalSpacing(12)

        # Add participants to the grid
        p_index = 0
        for r in range(rows):
            grid_layout.setRowStretch(r, 1)
            for c in range(cols):
                grid_layout.setColumnStretch(c, 1)
                if p_index >= num:
                    continue

                widget_to_add = participants[p_index]
                if widget_to_add.parent() is not None:
                    widget_to_add.setParent(None)

                grid_layout.addWidget(widget_to_add, r, c)
                p_index += 1



    # client_gui.py (Inside the ChatWindow class)



    def update_view_layout(self):
        """Switches between Gallery and Presenter view and rebuilds the gallery grid."""
        logging.debug("Updating view layout...")

        # --- 1. Clear existing gallery pages ---
        while self.gallery_stack.count() > 0:
            page = self.gallery_stack.widget(0)

            # --- THIS IS THE FIX ---
            self.gallery_stack.removeWidget(page)
            if page != self.presenter_view:
                layout = page.layout()
                if layout is not None:
                    while (item := layout.takeAt(0)) is not None:
                        widget = item.widget()
                        if widget and isinstance(widget, VideoWidget):
                            widget.setParent(None)
                        elif item.spacerItem():
                            layout.removeItem(item)
                page.deleteLater()
            # --- END FIX ---

        # --- 2. Ensure self_view is correctly un-parented and sized ---
        if not self.self_view_widget:
            logging.error("Self-view widget is missing!")
            return
        if self.self_view_widget.parent() is not None:
            self.self_view_widget.setParent(None)
        self.self_view_widget.setMinimumSize(QSize(160, 120))
        self.self_view_widget.setMaximumSize(QSize(10000, 10000))
        self.self_view_widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        
        # --- 3. Get all participant widgets ---
        all_participants = []
        sharer_widget = None

        if self.current_screen_sharer and self.current_screen_sharer in self.video_widgets:
            sharer_widget = self.video_widgets[self.current_screen_sharer]
        
        if self.self_view_widget and self.current_screen_sharer != self.username:
            all_participants.append(self.self_view_widget)
            
        all_participants.extend([
            widget for user, widget in sorted(self.video_widgets.items()) 
            if widget and widget != sharer_widget # Add everyone *except* the sharer
        ])

        # --- 4. Rebuild gallery_stack ---
        if self.current_screen_sharer:
            # --- Presenter is active ---
            
            # Re-parent self_view for PiP
            if self.self_view_widget.parent() != self.presenter_view:
                self.self_view_widget.setParent(self.presenter_view)
            self.self_view_widget.setFixedSize(180, 120)
            
            # Manually position it
            margin = 10
            pw_width = self.presenter_view.width()
            pw_height = self.presenter_view.height()
            svw_width = self.self_view_widget.width()
            svw_height = self.self_view_widget.height()
            new_x = pw_width - svw_width - margin
            new_y = pw_height - svw_height - margin
            self.self_view_widget.move(max(0, new_x), max(0, new_y))
            self.self_view_widget.show()

            # Add Presenter View as Page 0
            self.gallery_stack.addWidget(self.presenter_view)
            
            # Update presenter name
            sharer_name = "Your" if self.current_screen_sharer == self.username else self.current_screen_sharer
            self.presenter_view.screen_share_widget.name_label.setText(f"{sharer_name}'s Screen")
            
            # If the sharer is *not* us, we need to add their widget to the gallery list
            # so they appear on the next page
            if sharer_widget and self.current_screen_sharer != self.username:
                 all_participants.insert(0, sharer_widget) # Put them first in the grid

        # --- 5. Build gallery grid pages ---
        if not all_participants:
            self.gallery_stack.addWidget(QWidget()) # Add empty page if needed
        else:
            num_pages = math.ceil(len(all_participants) / config.USERS_PER_PAGE)
            logging.debug(f"Gallery view: Building {num_pages} pages for {len(all_participants)} participants.")
            for i in range(num_pages):
                page_widget = QWidget()
                page_grid = QGridLayout()
                page_widget.setLayout(page_grid)
                start_index = i * config.USERS_PER_PAGE
                end_index = min((i + 1) * config.USERS_PER_PAGE, len(all_participants))
                page_participants = all_participants[start_index:end_index]
                self._build_gallery_grid(page_grid, page_participants)
                self.gallery_stack.addWidget(page_widget)

        # --- 6. Update controls ---
        new_index = 0
        if self.current_screen_sharer and self.current_page_index != 0:
            # If a share just started, but we were on Page 2, jump to the page
            # that contains the self_view widget.
            for i in range(self.gallery_stack.count()):
                page = self.gallery_stack.widget(i)
                if self.self_view_widget.isAncestorOf(page):
                    new_index = i
                    break
        
        self.gallery_stack.setCurrentIndex(new_index) 
        self.current_page_index = new_index
        self.update_pagination_controls()
        self.refresh_control_labels()

    def clear_speaker_name(self):

        """Resets the presenter name label if someone else was speaking."""

        if self.current_screen_sharer:

            sharer_name = "Your" if self.current_screen_sharer == self.username else self.current_screen_sharer

            self.presenter_view.screen_share_widget.name_label.setText(f"{sharer_name}'s Screen")



    # --- Thread-safe TCP Send ---

    def safe_send_tcp(self, msg: bytes):

        """Acquires the TCP lock and sends a message using the global send_msg."""

        if not self.tcp_socket or self.tcp_socket.fileno() == -1:

            logging.warning("safe_send_tcp: Attempted to send but socket is closed.")

            raise OSError("Socket is closed")



        self.tcp_send_lock.acquire()

        try:

            send_msg(self.tcp_socket, msg)

            logging.debug(f"safe_send_tcp: Sent {len(msg)} bytes.")

        finally:

            self.tcp_send_lock.release()



    # --- Media Control ---

    def send_command(self, command, payload):

        """Sends a JSON command to the server via TCP safely."""

        if not self.tcp_socket or self.tcp_socket.fileno() == -1:

            logging.warning(f"Attempted to send command '{command}' but TCP socket is closed.")

            return

        try:

            msg = json.dumps({"command": command, "payload": payload}).encode('utf-8')

            logging.debug(f"Sending command: {command}, Payload: {payload}")

            self.safe_send_tcp(msg) # Use thread-safe sender

        except (OSError, ssl.SSLError) as e:

            logging.error(f"Failed to send command '{command}': {e}", exc_info=True)

            self.append_message(f"SYSTEM: Failed to send command - Connection error.")

        except Exception as e:

            logging.error(f"Unexpected error sending command '{command}': {e}", exc_info=True)

            self.append_message(f"SYSTEM: Error sending command.")



    def _update_stream_status(self):

        """Notifies the server if the client is actively streaming media."""

        is_streaming = not self.is_muted or self.is_video_on or self.is_screen_sharing

        if is_streaming != self.was_streaming:

            self.send_command("stream_control", {"active": is_streaming})

            self.was_streaming = is_streaming



    def toggle_mic(self, checked: bool):

        """Toggles microphone mute state."""

        self.is_muted = checked

        logging.info(f"Microphone toggled: {'Muted' if self.is_muted else 'Unmuted'}")

        icon_folder = ICON_DIR

        mic_icon_path = os.path.join(icon_folder,"mic-off.svg") if self.is_muted else os.path.join(icon_folder,"mic.svg")

        mic_icon = QIcon(mic_icon_path) if os.path.exists(mic_icon_path) else QIcon()

        self.mic_btn.setIcon(mic_icon)



        self.send_command("media_status", {"username": self.username, "is_muted": self.is_muted})



        if self.is_muted:

            self.stop_audio_stream()

        else:

            self.start_audio_stream()

        self._update_stream_status()
        self.refresh_control_labels()



    def toggle_video(self, checked: bool):

        """Toggles camera video state."""

        self.is_video_on = not checked # Button checked means video OFF

        logging.info(f"Video toggled: {'On' if self.is_video_on else 'Off'}")

        icon_folder = ICON_DIR

        video_icon_path = os.path.join(icon_folder,"video.svg") if self.is_video_on else os.path.join(icon_folder,"video-off.svg")

        video_icon = QIcon(video_icon_path) if os.path.exists(video_icon_path) else QIcon()

        self.video_btn.setIcon(video_icon)



        if self.is_video_on:

            if self.is_screen_sharing: # Turn off screen share if turning video on

                self.screen_btn.setChecked(False)

                self.toggle_screen_share(False)

            self.start_video_stream()

        else:

            self.stop_video_stream()



        self.send_command("media_status", {"username": self.username, "is_video_on": self.is_video_on})

        self._update_stream_status()
        self.refresh_control_labels()



    def toggle_screen_share(self, checked: bool):
        """Toggles screen sharing state and prompts for monitor/mode."""

        if checked == self.is_screen_sharing:
            self.refresh_control_labels()
            return

        if checked and self.current_screen_sharer is not None and self.current_screen_sharer != self.username:
            logging.warning(f"Screen share failed: {self.current_screen_sharer} is already sharing.")
            QMessageBox.warning(
                self,
                "Screen Share Busy",
                f"Cannot start screen share.\n{self.current_screen_sharer} is already sharing.",
            )
            self.screen_btn.setChecked(False)
            self.refresh_control_labels()
            return

        self.is_screen_sharing = checked
        logging.info(f"Screen share toggled: {'On' if self.is_screen_sharing else 'Off'}")

        if self.is_screen_sharing:
            try:
                with mss() as sct:
                    monitors = sct.monitors[1:]
                    if not monitors:
                        QMessageBox.warning(self, "Screen Share Error", "No monitors found to share.")
                        self.screen_btn.setChecked(False)
                        self.is_screen_sharing = False
                        self.refresh_control_labels()
                        return

                    monitor_names = [
                        f"Monitor {i + 1}: {m['width']}x{m['height']} at ({m['left']}, {m['top']})"
                        for i, m in enumerate(monitors)
                    ]
                    item, ok = QInputDialog.getItem(
                        self,
                        "Select Monitor",
                        "Which monitor do you want to share?",
                        monitor_names,
                        0,
                        False,
                    )
                    if not ok:
                        self.screen_btn.setChecked(False)
                        self.is_screen_sharing = False
                        self.refresh_control_labels()
                        return

                    self.selected_monitor = monitors[monitor_names.index(item)]
            except Exception as e:
                logging.error(f"Could not get monitor list: {e}", exc_info=True)
                QMessageBox.critical(self, "Screen Share Error", f"Could not get monitor list: {e}")
                self.screen_btn.setChecked(False)
                self.is_screen_sharing = False
                self.refresh_control_labels()
                return

            modes = ["Fast (Standard Video)", "High Clarity (Slides / Text)"]
            mode_str, ok = QInputDialog.getItem(
                self,
                "Select Share Mode",
                "Which mode do you want to use?",
                modes,
                0,
                False,
            )
            if not ok:
                self.screen_btn.setChecked(False)
                self.is_screen_sharing = False
                self.refresh_control_labels()
                return

            self.is_tcp_share = mode_str == modes[1]

            self.current_screen_sharer = self.username
            self.update_view_layout()
            if self.is_video_on:
                self.video_btn.setChecked(True)
                self.toggle_video(True)
            self.video_btn.setEnabled(False)

            if self.is_tcp_share:
                self.start_tcp_screen_stream(self.selected_monitor)
            else:
                self.start_udp_screen_stream(self.selected_monitor)

        else:
            if self.is_tcp_share:
                self.stop_tcp_screen_stream()
            else:
                self.stop_udp_screen_stream()

            self.current_screen_sharer = None
            self.presenter_view.screen_share_widget.clear_frame()
            self.clear_speaker_name()
            if self.speaker_name_timer.isActive():
                self.speaker_name_timer.stop()
            self.update_view_layout()
            self.video_btn.setEnabled(True)

        self._update_stream_status()
        self.refresh_control_labels()



    # --- Audio Device Utilities ---

    def refresh_audio_devices(self) -> None:
        """Enumerates available playback devices via PyAudio."""
        self.available_output_devices = []

        try:
            if not self.p_audio:
                self.p_audio = pyaudio.PyAudio()

            device_count = self.p_audio.get_device_count()
            default_index = None
            default_name = "System Default"

            try:
                default_info = self.p_audio.get_default_output_device_info()
                default_index = int(default_info.get("index", -1)) if isinstance(default_info, dict) else None
                default_name = default_info.get("name", default_name) if isinstance(default_info, dict) else default_name
            except Exception as err:
                logging.debug(f"Unable to query default output device: {err}")

            for idx in range(device_count):
                try:
                    info = self.p_audio.get_device_info_by_index(idx)
                except Exception as err:
                    logging.debug(f"Skipping audio device {idx}: {err}")
                    continue

                if info.get("maxOutputChannels", 0) <= 0:
                    continue

                entry = {
                    "index": idx,
                    "name": info.get("name", f"Device {idx}"),
                    "is_default": default_index is not None and idx == default_index,
                }
                self.available_output_devices.append(entry)

            if self.audio_output_device_index is None:
                self.audio_output_device_name = default_name

        except Exception as e:
            logging.error(f"Unable to enumerate audio output devices: {e}", exc_info=True)
            self.available_output_devices = []


    def _select_primary_output_devices(self) -> list[dict]:
        """Returns at most two non-default devices grouped by common usage."""
        if not self.available_output_devices:
            return []

        categories: dict[str, dict] = {}

        def classify_device(name: str) -> str:
            lname = name.lower()
            if any(keyword in lname for keyword in ("headphone", "earbud", "earphone", "headset")):
                return "headphones"
            if any(keyword in lname for keyword in ("speaker", "display audio", "monitor", "tv")):
                return "speakers"
            if "bluetooth" in lname:
                return "headphones"
            return "other"

        for info in self.available_output_devices:
            if info.get("is_default"):
                continue
            name = info.get("name", "")
            category = classify_device(name)
            if category not in categories:
                categories[category] = info

        ordered = []
        for key in ("speakers", "headphones", "other"):
            item = categories.get(key)
            if item:
                ordered.append(item)

        if not ordered:
            ordered = [info for info in self.available_output_devices if not info.get("is_default")]

        return ordered[:2]


    @staticmethod
    def _categorise_label(name: str) -> str | None:
        lname = name.lower()
        if any(keyword in lname for keyword in ("headphone", "earbud", "earphone", "headset")):
            return "Headphones"
        if any(keyword in lname for keyword in ("speaker", "display audio", "monitor", "tv")):
            return "Speakers"
        if "bluetooth" in lname:
            return "Bluetooth Audio"
        return None


    def populate_audio_output_menu(self) -> None:
        """Rebuilds the audio output selection menu."""
        menu = getattr(self, "audio_device_menu", None)
        if menu is None:
            return

        if not self.available_output_devices:
            self.refresh_audio_devices()

        menu.clear()
        self.audio_device_actions = {}
        self.audio_action_group = QActionGroup(menu)
        self.audio_action_group.setExclusive(True)

        def ensure_checked(action: QAction, checked: bool) -> None:
            block = action.blockSignals(True)
            action.setChecked(checked)
            action.blockSignals(block)

        display_devices = self._select_primary_output_devices()

        selected_visible = any(
            info.get("index") == self.audio_output_device_index for info in display_devices
        )

        # System default option
        default_action = menu.addAction("System Default")
        default_action.setCheckable(True)
        self.audio_action_group.addAction(default_action)
        ensure_checked(default_action, self.audio_output_device_index is None or not selected_visible)
        default_action.triggered.connect(lambda _: self.set_audio_output_device(None, "System Default"))
        self.audio_device_actions[None] = default_action

        if display_devices:
            menu.addSeparator()
            for info in display_devices:
                idx = info.get("index")
                name = info.get("name", f"Device {idx}")
                pretty_label = self._categorise_label(name) or name
                action = menu.addAction(pretty_label)
                action.setCheckable(True)
                self.audio_action_group.addAction(action)
                ensure_checked(action, idx == self.audio_output_device_index)
                action.triggered.connect(lambda checked, i=idx, n=name: self.set_audio_output_device(i, n))
                self.audio_device_actions[idx] = action
        else:
            no_device_action = menu.addAction("No playback devices detected")
            no_device_action.setEnabled(False)

        menu.addSeparator()
        label = "Share System Audio"
        self.system_audio_action = menu.addAction(label)
        self.system_audio_action.setCheckable(True)
        self.system_audio_action.setEnabled(self.system_audio_supported)
        self._set_system_audio_action_checked(self.share_system_audio)
        self.system_audio_action.triggered.connect(self.toggle_system_audio_sharing)
        if not self.system_audio_supported:
            self.system_audio_action.setToolTip("System audio capture is only available on Windows with the sounddevice package installed.")


    def _resolve_device_name(self, device_index: int | None) -> str:
        if device_index is None:
            return "System Default"
        for info in self.available_output_devices:
            if info.get("index") == device_index:
                return info.get("name", f"Device {device_index}")
        return f"Device {device_index}"


    def update_audio_device_button_tooltip(self) -> None:
        if not hasattr(self, "audio_device_button"):
            return
        playback_label = self._resolve_device_name(self.audio_output_device_index)
        share_state = "On" if self.share_system_audio else "Off"
        tooltip = f"Playback device: {playback_label}\nSystem audio share: {share_state}"
        self.audio_device_button.setToolTip(tooltip)


    def set_audio_output_device(self, device_index: int | None, device_name: str) -> None:
        if device_index == self.audio_output_device_index:
            return

        self.audio_output_device_index = device_index
        self.audio_output_device_name = device_name or self._resolve_device_name(device_index)

        success = self.restart_audio_output_stream()
        if success:
            self.update_audio_device_button_tooltip()
            self.populate_audio_output_menu()
            self.append_message(f"<font color='{SUCCESS_COLOR}'>SYSTEM: Audio playback routed to {self.audio_output_device_name}.</font>")
        else:
            # Revert selection on failure
            self.audio_output_device_index = None
            self.audio_output_device_name = "System Default"
            self.populate_audio_output_menu()


    def restart_audio_output_stream(self) -> bool:
        """Reopens the playback stream on the currently selected output device."""
        if not self.p_audio:
            try:
                self.p_audio = pyaudio.PyAudio()
            except Exception as e:
                logging.error(f"Unable to (re)initialise PyAudio: {e}", exc_info=True)
                QMessageBox.critical(self, "Audio Error", f"Unable to initialise audio output: {e}")
                return False

        if self.audio_stream_out:
            try:
                if self.audio_stream_out.is_active():
                    self.audio_stream_out.stop_stream()
                self.audio_stream_out.close()
            except Exception as e:
                logging.debug(f"Error closing previous audio output stream: {e}")
            finally:
                self.audio_stream_out = None

        kwargs = {
            "format": config.AUDIO_FORMAT,
            "channels": config.AUDIO_CHANNELS,
            "rate": config.AUDIO_RATE,
            "output": True,
            "frames_per_buffer": config.AUDIO_CHUNK,
        }
        if self.audio_output_device_index is not None:
            kwargs["output_device_index"] = self.audio_output_device_index

        try:
            self.audio_stream_out = self.p_audio.open(**kwargs)
            self.ensure_audio_playback_thread()
            logging.info(f"Audio output stream opened on {self._resolve_device_name(self.audio_output_device_index)}")
            return True
        except Exception as e:
            logging.error(f"Failed to open audio output stream: {e}", exc_info=True)
            QMessageBox.critical(self, "Audio Error", f"Failed to open audio output device: {e}")
            self.audio_stream_out = None
            return False


    def ensure_audio_playback_thread(self) -> None:
        if self.audio_playback_thread and self.audio_playback_thread.is_alive():
            return
        self.audio_playback_thread = threading.Thread(target=self.audio_playback_loop, name="AudioPlaybackThread", daemon=True)
        self.audio_playback_thread.start()


    def toggle_system_audio_sharing(self, checked: bool) -> None:
        if checked:
            if not self.system_audio_supported:
                self.append_message(f"<font color='{WARNING_COLOR}'>SYSTEM: System audio capture is not supported on this platform.</font>")
                self._set_system_audio_action_checked(False)
                return
            if not self.start_system_audio_share():
                self._set_system_audio_action_checked(False)
                return
        else:
            self.stop_system_audio_share()
        self.update_audio_device_button_tooltip()


    def start_system_audio_share(self) -> bool:
        if self.share_system_audio:
            return True
        if not sd:
            self.append_message(f"<font color='{WARNING_COLOR}'>SYSTEM: Install the 'sounddevice' package to capture system audio.</font>")
            return False

        self.share_system_audio = True
        self.system_audio_thread = threading.Thread(target=self._system_audio_capture_loop, name="SystemAudioLoop", daemon=True)
        self.system_audio_thread.start()
        self.append_message(f"<font color='{SUCCESS_COLOR}'>SYSTEM: System audio sharing enabled.</font>")
        return True


    def stop_system_audio_share(self, announce: bool = True) -> None:
        if not self.share_system_audio:
            return
        self.share_system_audio = False
        thread = self.system_audio_thread
        if thread and thread.is_alive() and threading.current_thread() is not thread:
            thread.join(timeout=1.5)
        self.system_audio_thread = None
        if announce:
            self.append_message(f"<font color='{WARNING_COLOR}'>SYSTEM: System audio sharing disabled.</font>")
        if self.system_audio_action:
            self._set_system_audio_action_checked(False)


    def _system_audio_capture_loop(self) -> None:
        logging.info("System audio capture thread started.")
        if not sd:
            logging.warning("Sounddevice module unavailable; aborting system audio capture loop.")
            self.share_system_audio = False
            return

        try:
            extra_settings = None
            if hasattr(sd, "WasapiSettings") and platform.system().lower().startswith("win"):
                extra_settings = sd.WasapiSettings(loopback=True)

            channels = max(1, config.AUDIO_CHANNELS)
            with sd.InputStream(
                samplerate=config.AUDIO_RATE,
                channels=max(1, channels),
                dtype="int16",
                blocksize=config.AUDIO_CHUNK,
                device=self.system_audio_device,
                latency="low",
                extra_settings=extra_settings,
            ) as stream:
                while self.is_running and self.share_system_audio:
                    frames, overflowed = stream.read(config.AUDIO_CHUNK)
                    if overflowed:
                        logging.debug("System audio capture overflow detected.")
                    if frames.size == 0:
                        continue
                    samples = np.array(frames, copy=False)
                    if samples.ndim > 1 and samples.shape[1] > 1:
                        samples = samples.mean(axis=1)
                    samples = np.asarray(samples, dtype=np.int16)
                    self._transmit_audio_samples(samples)

        except Exception as e:
            logging.error(f"System audio capture error: {e}", exc_info=True)
            QTimer.singleShot(0, lambda: self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: System audio capture error: {e}</font>"))
        finally:
            logging.info("System audio capture thread exiting.")
            self.share_system_audio = False
            self.system_audio_thread = None
            if self.system_audio_action:
                QTimer.singleShot(0, lambda: self._set_system_audio_action_checked(False))
            self.update_audio_device_button_tooltip()


    def _set_system_audio_action_checked(self, checked: bool) -> None:
        if not self.system_audio_action:
            return
        block = self.system_audio_action.blockSignals(True)
        self.system_audio_action.setChecked(checked)
        self.system_audio_action.blockSignals(block)


    # --- Media Stream Initialization ---

    def init_audio_output(self):

        """Initializes PyAudio, refreshes device list, and opens the playback stream."""

        self.refresh_audio_devices()

        if not self.restart_audio_output_stream():
            return

        self.populate_audio_output_menu()
        self.update_audio_device_button_tooltip()



    def start_audio_stream(self):

        """Ensures the audio capture stream is available and resumes capture."""

        # Attempt to mark the microphone as active; revert on failure
        self.is_muted = False

        # Make sure PyAudio is ready (initialises playback stream if needed)
        if not self.p_audio:
            self.init_audio_output()

        if not self.p_audio:
            logging.error("PyAudio is unavailable. Cannot start microphone input.")
            QMessageBox.critical(self, "Audio Error", "PyAudio is not available. Please install PyAudio to enable microphone input.")
            self.is_muted = True
            if not self.mic_btn.isChecked():
                self.mic_btn.setChecked(True)
            self.refresh_control_labels()
            return

        # Clean up a stale capture stream if the worker thread has exited
        if self.audio_stream_in and (not self.audio_send_thread or not self.audio_send_thread.is_alive()):
            logging.warning("Cleaning up stale audio capture stream before restarting.")
            try:
                if self.audio_stream_in.is_active():
                    self.audio_stream_in.stop_stream()
            except Exception:
                pass
            try:
                self.audio_stream_in.close()
            except Exception:
                pass
            self.audio_stream_in = None
            self.audio_send_thread = None

        # If the stream is already present and the worker thread is alive, we only needed to unmute
        if self.audio_stream_in:
            logging.debug("Audio capture stream already initialised; resuming without reopening device.")
            return

        try:
            logging.info("Opening audio capture stream...")
            self.audio_stream_in = self.p_audio.open(
                format=config.AUDIO_FORMAT,
                channels=config.AUDIO_CHANNELS,
                rate=config.AUDIO_RATE,
                input=True,
                frames_per_buffer=config.AUDIO_CHUNK
            )

            self.audio_send_thread = threading.Thread(
                target=self.send_audio_stream,
                name="AudioSendThread",
                daemon=True
            )
            self.audio_send_thread.start()
            logging.info("Audio input stream opened and audio send thread started.")

        except Exception as e:

            logging.error(f"Could not start microphone: {e}", exc_info=True)

            QMessageBox.critical(self, "Audio Error", f"Could not start microphone: {e}")

            self.audio_stream_in = None

            self.audio_send_thread = None

            self.is_muted = True

            if not self.mic_btn.isChecked():
                self.mic_btn.setChecked(True)
            self.refresh_control_labels()



    def stop_audio_stream(self):

        """Signals the audio sending thread to stop (by setting is_muted)."""

        logging.info("Stopping audio input stream...")

        self.is_muted = True # The send_audio_stream loop checks this flag

        stream = self.audio_stream_in
        if stream:
            try:
                if stream.is_active():
                    stream.stop_stream()
            except Exception:
                pass



    def start_video_stream(self):

        """Opens the video capture device and starts the sending thread."""

        if self.video_cap:

            logging.warning("Video capture already active.")

            return

        try:

            logging.info("Attempting to open video capture device 0...")

            self.video_cap = cv2.VideoCapture(0)

            if not self.video_cap.isOpened():

                raise Exception("Could not open webcam device 0.")

            threading.Thread(target=self.send_video_stream, daemon=True).start()

            logging.info("Video stream started.")

        except Exception as e:

            logging.error(f"Could not start camera: {e}", exc_info=True)

            QMessageBox.critical(self, "Media Error", f"Could not start camera: {e}")

            self.video_cap = None

            self.toggle_video(True) # Force video off state if cam fails



    def stop_video_stream(self):

        """Signals the video sending thread to stop and releases the capture device."""

        logging.info("Stopping video stream...")

        if self.video_cap:

            cap = self.video_cap

            self.video_cap = None # Signal thread to stop by setting cap to None

            QTimer.singleShot(50, cap.release) # Release camera shortly after

            self.self_view_widget.clear_frame()

            logging.info("Video stream stopped.")

        else:

            logging.debug("Video stream already stopped.")



    def start_udp_screen_stream(self, monitor):

        """Starts the UDP screen share thread."""

        logging.info(f"Starting UDP screen share stream for monitor: {monitor}")
        self.send_command("start_tcp_share", {})
        threading.Thread(target=self.send_udp_screen_stream, args=(monitor,), daemon=True).start()



    # client_gui.py



    def stop_udp_screen_stream(self):

        """Signals the UDP screen share thread to stop."""

        logging.info("Stopping UDP screen share stream...")

        # The send_udp_screen_stream loop checks is_screen_sharing and is_tcp_share

       

        # --- ADD THIS LINE ---

        # Reuse the "stop_tcp_share" command, as the server doesn't differentiate

        self.send_command("stop_tcp_share", {})

        # --- END ADDITION ---



        self.self_view_widget.clear_frame()

        logging.info("UDP screen share stream stopped signal sent.")



    def start_tcp_screen_stream(self, monitor):

        """Notifies server and starts the TCP screen share thread."""

        logging.info(f"Starting TCP screen share stream for monitor: {monitor}")

        self.send_command("start_tcp_share", {})

        threading.Thread(target=self.send_tcp_screen_stream, args=(monitor,), daemon=True).start()



    def stop_tcp_screen_stream(self):

        """Notifies server and signals the TCP screen share thread to stop."""

        logging.info("Stopping TCP screen share stream...")

        # The send_tcp_screen_stream loop checks is_screen_sharing and is_tcp_share

        # Setting is_screen_sharing to False (done in toggle_screen_share) is enough.

        self.send_command("stop_tcp_share", {}) # Notify others

        self.self_view_widget.clear_frame()

        logging.info("TCP screen share stream stopped signal sent.")



    # --- Network Connection & Loops ---

    def connect_to_server(self):

        """Establishes TCP and UDP connections to the server."""

        logging.info(f"Attempting to connect to {self.server_ip}:{config.TCP_PORT}...")

        if hasattr(self, "session_info_bar"):
            QTimer.singleShot(0, lambda: self.session_info_bar.update_status("Connecting…", ACCENT_COLOR))

        try:

            # TCP Setup with SSL

            raw_tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            raw_tcp_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) # Disable Nagle's algorithm

            context = ssl.create_default_context()

            context.check_hostname = False # We don't verify hostname for LAN IP

            context.verify_mode = ssl.CERT_NONE # Basic encryption without verification (Phase 3 improves this)

            self.tcp_socket = context.wrap_socket(raw_tcp_socket, server_hostname=self.server_ip)

            logging.debug("TCP socket wrapped with SSL.")

            self.tcp_socket.connect((self.server_ip, config.TCP_PORT))

            logging.info(f"TCP connected to {self.server_ip}:{config.TCP_PORT}.")

            cipher = self.tcp_socket.cipher()

            logging.info(f"SSL Cipher: {cipher}")



            # UDP Setup

            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self.udp_socket.bind(('0.0.0.0', 0)) # Bind to any available local port

            udp_addr = self.udp_socket.getsockname()

            logging.info(f"UDP socket bound to {udp_addr}")



            # Start background threads for network I/O and heartbeats

            threading.Thread(target=self.receive_tcp_messages, name="TCPReceiveThread", daemon=True).start()

            threading.Thread(target=self.receive_udp_stream, name="UDPReceiveThread", daemon=True).start()

            threading.Thread(target=self.send_udp_heartbeats, name="UDPHeartbeatThread", daemon=True).start()

            logging.info("Network listener and heartbeat threads started.")



        except ssl.SSLError as e:

             logging.error(f"SSL Error connecting: {e}", exc_info=True)

             self.comm.msg_signal.emit(f"SYSTEM: SSL Error: {e}. Is server running with SSL?")

             self.comm.connection_failed_signal.emit()

        except socket.gaierror as e:

             logging.error(f"DNS/Address Error for '{self.server_ip}': {e}", exc_info=True)

             self.comm.msg_signal.emit(f"SYSTEM: Connection Error: Invalid server address '{self.server_ip}'.")

             self.comm.connection_failed_signal.emit()

        except socket.error as e:

             logging.error(f"Socket Error connecting: {e}", exc_info=True)

             self.comm.msg_signal.emit(f"SYSTEM: Connection Error: {e}")

             self.comm.connection_failed_signal.emit()

        except Exception as e:

             logging.error(f"Unexpected error connecting: {e}", exc_info=True)

             self.comm.msg_signal.emit(f"SYSTEM: Error connecting: {e}")

             self.comm.connection_failed_signal.emit()



    def send_udp_heartbeats(self):

        """Periodically sends a heartbeat packet to the server via UDP."""

        logging.info("UDP Heartbeat thread started.")

        username_bytes = self.username.encode('utf-8')[:config.USERNAME_HEADER_LENGTH]
        heartbeat_packet = b'H' + username_bytes.ljust(config.USERNAME_HEADER_LENGTH, b' ')

        # Send heartbeats to the server's audio UDP port (could be video too)

        server_audio_addr = (self.server_ip, config.AUDIO_UDP_PORT)



        while self.is_running:

            try:

                if self.udp_socket and self.udp_socket.fileno() != -1:

                    self.udp_socket.sendto(heartbeat_packet, server_audio_addr)

                    logging.debug(f"Sent heartbeat to {server_audio_addr}")

                else:

                    logging.warning("Heartbeat thread: UDP socket closed or invalid.")

                    break # Stop if socket is gone



                time.sleep(3) # Send every 3 seconds



            except socket.error as e:

                if self.is_running: # Avoid errors during shutdown

                    logging.error(f"Heartbeat thread: UDP Socket error: {e}")

                    time.sleep(5) # Wait longer before retrying on error

                else: break

            except Exception as e:

                 if self.is_running:

                      logging.error(f"Heartbeat thread: Unexpected error: {e}", exc_info=True)

                      time.sleep(5)

                 else: break

        logging.info("UDP Heartbeat thread finished.")



    def receive_tcp_messages(self):

        """Listens for incoming TCP messages and routes them."""

        logging.info("TCP receive loop started.")

        while self.is_running:

            message_bytes = None

            try:

                # Check socket validity before blocking recv

                if not self.tcp_socket or self.tcp_socket.fileno() == -1:

                    logging.warning("TCP socket closed or invalid, exiting receive loop.")

                    break



                message_bytes = recv_msg(self.tcp_socket)



                if message_bytes is None: # Connection closed or error in recv_msg

                    if self.is_running: # Avoid duplicate messages on clean shutdown

                        logging.warning("TCP Connection closed by peer or recv_msg error.")

                        self.comm.msg_signal.emit("SYSTEM: Connection lost.")

                        self.comm.connection_failed_signal.emit()

                    break # Exit loop



                logging.debug(f"Received TCP message, {len(message_bytes)} bytes.")



                # Route message based on prefix

                if message_bytes.startswith(b'FILE_CHUNK:'):

                    self.handle_incoming_file_chunk(message_bytes)

                elif message_bytes.startswith(b'FILE_END:'):

                    self.handle_incoming_file_end(message_bytes)

                elif message_bytes.startswith(b'S_FRAME:'): # TCP Screen Frame

                    self.handle_tcp_screen_frame(message_bytes)

                else: # Assume chat or JSON command

                    self.handle_message(message_bytes)



            except ConnectionAbortedError:

                if self.is_running:

                    logging.warning("Connection aborted during TCP receive.")

                    self.comm.msg_signal.emit("SYSTEM: Connection aborted.")

                    self.comm.connection_failed_signal.emit()

                break

            except ConnectionResetError:

                 if self.is_running:

                     logging.warning("Connection reset during TCP receive.")

                     self.comm.msg_signal.emit("SYSTEM: Connection reset by peer.")

                     self.comm.connection_failed_signal.emit()

                 break

            except ssl.SSLError as ssl_err:

                 if self.is_running:

                     logging.error(f"SSL error during TCP receive: {ssl_err}", exc_info=True)

                     self.comm.msg_signal.emit(f"SYSTEM: SSL error occurred.")

                     self.comm.connection_failed_signal.emit()

                 break

            except Exception as e: # Catch-all for unexpected errors

                if self.is_running:

                    logging.error(f"Unexpected error in receive_tcp_messages loop: {e}", exc_info=True)

                    logging.debug(f"Last received bytes (partial): {message_bytes[:100] if message_bytes else 'None'}")

                    # Trigger general connection failure for safety

                    self.comm.connection_failed_signal.emit()

                break # Exit loop on unexpected error



        logging.info("Exiting TCP receive loop.")



    def receive_udp_stream(self):

        """Listens for incoming UDP packets (video/audio)."""

        logging.info("UDP receive loop started.")

        while self.is_running:

            try:

                # Check socket validity before blocking recvfrom

                if not self.udp_socket or self.udp_socket.fileno() == -1:

                    logging.warning("UDP socket closed or invalid, exiting receive loop.")

                    break



                data, addr = self.udp_socket.recvfrom(config.BUFFER_SIZE)

                ptype, payload = data[0:1], data[1:] # Split packet type from payload

                logging.debug(f"Received UDP packet type {ptype.decode(errors='ignore')} from {addr}, {len(payload)} bytes payload.")



                # Emit signals based on packet type

                if ptype in [b'V', b'S']: # Video or UDP Screen share

                    self.comm.video_data_signal.emit(ptype, payload)

                elif ptype == b'A': # Audio

                    self.comm.audio_data_signal.emit(payload)

                # Ignore heartbeat 'H' packets here

                elif ptype != b'H':

                    logging.warning(f"Received unknown UDP packet type: {ptype} from {addr}")



            except socket.error as e:

                if self.is_running:

                    if e.errno == 10054: # Connection reset - common, often ignorable

                        logging.debug(f"UDP Socket connection reset error (errno 10054) from {addr if 'addr' in locals() else 'unknown'}.")

                    elif e.errno == 9 or e.errno == 10004: # Bad file descriptor / Interrupted system call (socket closed)

                        logging.info("UDP socket closed, exiting receive loop.")

                        break

                    else: # Log other socket errors

                        logging.error(f"UDP Socket error in receive loop: {e}", exc_info=True)

                else: # Socket error during shutdown, expected

                    logging.info("UDP socket error caught during shutdown, exiting loop.")

                    break

            except Exception as e: # Catch-all

                if self.is_running:

                    logging.error(f"Unexpected error in UDP receive loop: {e}", exc_info=True)

                break # Exit loop on unexpected error



        logging.info("Exiting UDP receive loop.")





    # --- Media Sending Loops (Worker Threads) ---

    def send_video_stream(self):

        """Captures webcam frames, encodes, and sends them via UDP."""

        logging.info("Video sending thread started.")

        username_bytes = self.username.encode('utf-8').ljust(config.USERNAME_HEADER_LENGTH)

        # Use a local reference to video_cap for thread safety

        local_video_cap = self.video_cap

        if not local_video_cap:

            logging.error("send_video_stream started but video_cap is None.")

            return



        while self.is_running and self.video_cap == local_video_cap: # Loop continues only if self.video_cap hasn't changed

            try:

                if not local_video_cap.isOpened():

                    logging.warning("Video capture device became unopened.")

                    break

                ret, frame = local_video_cap.read()

                if not ret:

                    logging.warning("Failed to read frame from video capture."); time.sleep(0.1); continue



                # Update self-view in GUI thread

                self.comm.self_video_frame_signal.emit(frame)



                # Resize, encode, and packetize

                frame_resized = cv2.resize(frame, config.VIDEO_RESOLUTION)

                ret_encode, buffer = cv2.imencode('.jpg', frame_resized, [cv2.IMWRITE_JPEG_QUALITY, config.VIDEO_QUALITY])

                if not ret_encode:

                    logging.warning("JPEG encoding failed for video frame."); continue



                packet = b'V' + username_bytes + buffer.tobytes()



                # Send via UDP if socket is valid and packet isn't too large

                if len(packet) < config.BUFFER_SIZE:

                    if self.udp_socket and self.udp_socket.fileno() != -1:

                        self.udp_socket.sendto(packet, (self.server_ip, config.VIDEO_UDP_PORT))

                    else: logging.warning("UDP socket closed, cannot send video."); break

                else: logging.warning(f"Video packet too large: {len(packet)} bytes. Skipping.")



            except cv2.error as e:

                logging.error(f"OpenCV error in send_video_stream: {e}", exc_info=True); break

            except Exception as e:

                logging.error(f"Unexpected error in send_video_stream: {e}", exc_info=True); time.sleep(0.5) # Avoid rapid error loops



        logging.info("Exiting video sending loop.")

        # Attempt to release camera if this thread was the last one using it

        if self.video_cap is None and local_video_cap and local_video_cap.isOpened():

             try: local_video_cap.release(); logging.info("Video capture released by sending thread.")

             except Exception as e: logging.error(f"Error releasing video capture in send_video_stream: {e}")



    def send_udp_screen_stream(self, monitor):

        """Captures screen, encodes, and sends frames via UDP."""

        logging.info(f"UDP Screen sending thread started for monitor: {monitor}")

        username_bytes = self.username.encode('utf-8').ljust(config.USERNAME_HEADER_LENGTH)

        try:

            with mss() as sct:

                # Loop while screen sharing is active AND in UDP mode

                while self.is_running and self.is_screen_sharing and not self.is_tcp_share:

                    try:

                        img = sct.grab(monitor)

                        frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR) # Convert to BGR for OpenCV

                        if frame is None or frame.size == 0:

                            logging.warning("UDP Screen grab failed or produced empty frame."); time.sleep(0.1); continue



                        # Update self-view in GUI thread

                        self.comm.self_video_frame_signal.emit(frame)



                        # Resize, encode, packetize

                        frame_resized = cv2.resize(frame, config.SCREEN_SHARE_RESOLUTION)

                        ret_encode, buffer = cv2.imencode('.jpg', frame_resized, [cv2.IMWRITE_JPEG_QUALITY, 30])

                        if not ret_encode:

                            logging.warning("JPEG encoding failed for UDP screen frame."); continue



                        packet = b'S' + username_bytes + buffer.tobytes() # 'S' for UDP screen share



                        # Send via UDP

                        if len(packet) < config.BUFFER_SIZE:

                            if self.udp_socket and self.udp_socket.fileno() != -1:

                                self.udp_socket.sendto(packet, (self.server_ip, config.VIDEO_UDP_PORT))

                            else: logging.warning("UDP socket closed, cannot send screen share."); break

                        else: logging.warning(f"UDP Screen share packet too large: {len(packet)} bytes. Skipping.")



                        time.sleep(1 / 15) # Cap FPS for UDP share



                    except (mss.ScreenShotError, cv2.error) as e:

                        logging.error(f"Error during UDP screen capture/processing: {e}", exc_info=True); time.sleep(0.5)

                    except Exception as e:

                        logging.error(f"Unexpected error in UDP screen sharing loop: {e}", exc_info=True); time.sleep(1)

        except Exception as e:

            logging.error(f"Error initializing screen capture (mss) for UDP: {e}", exc_info=True)



        logging.info("Exiting UDP screen sending loop.")

        # Clear self-view if video wasn't also on

        if not self.is_video_on:

            QTimer.singleShot(0, self.self_view_widget.clear_frame)



    def send_tcp_screen_stream(self, monitor):

        """Captures screen, encodes, and sends frames via TCP (thread-safe)."""

        logging.info(f"TCP Screen sending thread started for monitor: {monitor}")

        username_bytes = self.username.encode('utf-8').ljust(config.USERNAME_HEADER_LENGTH)

        try:

            with mss() as sct:

                 # Loop while screen sharing is active AND in TCP mode

                while self.is_running and self.is_screen_sharing and self.is_tcp_share:

                    try:

                        img = sct.grab(monitor)

                        frame = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)

                        if frame is None or frame.size == 0:

                            logging.warning("TCP Screen grab failed."); time.sleep(0.1); continue



                        self.comm.self_video_frame_signal.emit(frame) # Update self-view



                        # Use slightly higher quality for TCP

                        frame_resized = cv2.resize(frame, config.SCREEN_SHARE_RESOLUTION)

                        quality = min(100, config.SCREEN_SHARE_QUALITY + 10) # Clamp quality at 100

                        ret_encode, buffer = cv2.imencode('.jpg', frame_resized, [cv2.IMWRITE_JPEG_QUALITY, quality])

                        if not ret_encode:

                            logging.warning("JPEG encoding failed for TCP screen frame."); continue



                        # Construct packet: PREFIX + USERNAME + FILEDATA

                        packet = b'S_FRAME:' + username_bytes + buffer.tobytes()



                        self.safe_send_tcp(packet) # Send using thread-safe method



                        time.sleep(1 / 5) # Cap at ~5 FPS for TCP reliability



                    except (mss.ScreenShotError, cv2.error) as e:

                        logging.error(f"Error during TCP screen capture/processing: {e}", exc_info=True); time.sleep(0.5)

                    except (OSError, ssl.SSLError) as e: # Catch socket errors from safe_send_tcp

                        logging.error(f"Socket error in send_tcp_screen_stream: {e}. Stopping thread.")

                        QTimer.singleShot(0, lambda: self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Connection error during screen share.</font>"))

                        break # Exit loop on socket error

                    except Exception as e:

                        logging.error(f"Unexpected error in TCP screen sharing loop: {e}", exc_info=True); time.sleep(1)

        except Exception as e:

            logging.error(f"Error initializing screen capture (mss) for TCP: {e}", exc_info=True)



        logging.info("Exiting TCP screen sending loop.")

        if not self.is_video_on:

            QTimer.singleShot(0, self.self_view_widget.clear_frame)



    def _transmit_audio_samples(self, samples: np.ndarray) -> None:
        if samples.size == 0:
            return

        samples = np.asarray(samples, dtype=np.int16)
        peak = int(np.max(np.abs(samples))) if samples.size else 0
        if peak < config.AUDIO_SILENCE_THRESHOLD:
            return

        if not self.udp_socket or self.udp_socket.fileno() == -1:
            logging.warning("UDP socket closed, cannot send audio.")
            return

        encoded_chunk = encode_ulaw(samples).tobytes()
        packet = b'A' + self.username_audio_header + encoded_chunk

        try:
            self.udp_socket.sendto(packet, (self.server_ip, config.AUDIO_UDP_PORT))
        except Exception as e:
            if self.is_running:
                logging.error(f"Unexpected error sending audio packet: {e}", exc_info=True)


    def send_audio_stream(self):

        """Captures audio chunks, encodes, and sends them via UDP respecting mute state."""

        stream = self.audio_stream_in
        if not stream:
            logging.error("send_audio_stream started but audio_stream_in is None.")
            self.audio_send_thread = None
            return

        logging.info("Audio sending thread started.")

        try:
            while self.is_running and stream:
                if self.is_muted:
                    # Pause capture while muted to avoid sending microphone data
                    try:
                        if stream.is_active():
                            stream.stop_stream()
                    except Exception:
                        pass
                    time.sleep(0.05)
                    continue

                if not stream.is_active():
                    try:
                        stream.start_stream()
                    except Exception as e:
                        if self.is_running:
                            logging.error(f"Failed to start audio input stream: {e}")
                        time.sleep(0.2)
                        continue

                try:
                    audio_chunk_bytes = stream.read(config.AUDIO_CHUNK, exception_on_overflow=False)
                except IOError as e:
                    if self.is_running and not self.is_muted:
                        logging.error(f"PyAudio IOError in send_audio_stream: {e}")
                    time.sleep(0.1)
                    break
                except Exception as e:
                    if self.is_running and not self.is_muted:
                        logging.error(f"Unexpected microphone read error: {e}", exc_info=True)
                    time.sleep(0.1)
                    break

                if not audio_chunk_bytes:
                    time.sleep(0.01)
                    continue

                audio_data = np.frombuffer(audio_chunk_bytes, dtype=np.int16)
                if audio_data.size == 0:
                    continue

                self._transmit_audio_samples(audio_data)

        finally:
            logging.info("Exiting audio sending loop.")
            try:
                if stream.is_active():
                    stream.stop_stream()
            except Exception:
                pass
            try:
                stream.close()
            except Exception as e:
                logging.debug(f"Error closing audio input stream: {e}")

            if self.audio_stream_in is stream:
                self.audio_stream_in = None

            self.audio_send_thread = None

            logging.info("Audio input stream closed by sending thread.")





    # --- Media Processing Loops (Worker Threads) ---

    def audio_playback_loop(self):

        """Plays audio chunks received from the queue."""

        logging.info("Audio playback thread started.")

        while self.is_running:

            try:

                # Get audio data from queue (blocks with timeout)

                username, audio_bytes = self.audio_playback_queue.get(timeout=0.2)

                backlog = self.audio_playback_queue.qsize()
                if backlog > config.AUDIO_JITTER_MAX_CHUNKS:
                    dropped = 0
                    while backlog > config.AUDIO_JITTER_MAX_CHUNKS:
                        try:
                            username, audio_bytes = self.audio_playback_queue.get_nowait()
                            dropped += 1
                        except queue.Empty:
                            break
                        backlog = self.audio_playback_queue.qsize()
                    if dropped:
                        logging.debug(f"Dropped {dropped} buffered audio chunk(s) to reduce playback latency.")

                # Play audio if output stream is valid

                if self.audio_stream_out and not self.audio_stream_out.is_stopped():

                    try:

                        self.audio_stream_out.write(audio_bytes)

                    except IOError as e: # Handle potential blocking/buffer issues

                        logging.error(f"PyAudio output stream write error: {e}"); time.sleep(0.5) # Wait before retrying



                # Update speaker indication in GUI thread

                widget = self.video_widgets.get(username)

                if widget:

                    # Set speaking indicator immediately

                    QTimer.singleShot(0, lambda w=widget: w.set_speaking(True))

                    # Reset speaking indicator after a short delay

                    if username in self.audio_activity_timers:

                        QTimer.singleShot(0, lambda t=self.audio_activity_timers[username]: t.start(300)) # Restart 300ms timer



                # Update presenter view speaker name (if applicable)

                if self.current_screen_sharer and username != self.current_screen_sharer and username != self.username:

                    QTimer.singleShot(0, lambda u=username: self.update_presenter_speaker_name(u))



            except queue.Empty:

                continue # Timeout occurred, loop again

            except Exception as e:

                logging.error(f"Error in audio playback loop: {e}", exc_info=True)

                time.sleep(0.5) # Avoid rapid error loops

        logging.info("Exiting audio playback loop.")



    def update_presenter_speaker_name(self, username: str):

        """Updates the presenter widget's name label to show who is speaking."""

        if self.current_screen_sharer:

            sharer_name = "Your" if self.current_screen_sharer == self.username else self.current_screen_sharer

            self.presenter_view.screen_share_widget.name_label.setText(f"{sharer_name}'s Screen (Speaking: {username})")

            self.speaker_name_timer.start(1500) # Reset name after 1.5 seconds



    def video_processing_loop(self):

        """Decodes raw video frames received from the queue."""

        logging.info("Video processing thread started.")

        while self.is_running:

            try:

                # Get raw frame data (blocks with timeout)

                ptype, username, raw_frame_data = self.video_processing_queue.get(timeout=0.2)



                # Decode JPEG data

                frame = cv2.imdecode(np.frombuffer(raw_frame_data, dtype=np.uint8), cv2.IMREAD_COLOR)



                # Emit decoded frame to GUI thread if successful

                if frame is not None:

                    self.comm.processed_frame_signal.emit(ptype, username, frame)

                else:

                    logging.warning(f"Failed to decode video frame for user '{username}'.")



            except queue.Empty:

                continue # Timeout occurred, loop again

            except Exception as e:

                # Log error with username if available

                user_ctx = f"for user '{username}'" if 'username' in locals() else ""

                logging.error(f"Error in video processing loop {user_ctx}: {e}", exc_info=True)

                time.sleep(0.5) # Avoid rapid error loops

        logging.info("Exiting video processing loop.")





    # --- GUI Slots (Main Thread) ---

    def handle_message(self, message_bytes: bytes):

        """Handles non-media TCP messages (chat, JSON commands, handshake)."""

        # Try decoding as JSON first

        try:

            decoded_json = json.loads(message_bytes.decode('utf-8'))

            self.comm.json_command_signal.emit(decoded_json) # Emit signal for JSON commands

            return

        except (json.JSONDecodeError, UnicodeDecodeError):

            pass # Not JSON, proceed



        # Handle known non-JSON text commands/messages

        try:

            msg_str = message_bytes.decode('utf-8')

            logging.debug(f"Received non-JSON message: {msg_str[:100]}") # Log first 100 chars



            if msg_str.startswith("USERLIST,"):

                self.comm.user_list_signal.emit(msg_str.split(',')[1:])

            elif msg_str == "GET_SESSION_INFO": # Server requests client info during handshake

                info = {"username": self.username, "session_id": self.session_id}

                logging.debug(f"Responding to GET_SESSION_INFO with: {info}")

                try:

                    if self.tcp_socket and self.tcp_socket.fileno() != -1:

                        self.safe_send_tcp(json.dumps(info).encode('utf-8'))

                        logging.debug("Sent session info successfully.")

                    else: logging.warning("Attempted to send session info, but socket is closed.")

                except Exception as e: logging.error(f"Error sending session info: {e}", exc_info=True)

            elif msg_str == "GET_UDP_PORT": # Server requests UDP port during handshake

                if self.udp_socket:

                    _, p = self.udp_socket.getsockname()

                    try:

                        self.safe_send_tcp(f"UDP_PORT:{p}".encode('utf-8'))

                    except Exception as e: logging.error(f"Error sending UDP port: {e}")

                else: logging.error("GET_UDP_PORT requested but UDP socket not ready.")

            elif msg_str == "USERNAME_TAKEN":

                self.comm.username_taken_signal.emit()

            else: # Assume it's a chat message

                self.comm.msg_signal.emit(msg_str)



        except UnicodeDecodeError:

            logging.warning(f"Received non-JSON, non-UTF8 message. Ignoring. Bytes: {message_bytes[:100].hex()}")

        except Exception as e:

            logging.error(f"Error processing message: {e}", exc_info=True)



    def handle_json_command(self, msg_data: dict):

        """Handles commands received as JSON objects."""

        command = msg_data.get("command")

        payload = msg_data.get("payload", {})

        logging.debug(f"Handling JSON command: {command}")



        try:

            if command == "media_status":

                target_user = payload.get("username")

                if target_user == self.username: return # Ignore self-updates

                widget = self.video_widgets.get(target_user)

                if widget:

                    is_muted = payload.get("is_muted")

                    is_video_on = payload.get("is_video_on")

                    widget.update_status(is_muted=is_muted, is_video_on=is_video_on)

                    if is_video_on is False: widget.clear_frame() # Clear frame if video turned off

                else: logging.warning(f"Received media_status for unknown user: {target_user}")



            elif command == "file_list":

                self.update_file_list(payload)



            elif command == "initiate_upload": # Server tells us to start sending a file

                filename = payload.get("filename", "N/A")

                transfer_id = payload.get("transfer_id", "N/A")

                logging.info(f"Received 'initiate_transfer' request. Starting send thread for '{filename}' (ID: {transfer_id}).")

                threading.Thread(target=self.send_file, args=(payload,), name=f"FileSend_{transfer_id}", daemon=True).start()



            elif command == "handshake_ok": # Server confirmed handshake

                logging.info("Handshake with server complete. Requesting file list.")

                if hasattr(self, "session_info_bar"):
                    self.session_info_bar.update_status("Connected", SUCCESS_COLOR)

                self.send_command("get_file_list", {})



            elif command == "transfer_error": # Server reported an error during file transfer

                reason = payload.get("reason", "Unknown error")

                transfer_id = payload.get("transfer_id", "N/A")

                logging.error(f"Received transfer error from server (ID: {transfer_id}): {reason}")

                self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: File transfer failed: {reason}</font>")

                # Clean up if it was an incoming transfer

                if transfer_id in self.incoming_files:

                    logging.info(f"Cleaning up failed download for {transfer_id}")

                    transfer = self.incoming_files.pop(transfer_id)

                    try:

                        if not transfer["file_handle"].closed: transfer["file_handle"].close()

                    except Exception: pass

                    self.progress_bar.setVisible(False)


            elif command == "file_download_ack":
                owner = payload.get("owner")
                filename = payload.get("filename", "shared file")
                downloader = payload.get("downloader", "A participant")
                if owner == self.username:
                    self.append_message(
                        f"<font color='{SUCCESS_COLOR}'>SYSTEM: {downloader} downloaded '{filename}'.</font>"
                    )
                else:
                    logging.debug(
                        "Received file_download_ack for another owner: %s", owner
                    )



            elif command == "user_starting_tcp_share": # Another user started TCP share

                username = payload.get("username")

                if username and username != self.username:

                    logging.info(f"User '{username}' is starting a TCP share.")

                    self.current_screen_sharer = username

                    self.update_view_layout()



            elif command == "user_stopping_tcp_share": # Another user stopped TCP share

                username = payload.get("username")

                logging.debug(f"[RECV STOP SHARE] Received for '{username}'. Current sharer='{self.current_screen_sharer}'") # << DEBUG LOG



                if username == self.username:

                    logging.debug("[RECV STOP SHARE] Ignored self-broadcast.")

                    return # Do nothing



                # Only act if the stopping user *was* the current sharer

                if username and self.current_screen_sharer == username:

                    logging.info(f"[RECV STOP SHARE] Processing stop from '{username}'.") # << INFO LOG

                    self.current_screen_sharer = None

                    logging.debug("[RECV STOP SHARE] Calling clear_frame on presenter widget.") # << DEBUG LOG

                    self.presenter_view.screen_share_widget.clear_frame() # Ensure frame clears

                    self.clear_speaker_name()

                    if self.speaker_name_timer.isActive():

                        self.speaker_name_timer.stop()



                    logging.debug("[RECV STOP SHARE] Calling update_view_layout to switch back.") # << DEBUG LOG

                    self.update_view_layout()

                    logging.debug("[RECV STOP SHARE] Returned from update_view_layout.") # << DEBUG LOG



                elif username:

                    # Log if we received a stop command but didn't think that user was sharing

                    logging.warning(f"[RECV STOP SHARE] Received from '{username}', but current sharer is '{self.current_screen_sharer}'. State mismatch? Ignoring stop.")



            else:

                logging.warning(f"Received unhandled JSON command: {command}")



        except Exception as e:

            logging.error(f"Error handling JSON command '{command}': {e}", exc_info=True)



    def update_self_video_frame(self, frame: np.ndarray):
        """Updates the self-view widget(s) with the latest frame."""
        
        # If we are screen sharing, the 'frame' is our screen.
        # It must go to the main presenter widget AND our self-view PiP.
        if self.is_screen_sharing:
            self.presenter_view.screen_share_widget.set_frame(frame)
            self.self_view_widget.set_frame(frame)
        
        # If we are just using our webcam (not screen sharing)
        elif self.is_video_on:
            self.self_view_widget.set_frame(frame)



    def handle_tcp_screen_frame(self, data: bytes):

        """Processes a raw TCP screen frame packet."""

        try:

            prefix_len = len(b'S_FRAME:')

            header_end = prefix_len + config.USERNAME_HEADER_LENGTH

            if len(data) <= header_end:

                logging.warning(f"Received truncated TCP screen frame. Length: {len(data)}")

                return



            username = data[prefix_len:header_end].strip().decode('utf-8')

            raw_frame_data = data[header_end:]



            # Put in video queue with type 'T' (TCP)

            self.video_processing_queue.put((b'T', username, raw_frame_data))



        except UnicodeDecodeError:

            logging.warning("Failed to decode username from TCP screen frame.")

        except Exception as e:

            logging.error(f"Error queueing received TCP screen data: {e}", exc_info=True)



    def handle_received_video_data(self, ptype: bytes, data: bytes):

        """Handles raw UDP video/screen data, extracts username, puts in queue."""

        try:

            if len(data) <= config.USERNAME_HEADER_LENGTH:

                logging.warning(f"Received truncated video packet (type {ptype.decode(errors='ignore')}). Length: {len(data)}")

                return

            username = data[:config.USERNAME_HEADER_LENGTH].strip().decode('utf-8')

            raw_frame_data = data[config.USERNAME_HEADER_LENGTH:]

            self.video_processing_queue.put((ptype, username, raw_frame_data))

        except UnicodeDecodeError:

            logging.warning("Failed to decode username from video packet.")

        except Exception as e:

            logging.error(f"Error queueing received video data: {e}", exc_info=True)



    def handle_received_audio_data(self, data: bytes):

        """Handles raw UDP audio data, extracts username, decodes, puts in queue."""

        try:

            if len(data) <= config.USERNAME_HEADER_LENGTH:

                logging.warning(f"Received truncated audio packet. Length: {len(data)}")

                return

            username = data[:config.USERNAME_HEADER_LENGTH].strip().decode('utf-8')

            encoded_bytes = data[config.USERNAME_HEADER_LENGTH:]

            if not encoded_bytes: # Handle empty payload edge case

                logging.warning(f"Received audio packet with no payload from {username}")

                return



            # Decode mu-law audio

            decoded_data = decode_ulaw(np.frombuffer(encoded_bytes, dtype=np.uint8))

            dropped = 0
            while self.audio_playback_queue.qsize() >= config.AUDIO_JITTER_MAX_CHUNKS:
                try:
                    self.audio_playback_queue.get_nowait()
                    dropped += 1
                except queue.Empty:
                    break
            if dropped:
                logging.debug(f"Audio jitter buffer trimmed by {dropped} chunk(s) for {username}.")

            try:
                self.audio_playback_queue.put_nowait((username, decoded_data.tobytes()))
            except queue.Full:
                logging.debug("Audio playback queue full; dropping oldest chunk before enqueue.")
                try:
                    self.audio_playback_queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self.audio_playback_queue.put_nowait((username, decoded_data.tobytes()))
                except queue.Full:
                    logging.warning("Unable to enqueue audio chunk after drop; discarding latest chunk.")

        except UnicodeDecodeError:

            logging.warning("Failed to decode username from audio packet.")

        except Exception as e:

            logging.error(f"Error handling received audio: {e}", exc_info=True)



    def handle_processed_frame(self, ptype: bytes, username: str, frame: np.ndarray):
        """Displays a decoded frame in the appropriate widget."""
        try:
            if ptype == b'S' or ptype == b'T': # Screen share (UDP or TCP)
                
                # --- START OF FIX ---
                #
                # We NO LONGER change state here. We ONLY display the frame
                # if the state (set by JSON command) is already correct.
                #
                if self.current_screen_sharer == username:
                    # If we are in presenter mode and the packet is from the
                    # correct sharer, display the frame.
                    self.presenter_view.screen_share_widget.set_frame(frame)
                else:
                    # This is a stray packet from a user who is not the
                    # current sharer (or the share has ended). Ignore it.
                    logging.debug(f"Ignored stray screen share packet from {username} (current sharer is {self.current_screen_sharer}).")
                #
                # --- END OF FIX ---

            elif ptype == b'V': # Webcam video
                
                # --- CLEANED UP WEBCAM LOGIC ---
                # (The old logic here was also flawed and could cause a 
                # webcam packet to incorrectly stop a share)
                #
                widget = self.video_widgets.get(username)
                if widget:
                    # Only set the frame if the widget's state (set by JSON)
                    # is that the video is ON.
                    if widget.is_video_on:
                        widget.set_frame(frame)
                    else:
                        logging.debug(f"Ignored stray video frame from {username} (their video is off).")

        except Exception as e:
            logging.error(f"Error handling processed frame for {username}: {e}", exc_info=True)



    def update_user_list_and_grid(self, users: list):

        """Updates the user list widget and adds/removes video widgets."""

        logging.info(f"Updating user list: {users}")

        self.user_list_widget.clear()

        self.user_list_widget.addItems(sorted(users))



        # Determine who joined and left

        other_users = {user for user in users if user != self.username}

        current_widgets = set(self.video_widgets.keys())

        users_who_left = current_widgets - other_users

        users_who_joined = other_users - current_widgets



        # Remove widgets for users who left

        for user in users_who_left:

            logging.info(f"User left: {user}. Removing widget.")

            widget = self.video_widgets.pop(user, None)

            if widget:

                widget.deleteLater() # Schedule deletion

            # Stop and remove audio activity timer

            timer = self.audio_activity_timers.pop(user, None)

            if timer: timer.stop()



        # Add widgets for users who joined

        for user in users_who_joined:

            logging.info(f"User joined: {user}. Adding widget.")

            self.video_widgets[user] = VideoWidget(user)

            # Create timer for audio activity indicator

            timer = QTimer(self)

            timer.setSingleShot(True)

            timer.timeout.connect(lambda u=user: self.set_user_not_speaking(u))

            self.audio_activity_timers[user] = timer



        # Handle case where the screen sharer leaves

        if self.current_screen_sharer and self.current_screen_sharer in users_who_left:

            logging.info(f"Screen sharer '{self.current_screen_sharer}' left.")

            self.current_screen_sharer = None

            self.presenter_view.screen_share_widget.clear_frame()

            self.clear_speaker_name()

            if self.speaker_name_timer.isActive(): self.speaker_name_timer.stop()



        # Rebuild the gallery view layout

        self.update_view_layout()

        if hasattr(self, "session_info_bar"):
            self.session_info_bar.update_participants(len(users))



    def set_user_not_speaking(self, username: str):

        """Callback for QTimer to turn off the speaking indicator."""

        widget = self.video_widgets.get(username)

        if widget:

            widget.set_speaking(False)



    def send_chat_message(self):

        """Sends the text from the input field as a chat message."""

        message = self.message_input.text().strip()

        if message and self.tcp_socket:

            logging.info(f"Sending chat message: {message}")

            try:

                self.safe_send_tcp(message.encode('utf-8')) # Use safe sender

                # Display own message locally immediately

                self.append_message(f"<font color='{ACCENT_COLOR}'>You:</font> {message}")

                self.message_input.clear()

            except Exception as e:

                logging.error(f"Error sending chat message: {e}", exc_info=True)

                self.append_message(f"SYSTEM: Failed to send chat. Connection error?")



    def append_message(self, message: str):
        """Parses legacy chat strings and pushes them into the bubble list."""

        if not message:
            return

        raw = message.strip()
        plain = html.unescape(re.sub(r"<[^>]+>", "", raw)).strip()

        sender = ""
        text = plain
        bubble_type = "system"
        color_override = None

        color_match = re.search(r"color=['\"]([^'\"]+)['\"]", raw)
        if color_match:
            color_override = color_match.group(1)

        if plain.upper().startswith("SYSTEM:"):
            text = plain[len("SYSTEM:"):].strip()
        else:
            if ":" in plain:
                sender, text = plain.split(":", 1)
                sender = sender.strip()
                text = text.strip()
            else:
                sender = ""
                text = plain

            if sender.lower() in ("you", self.username.lower()):
                bubble_type = "self"
                sender = "You"
            else:
                bubble_type = "other"
                if not sender:
                    sender = "Participant"

        if bubble_type == "system":
            sender = ""

        self._add_chat_message(sender, text, bubble_type, color_override)

        if bubble_type == "other" and not self.is_chat_tab_active():
            self.chat_has_unread = True
            self.chat_toggle_btn.set_badge_visible(True)

    def _add_chat_message(self, sender: str, text: str, bubble_type: str, color: str | None = None) -> None:
        if not text:
            return

        item = QListWidgetItem()
        bubble = ChatBubbleWidget(sender, text, bubble_type, color)
        item.setSizeHint(bubble.sizeHint())
        self.chat_list.addItem(item)
        self.chat_list.setItemWidget(item, bubble)
        self.chat_list.scrollToBottom()

    def is_chat_tab_active(self) -> bool:
        return self.is_side_panel_visible and self.current_side_panel_tab == 2

    def is_files_tab_active(self) -> bool:
        return self.is_side_panel_visible and self.current_side_panel_tab == 1





    # --- File Transfer Methods ---

    def select_files_to_share(self):

        """Opens a dialog to select files and adds them to the shared list."""

        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Share")

        if files:

            new_files_added = False

            for path in files:

                 # Avoid adding duplicates

                if not any(f['filepath'] == path for f in self.my_shared_files):

                    try:

                        filesize = os.path.getsize(path)

                        filename = os.path.basename(path)

                        self.my_shared_files.append({"filepath": path, "filename": filename, "filesize": filesize})

                        new_files_added = True

                        logging.info(f"Added '{filename}' ({filesize} bytes) to shared files.")

                    except OSError as e:

                        logging.error(f"Could not get info for file {path}: {e}")

                        self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Error adding file {os.path.basename(path)}.</font>")

            # If new files were added, notify the server

            if new_files_added:

                self.broadcast_my_shared_files()



    def broadcast_my_shared_files(self):

        """Sends the current list of shared files to the server."""

        logging.info(f"Broadcasting updated shared file list (count: {len(self.my_shared_files)}).")

        # Send only filename and size, not the full path

        payload = [{"filename": f["filename"], "filesize": f["filesize"]} for f in self.my_shared_files]

        self.send_command("share_files", payload)

        self.append_message(f"<font color='{SUCCESS_COLOR}'>SYSTEM: Your shared file list updated.</font>")



    def update_file_list(self, files: list):

        """Updates the file list widget with files shared by others."""

        logging.info(f"Updating file list widget with {len(files)} items.")

        new_remote_keys = set()
        has_new_remote = False

        self.file_list_widget.clear()

        for info in files:

            # Don't list own files
            if info.get("owner") == self.username:
                continue

            try:

                filename = info.get('filename', 'Unknown File')
                filesize = int(info.get('filesize', 0))
                owner = info.get('owner', 'Unknown Owner')

                key = (owner, filename, filesize)
                new_remote_keys.add(key)
                if key not in self.known_shared_file_keys:
                    has_new_remote = True

                size_mb = filesize / (1024 * 1024)
                item_text = f"{filename} ({size_mb:.2f} MB) - from {owner}"

                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, info) # Store full info in the item
                self.file_list_widget.addItem(item)

            except Exception as e:

                logging.error(f"Error processing file list item: {info} - {e}", exc_info=True)

        if has_new_remote and not self.is_files_tab_active():
            self.files_have_unread = True
            if hasattr(self, "files_toggle_btn"):
                self.files_toggle_btn.set_badge_visible(True)
        elif self.is_files_tab_active():
            self.files_have_unread = False
            if hasattr(self, "files_toggle_btn"):
                self.files_toggle_btn.set_badge_visible(False)

        self.known_shared_file_keys = new_remote_keys



    def download_selected_file(self):

        """Initiates a download request for the selected file."""

        selected = self.file_list_widget.selectedItems()

        if not selected:

            self.append_message(f"<font color='{WARNING_COLOR}'>SYSTEM: Select a file to download.</font>")

            return



        file_info = selected[0].data(Qt.ItemDataRole.UserRole)

        if not file_info:

            logging.error("Selected file item has no associated data.")

            self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Internal error selecting file.</font>")

            return



        filename = file_info.get('filename', 'downloaded_file')

        owner = file_info.get('owner')

        try:

            # Ensure filesize is stored as an integer, not a string from JSON

            filesize = int(file_info.get('filesize', 0))

        except (ValueError, TypeError):

            logging.error(f"Invalid filesize in file_info: {file_info.get('filesize')}")

            filesize = 0



        if not owner or filename == 'downloaded_file': # Basic validation

            logging.error(f"Invalid file info selected: {file_info}")

            self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Invalid file information selected.</font>")

            return



        # Prompt user for save location

        save_path, _ = QFileDialog.getSaveFileName(self, "Save File As...", filename)

        if not save_path:

            logging.info("File download cancelled by user.")

            return



        # Create unique transfer ID

        transfer_id = f"{self.username}_download_{owner}_{filename}"

        logging.info(f"Attempting to download '{filename}' from '{owner}' as ID: {transfer_id} to {save_path}")



        # Prevent duplicate downloads

        if transfer_id in self.incoming_files:

            logging.warning(f"Download for {transfer_id} is already in progress.")

            self.append_message(f"<font color='{WARNING_COLOR}'>SYSTEM: Download for '{filename}' is already in progress.</font>")

            return



        # Open file handle and prepare tracking info

        try:

            file_handle = open(save_path, 'wb')

            self.incoming_files[transfer_id] = {

                "filepath": save_path,

                "file_handle": file_handle,

                "filesize": filesize,

                "progress": 0,
                "owner": owner,
                "filename": filename

            }

        except IOError as e:

            logging.error(f"Failed to open file for writing: {save_path} - {e}", exc_info=True)

            self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Error opening file '{os.path.basename(save_path)}' for download.</font>")

            return



        # Show progress bar and send request to server

        self.progress_bar.setValue(0)

        self.progress_bar.setVisible(True)

        self.progress_bar.setFormat("%p% - Downloading...")

        self.append_message(f"<font color='{ACCENT_COLOR}'>SYSTEM: Requesting '{filename}'...</font>")

        self.send_command("request_file", file_info) # Send original info (owner, filename, size)

        logging.info(f"Sent 'request_file' command for ID: {transfer_id}")



    def send_file(self, payload: dict):
        """Worker thread function to send a requested file in chunks via TCP."""
        filename = payload.get("filename", "N/A")
        transfer_id = payload.get("transfer_id", "N/A")

        # --- MODIFIED BLOCK FOR DEBUGGING ---
        logging.info(f"[SEND {transfer_id}] Received request for file '{filename}'.")
        filepath = next((f["filepath"] for f in self.my_shared_files if f["filename"] == filename), None)

        if not filepath:
            logging.error(f"[SEND {transfer_id}] CRITICAL: Cannot find file '{filename}' in my shared list.")
            logging.error(f"[SEND {transfer_id}] My shared list contains: {[f['filename'] for f in self.my_shared_files]}")
            # --- We must notify the server of the failure ---
            self.send_command("transfer_error", {"reason": f"File '{filename}' not found by owner.", "transfer_id": transfer_id})
            return
       
        if not os.path.exists(filepath):
            logging.error(f"[SEND {transfer_id}] CRITICAL: Filepath does not exist: {filepath}")
            self.send_command("transfer_error", {"reason": f"File '{filename}' no longer exists on owner's computer.", "transfer_id": transfer_id})
            return

        logging.info(f"[SEND {transfer_id}] Starting send for '{filename}' from {filepath}")
        file_handle = None
        try:
            # Prepare header components
            transfer_id_bytes = transfer_id.encode('utf-8')
            id_len_bytes = struct.pack('>H', len(transfer_id_bytes)) # Pack ID length as 2-byte unsigned short

            sent_bytes = 0
            file_handle = open(filepath, 'rb')
            logging.debug(f"[SEND {transfer_id}] File opened successfully.")

            # Read and send file in chunks
            while chunk := file_handle.read(4096): # Read up to 4KB chunks
                if not self.is_running: # Check if app is closing
                    logging.warning(f"[SEND {transfer_id}] Stopping mid-transfer due to shutdown.")
                    return
                # Construct message: PREFIX + ID_LEN + ID + CHUNK_DATA
                message = b'FILE_CHUNK:' + id_len_bytes + transfer_id_bytes + chunk
                logging.debug(f"[SEND {transfer_id}] Sending chunk, {len(chunk)} bytes.")
                self.safe_send_tcp(message) # Use thread-safe sender
                sent_bytes += len(chunk)

            file_handle.close(); file_handle = None # Ensure handle is closed and None after loop
            logging.debug(f"[SEND {transfer_id}] Finished reading file, total bytes read: {sent_bytes}")

            # Send end marker
            end_message = b'FILE_END:' + id_len_bytes + transfer_id_bytes
            logging.info(f"[SEND {transfer_id}] Sending END marker.")
            self.safe_send_tcp(end_message)

            logging.info(f"[SEND {transfer_id}] Finished sending file: '{filename}', {sent_bytes} bytes.")

        except FileNotFoundError:
            logging.error(f"[SEND {transfer_id}] File not found during sending: {filepath}")
            # Optionally notify server/requester of error here
        except (OSError, ssl.SSLError) as e: # Catch errors from safe_send_tcp
            logging.error(f"[SEND {transfer_id}] Socket error sending file '{filename}': {e}", exc_info=True)
            QTimer.singleShot(0, lambda: self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Error sending file '{filename}'. Connection lost?</font>"))
        except Exception as e:
            logging.error(f"[SEND {transfer_id}] Unexpected error sending file '{filename}': {e}", exc_info=True)
            QTimer.singleShot(0, lambda: self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Unexpected error sending file '{filename}'.</font>"))
        finally:
             # Ensure file handle is closed even if errors occurred mid-send
            if file_handle and not file_handle.closed:
                try: file_handle.close(); logging.warning(f"[SEND {transfer_id}] Closed file handle in finally block.")
                except Exception as close_err: logging.error(f"[SEND {transfer_id}] Error closing file handle in finally block: {close_err}")

    def handle_incoming_file_chunk(self, data: bytes):
        """Processes a received file chunk."""
        transfer = None
        transfer_id = "UNKNOWN"
        try:
            # --- Header Parsing & Validation ---
            prefix = b'FILE_CHUNK:'; prefix_len = len(prefix)
            header_struct_format = '>H'; header_len = struct.calcsize(header_struct_format)
            min_expected_len = prefix_len + header_len
            if len(data) < min_expected_len:
                logging.error(f"Malformed FILE_CHUNK (too short): {len(data)} bytes."); return
            id_len = struct.unpack(header_struct_format, data[prefix_len : prefix_len + header_len])[0]
            id_start = prefix_len + header_len
            if len(data) < id_start + id_len:
                logging.error(f"Malformed FILE_CHUNK (ID length mismatch). Declared={id_len}, Available={len(data)-id_start}"); return
            # --- End Validation ---

            transfer_id_bytes = data[id_start : id_start + id_len]
            chunk = data[id_start + id_len :]
            transfer_id = transfer_id_bytes.decode('utf-8')
            logging.debug(f"[RECV {transfer_id}] Received CHUNK, {len(chunk)} bytes.")

            # Find corresponding transfer info
            if transfer_id in self.incoming_files:
                transfer = self.incoming_files[transfer_id]

                # Check if file handle is still open
                if transfer["file_handle"].closed:
                    logging.warning(f"[RECV {transfer_id}] Received chunk for already closed file handle. Ignoring.")
                    return # Don't try to write or update progress

                # Write chunk to file and update progress
                transfer["file_handle"].write(chunk)
                transfer["progress"] += len(chunk)
                logging.debug(f"[RECV {transfer_id}] Progress: {transfer['progress']} / {transfer.get('filesize', '?')}")

                # Update progress bar in GUI thread
                filesize = transfer.get("filesize")
                if filesize is not None and filesize > 0:
                    progress_percent = int((transfer["progress"] / filesize) * 100)
                    QTimer.singleShot(0, lambda p=progress_percent: self.progress_bar.setValue(p))
                else: # Handle zero-size files or unknown size
                    QTimer.singleShot(0, lambda: self.progress_bar.setValue(100 if filesize == 0 else 0))
            else:
                logging.warning(f"[RECV {transfer_id}] Received chunk for unknown/completed transfer.")

        except struct.error as e:
            logging.error(f"Struct unpacking error (CHUNK ID '{transfer_id}'): {e}. Data: {data[:50].hex()}...", exc_info=True)
        except UnicodeDecodeError as e:
            logging.error(f"Unicode decode error (CHUNK ID): {e}. Bytes: {transfer_id_bytes}", exc_info=True)
        except IOError as e: # Handle file write errors
            logging.error(f"[RECV {transfer_id}] File write error: {e}", exc_info=True)
            # Clean up the failed transfer
            if transfer and "file_handle" in transfer and not transfer["file_handle"].closed:
                try: transfer["file_handle"].close()
                except Exception: pass
            if transfer_id in self.incoming_files: del self.incoming_files[transfer_id]
            QTimer.singleShot(0, lambda: self.append_message(f"<font color='{DANGER_COLOR}'>SYSTEM: Error writing downloaded file.</font>"))
            QTimer.singleShot(0, self.progress_bar.setVisible(False))
        except Exception as e:
            logging.error(f"[RECV {transfer_id}] Unexpected error handling file chunk: {e}", exc_info=True)

    def handle_incoming_file_end(self, data: bytes):
        """Finalizes an incoming file transfer (simplified version)."""
        transfer_id = "UNKNOWN"
        transfer_id_bytes = b''
        try:
            # --- Header Parsing & Validation ---
            prefix = b'FILE_END:'; prefix_len = len(prefix)
            header_struct_format = '>H'; header_len = struct.calcsize(header_struct_format)
            expected_len = prefix_len + header_len
            if len(data) < expected_len:
                logging.error(f"Malformed FILE_END (too short): {len(data)} bytes."); return
            id_len = struct.unpack(header_struct_format, data[prefix_len : prefix_len + header_len])[0]
            id_start = prefix_len + header_len
            if len(data) < id_start + id_len:
                    logging.error(f"Malformed FILE_END (ID length mismatch). Declared={id_len}, Available={len(data)-id_start}"); return
            # --- End Validation ---

            transfer_id_bytes = data[id_start : id_start + id_len]
            transfer_id = transfer_id_bytes.decode('utf-8')
            logging.info(f"[RECV {transfer_id}] Received END marker. Finalizing.")

            if transfer_id in self.incoming_files:
                # Pop removes the entry, preventing further chunks from being processed
                transfer = self.incoming_files.pop(transfer_id)

                # Close the file handle
                if not transfer["file_handle"].closed:
                    logging.debug(f"[RECV {transfer_id}] Closing file handle.")
                    transfer["file_handle"].close()
                else:
                    logging.warning(f"[RECV {transfer_id}] File handle already closed for {transfer_id}.")

                # Final checks and UI updates
                final_filepath = transfer.get('filepath', 'Unknown File')
                final_progress = transfer.get('progress', 0)
                final_expected = transfer.get('filesize', -1)

                if final_expected >= 0 and final_progress != final_expected:
                    logging.warning(f"[RECV {transfer_id}] Size mismatch! Expected={final_expected}, Received={final_progress}.")
                    QTimer.singleShot(0, lambda: self.append_message(f"<font color='{WARNING_COLOR}'>SYSTEM: Downloaded '{os.path.basename(final_filepath)}' (size mismatch).</font>"))
                else:
                    logging.info(f"[RECV {transfer_id}] Download successful. Size={final_progress}.")
                    QTimer.singleShot(0, lambda: self.append_message(f"<font color='{SUCCESS_COLOR}'>SYSTEM: Downloaded '{os.path.basename(final_filepath)}'.</font>"))

                owner_username = transfer.get('owner') if transfer else None
                downloaded_filename = transfer.get('filename') if transfer else None
                if owner_username and owner_username != self.username:
                    ack_payload = {
                        "filename": downloaded_filename or os.path.basename(final_filepath),
                        "filesize": final_progress,
                        "owner": owner_username,
                        "downloader": self.username
                    }
                    self.send_command("file_download_ack", ack_payload)

                # --- CORRECTED UI LOGIC ---
                # The file transfer is complete. We will *directly* update the
                # progress bar, bypassing the QTimer queue. This forces the
                # UI to render the "Complete" state even on fast transfers.

                # 1. Set values directly.
                self.progress_bar.setValue(100)
                self.progress_bar.setFormat("Download Complete!")

                # 2. Ensure it's visible (in case it was hidden by a race condition)
                self.progress_bar.setVisible(True)

                # 3. Use QTimer.singleShot *only* to hide the bar later.
                # This gives the user time to see the "Complete!" message.
                QTimer.singleShot(3000, lambda: self.progress_bar.setVisible(False))
                # --- END CORRECTION ---

                logging.info(f"[RECV {transfer_id}] Successfully processed FILE_END.")
            else:
                logging.warning(f"[RECV {transfer_id}] Received FILE_END for unknown/completed transfer.")

        except (struct.error, UnicodeDecodeError) as e:
            logging.error(f"Error parsing FILE_END header: {e}. Data: {data[:50].hex()}...", exc_info=True)
            QTimer.singleShot(0, self.progress_bar.setVisible(False)) # Hide bar on error
        except IOError as e: # File closing error
            logging.error(f"File close error finalizing '{transfer_id}': {e}", exc_info=True)
            QTimer.singleShot(0, self.progress_bar.setVisible(False)) # Hide bar on error
        except Exception as e:
            logging.error(f"Unexpected error finalizing '{transfer_id}': {e}", exc_info=True)
            QTimer.singleShot(0, self.progress_bar.setVisible(False)) # Hide bar on error
            # Failsafe: Ensure removed if error happened after ID parse but before pop
            if transfer_id != "UNKNOWN" and transfer_id in self.incoming_files:
                self.incoming_files.pop(transfer_id)


    # --- Cleanup and Shutdown ---
    def handle_connection_failure(self, manual_close=True):
        """Handles connection loss triggered by network threads."""
        if not self.is_running: return # Avoid multiple calls
        logging.warning("handle_connection_failure called.")
        self.is_running = False # Stop all loops/threads

        if hasattr(self, "session_info_bar"):
            self.session_info_bar.update_status("Disconnected", DANGER_COLOR)
            self.session_info_bar.update_participants(0)

        # Show error message only if not manually closing
        if manual_close:
            QTimer.singleShot(0, lambda: QMessageBox.critical(self, "Connection Error", "Could not connect to or lost connection with the server."))

        self.cleanup_resources()
        # Schedule the window close event to run after cleanup
        QTimer.singleShot(100, super(ChatWindow, self).close)

    def handle_username_taken(self):
        """Handles the 'username taken' message from the server."""
        logging.warning("Username taken signal received.")
        if hasattr(self, "session_info_bar"):
            self.session_info_bar.update_status("Username taken", WARNING_COLOR)
        QMessageBox.warning(self, "Username Error", "That username is already taken in this session.")
        self.close() # Close the application

    def cleanup_resources(self):
        """Stops threads, closes sockets, streams, and file handles."""
        # Prevent recursive cleanup calls
        if hasattr(self, '_cleanup_called') and self._cleanup_called:
            logging.debug("Cleanup already called.")
            return
        self._cleanup_called = True
        logging.info("Cleaning up resources...")
        self.is_running = False # Ensure all loops stop

        # Close TCP Socket
        if self.tcp_socket:
            logging.debug("Closing TCP socket...")
            sock = self.tcp_socket; self.tcp_socket = None # Avoid race conditions
            try: sock.shutdown(socket.SHUT_RDWR) # Signal intent to close
            except (OSError, ssl.SSLError): pass # Ignore errors if already closed
            try: sock.close()
            except (OSError, ssl.SSLError): pass
            logging.debug("TCP socket closed.")

        # Close UDP Socket
        if self.udp_socket:
            logging.debug("Closing UDP socket...")
            sock = self.udp_socket; self.udp_socket = None
            try: sock.close()
            except OSError: pass
            logging.debug("UDP socket closed.")

        # Stop audio input thread (signals loop to exit and close stream)
        self.stop_audio_stream()
        self.stop_system_audio_share(announce=False)

        audio_thread = self.audio_send_thread
        if audio_thread and audio_thread.is_alive():
            if threading.current_thread() is audio_thread:
                logging.debug("Cleanup running on audio capture thread; skipping self-join.")
            else:
                logging.debug("Waiting for audio send thread to terminate...")
                audio_thread.join(timeout=1.5)
                if audio_thread.is_alive():
                    logging.warning("Audio send thread did not terminate within timeout.")
        self.audio_send_thread = None

        # Close audio output stream
        if self.audio_stream_out:
            logging.debug("Stopping and closing audio output stream...")
            stream = self.audio_stream_out; self.audio_stream_out = None
            try:
                if stream.is_active(): stream.stop_stream()
                stream.close()
                logging.debug("Audio output stream closed.")
            except Exception as e: logging.warning(f"Error closing audio output: {e}")

        playback_thread = self.audio_playback_thread
        if playback_thread and playback_thread.is_alive():
            if threading.current_thread() is playback_thread:
                logging.debug("Cleanup running on playback thread; skipping self-join.")
            else:
                logging.debug("Waiting for audio playback thread to terminate...")
                playback_thread.join(timeout=1.5)
                if playback_thread.is_alive():
                    logging.warning("Audio playback thread did not terminate within timeout.")
        self.audio_playback_thread = None

        # Terminate PyAudio
        if self.p_audio:
            logging.debug("Terminating PyAudio...")
            pa = self.p_audio; self.p_audio = None
            try: pa.terminate()
            except Exception as e: logging.warning(f"Error terminating PyAudio: {e}")
            logging.debug("PyAudio terminated.")

        # Release video capture
        if self.video_cap:
            logging.debug("Releasing video capture...")
            cap = self.video_cap; self.video_cap = None # Signals video thread to stop
            try: cap.release() # Release immediately
            except Exception as e: logging.warning(f"Error releasing video capture: {e}")
            logging.debug("Video capture released.")

        # Close any open incoming file handles
        logging.debug(f"Closing {len(self.incoming_files)} incoming file handles...")
        for transfer_id in list(self.incoming_files.keys()): # Iterate over keys copy
            transfer = self.incoming_files.pop(transfer_id)
            try:
                handle = transfer.get("file_handle")
                if handle and not handle.closed:
                    handle.close()
                    logging.debug(f"Closed dangling file handle for {transfer_id}")
            except Exception as e:
                logging.error(f"Error closing file handle for {transfer_id} during cleanup: {e}")
        self.incoming_files.clear() # Ensure dictionary is empty
        logging.info("Cleanup finished.")


    def closeEvent(self, event):
        """Overrides the window close event to ensure cleanup."""
        logging.info("Close event triggered.")
        if self.is_running:
            self.cleanup_resources() # Perform cleanup if still running
        event.accept() # Allow the window to close

# --- Stylesheet ---
STYLE_SHEET = f"""
QWidget {{ background-color: {PRIMARY_BG}; color: {TEXT_PRIMARY}; font-family: "Segoe UI", Arial, sans-serif; font-size: 14px; }}
QDialog {{ background-color: {SURFACE_BG}; }}
QTextEdit, QListWidget {{ background-color: {SURFACE_BG}; border: 1px solid {BORDER_COLOR}; border-radius: 6px; padding: 6px; color: {TEXT_PRIMARY}; }}
QLineEdit {{ background-color: {CARD_BG}; border: 1px solid {BORDER_COLOR}; border-radius: 6px; padding: 8px; font-size: 14px; color: {TEXT_PRIMARY}; }}
QPushButton {{ background-color: {ACCENT_COLOR}; color: {TEXT_PRIMARY}; border: none; padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 14px; }}
QPushButton:hover {{ background-color: {ACCENT_HOVER}; }}
QPushButton:pressed {{ background-color: {ACCENT_PRESSED}; }}
QPushButton:disabled {{ background-color: {BORDER_COLOR}; color: {TEXT_MUTED}; }}
QSplitter::handle {{ background-color: {BORDER_COLOR}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QListWidget::item:hover {{ background-color: {CARD_BG}; }}
QListWidget::item:selected {{ background-color: {ACCENT_COLOR}; color: {TEXT_PRIMARY}; }}
QScrollBar:vertical {{ border: none; background: {SURFACE_BG}; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {BORDER_COLOR}; min-height: 20px; border-radius: 5px; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0px; }}
QLabel {{ background-color: transparent; color: {TEXT_PRIMARY}; }}
"""

# --- Main Execution ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET) # Apply stylesheet
    logging.info("Application starting...")

    default_server_ip = resolve_default_server_ip()
    logging.info(f"Default server IPv4: {default_server_ip}")

    # Show login dialog
    login_dialog = LoginDialog(default_server_ip)
    if login_dialog.exec() == QDialog.DialogCode.Accepted:
        server_ip, username, session_id = login_dialog.get_details()

        # Basic input validation
        if not username.strip() or not session_id.strip():
            QMessageBox.warning(None, "Invalid Input", "Username and Session ID cannot be empty.")
            logging.warning("Empty username or session ID provided.")
            sys.exit(1)
        else:
            # Start main chat window if login is successful
            logging.info(f"Login successful: User='{username.strip()}', Session='{session_id.strip()}', Server='{server_ip.strip()}'")
            chat_window = ChatWindow(server_ip.strip(), username.strip(), session_id.strip())
            chat_window.show()
            sys.exit(app.exec()) # Start the Qt event loop
    else:
        # User cancelled login
        logging.info("Login dialog cancelled.")
        sys.exit(0)