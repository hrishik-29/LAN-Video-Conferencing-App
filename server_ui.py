from __future__ import annotations

import asyncio
import logging
import socket
import sys
import threading
import time
from typing import Optional

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

import config
from server import Server


def detect_primary_ipv4() -> Optional[str]:
    """Attempt to determine the primary LAN IPv4 address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            candidate = probe.getsockname()[0]
            if candidate and not candidate.startswith("127."):
                return candidate
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            candidate = info[4][0]
            if candidate and not candidate.startswith("127."):
                return candidate
    except OSError:
        pass

    return None


class QtLogHandler(QObject, logging.Handler):
    """Bridges Python logging records into the Qt event loop."""

    log_message = pyqtSignal(str)

    def __init__(self) -> None:
        QObject.__init__(self)
        logging.Handler.__init__(self)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        self.setFormatter(formatter)
        self.setLevel(logging.INFO)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = self.format(record)
        except Exception:
            return
        self.log_message.emit(message)


class ServerWorker(QObject):
    """Runs the asyncio server inside a background thread."""

    server_started = pyqtSignal(tuple)
    server_stopped = pyqtSignal()
    server_error = pyqtSignal(str)
    snapshot_ready = pyqtSignal(dict)

    def __init__(self) -> None:
        super().__init__()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._server: Optional[Server] = None
        self._lock = threading.Lock()
        self._cleanup_default = True
        self._is_running = False

    def start(self, host: str, cleanup_storage: bool) -> bool:
        """Starts the server thread if not already active."""
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self._cleanup_default = cleanup_storage
            self._server = Server(host=host)
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            return True

    def stop(self, cleanup_storage: Optional[bool] = None) -> None:
        """Requests a graceful server shutdown."""
        with self._lock:
            loop = self._loop
            server = self._server
        if not loop or not server:
            return
        future = asyncio.run_coroutine_threadsafe(server.stop(cleanup_storage), loop)

        def _on_stopped(done_future: asyncio.Future) -> None:
            try:
                done_future.result()
            except Exception as exc:  # pragma: no cover - defensive
                self.server_error.emit(f"Failed to stop server: {exc}")

        future.add_done_callback(_on_stopped)

    def request_snapshot(self) -> None:
        """Asks the running server for a fresh state snapshot."""
        with self._lock:
            loop = self._loop
            server = self._server
            running = self._is_running
        if not loop or not server or not running:
            return
        future = asyncio.run_coroutine_threadsafe(server.get_state_snapshot(), loop)

        def _on_snapshot(done_future: asyncio.Future) -> None:
            try:
                snapshot = done_future.result()
            except Exception as exc:  # pragma: no cover - defensive
                self.server_error.emit(f"Snapshot failed: {exc}")
                return
            self.snapshot_ready.emit(snapshot)

        future.add_done_callback(_on_snapshot)

    def wait_until_stopped(self, timeout: Optional[float] = None) -> None:
        thread: Optional[threading.Thread]
        with self._lock:
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout)

    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    # --- Internal helpers -------------------------------------------------

    def _run(self) -> None:
        try:
            asyncio.run(self._async_entry())
        except Exception as exc:
            self.server_error.emit(str(exc))
        finally:
            with self._lock:
                self._loop = None
                self._server = None
                self._is_running = False
                thread = self._thread
                self._thread = None
            self.server_stopped.emit()
            if thread and thread.is_alive():
                # Thread is finishing naturally; nothing else to do.
                pass

    async def _async_entry(self) -> None:
        assert self._server is not None
        loop = asyncio.get_running_loop()
        with self._lock:
            self._loop = loop
            self._is_running = True
        try:
            await self._server.start(on_ready=self._handle_ready, cleanup_storage=self._cleanup_default)
        finally:
            with self._lock:
                self._is_running = False

    def _handle_ready(self, addr: Optional[tuple]) -> None:
        if addr is None:
            self.server_error.emit("Server failed to bind ports. Check logs for details.")
            return
        self.server_started.emit(addr)


class ServerDashboard(QWidget):
    """Simple control surface for starting/stopping the media server."""

    SNAPSHOT_INTERVAL_MS = 2000

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Server Control Console")
        self.resize(1024, 720)

        self.detected_ip: Optional[str] = detect_primary_ipv4()

        self.worker = ServerWorker()
        self.worker.server_started.connect(self.on_server_started)
        self.worker.server_stopped.connect(self.on_server_stopped)
        self.worker.server_error.connect(self.on_server_error)
        self.worker.snapshot_ready.connect(self.on_snapshot_ready)

        self.log_handler = QtLogHandler()
        self.log_handler.log_message.connect(self.append_log)
        logging.getLogger().addHandler(self.log_handler)

        self.poll_timer = QTimer(self)
        self.poll_timer.setInterval(self.SNAPSHOT_INTERVAL_MS)
        self.poll_timer.timeout.connect(self.worker.request_snapshot)

        self._install_fonts()
        self._apply_styles()
        self._build_ui()
        self._update_controls(False)

        self.append_log("Server dashboard ready.")

    # --- UI construction --------------------------------------------------

    def _install_fonts(self) -> None:
        font = QFont("Segoe UI", 10)
        QApplication.instance().setFont(font)

    def _apply_styles(self) -> None:
        accent = "#38bdf8"
        accent_hover = "#0ea5e9"
        accent_pressed = "#0284c7"
        danger = "#f87171"
        success = "#34d399"
        surface = "#111827"
        surface_alt = "#0f172a"
        panel = "#1e293b"
        outline = "#1f2a3b"

        self.setStyleSheet(
            f"""
            QWidget {{
                background-color: {surface_alt};
                color: #e2e8f0;
            }}
            QFrame, QTreeWidget, QTableWidget, QPlainTextEdit {{
                background-color: {surface};
                border: 1px solid {outline};
                border-radius: 8px;
            }}
            QLineEdit, QPlainTextEdit, QTableWidget::item, QTreeWidget::item {{
                background-color: {panel};
                border: 1px solid {outline};
                border-radius: 6px;
                selection-background-color: {accent_hover};
                selection-color: #0f172a;
            }}
            QPushButton {{
                background-color: {panel};
                padding: 8px 18px;
                border-radius: 20px;
                border: 1px solid {outline};
                color: #f1f5f9;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {accent_hover};
                border-color: {accent_hover};
                color: #0f172a;
            }}
            QPushButton:pressed {{
                background-color: {accent_pressed};
                border-color: {accent_pressed};
                color: #0f172a;
            }}
            QPushButton#startButton {{
                background-color: {accent};
                border-color: {accent};
                color: #0f172a;
            }}
            QPushButton#startButton:hover {{
                background-color: {accent_hover};
                border-color: {accent_hover};
            }}
            QPushButton#stopButton {{
                background-color: {danger};
                border-color: {danger};
                color: #0f172a;
            }}
            QPushButton#stopButton:hover {{
                background-color: #ef4444;
                border-color: #ef4444;
            }}
            QCheckBox {{
                spacing: 6px;
            }}
            QSplitter::handle {{
                background-color: {outline};
                width: 4px;
            }}
            QHeaderView::section {{
                background-color: {surface};
                border: none;
                padding: 6px 8px;
                font-weight: 600;
            }}
            QTreeWidget::item:hover, QTableWidget::item:hover {{
                background-color: {accent_hover};
                color: #0f172a;
            }}
            QScrollBar:vertical {{
                background: {panel};
                width: 12px;
                margin: 12px 0 12px 0;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical {{
                background: {accent};
                min-height: 20px;
                border-radius: 6px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QPlainTextEdit {{
                font-family: "Cascadia Code", "Consolas", monospace;
                font-size: 11pt;
            }}
            QLabel {{
                font-weight: 600;
            }}
        """
        )

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        controls = QHBoxLayout()
        controls.setSpacing(8)

        default_host = self.detected_ip or "0.0.0.0"
        self.host_edit = QLineEdit(default_host)
        self.host_edit.setClearButtonEnabled(True)
        self.host_edit.setPlaceholderText("Server bind address")
        self.host_edit.setMaximumWidth(200)

        self.cleanup_check = QCheckBox("Clean storage on stop")
        self.cleanup_check.setChecked(True)

        self.start_btn = QPushButton("Start Server")
        self.start_btn.setObjectName("startButton")
        self.start_btn.clicked.connect(self.on_start_clicked)

        self.stop_btn = QPushButton("Stop Server")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.clicked.connect(self.on_stop_clicked)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.worker.request_snapshot)

        self.status_label = QLabel("Status: offline")
        self.status_label.setMinimumWidth(220)

        controls.addWidget(QLabel("Host:"))
        controls.addWidget(self.host_edit)
        controls.addWidget(self.cleanup_check)
        controls.addSpacing(12)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.stop_btn)
        controls.addWidget(self.refresh_btn)
        controls.addStretch(1)
        controls.addWidget(self.status_label)

        layout.addLayout(controls)

        self.share_label = QLabel("")
        self.share_label.setWordWrap(True)
        self.share_label.setStyleSheet("color: #38bdf8; font-weight: 500;")
        self.share_label.hide()
        layout.addWidget(self.share_label)

        self.stats_label = QLabel("")
        self.stats_label.setWordWrap(True)
        layout.addWidget(self.stats_label)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter, 1)

        # Sessions tree
        self.session_tree = QTreeWidget()
        self.session_tree.setHeaderLabels(["Session / Client", "Status", "TCP", "UDP"])
        self.session_tree.setRootIsDecorated(True)
        self.session_tree.setColumnWidth(0, 240)

        # Files table
        self.files_table = QTableWidget(0, 4)
        self.files_table.setHorizontalHeaderLabels(["Owner", "Filename", "Size", "Stored At"])
        self.files_table.horizontalHeader().setStretchLastSection(True)
        self.files_table.verticalHeader().setVisible(False)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        splitter.addWidget(self.session_tree)
        splitter.addWidget(self.files_table)
        splitter.setSizes([420, 280])

        # Log view occupying bottom area
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(500)
        self.log_view.setPlaceholderText("Server logs appear here...")
        self.log_view.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        layout.addWidget(self.log_view, 1)

    # --- Button handlers --------------------------------------------------

    def on_start_clicked(self) -> None:
        self._refresh_detected_ip()
        host = self.host_edit.text().strip()
        if not host:
            host = self.detected_ip or "0.0.0.0"
            self.host_edit.setText(host)
        cleanup = self.cleanup_check.isChecked()
        self._update_share_hint(None)
        started = self.worker.start(host, cleanup)
        if started:
            self.append_log(f"Starting server on {host}:{config.TCP_PORT}...")
            self.status_label.setText("Status: starting...")
            self._update_controls(True)
        else:
            self.append_log("Server already running.")

    def on_stop_clicked(self) -> None:
        cleanup = self.cleanup_check.isChecked()
        self.worker.stop(cleanup)
        self.append_log("Stop requested.")

    def on_server_started(self, addr: tuple) -> None:
        host, port, *_ = addr + (None, None)
        port = port or config.TCP_PORT
        share_ip = self._derive_share_ip(host)

        status_text = f"Status: online @ {host}:{port}"
        if share_ip and share_ip != host:
            status_text += f" • share {share_ip}:{port}"
        self.status_label.setText(status_text)

        self.append_log(f"Server listening on {host}:{port}")
        if share_ip:
            self.append_log(f"Share this address with clients: {share_ip}:{port}")

        self._update_share_hint(share_ip, port)
        self.poll_timer.start()
        self._update_controls(True)
        self.worker.request_snapshot()

    def on_server_stopped(self) -> None:
        self.poll_timer.stop()
        self.status_label.setText("Status: offline")
        self.append_log("Server stopped.")
        self._update_share_hint(None)
        self._update_controls(False)

    def on_server_error(self, message: str) -> None:
        self.append_log(f"ERROR: {message}")
        QMessageBox.warning(self, "Server Error", message)

    def on_snapshot_ready(self, snapshot: dict) -> None:
        self._render_snapshot(snapshot)

    # --- Snapshot rendering ----------------------------------------------

    def _render_snapshot(self, snapshot: dict) -> None:
        session_count = snapshot.get("session_count", 0)
        total_clients = snapshot.get("total_clients", 0)
        total_files = snapshot.get("total_files", 0)
        storage_path = snapshot.get("storage_dir", "server_storage")
        cleanup_flag = "enabled" if snapshot.get("cleanup_storage_on_stop") else "disabled"

        # Get throughput data
        overall_recv = snapshot.get("throughput_recv_bps", 0.0)
        overall_sent = snapshot.get("throughput_sent_bps", 0.0)
        files_rate = snapshot.get("throughput_files_bps", 0.0)

        stats_line1 = (
            f"Sessions: {session_count} | Clients: {total_clients} | Shared files: {total_files} | "
            f"Storage: {storage_path} | Auto cleanup: {cleanup_flag}"
        )
        stats_line2 = (
            f"Total Traffic: {self._format_speed(overall_recv)} In / {self._format_speed(overall_sent)} Out | "
            f"File Traffic: {self._format_speed(files_rate)}"
        )
        self.stats_label.setText(f"{stats_line1}\n{stats_line2}")

        self._populate_sessions(snapshot.get("sessions", []))
        self._populate_files(snapshot.get("sessions", []))

    def _populate_sessions(self, sessions: list[dict]) -> None:
        self.session_tree.clear()
        for session in sessions:
            session_id = session.get("session_id", "unknown")
            client_count = session.get("client_count", 0)
            shared_files = len(session.get("shared_files", []))
            active_uploads = len(session.get("active_uploads", []))

            status_parts = [f"{client_count} clients"]
            if shared_files:
                status_parts.append(f"{shared_files} files")
            if active_uploads:
                status_parts.append(f"{active_uploads} uploads")

            session_item = QTreeWidgetItem([
                session_id,
                ", ".join(status_parts),
                "",
                "",
            ])
            self.session_tree.addTopLevelItem(session_item)
            session_item.setExpanded(True)

            for client in session.get("clients", []):
                username = client.get("username", "?")
                tcp = self._format_addr(client.get("tcp_addr"))
                udp = self._format_addr(client.get("udp_addr"))
                streaming = "Streaming" if client.get("is_streaming") else "Idle"
                last_seen = self._format_last_seen(client.get("last_heartbeat_time"))
                status = f"{streaming}, last heartbeat {last_seen}"
                client_item = QTreeWidgetItem([username, status, tcp, udp])
                session_item.addChild(client_item)

    def _populate_files(self, sessions: list[dict]) -> None:
        rows = []
        for session in sessions:
            for file_info in session.get("shared_files", []):
                rows.append(
                    (
                        file_info.get("owner", ""),
                        file_info.get("filename", ""),
                        self._format_size(file_info.get("filesize", 0)),
                        file_info.get("filepath", ""),
                    )
                )

        self.files_table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for col_index, value in enumerate(row):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() ^ Qt.ItemFlag.ItemIsEditable)
                self.files_table.setItem(row_index, col_index, item)
        if rows:
            self.files_table.resizeColumnsToContents()  # keep columns tidy

    # --- Utility helpers --------------------------------------------------

    @staticmethod
    def _format_speed(size_bytes: float) -> str:
        if size_bytes <= 0:
            return "0 B/s"
        units = ["B/s", "KB/s", "MB/s", "GB/s"]
        magnitude = 0
        value = float(size_bytes)
        while value >= 1024 and magnitude < len(units) - 1:
            value /= 1024
            magnitude += 1
        return f"{value:.1f} {units[magnitude]}"

    @staticmethod
    def _format_addr(value: Optional[tuple]) -> str:
        if not value:
            return "-"
        try:
            host, port = value[0], value[1]
            return f"{host}:{port}"
        except (IndexError, TypeError):
            return "-"

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        if size_bytes <= 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB"]
        magnitude = 0
        value = float(size_bytes)
        while value >= 1024 and magnitude < len(units) - 1:
            value /= 1024
            magnitude += 1
        return f"{value:.1f} {units[magnitude]}"

    @staticmethod
    def _format_last_seen(timestamp: Optional[float]) -> str:
        if not timestamp:
            return "unknown"
        delta = time.time() - timestamp
        if delta < 1:
            return "<1s ago"
        if delta < 60:
            return f"{int(delta)}s ago"
        if delta < 3600:
            minutes = int(delta // 60)
            return f"{minutes}m ago"
        hours = int(delta // 3600)
        return f"{hours}h ago"

    def append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        cursor = self.log_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_view.setTextCursor(cursor)

    def _refresh_detected_ip(self) -> None:
        ip = detect_primary_ipv4()
        if ip:
            self.detected_ip = ip

    def _derive_share_ip(self, bound_host: Optional[str]) -> Optional[str]:
        self._refresh_detected_ip()
        candidates = [
            self.detected_ip,
            self.host_edit.text().strip() if self.host_edit.text().strip() not in ("", "0.0.0.0") else None,
            bound_host if bound_host not in (None, "0.0.0.0", "127.0.0.1") else None,
        ]
        for candidate in candidates:
            if candidate:
                return candidate
        return None

    def _update_share_hint(self, ip: Optional[str], port: Optional[int] = None) -> None:
        if not ip:
            self.share_label.hide()
            self.share_label.setText("")
            return

        display = f"{ip}:{port}" if port else ip
        self.share_label.setText(f"Share this address with clients: {display}")
        self.share_label.show()

    def _update_controls(self, running: bool) -> None:
        is_running = running or self.worker.is_running()
        self.start_btn.setEnabled(not is_running)
        self.host_edit.setEnabled(not is_running)
        self.cleanup_check.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)
        self.refresh_btn.setEnabled(is_running)

    # --- Qt events --------------------------------------------------------

    def closeEvent(self, event) -> None:  # type: ignore[override]
        logging.getLogger().removeHandler(self.log_handler)
        if self.worker.is_running():
            self.worker.stop(self.cleanup_check.isChecked())
            self.worker.wait_until_stopped(timeout=5)
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    dashboard = ServerDashboard()
    dashboard.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
