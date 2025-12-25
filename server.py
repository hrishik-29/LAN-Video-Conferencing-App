# server.py - Centralized File Storage Version

import asyncio
import json
import struct
import ssl
import socket
import logging
import threading
import config
import time
import os
import sys
from pathlib import Path
from typing import Optional
import shutil  # <-- 1. IMPORT ADDED

# --- Logging Setup ---
logging.basicConfig(level=config.LOG_LEVEL,
                    format='%(asctime)s [%(levelname)s] [%(name)s] %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
log = logging.getLogger("Server")

# --- Constants ---
HEARTBEAT_TIMEOUT = 10
STORAGE_DIR = "server_storage"  # NEW: Directory for file storage


def resource_path(relative: str) -> str:
    """Resolve resource paths for both source runs and PyInstaller bundles."""
    search_roots: list[Path] = []
    if hasattr(sys, "_MEIPASS"):
        search_roots.append(Path(getattr(sys, "_MEIPASS")))
    module_dir = Path(__file__).resolve().parent
    search_roots.extend([module_dir, Path.cwd()])
    for root in search_roots:
        candidate = root / relative
        if candidate.exists():
            return str(candidate)
    return str(module_dir / relative)


CERT_FILE = resource_path("server.crt")
KEY_FILE = resource_path("server.key")

# --- Create storage directory ---
Path(STORAGE_DIR).mkdir(exist_ok=True)

# --- Asynchronous Message Handling ---
async def recv_msg(reader: asyncio.StreamReader, counter_obj: Optional['Server'] = None) -> Optional[bytes]:
    try:
        raw_msglen = await reader.readexactly(config.TCP_MSG_HEADER_SIZE)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        if msglen > 10 * 1024 * 1024:
            log.error(f"recv_msg: Excessive message length declared: {msglen}. Closing connection.")
            return None
        data = await reader.readexactly(msglen)
        
        # Track received bytes
        if counter_obj:
            counter_obj.total_tcp_recv += msglen + config.TCP_MSG_HEADER_SIZE
        
        return data
    except (asyncio.IncompleteReadError, ConnectionError, struct.error) as e:
        log.debug(f"recv_msg: Connection lost or incomplete read: {e}")
        return None
    except Exception as e:
        log.error(f"recv_msg: Unexpected error: {e}", exc_info=True)
        return None

async def send_msg(writer: asyncio.StreamWriter, msg: bytes, counter_obj: Optional['Server'] = None) -> bool:
    try:
        msg_len_bytes = struct.pack('>I', len(msg))
        
        # Track sent bytes
        if counter_obj:
            counter_obj.total_tcp_sent += len(msg_len_bytes) + len(msg)
        
        writer.write(msg_len_bytes + msg)
        await writer.drain()
        return True
    except (ConnectionError, BrokenPipeError, asyncio.CancelledError) as e:
        log.warning(f"send_msg: Client connection lost or write cancelled during write: {e}")
        return False
    except Exception as e:
       log.error(f"send_msg: Unexpected error: {e}", exc_info=True)
       return False

# --- Session Class ---

class Session:
    """Manages all logic for a single session/room."""
    def __init__(self, session_id, server_instance: 'Server'):
        self.session_id = session_id
        self.clients = {}
        self.clients_lock = asyncio.Lock()
        self.shared_files = {}  # {(owner, filename): {metadata}}
        self.shared_files_lock = asyncio.Lock()
        self.active_uploads = {}  # {transfer_id: file_handle}
        self.active_uploads_lock = asyncio.Lock()
        self.session_storage_dir = os.path.join(STORAGE_DIR, session_id)
        self.server = server_instance  # Reference to the main server for counters
        Path(self.session_storage_dir).mkdir(exist_ok=True)
        log.info(f"[SESSION {self.session_id}] Created with storage at {self.session_storage_dir}")

    async def snapshot(self) -> dict:
        """Returns a serialisable snapshot of the session state."""
        async with self.clients_lock:
            clients = [
                {
                    "username": info.get("username"),
                    "tcp_addr": info.get("tcp_addr"),
                    "udp_addr": info.get("udp_addr"),
                    "is_streaming": info.get("is_streaming", False),
                    "last_heartbeat_time": info.get("last_heartbeat_time", 0.0),
                }
                for info in self.clients.values()
            ]

        async with self.shared_files_lock:
            shared_files = [
                {
                    "owner": owner,
                    "filename": meta.get("filename"),
                    "filesize": meta.get("filesize", 0),
                    "filepath": meta.get("filepath", ""),
                }
                for (owner, _filename), meta in self.shared_files.items()
            ]

        async with self.active_uploads_lock:
            active_uploads = [
                {
                    "transfer_id": transfer_id,
                    "filepath": upload.get("filepath", ""),
                    "bytes_received": upload.get("bytes_received", 0),
                }
                for transfer_id, upload in self.active_uploads.items()
            ]

        return {
            "session_id": self.session_id,
            "client_count": len(clients),
            "clients": clients,
            "shared_files": shared_files,
            "active_uploads": active_uploads,
        }

    async def add_client(self, writer: asyncio.StreamWriter, username: str, tcp_addr: tuple, udp_addr: tuple) -> bool:
        """Adds a new client to the session, checking for username uniqueness."""
        async with self.clients_lock:
            if any(client['username'] == username for client in self.clients.values()):
                return False
            self.clients[writer] = {
                "username": username,
                "tcp_addr": tcp_addr,
                "udp_addr": udp_addr,
                "is_streaming": False,
                "last_heartbeat_time": time.time()
            }

        log.info(f"[SESSION {self.session_id}] User '{username}' joined from {tcp_addr} (UDP {udp_addr}).")
        await self.broadcast_user_list()
        await self.send_file_list(writer)
        return True

    async def update_last_heartbeat(self, udp_addr: tuple):
        """Updates the last heartbeat time for a client identified by UDP address."""
        async with self.clients_lock:
            writer_to_update = None
            for writer, client_info in self.clients.items():
                if client_info.get("udp_addr") == udp_addr:
                    writer_to_update = writer
                    break

            if writer_to_update:
                self.clients[writer_to_update]["last_heartbeat_time"] = time.time()
            else:
                log.warning(f"Heartbeat received from unknown UDP address {udp_addr} for session {self.session_id}")

    async def remove_client(self, writer: asyncio.StreamWriter) -> Optional[tuple]:
        udp_addr = None
        username = None

        async with self.clients_lock:
            if writer in self.clients:
                client_info = self.clients.pop(writer)
                udp_addr = client_info["udp_addr"]
                username = client_info["username"]
                log.info(f"[SESSION {self.session_id}] User '{username}' disconnected.")
            else:
                log.debug(f"Attempted to remove writer but not found in session {self.session_id}")
                return None

        if username:
            await self.broadcast_user_list()

        try:
            if not writer.is_closing():
                writer.close()
                log.debug(f"Closed writer for disconnected user '{username}'.")
        except Exception as e:
            log.warning(f"Error closing writer for '{username}' during removal: {e}")

        return udp_addr

    async def handle_command_or_chat(self, writer: asyncio.StreamWriter, username: str, message: bytes):
        try:
            msg_data = json.loads(message.decode('utf-8'))
            command = msg_data.get("command")
            payload = msg_data.get("payload", {})

            if command == "stream_control":
                async with self.clients_lock:
                    if writer in self.clients:
                        self.clients[writer]["is_streaming"] = payload.get("active", False)
                log.debug(f"[SESSION {self.session_id}] '{username}' streaming: {payload.get('active', False)}")
            elif command == "media_status":
                 await self.broadcast_tcp(message, source_writer=writer)
            elif command == "share_files":
                await self.handle_share_files(username, payload)
            elif command == "get_file_list":
                await self.send_file_list(writer)
            elif command == "request_file":
                await self.handle_download_request(writer, username, payload)
            elif command == "file_download_ack":
                await self.handle_file_download_ack(writer, username, payload)
            elif command == "start_tcp_share":
                log.info(f"[SESSION {self.session_id}] User '{username}' starting TCP share.")
                await self.broadcast_tcp(json.dumps({"command": "user_starting_tcp_share","payload": {"username": username}}).encode('utf-8'), source_writer=writer)
            elif command == "stop_tcp_share":
                log.info(f"[SESSION {self.session_id}] User '{username}' stopping TCP share.")
                await self.broadcast_tcp(json.dumps({"command": "user_stopping_tcp_share","payload": {"username": username}}).encode('utf-8'), source_writer=writer)

        except (json.JSONDecodeError, UnicodeDecodeError):
            try:
                chat_text = message.decode('utf-8')
                chat_message = f"<font color='#64B5F6'>{username}:</font> {chat_text}"
                log.info(f"[SESSION {self.session_id}] [CHAT] {username}: {chat_text}")
                await self.broadcast_tcp(chat_message.encode('utf-8'), source_writer=writer)
            except UnicodeDecodeError:
                log.warning(f"Received non-JSON, non-UTF8 message from '{username}'. Ignoring.")
        except Exception as e:
            log.error(f"Error handling command/chat from '{username}': {e}", exc_info=True)

    async def broadcast_tcp(self, message: bytes, source_writer: asyncio.StreamWriter = None):
        async with self.clients_lock: 
            writers = list(self.clients.keys())
        if not writers: 
            return
        tasks = [asyncio.create_task(send_msg(cw, message, self.server)) for cw in writers if cw != source_writer]
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception): 
                    log.warning(f"Error broadcasting TCP message: {res}")

    def broadcast_udp(self, data: bytes, source_addr: tuple, udp_socket: socket.socket):
        clients_snapshot = list(self.clients.values())
        for client_info in clients_snapshot:
            dest_addr = client_info.get("udp_addr")
            if dest_addr and dest_addr != source_addr:
                try: 
                    udp_socket.sendto(data, dest_addr)
                except Exception: 
                    pass

    async def broadcast_user_list(self):
        async with self.clients_lock: 
            user_list = [c['username'] for c in self.clients.values()]
        message = f"USERLIST,{','.join(user_list)}"
        log.info(f"[SESSION {self.session_id}] Broadcasting user list: {user_list}")
        await self.broadcast_tcp(message.encode('utf-8'))

    # --- NEW: File Sharing with Centralized Storage ---
    
    async def handle_share_files(self, owner_username: str, files_payload: list):
        """Client announces they want to upload files - we prepare to receive them."""
        log.info(f"[SESSION {self.session_id}] User '{owner_username}' wants to share {len(files_payload)} files.")
        
        # Send acknowledgment to client to start uploading
        for file_info in files_payload:
            filename = file_info.get("filename")
            filesize = file_info.get("filesize")
            transfer_id = f"{self.session_id}_{owner_username}_{filename}"
            
            # Send upload initiation command
            initiate_command = {
                "command": "initiate_upload",
                "payload": {
                    "filename": filename,
                    "transfer_id": transfer_id
                }
            }
            
            # Find the client's writer
            async with self.clients_lock:
                owner_writer = next((w for w, d in self.clients.items() if d["username"] == owner_username), None)
            
            if owner_writer:
                await send_msg(owner_writer, json.dumps(initiate_command).encode('utf-8'), self.server)
                log.info(f"[UPLOAD {transfer_id}] Requested upload from '{owner_username}'")

    async def handle_file_download_ack(self, requester_writer: asyncio.StreamWriter, downloader_username: str, payload: dict) -> None:
        owner_username = payload.get("owner")
        filename = payload.get("filename")
        filesize = payload.get("filesize", 0)

        if not owner_username or not filename:
            log.warning(f"[SESSION {self.session_id}] Invalid file_download_ack payload from '{downloader_username}': {payload}")
            transfer_id = f"{downloader_username}_download_{owner_username or 'unknown'}_{filename or 'unknown'}"
            error_msg = {
                "command": "transfer_error",
                "payload": {
                    "reason": "Invalid download request",
                    "transfer_id": transfer_id
                }
            }
            await send_msg(requester_writer, json.dumps(error_msg).encode('utf-8'), self.server)
            return

        log.info(f"[DOWNLOAD] User '{downloader_username}' requested file '{filename}' from '{owner_username}'")

        requested_filename = os.path.basename(filename)
        key = (owner_username, requested_filename)
        async with self.shared_files_lock:
            file_info = self.shared_files.get(key)

        requested_transfer_id = f"{downloader_username}_download_{owner_username}_{requested_filename}"

        if not file_info:
            log.warning(f"[DOWNLOAD] File '{filename}' from '{owner_username}' not found in session storage")
            error_msg = {
                "command": "transfer_error",
                "payload": {
                    "reason": "File not found on server",
                    "transfer_id": requested_transfer_id
                }
            }
            await send_msg(requester_writer, json.dumps(error_msg).encode('utf-8'), self.server)
            return

        # Start sending file
        filepath = file_info["filepath"]
        safe_filename = file_info["filename"]
        transfer_id = f"{downloader_username}_download_{owner_username}_{safe_filename}"
        
        log.info(f"[DOWNLOAD {transfer_id}] Starting file transfer from {filepath}")
        
        try:
            # Find the client's writer
            async with self.clients_lock:
                owner_writer = next((w for w, d in self.clients.items() if d["username"] == owner_username), None)
            
            if owner_writer:
                ack_payload = {
                    "command": "file_download_ack",
                    "payload": {
                        "filename": filename,
                        "filesize": filesize,
                        "owner": owner_username,
                        "downloader": downloader_username,
                    },
                }
                await send_msg(owner_writer, json.dumps(ack_payload).encode('utf-8'), self.server)
                log.info(f"[SESSION {self.session_id}] Notified '{owner_username}' of download by '{downloader_username}' for '{filename}'.")
        except Exception as e:
            log.error(f"[DOWNLOAD {transfer_id}] Error sending file: {e}", exc_info=True)
    
    async def handle_file_chunk(self, data: bytes):
        """Receives file chunks from uploader and saves to server storage."""
        transfer_id = "UNKNOWN"
        try:
            prefix = b'FILE_CHUNK:'
            prefix_len = len(prefix)
            header_fmt = '>H'
            header_len = struct.calcsize(header_fmt)
            min_len = prefix_len + header_len
            
            if len(data) < min_len:
                log.error("Received malformed FILE_CHUNK (too short)")
                return
            
            id_len = struct.unpack(header_fmt, data[prefix_len:prefix_len+header_len])[0]
            id_start = prefix_len + header_len
            
            if len(data) < id_start + id_len:
                log.error("Received malformed FILE_CHUNK (ID length mismatch)")
                return
            
            transfer_id = data[id_start:id_start+id_len].decode('utf-8')
            chunk = data[id_start+id_len:]
            
            # Track file upload bytes
            if self.server:
                self.server.total_file_upload_bytes += len(chunk)
            
            log.debug(f"[UPLOAD {transfer_id}] Received chunk of {len(chunk)} bytes")
            
            # Save chunk to file
            async with self.active_uploads_lock:
                if transfer_id not in self.active_uploads:
                    parts = transfer_id.split('_', 2)
                    if len(parts) != 3:
                        log.error(f"[UPLOAD {transfer_id}] Invalid transfer identifier format. Expected 3 parts.")
                        return

                    _, owner_username, raw_filename = parts
                    filename = os.path.basename(raw_filename)
                    if not filename:
                        log.error(f"[UPLOAD {transfer_id}] Filename component is empty after sanitisation.")
                        return

                    owner_dir_name = owner_username.replace(os.sep, '_')
                    if os.altsep:
                        owner_dir_name = owner_dir_name.replace(os.altsep, '_')
                    owner_dir = os.path.join(self.session_storage_dir, owner_dir_name)
                    Path(owner_dir).mkdir(parents=True, exist_ok=True)
                    filepath = os.path.join(owner_dir, filename)

                    self.active_uploads[transfer_id] = {
                        "file_handle": open(filepath, 'wb'),
                        "filepath": filepath,
                        "bytes_received": 0
                    }
                    log.info(f"[UPLOAD {transfer_id}] Started receiving file at {filepath}")
                
                upload_info = self.active_uploads[transfer_id]
                upload_info["file_handle"].write(chunk)
                upload_info["bytes_received"] += len(chunk)
                
        except Exception as e:
            log.error(f"[UPLOAD {transfer_id}] Error handling chunk: {e}", exc_info=True)

    async def shutdown(self):
        async with self.clients_lock:
            client_writers = list(self.clients.keys())
            self.clients.clear()

        for writer in client_writers:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception as e:
                log.debug(f"Error closing writer during session shutdown: {e}")

        async with self.active_uploads_lock:
            uploads = list(self.active_uploads.values())
            self.active_uploads.clear()

        for upload in uploads:
            handle = upload.get("file_handle")
            if handle and not handle.closed:
                try:
                    handle.close()
                except Exception:
                    pass
    
    async def handle_file_end(self, data: bytes):
        """Finalizes file upload and broadcasts availability."""
        transfer_id = "UNKNOWN"
        try:
            prefix = b'FILE_END:'
            prefix_len = len(prefix)
            header_fmt = '>H'
            header_len = struct.calcsize(header_fmt)
            expected_len = prefix_len + header_len
            
            if len(data) < expected_len:
                log.error("Received malformed FILE_END (too short)")
                return
            
            id_len = struct.unpack(header_fmt, data[prefix_len:prefix_len+header_len])[0]
            id_start = prefix_len + header_len
            
            if len(data) < id_start + id_len:
                log.error("Received malformed FILE_END (ID length mismatch)")
                return
            
            transfer_id = data[id_start:id_start+id_len].decode('utf-8')
            log.info(f"[UPLOAD {transfer_id}] Received FILE_END marker")
            
            # Finalize the upload
            async with self.active_uploads_lock:
                if transfer_id in self.active_uploads:
                    upload_info = self.active_uploads.pop(transfer_id)
                    upload_info["file_handle"].close()
                    
                    # Extract metadata
                    parts = transfer_id.split('_', 2)
                    if len(parts) != 3:
                        log.error(f"[UPLOAD {transfer_id}] Invalid transfer identifier during finalisation.")
                        return

                    owner_username = parts[1]
                    filename = os.path.basename(parts[2])
                    if not filename:
                        log.error(f"[UPLOAD {transfer_id}] Filename component empty during finalisation.")
                        return
                    filepath = upload_info["filepath"]
                    filesize = os.path.getsize(filepath)
                    
                    # Add to shared files registry
                    async with self.shared_files_lock:
                        key = (owner_username, filename)
                        self.shared_files[key] = {
                            "filename": filename,
                            "filesize": filesize,
                            "owner": owner_username,
                            "filepath": filepath
                        }
                    
                    log.info(f"[UPLOAD {transfer_id}] File saved successfully: {filepath} ({filesize} bytes)")
                    
                    # Broadcast updated file list to all clients
                    await self.broadcast_full_file_list()
                else:
                    log.warning(f"[UPLOAD {transfer_id}] Received FILE_END for unknown upload")
                    
        except Exception as e:
            log.error(f"[UPLOAD {transfer_id}] Error finalizing upload: {e}", exc_info=True)
    
    async def handle_download_request(self, requester_writer: asyncio.StreamWriter, requester_username: str, payload: dict):
        """Handles client download request - server sends file from storage."""
        filename = payload.get("filename")
        owner_username = payload.get("owner")

        if not filename or not owner_username:
            log.warning(f"[DOWNLOAD] Invalid download request from '{requester_username}': {payload}")
            transfer_id = f"{requester_username}_download_{owner_username or 'unknown'}_{filename or 'unknown'}"
            error_msg = {
                "command": "transfer_error",
                "payload": {
                    "reason": "Invalid download request",
                    "transfer_id": transfer_id
                }
            }
            await send_msg(requester_writer, json.dumps(error_msg).encode('utf-8'), self.server)
            return

        log.info(f"[DOWNLOAD] User '{requester_username}' requested file '{filename}' from '{owner_username}'")

        requested_filename = os.path.basename(filename)
        key = (owner_username, requested_filename)
        async with self.shared_files_lock:
            file_info = self.shared_files.get(key)

        requested_transfer_id = f"{requester_username}_download_{owner_username}_{requested_filename}"

        if not file_info:
            log.warning(f"[DOWNLOAD] File '{filename}' from '{owner_username}' not found in session storage")
            error_msg = {
                "command": "transfer_error",
                "payload": {
                    "reason": "File not found on server",
                    "transfer_id": requested_transfer_id
                }
            }
            await send_msg(requester_writer, json.dumps(error_msg).encode('utf-8'))
            return

        # Start sending file
        filepath = file_info["filepath"]
        safe_filename = file_info["filename"]
        transfer_id = f"{requester_username}_download_{owner_username}_{safe_filename}"
        
        log.info(f"[DOWNLOAD {transfer_id}] Starting file transfer from {filepath}")
        
        try:
            transfer_id_bytes = transfer_id.encode('utf-8')
            id_len_bytes = struct.pack('>H', len(transfer_id_bytes))
            
            with open(filepath, 'rb') as f:
                sent_bytes = 0
                while chunk := f.read(4096):
                    message = b'FILE_CHUNK:' + id_len_bytes + transfer_id_bytes + chunk
                    success = await send_msg(requester_writer, message, self.server)
                    
                    # Track file download bytes
                    if success and self.server:
                        self.server.total_file_download_bytes += len(chunk)
                    
                    if not success:
                        log.error(f"[DOWNLOAD {transfer_id}] Failed to send chunk")
                        return
                    sent_bytes += len(chunk)
                    log.debug(f"[DOWNLOAD {transfer_id}] Sent {sent_bytes} bytes")
            
            # Send end marker
            end_message = b'FILE_END:' + id_len_bytes + transfer_id_bytes
            await send_msg(requester_writer, end_message, self.server)
            
            log.info(f"[DOWNLOAD {transfer_id}] Completed successfully ({sent_bytes} bytes)")
            
        except Exception as e:
            log.error(f"[DOWNLOAD {transfer_id}] Error during transfer: {e}", exc_info=True)
            error_msg = {
                "command": "transfer_error",
                "payload": {
                    "reason": f"Server error: {str(e)}",
                    "transfer_id": transfer_id
                }
            }
            await send_msg(requester_writer, json.dumps(error_msg).encode('utf-8'))
    
    async def get_full_file_list(self) -> list:
        """Returns list of all files available in this session."""
        async with self.shared_files_lock:
            return [
                {
                    "filename": info["filename"],
                    "filesize": info["filesize"],
                    "owner": info["owner"]
                }
                for info in self.shared_files.values()
            ]
    
    async def send_file_list(self, target_writer: asyncio.StreamWriter):
        """Sends file list to a specific client."""
        try:
            file_list = await self.get_full_file_list()
            command = {"command": "file_list", "payload": file_list}
            await send_msg(target_writer, json.dumps(command).encode('utf-8'), self.server)
            log.debug(f"Sent file list with {len(file_list)} files")
        except Exception as e:
            log.error(f"Error sending file list: {e}", exc_info=True)
    
    async def broadcast_full_file_list(self):
        """Broadcasts file list to all clients."""
        try:
            file_list = await self.get_full_file_list()
            command = {"command": "file_list", "payload": file_list}
            await self.broadcast_tcp(json.dumps(command).encode('utf-8'))
            log.info(f"Broadcasted file list with {len(file_list)} files")
        except Exception as e:
            log.error(f"Error broadcasting file list: {e}", exc_info=True)


# --- Main Server Class ---

class Server:
    def __init__(self, host='0.0.0.0'):
        self.host = host
        self.sessions = {}
        self.sessions_lock = asyncio.Lock()
        self.udp_addr_to_session_map = {}
        self.udp_addr_to_session_lock = threading.Lock()
        self.video_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.audio_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ssl_context = None
        self.main_event_loop = None
        self.tcp_server: Optional[asyncio.base_events.Server] = None
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.cleanup_storage_on_stop = True
        self.udp_threads: list[threading.Thread] = []
        self._shutdown_complete = False
        self.is_running = False
        
        # Throughput tracking counters
        self.total_tcp_recv = 0
        self.total_tcp_sent = 0
        self.total_udp_recv = 0
        self.total_file_upload_bytes = 0
        self.total_file_download_bytes = 0
        
        # Last snapshot values for rate calculation
        self.last_snapshot_time = time.time()
        self.last_snapshot_tcp_recv = 0
        self.last_snapshot_tcp_sent = 0
        self.last_snapshot_udp_recv = 0
        self.last_snapshot_file_uploads = 0
        self.last_snapshot_file_downloads = 0

    def setup_ssl_context(self):
        # <-- 2. MODIFIED FUNCTION
        # Removed try/except block. Errors will now "bubble up" 
        # to the main __main__ try/except block.
        self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        log.info("SSL context created and certificates loaded.")

    def setup_udp_sockets(self):
        # <-- 2. MODIFIED FUNCTION
        # Removed try/except block. Errors will now "bubble up" 
        # to the main __main__ try/except block.
        try:
            self.video_udp_socket.close()
        except Exception:
            pass
        try:
            self.audio_udp_socket.close()
        except Exception:
            pass

        self.video_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.audio_udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.video_udp_socket.bind((self.host, config.VIDEO_UDP_PORT))
        self.audio_udp_socket.bind((self.host, config.AUDIO_UDP_PORT))
        log.info(f"UDP Video listener ready on port {config.VIDEO_UDP_PORT}")
        log.info(f"UDP Audio listener ready on port {config.AUDIO_UDP_PORT}")

    def udp_listener_thread(self, sock: socket.socket, stream_type: str, loop: asyncio.AbstractEventLoop):
        log.info(f"UDP {stream_type} listener thread started.")
        while True:
            try:
                data, addr = sock.recvfrom(config.BUFFER_SIZE)
                
                # Track UDP received bytes
                self.total_udp_recv += len(data)

                if data and data[:1] == b'H':
                    username = None
                    if len(data) > 1:
                        try:
                            username = data[1:1 + config.USERNAME_HEADER_LENGTH].decode('utf-8', errors='ignore').strip()
                        except Exception:
                            username = None
                    self._handle_udp_heartbeat(addr, username if username else None, loop)
                    continue

                if data and data[:1] != b'H':
                    future = asyncio.run_coroutine_threadsafe(
                        self._route_udp_packet(data, addr, sock, stream_type),
                        loop,
                    )
                    # Best-effort: avoid leaking futures on shutdown
                    if future and future.done() and future.exception():
                        log.debug(f"UDP {stream_type} routing task error: {future.exception()}")

            except ConnectionResetError:
                log.debug(f"UDP {stream_type} connection reset error from {addr}.")
            except OSError as e:
                errno = getattr(e, "errno", None)
                if errno in (9, 10004, 10038):
                    log.debug(f"UDP {stream_type} listener stopping (socket closed).")
                    break
                log.error(f"[ERROR] UDP {stream_type} listener OS error: {e}", exc_info=True)
            except Exception as e:
                log.error(f"[ERROR] UDP {stream_type} listener unexpected error: {e}", exc_info=True)
        log.info(f"UDP {stream_type} listener thread finished.")

    def _handle_udp_heartbeat(self, addr: tuple, username: Optional[str], loop: asyncio.AbstractEventLoop) -> None:
        session_id = None
        with self.udp_addr_to_session_lock:
            session_id = self.udp_addr_to_session_map.get(addr)

        if session_id:
            session = self.sessions.get(session_id)
            if session:
                try:
                    asyncio.run_coroutine_threadsafe(session.update_last_heartbeat(addr), loop)
                except RuntimeError:
                    log.debug(f"Heartbeat update skipped; event loop closed for {addr}.")
            return

        if username:
            try:
                future = asyncio.run_coroutine_threadsafe(self._remap_udp_addr(username, addr), loop)
            except RuntimeError:
                log.debug(f"Heartbeat remap skipped; event loop closed for {addr}.")
                return

            def _log_future_result(fut):
                exc = fut.exception()
                if exc:
                    log.error(f"Heartbeat remap error for '{username}' from {addr}: {exc}", exc_info=True)

            future.add_done_callback(_log_future_result)
        else:
            log.debug(f"Heartbeat from {addr} has no mapping and no username; ignoring.")

    async def _route_udp_packet(self, data: bytes, addr: tuple, sock: socket.socket, stream_type: str) -> None:
        session = await self._resolve_session_for_udp(addr, data)
        if session:
            session.broadcast_udp(data, addr, sock)
        else:
            log.debug(f"UDP {stream_type}: Unmapped packet from {addr}; dropping {len(data)} bytes.")

    async def _remap_udp_addr(self, username: str, addr: tuple) -> None:
        session = await self._find_session_by_username(username)
        if not session:
            log.debug(f"Heartbeat: No session found for username '{username}' from {addr}.")
            return

        target_writer = None
        previous_addr: Optional[tuple] = None

        async with session.clients_lock:
            for writer, info in session.clients.items():
                if info.get("username") == username:
                    target_writer = writer
                    previous_addr = info.get("udp_addr")
                    info["udp_addr"] = addr
                    info["last_heartbeat_time"] = time.time()
                    break

        if not target_writer:
            log.debug(f"Heartbeat: Username '{username}' disappeared before remap could complete.")
            return

        if previous_addr == addr:
            await session.update_last_heartbeat(addr)
            return

        with self.udp_addr_to_session_lock:
            if previous_addr:
                self.udp_addr_to_session_map.pop(previous_addr, None)
            self.udp_addr_to_session_map[addr] = session.session_id

        log.info(f"Heartbeat remapped '{username}' to {addr} (was {previous_addr}).")
        await session.update_last_heartbeat(addr)

    async def _resolve_session_for_udp(self, addr: tuple, data: bytes) -> Optional[Session]:
        with self.udp_addr_to_session_lock:
            session_id = self.udp_addr_to_session_map.get(addr)

        candidate: Optional[Session] = None
        if session_id:
            async with self.sessions_lock:
                candidate = self.sessions.get(session_id)
        if candidate:
            return candidate

        username = self._extract_username_from_udp(data)
        if not username:
            return None

        candidate = await self._find_session_by_username(username)
        if candidate:
            with self.udp_addr_to_session_lock:
                self.udp_addr_to_session_map[addr] = candidate.session_id
        return candidate

    async def _find_session_by_username(self, username: str) -> Optional[Session]:
        async with self.sessions_lock:
            sessions_snapshot = list(self.sessions.values())

        for session in sessions_snapshot:
            async with session.clients_lock:
                for info in session.clients.values():
                    if info.get("username") == username:
                        return session
        return None

    @staticmethod
    def _extract_username_from_udp(data: bytes) -> Optional[str]:
        if not data:
            return None
        packet_type = data[:1]
        if packet_type in (b'H', b'F'):  # Heartbeat or file packets
            return None
        header_len = 1 + config.USERNAME_HEADER_LENGTH
        if len(data) <= header_len:
            return None
        try:
            return data[1:header_len].strip().decode('utf-8')
        except UnicodeDecodeError:
            return None

    async def _shutdown_runtime(self):
        if self._shutdown_complete:
            return
        self._shutdown_complete = True

        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.debug(f"Error awaiting heartbeat task during shutdown: {e}")
            self.heartbeat_task = None

        if self.tcp_server:
            self.tcp_server.close()
            try:
                await self.tcp_server.wait_closed()
            except Exception as e:
                log.debug(f"Error waiting for TCP server to close: {e}")
            self.tcp_server = None

        try:
            self.video_udp_socket.close()
        except Exception:
            pass
        try:
            self.audio_udp_socket.close()
        except Exception:
            pass

        for thread in self.udp_threads:
            if thread.is_alive():
                thread.join(timeout=1.5)
        self.udp_threads.clear()

        async with self.sessions_lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()

        for session in sessions:
            await session.shutdown()

        with self.udp_addr_to_session_lock:
            self.udp_addr_to_session_map.clear()
        self.is_running = False

    async def stop(self, cleanup_storage: Optional[bool] = None):
        if cleanup_storage is not None:
            self.cleanup_storage_on_stop = cleanup_storage
        await self._shutdown_runtime()
        if self.cleanup_storage_on_stop:
            self.cleanup_storage_dir()
            self.cleanup_storage_on_stop = False

    def cleanup_storage_dir(self):
        log.info(f"Cleaning up storage directory: {STORAGE_DIR}")
        if os.path.exists(STORAGE_DIR):
            try:
                shutil.rmtree(STORAGE_DIR)
                log.info(f"Successfully deleted storage directory: {STORAGE_DIR}")
            except OSError as e:
                log.error(f"Failed to delete storage directory {STORAGE_DIR}: {e}")

    async def get_state_snapshot(self) -> dict:
        """Returns an aggregated view of server state for dashboards."""
        # Calculate throughput rates
        current_time = time.time()
        time_delta = current_time - self.last_snapshot_time
        if time_delta < 1e-6:  # Avoid division by zero
            time_delta = 1e-6

        # Calculate current throughput rates (bytes/sec)
        tcp_recv_rate = (self.total_tcp_recv - self.last_snapshot_tcp_recv) / time_delta
        tcp_sent_rate = (self.total_tcp_sent - self.last_snapshot_tcp_sent) / time_delta
        udp_recv_rate = (self.total_udp_recv - self.last_snapshot_udp_recv) / time_delta
        
        file_upload_rate = (self.total_file_upload_bytes - self.last_snapshot_file_uploads) / time_delta
        file_download_rate = (self.total_file_download_bytes - self.last_snapshot_file_downloads) / time_delta

        # Update last snapshot values for next calculation
        self.last_snapshot_time = current_time
        self.last_snapshot_tcp_recv = self.total_tcp_recv
        self.last_snapshot_tcp_sent = self.total_tcp_sent
        self.last_snapshot_udp_recv = self.total_udp_recv
        self.last_snapshot_file_uploads = self.total_file_upload_bytes
        self.last_snapshot_file_downloads = self.total_file_download_bytes

        # Calculate aggregate rates
        overall_recv_rate = tcp_recv_rate + udp_recv_rate
        overall_sent_rate = tcp_sent_rate
        file_throughput_rate = file_upload_rate + file_download_rate
        
        async with self.sessions_lock:
            sessions = list(self.sessions.values())

        session_snapshots = []
        for session in sessions:
            try:
                snapshot = await session.snapshot()
            except Exception as exc:
                log.error(f"Failed to snapshot session {session.session_id}: {exc}")
                continue
            session_snapshots.append(snapshot)

        total_clients = sum(snap.get("client_count", 0) for snap in session_snapshots)
        total_files = sum(len(snap.get("shared_files", [])) for snap in session_snapshots)

        return {
            "host": self.host,
            "tcp_port": config.TCP_PORT,
            "video_udp_port": config.VIDEO_UDP_PORT,
            "audio_udp_port": config.AUDIO_UDP_PORT,
            "is_running": self.is_running,
            "session_count": len(session_snapshots),
            "total_clients": total_clients,
            "total_files": total_files,
            "sessions": session_snapshots,
            "storage_dir": STORAGE_DIR,
            "cleanup_storage_on_stop": self.cleanup_storage_on_stop,
            "udp_threads_alive": sum(1 for thread in self.udp_threads if thread.is_alive()),
            "throughput_recv_bps": overall_recv_rate,
            "throughput_sent_bps": overall_sent_rate,
            "throughput_files_bps": file_throughput_rate,
            "throughput_files_upload_bps": file_upload_rate,
            "throughput_files_download_bps": file_download_rate,
        }

    async def check_heartbeats(self):
        log.info("Heartbeat checker task started.")
        while True:
            await asyncio.sleep(5)
            now = time.time()
            stale_writers = []

            async with self.sessions_lock:
                for session_id, session in list(self.sessions.items()):
                    async with session.clients_lock:
                        for writer, client_info in list(session.clients.items()):
                            last_seen = client_info.get("last_heartbeat_time", 0)
                            if now - last_seen > HEARTBEAT_TIMEOUT:
                                username = client_info.get('username', 'Unknown')
                                log.warning(f"[TIMEOUT] Client '{username}' ({client_info.get('tcp_addr')}) timed out.")
                                stale_writers.append(writer)

            for writer in stale_writers:
                if not writer.is_closing():
                    try:
                        writer.close()
                    except Exception as e:
                        log.error(f"Error closing writer during heartbeat cleanup: {e}")

            stale_writers.clear()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        cipher = writer.get_extra_info('cipher')
        log.info(f"[NEW CONNECTION] {addr} via {cipher}")
        
        session_id = None
        username = None
        client_session = None
        client_udp_addr = None
        client_fully_added = False
        
        try:
            # Handshake
            await send_msg(writer, b"GET_SESSION_INFO", self)
            info_bytes = await recv_msg(reader, self)
            if not info_bytes:
                raise ConnectionError("Handshake: No session info")
            
            info = json.loads(info_bytes.decode('utf-8'))
            session_id = info.get("session_id")
            username = info.get("username")
            
            if not session_id or not username:
                raise ValueError("Handshake: Invalid session info")
            
            log.debug(f"Handshake from {addr}: User='{username}', Session='{session_id}'")
            
            async with self.sessions_lock:
                if session_id not in self.sessions:
                    log.info(f"Creating session: {session_id}")
                    self.sessions[session_id] = Session(session_id, self)
                client_session = self.sessions[session_id]
            
            await send_msg(writer, b"GET_UDP_PORT", self)
            udp_port_msg_bytes = await recv_msg(reader, self)
            if not udp_port_msg_bytes:
                raise ConnectionError("Handshake: No UDP port")
            
            udp_port_msg = udp_port_msg_bytes.decode('utf-8', errors='ignore')
            if not udp_port_msg.startswith("UDP_PORT:"):
                raise ValueError("Handshake: Invalid UDP msg")
            
            udp_port = int(udp_port_msg.split(':')[1])
            client_udp_addr = (addr[0], udp_port)
            
            if not await client_session.add_client(writer, username, addr, client_udp_addr):
                log.warning(f"Username '{username}' taken in '{session_id}'")
                await send_msg(writer, b"USERNAME_TAKEN", self)
                async with self.sessions_lock:
                    if session_id in self.sessions and not self.sessions[session_id].clients:
                        del self.sessions[session_id]
                return
            
            client_fully_added = True
            
            with self.udp_addr_to_session_lock:
                self.udp_addr_to_session_map[client_udp_addr] = session_id
            
            await send_msg(writer, json.dumps({"command": "handshake_ok"}).encode('utf-8'), self)
            log.info(f"Handshake complete for '{username}' in '{session_id}'")
            
            # Main message loop
            while True:
                message = await recv_msg(reader, self)
                if message is None:
                    log.info(f"Client '{username}' disconnected gracefully")
                    break
                
                if message.startswith(b'FILE_CHUNK:'):
                    await client_session.handle_file_chunk(message)
                elif message.startswith(b'FILE_END:'):
                    await client_session.handle_file_end(message)
                elif message.startswith(b'S_FRAME:'):
                    await client_session.broadcast_tcp(message, source_writer=writer)
                else:
                    await client_session.handle_command_or_chat(writer, username, message)
                    
        except Exception as e:
            log.error(f"Error handling client '{username}': {e}", exc_info=True)
        finally:
            if client_udp_addr:
                with self.udp_addr_to_session_lock:
                    self.udp_addr_to_session_map.pop(client_udp_addr, None)
            
            if client_session and client_fully_added:
                await client_session.remove_client(writer)
                async with self.sessions_lock:
                    if session_id in self.sessions and not self.sessions[session_id].clients:
                        log.info(f"[SESSION {session_id}] Empty, cleaning up")
                        del self.sessions[session_id]
            else:
                if not writer.is_closing():
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            
            log.info(f"Cleanup complete for {addr} (User: '{username}')")

    async def start(self, on_ready=None, cleanup_storage: bool = True):
        self.cleanup_storage_on_stop = cleanup_storage
        self._shutdown_complete = False
        self.main_event_loop = asyncio.get_running_loop()
        self.is_running = False

        self.setup_ssl_context()
        self.setup_udp_sockets()

        self.udp_threads = [
            threading.Thread(target=self.udp_listener_thread, args=(self.video_udp_socket, "Video", self.main_event_loop), daemon=True),
            threading.Thread(target=self.udp_listener_thread, args=(self.audio_udp_socket, "Audio", self.main_event_loop), daemon=True),
        ]
        for thread in self.udp_threads:
            thread.start()

        try:
            self.tcp_server = await asyncio.start_server(
                self.handle_client,
                self.host,
                config.TCP_PORT,
                ssl=self.ssl_context,
            )
        except OSError as e:
            log.critical(f"Failed to start TCP server: {e}")
            await self._shutdown_runtime()
            if on_ready:
                self.main_event_loop.call_soon(on_ready, None)
            return

        addr = self.tcp_server.sockets[0].getsockname()
        log.info(f"[*] Secure TCP Server listening on {addr}")

        if on_ready:
            self.main_event_loop.call_soon(on_ready, addr)

        self.heartbeat_task = asyncio.create_task(self.check_heartbeats())
        self.is_running = True

        try:
            await self.tcp_server.serve_forever()
        except asyncio.CancelledError:
            log.info("Server task cancelled.")
        except Exception as e:
            log.critical(f"Server error: {e}", exc_info=True)
            raise
        finally:
            await self._shutdown_runtime()
            if self.cleanup_storage_on_stop:
                self.cleanup_storage_dir()


if __name__ == "__main__":
    try:
        asyncio.run(Server().start())
    except KeyboardInterrupt:
        log.info("Server shutting down due to KeyboardInterrupt.")
    except Exception as e:
        log.critical(f"Server failed to start or run: {e}", exc_info=True)
    finally:
        log.info("Server process finished.")