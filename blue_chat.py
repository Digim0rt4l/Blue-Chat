#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    X25519PrivateKey.generate().public_key()
    ChaCha20Poly1305(bytes(32)).encrypt(bytes(12), b"", b"")
except Exception:
    X25519PrivateKey = None

try:
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox, ttk
except ImportError:
    tk = None


APP_NAME = "Blue Chat Server"
APP_VERSION = "4.3.1"
APP_DESKTOP_ID = "bluechatserver"
APP_CLASS = APP_DESKTOP_ID.capitalize()
APP_DIR = Path(__file__).resolve().parent
HTML_PATH = APP_DIR / "index.html"
SETTINGS_PATH = APP_DIR / "blue_chat_settings.json"
BANS_PATH = APP_DIR / "blue_chat_bans.json"
ARP_PATH = Path("/proc/net/arp")
ROUTE_PATH = Path("/proc/net/route")
NEIGHBOUR_REFRESH = 5.0
NEIGHBOUR_RETRY = 1.0
EMPTY_MAC = "00:00:00:00:00:00"

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WEB_PORT_RANGE = (8080, 8280)
PORT_LIMITS = (1024, 65535)
PORT_ATTEMPTS = 60

HISTORY_REPLAY = 75
HISTORY_LIMITS = (10, 5000)
MAX_CLIENTS = 256
MAX_MESSAGE_BYTES = 64 * 1024
MAX_TEXT_LENGTH = 1000
MAX_NAME_LENGTH = 32
MAX_ID_LENGTH = 64
PUBLIC_ID_LENGTH = 20
RATE_WINDOW = 10
RATE_LIMIT = 30
EVENT_WINDOW = 10
EVENT_LIMIT = 150
MAX_PENDING_HANDSHAKES = 64
MAX_READERS = 500
SEND_TIMEOUT = 5
HTTP_TIMEOUT = 15
READ_POLL = 1.0
RECV_CHUNK = 65536
KEX_TIMEOUT = 10
KEX_NONCE_BYTES = 32
PAD_BLOCK = 256
PROTOCOL_VERSION = 1
PROTOCOL_NAME = "X25519 + ML-KEM-768 key exchange, ChaCha20-Poly1305 messages"
ENCRYPTION_SHORT = "PQ hybrid"
KEX_LABEL = b"BlueChat key exchange v1"
KEY_INFO = b"BlueChat session keys v1"
AAD_CLIENT = b"BlueChat client to server v1"
AAD_SERVER = b"BlueChat server to client v1"
NOTICE_INTERVAL = 60
HEARTBEAT_TICK = 5
PING_INTERVAL = 15
IDLE_TIMEOUT = 45
STALE_AFTER = PING_INTERVAL + 5
RESUME_WINDOW = 15 * 60

DEFAULT_USER_COLOR = "#4a90e2"
DEFAULT_HOST_COLOR = "#f0ad4e"
DEFAULT_HOST_NAME = "Admin"
LEGACY_HOST_NAME = "Host"
HEX_COLOR = re.compile(r"#[0-9a-fA-F]{6}")
MAC_ADDRESS = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
LONG_HEX_COLOR = re.compile(r"#[0-9a-f]{12}")
RGB_COLOR = re.compile(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*[\d.]+\s*)?\)")
PICKER_TIMEOUT = 600
GTK_PICKER_SCRIPT = """
import sys
try:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gdk, Gtk
    if not Gtk.init_check([])[0]:
        sys.exit(3)
    dialog = Gtk.ColorChooserDialog(title=sys.argv[2])
    dialog.set_use_alpha(False)
    color = Gdk.RGBA()
    if color.parse(sys.argv[1]):
        dialog.set_rgba(color)
    response = dialog.run()
    chosen = dialog.get_rgba()
    dialog.destroy()
except Exception:
    sys.exit(3)
if response != Gtk.ResponseType.OK:
    sys.exit(4)
print("#%02x%02x%02x" % (round(chosen.red * 255), round(chosen.green * 255), round(chosen.blue * 255)))
"""
PICKER_CANCELLED = {"zenity": 1, "gtk": 4}
PRESET_COLORS = (
    "#4a90e2",
    "#17a2b8",
    "#20c997",
    "#2d9962",
    "#8bc34a",
    "#ffc107",
    "#f0ad4e",
    "#fd7e14",
    "#ff5733",
    "#d9534f",
    "#e83e8c",
    "#9b59b6",
    "#6f42c1",
    "#7f93b5",
    "#9aa4b2",
    "#e6eaf0",
    "#ffffff",
    "#5cb88a",
)
PALETTE_COLUMNS = 6

OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

CLOSE_NORMAL = 1000
CLOSE_GOING_AWAY = 1001
CLOSE_POLICY = 1008

STORED_EVENT_TYPES = frozenset({"message", "presence", "system", "identity"})
CHAT_EVENT_TYPES = frozenset({"message", "system"})
KIND_STYLES = {
    "kick": "system_alert",
    "ban": "system_alert",
    "shutdown": "system_alert",
    "away": "system_idle",
    "timeout": "system_idle",
    "back": "system_back",
}

INLINE_SCRIPT = re.compile(rb"<script>(.*?)</script>", re.DOTALL)

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self' {scripts}",
        "style-src 'self' 'unsafe-inline'",
        "connect-src 'self' ws:",
        "img-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ]
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}

DEFAULT_SETTINGS = {
    "bind": "0.0.0.0",
    "web_port_auto": True,
    "web_port": 8080,
    "history_max": 150,
    "host_name": DEFAULT_HOST_NAME,
    "host_color": DEFAULT_HOST_COLOR,
    "autostart": True,
    "open_browser": False,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def format_local_time(iso_value: str | None, pattern: str) -> str:
    try:
        return datetime.fromisoformat(str(iso_value)).astimezone().strftime(pattern)
    except (TypeError, ValueError):
        return datetime.now().strftime(pattern)


def clean_color(value: object, default: str = DEFAULT_USER_COLOR) -> str:
    candidate = str(value or "").strip().lower()
    return candidate if HEX_COLOR.fullmatch(candidate) else default


def strip_unsafe(text: str, keep_newlines: bool) -> str:
    kept = []
    for ch in text:
        if ch == "\n" and keep_newlines:
            kept.append(ch)
        elif ch in "\t\r\n":
            kept.append(" ")
        elif unicodedata.category(ch) in ("Cc", "Cs") or ch in BIDI_CONTROLS:
            continue
        else:
            kept.append(ch)
    return "".join(kept)


def clean_text(value: object, limit: int) -> str:
    raw = str(value if value is not None else "").replace("\r\n", "\n")
    return strip_unsafe(raw, keep_newlines=False)[:limit].strip()


def clean_name(value: object, limit: int = MAX_NAME_LENGTH) -> str:
    return " ".join(clean_text(value, limit * 2).split())[:limit].strip()


def clean_message(value: object, limit: int = MAX_TEXT_LENGTH) -> str:
    raw = str(value if value is not None else "").replace("\r\n", "\n").replace("\r", "\n")
    return strip_unsafe(raw, keep_newlines=True)[:limit].strip()


def public_id(client_id: str, ip: str) -> str:
    return hashlib.sha256(f"{client_id}|{ip}".encode("utf-8")).hexdigest()[:PUBLIC_ID_LENGTH]


def format_duration(seconds: float) -> str:
    total = int(max(0, seconds))
    if total < 60:
        return f"{total}s"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def printable(value: object, limit: int = 80) -> str:
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:limit]


def is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("8.8.8.8", 80))
            return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def clamp_int(value: object, low: int, high: int, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if low <= number <= high else default


def normalize_settings(raw: object) -> dict:
    source = raw if isinstance(raw, dict) else {}
    settings = dict(DEFAULT_SETTINGS)

    for key in ("web_port_auto", "autostart", "open_browser"):
        if isinstance(source.get(key), bool):
            settings[key] = source[key]

    settings["web_port"] = clamp_int(source.get("web_port"), *PORT_LIMITS, DEFAULT_SETTINGS["web_port"])
    settings["history_max"] = clamp_int(
        source.get("history_max"), *HISTORY_LIMITS, DEFAULT_SETTINGS["history_max"]
    )

    bind = str(source.get("bind", "")).strip()
    settings["bind"] = bind if is_ipv4(bind) else DEFAULT_SETTINGS["bind"]
    host_name = clean_name(source.get("host_name"))
    settings["host_name"] = DEFAULT_HOST_NAME if host_name in ("", LEGACY_HOST_NAME) else host_name
    settings["host_color"] = clean_color(source.get("host_color"), DEFAULT_HOST_COLOR)
    return settings


def load_settings() -> dict:
    try:
        return normalize_settings(json.loads(SETTINGS_PATH.read_text("utf-8")))
    except (OSError, ValueError):
        return normalize_settings({})


def page_policy(page: bytes) -> str:
    hashes = []
    for script in INLINE_SCRIPT.findall(page):
        normalised = script.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest = base64.b64encode(hashlib.sha256(normalised).digest()).decode("ascii")
        hashes.append(f"'sha256-{digest}'")
    return CONTENT_SECURITY_POLICY.format(scripts=" ".join(hashes) or "'none'")


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-", suffix=".tmp")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except BaseException:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def save_settings(settings: dict) -> bool:
    try:
        atomic_write(SETTINGS_PATH, json.dumps(settings, indent=2).encode("utf-8"))
    except OSError:
        return False
    return True


def parse_picker_color(text: str) -> str | None:
    value = text.strip().lower()
    if HEX_COLOR.fullmatch(value):
        return value
    match = RGB_COLOR.fullmatch(value)
    if match:
        return "#" + "".join(f"{min(255, int(part)):02x}" for part in match.groups())
    if LONG_HEX_COLOR.fullmatch(value):
        return f"#{value[1:3]}{value[5:7]}{value[9:11]}"
    return None


class ColorPicker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._process: subprocess.Popen | None = None
        self._cancelled = False

    def _run(self, command: list[str]) -> tuple[int, str] | None:
        with self._lock:
            if self._cancelled:
                return None
            try:
                self._process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    text=True,
                )
            except OSError:
                return None
            process = self._process
        try:
            output, _ = process.communicate(timeout=PICKER_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            return None
        finally:
            with self._lock:
                self._process = None
        return process.returncode, output or ""

    def choose(self, current: str, title: str) -> tuple[bool, str | None]:
        zenity = shutil.which("zenity")
        if zenity:
            result = self._run(
                [zenity, "--color-selection", "--show-palette", f"--color={current}", f"--title={title}"]
            )
            if result is not None:
                code, output = result
                if code == 0:
                    return True, parse_picker_color(output)
                if code == PICKER_CANCELLED["zenity"]:
                    return True, None

        result = self._run([sys.executable, "-I", "-c", GTK_PICKER_SCRIPT, current, title])
        if result is not None:
            code, output = result
            if code == 0:
                return True, parse_picker_color(output)
            if code == PICKER_CANCELLED["gtk"]:
                return True, None
        return False, None

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            process = self._process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass


def encode_frame(opcode: int, payload: bytes = b"") -> bytes:
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = bytes([first, length])
    elif length < (1 << 16):
        header = bytes([first, 126]) + length.to_bytes(2, "big")
    else:
        header = bytes([first, 127]) + length.to_bytes(8, "big")
    return header + payload


def encode_json(event: dict) -> bytes:
    return encode_frame(OP_TEXT, json.dumps(event, separators=(",", ":")).encode("utf-8"))


def encode_close(code: int = CLOSE_NORMAL) -> bytes:
    return encode_frame(OP_CLOSE, struct.pack("!H", code))


def unmask(payload: bytes, mask: bytes) -> bytes:
    length = len(payload)
    if not length:
        return payload
    key = (mask * (length // 4 + 1))[:length]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(key, "big")).to_bytes(length, "big")


def read_frame(client: Client) -> tuple[bool, int, bytes] | None:
    header = client.read_exact(2)
    if header is None:
        return None

    fin = bool(header[0] & 0x80)
    reserved = header[0] & 0x70
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if reserved or not masked:
        return None

    if length == 126:
        extended = client.read_exact(2)
        if extended is None:
            return None
        length = int.from_bytes(extended, "big")
    elif length == 127:
        extended = client.read_exact(8)
        if extended is None:
            return None
        length = int.from_bytes(extended, "big")

    if length > MAX_MESSAGE_BYTES:
        return None
    if opcode >= OP_CLOSE and (length > 125 or not fin):
        return None

    mask = client.read_exact(4)
    if mask is None:
        return None
    payload = client.read_exact(length) if length else b""
    if payload is None:
        return None
    return fin, opcode, unmask(payload, mask)


class NeighbourTable:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._macs: dict[str, str] = {}
        self._gateway_mac: str | None = None
        self._loaded_at = float("-inf")

    @staticmethod
    def _read_macs() -> dict[str, str]:
        table: dict[str, str] = {}
        try:
            lines = ARP_PATH.read_text("ascii", "replace").splitlines()[1:]
        except OSError:
            return table
        for line in lines:
            parts = line.split()
            if len(parts) >= 4:
                mac = parts[3].lower()
                if MAC_ADDRESS.fullmatch(mac) and mac != EMPTY_MAC:
                    table[parts[0]] = mac
        return table

    @staticmethod
    def _read_gateway() -> str | None:
        try:
            lines = ROUTE_PATH.read_text("ascii", "replace").splitlines()[1:]
        except OSError:
            return None
        for line in lines:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "00000000":
                try:
                    return socket.inet_ntoa(struct.pack("<I", int(parts[2], 16)))
                except (ValueError, struct.error, OSError):
                    return None
        return None

    def mac_for(self, ip: str, fresh: bool = False) -> str | None:
        with self._lock:
            now = time.monotonic()
            age = now - self._loaded_at
            missing = ip not in self._macs and age >= NEIGHBOUR_RETRY
            if fresh or missing or age >= NEIGHBOUR_REFRESH:
                self._macs = self._read_macs()
                gateway = self._read_gateway()
                self._gateway_mac = self._macs.get(gateway) if gateway else None
                self._loaded_at = now
            mac = self._macs.get(ip)
            if mac is None or mac == self._gateway_mac:
                return None
            return mac


def load_bans() -> dict[str, dict]:
    try:
        raw = json.loads(BANS_PATH.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    bans: dict[str, dict] = {}
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        value = str(entry.get("value", "")).strip().lower()
        if (kind == "mac" and MAC_ADDRESS.fullmatch(value)) or (kind == "ip" and is_ipv4(value)):
            bans[f"{kind}:{value}"] = {
                "kind": kind,
                "value": value,
                "name": clean_name(entry.get("name")) or "Guest",
                "ip": str(entry.get("ip", "")) if is_ipv4(str(entry.get("ip", ""))) else "",
                "since": clean_text(entry.get("since"), 40),
            }
    return bans


def save_bans(bans: dict[str, dict]) -> bool:
    try:
        atomic_write(BANS_PATH, json.dumps(list(bans.values()), indent=2).encode("utf-8"))
    except OSError:
        return False
    return True


def wait_for_socket(conn: socket.socket, writable: bool, timeout: float) -> bool:
    descriptor = conn.fileno()
    if descriptor < 0:
        raise ValueError("socket is closed")
    if hasattr(select, "poll"):
        poller = select.poll()
        poller.register(descriptor, select.POLLOUT if writable else select.POLLIN | select.POLLPRI)
        events = poller.poll(int(timeout * 1000))
        if any(flags & select.POLLNVAL for _, flags in events):
            raise ValueError("socket is closed")
        return bool(events)
    readable, ready, _ = select.select([] if writable else [conn], [conn] if writable else [], [], timeout)
    return bool(ready if writable else readable)


class Client:
    def __init__(self, conn: socket.socket, address: tuple) -> None:
        self.conn = conn
        self.ip = address[0]
        self.id = f"{address[0]}:{address[1]}:{secrets.token_hex(3)}"
        self.cid: str | None = None
        self.username = "Guest"
        self.color = DEFAULT_USER_COLOR
        self.seen_hello = False
        self.typing = False
        self.away = False
        self.away_since: float | None = None
        self.connected_at = time.time()
        self.last_seen = time.monotonic()
        self.last_seen_wall = time.time()
        self.public_id: str | None = None
        self.recent_messages: list[float] = []
        self.warned_rate = False
        self.closed = False
        self.handshake_reserved = False
        self.channel: SecureChannel | None = None
        self.deadline: float | None = None
        self._buffer = bytearray()
        self._io_lock = threading.Lock()
        self.order_lock = threading.RLock()
        self.recent_frames: list[float] = []

    def claim(self, client_id: object) -> None:
        cleaned = clean_text(client_id, MAX_ID_LENGTH)
        if cleaned and not self.cid:
            self.cid = cleaned
            self.public_id = public_id(cleaned, self.ip)

    def allow_message(self) -> bool:
        now = time.monotonic()
        self.recent_messages = [stamp for stamp in self.recent_messages if now - stamp < RATE_WINDOW]
        if len(self.recent_messages) >= RATE_LIMIT:
            return False
        self.recent_messages.append(now)
        self.warned_rate = False
        return True

    def allow_frame(self) -> bool:
        now = time.monotonic()
        if len(self.recent_frames) >= EVENT_LIMIT:
            self.recent_frames = [stamp for stamp in self.recent_frames if now - stamp < EVENT_WINDOW]
            if len(self.recent_frames) >= EVENT_LIMIT:
                return False
        self.recent_frames.append(now)
        return True

    def touch(self) -> None:
        self.last_seen = time.monotonic()
        self.last_seen_wall = time.time()

    def quiet_since(self) -> float:
        return self.away_since if self.away and self.away_since else self.last_seen_wall

    @property
    def uid(self) -> str:
        return self.public_id or self.id

    def _fill(self) -> bool:
        while not self.closed:
            if self.deadline is not None and time.monotonic() > self.deadline:
                return False
            try:
                readable = wait_for_socket(self.conn, writable=False, timeout=READ_POLL)
            except (OSError, ValueError):
                return False
            if not readable:
                continue
            with self._io_lock:
                try:
                    chunk = self.conn.recv(RECV_CHUNK)
                except (BlockingIOError, InterruptedError):
                    continue
                except (OSError, ValueError):
                    return False
            if not chunk:
                return False
            self._buffer += chunk
            return True
        return False

    def read_exact(self, size: int) -> bytes | None:
        while len(self._buffer) < size:
            if not self._fill():
                return None
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def send_raw(self, data: bytes) -> None:
        view = memoryview(data)
        deadline = time.monotonic() + SEND_TIMEOUT
        with self._io_lock:
            while view:
                if self.closed:
                    raise ConnectionError("connection closed")
                try:
                    sent = self.conn.send(view)
                except (BlockingIOError, InterruptedError):
                    sent = 0
                except ValueError as error:
                    raise ConnectionError("connection closed") from error
                if sent:
                    view = view[sent:]
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("send timed out")
                try:
                    wait_for_socket(self.conn, writable=True, timeout=min(remaining, READ_POLL))
                except (OSError, ValueError) as error:
                    raise ConnectionError("connection closed") from error

    def send_event(self, event: dict) -> None:
        with self.order_lock:
            if self.channel is not None and self.channel.ready:
                frame = encode_frame(OP_BINARY, self.channel.seal(event))
            else:
                frame = encode_json(event)
            self.send_raw(frame)

    def try_event(self, event: dict) -> None:
        try:
            self.send_event(event)
        except OSError:
            pass

    def try_send(self, data: bytes) -> None:
        try:
            self.send_raw(data)
        except OSError:
            pass

    def close(self) -> None:
        self.closed = True
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except (OSError, ValueError):
            pass
        try:
            self.conn.close()
        except (OSError, ValueError):
            pass


KYBER_Q = 3329
KYBER_N = 256
KYBER_K = 3
KYBER_ETA1 = 2
KYBER_ETA2 = 2
KYBER_DU = 10
KYBER_DV = 4
MLKEM_CT_BYTES = 32 * (KYBER_DU * KYBER_K + KYBER_DV)


def _bitrev7(value: int) -> int:
    return int(f"{value:07b}"[::-1], 2)


ZETAS = [pow(17, _bitrev7(index), KYBER_Q) for index in range(128)]
GAMMAS = [pow(17, 2 * _bitrev7(index) + 1, KYBER_Q) for index in range(128)]


def _ntt(poly: list[int]) -> list[int]:
    f = list(poly)
    k = 1
    length = 128
    while length >= 2:
        for start in range(0, KYBER_N, 2 * length):
            zeta = ZETAS[k]
            k += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % KYBER_Q
                f[j + length] = (f[j] - t) % KYBER_Q
                f[j] = (f[j] + t) % KYBER_Q
        length //= 2
    return f


def _ntt_inverse(poly: list[int]) -> list[int]:
    f = list(poly)
    k = 127
    length = 2
    while length <= 128:
        for start in range(0, KYBER_N, 2 * length):
            zeta = ZETAS[k]
            k -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % KYBER_Q
                f[j + length] = zeta * (f[j + length] - t) % KYBER_Q
        length *= 2
    return [value * 3303 % KYBER_Q for value in f]


def _multiply_ntts(f: list[int], g: list[int]) -> list[int]:
    h = [0] * KYBER_N
    for index in range(128):
        a0, a1 = f[2 * index], f[2 * index + 1]
        b0, b1 = g[2 * index], g[2 * index + 1]
        h[2 * index] = (a0 * b0 + a1 * b1 * GAMMAS[index]) % KYBER_Q
        h[2 * index + 1] = (a0 * b1 + a1 * b0) % KYBER_Q
    return h


def _add(f: list[int], g: list[int]) -> list[int]:
    return [(a + b) % KYBER_Q for a, b in zip(f, g)]


def _subtract(f: list[int], g: list[int]) -> list[int]:
    return [(a - b) % KYBER_Q for a, b in zip(f, g)]


def _sample_ntt(seed: bytes) -> list[int]:
    size = 840
    while True:
        stream = hashlib.shake_128(seed).digest(size)
        coefficients: list[int] = []
        position = 0
        while len(coefficients) < KYBER_N and position + 3 <= len(stream):
            b0, b1, b2 = stream[position], stream[position + 1], stream[position + 2]
            position += 3
            d1 = b0 + 256 * (b1 % 16)
            d2 = (b1 >> 4) + 16 * b2
            if d1 < KYBER_Q:
                coefficients.append(d1)
            if d2 < KYBER_Q and len(coefficients) < KYBER_N:
                coefficients.append(d2)
        if len(coefficients) == KYBER_N:
            return coefficients
        size *= 2


def _sample_cbd(data: bytes, eta: int) -> list[int]:
    bits = int.from_bytes(data, "little")
    coefficients = []
    for index in range(KYBER_N):
        x = 0
        y = 0
        base = 2 * index * eta
        for j in range(eta):
            x += (bits >> (base + j)) & 1
            y += (bits >> (base + eta + j)) & 1
        coefficients.append((x - y) % KYBER_Q)
    return coefficients


def _prf(seed: bytes, counter: int, eta: int) -> bytes:
    return hashlib.shake_256(seed + bytes([counter])).digest(64 * eta)


def _encode(poly: list[int], bits: int) -> bytes:
    value = 0
    for index, coefficient in enumerate(poly):
        value |= coefficient << (index * bits)
    return value.to_bytes(32 * bits, "little")


def _decode(data: bytes, bits: int) -> list[int]:
    value = int.from_bytes(data, "little")
    mask = (1 << bits) - 1
    modulus = KYBER_Q if bits == 12 else 1 << bits
    return [((value >> (index * bits)) & mask) % modulus for index in range(KYBER_N)]


def _compress(poly: list[int], bits: int) -> list[int]:
    mask = (1 << bits) - 1
    return [(((value << bits) + KYBER_Q // 2) // KYBER_Q) & mask for value in poly]


def _decompress(poly: list[int], bits: int) -> list[int]:
    return [(value * KYBER_Q + (1 << (bits - 1))) >> bits for value in poly]


def _matrix(rho: bytes) -> list[list[list[int]]]:
    return [[_sample_ntt(rho + bytes([j, i])) for j in range(KYBER_K)] for i in range(KYBER_K)]


def _pke_keygen(d: bytes) -> tuple[bytes, bytes, list]:
    expanded = hashlib.sha3_512(d + bytes([KYBER_K])).digest()
    rho, sigma = expanded[:32], expanded[32:]
    matrix = _matrix(rho)
    counter = 0
    secret = []
    for _ in range(KYBER_K):
        secret.append(_ntt(_sample_cbd(_prf(sigma, counter, KYBER_ETA1), KYBER_ETA1)))
        counter += 1
    error = []
    for _ in range(KYBER_K):
        error.append(_ntt(_sample_cbd(_prf(sigma, counter, KYBER_ETA1), KYBER_ETA1)))
        counter += 1
    public = []
    for i in range(KYBER_K):
        total = error[i]
        for j in range(KYBER_K):
            total = _add(total, _multiply_ntts(matrix[i][j], secret[j]))
        public.append(total)
    ek = b"".join(_encode(poly, 12) for poly in public) + rho
    dk = b"".join(_encode(poly, 12) for poly in secret)
    return ek, dk, matrix


def _pke_encrypt(ek: bytes, message: bytes, randomness: bytes, matrix: list | None = None) -> bytes:
    public = [_decode(ek[384 * i : 384 * (i + 1)], 12) for i in range(KYBER_K)]
    rho = ek[384 * KYBER_K :]
    if matrix is None:
        matrix = _matrix(rho)
    counter = 0
    y = []
    for _ in range(KYBER_K):
        y.append(_ntt(_sample_cbd(_prf(randomness, counter, KYBER_ETA1), KYBER_ETA1)))
        counter += 1
    e1 = []
    for _ in range(KYBER_K):
        e1.append(_sample_cbd(_prf(randomness, counter, KYBER_ETA2), KYBER_ETA2))
        counter += 1
    e2 = _sample_cbd(_prf(randomness, counter, KYBER_ETA2), KYBER_ETA2)

    u = []
    for i in range(KYBER_K):
        total = [0] * KYBER_N
        for j in range(KYBER_K):
            total = _add(total, _multiply_ntts(matrix[j][i], y[j]))
        u.append(_add(_ntt_inverse(total), e1[i]))
    mu = _decompress(_decode(message, 1), 1)
    total = [0] * KYBER_N
    for i in range(KYBER_K):
        total = _add(total, _multiply_ntts(public[i], y[i]))
    v = _add(_add(_ntt_inverse(total), e2), mu)

    c1 = b"".join(_encode(_compress(poly, KYBER_DU), KYBER_DU) for poly in u)
    c2 = _encode(_compress(v, KYBER_DV), KYBER_DV)
    return c1 + c2


def _pke_decrypt(dk: bytes, ciphertext: bytes) -> bytes:
    size = 32 * KYBER_DU
    u = [
        _decompress(_decode(ciphertext[size * i : size * (i + 1)], KYBER_DU), KYBER_DU)
        for i in range(KYBER_K)
    ]
    v = _decompress(_decode(ciphertext[size * KYBER_K :], KYBER_DV), KYBER_DV)
    secret = [_decode(dk[384 * i : 384 * (i + 1)], 12) for i in range(KYBER_K)]
    total = [0] * KYBER_N
    for i in range(KYBER_K):
        total = _add(total, _multiply_ntts(secret[i], _ntt(u[i])))
    w = _subtract(v, _ntt_inverse(total))
    return _encode(_compress(w, 1), 1)


class MlKem768:
    def __init__(self, seed: bytes | None = None) -> None:
        seed = seed or secrets.token_bytes(64)
        d, z = seed[:32], seed[32:64]
        ek, dk_pke, matrix = _pke_keygen(d)
        self.public_key = ek
        self._dk_pke = dk_pke
        self._z = z
        self._hash = hashlib.sha3_256(ek).digest()
        self._matrix = matrix

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != MLKEM_CT_BYTES:
            raise ValueError("ML-KEM ciphertext has the wrong length")
        message = _pke_decrypt(self._dk_pke, ciphertext)
        expanded = hashlib.sha3_512(message + self._hash).digest()
        shared, randomness = expanded[:32], expanded[32:]
        rejected = hashlib.shake_256(self._z + ciphertext).digest(32)
        check = _pke_encrypt(self.public_key, message, randomness, self._matrix)
        return shared if hmac.compare_digest(check, ciphertext) else rejected


X25519_P = 2**255 - 19
X25519_A24 = 121665


def _x25519_scalar(k: bytes, u: bytes) -> bytes:
    scalar = bytearray(k)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    k_int = int.from_bytes(scalar, "little")
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    p = X25519_P
    for t in range(254, -1, -1):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % p
        aa = a * a % p
        b = (x2 - z2) % p
        bb = b * b % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = d * a % p
        cb = c * b % p
        x3 = (da + cb) ** 2 % p
        z3 = x1 * (da - cb) ** 2 % p
        x2 = aa * bb % p
        z2 = e * (aa + X25519_A24 * e) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")


class X25519:
    def __init__(self) -> None:
        if X25519PrivateKey is not None:
            self._key = X25519PrivateKey.generate()
            self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            self._key = None
            self._secret = secrets.token_bytes(32)
            self.public_key = _x25519_scalar(self._secret, (9).to_bytes(32, "little"))

    def exchange(self, peer: bytes) -> bytes:
        if len(peer) != 32:
            raise ValueError("X25519 public key has the wrong length")
        if self._key is not None:
            shared = self._key.exchange(X25519PublicKey.from_public_bytes(peer))
        else:
            shared = _x25519_scalar(self._secret, peer)
        if not any(shared):
            raise ValueError("X25519 produced an all-zero shared secret")
        return shared


def _rotate(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key))
    state += [counter & 0xFFFFFFFF]
    state += list(struct.unpack("<3I", nonce))
    x = list(state)
    for _ in range(10):
        for a, b, c, d in (
            (0, 4, 8, 12),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
            (0, 5, 10, 15),
            (1, 6, 11, 12),
            (2, 7, 8, 13),
            (3, 4, 9, 14),
        ):
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = _rotate(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = _rotate(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF
            x[d] = _rotate(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF
            x[b] = _rotate(x[b] ^ x[c], 7)
    return struct.pack("<16I", *((x[i] + state[i]) & 0xFFFFFFFF for i in range(16)))


def _chacha_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    output = bytearray()
    for offset in range(0, len(data), 64):
        block = _chacha_block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        output += bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(output)


def _poly1305(key: bytes, message: bytes) -> bytes:
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    accumulator = 0
    for offset in range(0, len(message), 16):
        chunk = message[offset : offset + 16] + b"\x01"
        accumulator = (accumulator + int.from_bytes(chunk, "little")) * r % p
    return ((accumulator + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    return b"\x00" * (-len(data) % 16)


def _aead_tag(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    one_time_key = _chacha_block(key, 0, nonce)[:32]
    mac_data = (
        aad + _pad16(aad) + ciphertext + _pad16(ciphertext) + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    return _poly1305(one_time_key, mac_data)


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    if X25519PrivateKey is not None:
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    ciphertext = _chacha_xor(key, 1, nonce, plaintext)
    return ciphertext + _aead_tag(key, nonce, aad, ciphertext)


def aead_decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes) -> bytes:
    if len(sealed) < 16:
        raise ValueError("message is too short")
    if X25519PrivateKey is not None:
        try:
            return ChaCha20Poly1305(key).decrypt(nonce, sealed, aad)
        except InvalidTag as error:
            raise ValueError("message failed authentication") from error
    ciphertext, tag = sealed[:-16], sealed[-16:]
    if not hmac.compare_digest(tag, _aead_tag(key, nonce, aad, ciphertext)):
        raise ValueError("message failed authentication")
    return _chacha_xor(key, 1, nonce, ciphertext)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_base64(value: object, size: int) -> bytes:
    if not isinstance(value, str) or len(value) > size * 2:
        raise ValueError("bad key exchange field")
    data = base64.b64decode(value, validate=True)
    if len(data) != size:
        raise ValueError("key exchange field has the wrong length")
    return data


class SecureChannel:
    def __init__(self) -> None:
        self._kem: MlKem768 | None = MlKem768()
        self._dh: X25519 | None = X25519()
        self._nonce = secrets.token_bytes(KEX_NONCE_BYTES)
        self._tx_key: bytes | None = None
        self._rx_key: bytes | None = None
        self._tx_counter = 0
        self._rx_counter = 0
        self.code = ""

    @property
    def ready(self) -> bool:
        return self._tx_key is not None

    def offer(self) -> dict:
        return {
            "type": "kex",
            "v": PROTOCOL_VERSION,
            "x25519": encode_base64(self._dh.public_key),
            "mlkem": encode_base64(self._kem.public_key),
            "nonce": encode_base64(self._nonce),
        }

    def accept(self, reply: object) -> None:
        if not isinstance(reply, dict) or reply.get("type") != "kex" or reply.get("v") != PROTOCOL_VERSION:
            raise ValueError("not a key exchange reply")
        if self._kem is None or self._dh is None:
            raise ValueError("key exchange already finished")
        peer = decode_base64(reply.get("x25519"), 32)
        ciphertext = decode_base64(reply.get("mlkem"), MLKEM_CT_BYTES)
        nonce = decode_base64(reply.get("nonce"), KEX_NONCE_BYTES)
        transcript = hashlib.sha256(
            KEX_LABEL + self._dh.public_key + self._kem.public_key + self._nonce + peer + ciphertext + nonce
        ).digest()
        secret = self._kem.decapsulate(ciphertext) + self._dh.exchange(peer)
        material = hkdf_sha256(secret, transcript, KEY_INFO, 72)
        self._rx_key, self._tx_key = material[:32], material[32:64]
        number = int.from_bytes(material[64:72], "big") % 100_000_000
        self.code = f"{number // 10000:04d} {number % 10000:04d}"
        self._kem = None
        self._dh = None

    def seal(self, event: dict) -> bytes:
        data = json.dumps(event, separators=(",", ":")).encode("utf-8")
        data += b" " * (-len(data) % PAD_BLOCK)
        header = self._tx_counter.to_bytes(8, "big")
        self._tx_counter += 1
        return header + aead_encrypt(self._tx_key, bytes(4) + header, data, AAD_SERVER)

    def open(self, payload: bytes) -> bytes:
        if self._rx_key is None or len(payload) < 24:
            raise ValueError("message is too short")
        header = payload[:8]
        if int.from_bytes(header, "big") != self._rx_counter:
            raise ValueError("message is out of order or replayed")
        data = aead_decrypt(self._rx_key, bytes(4) + header, payload[8:], AAD_CLIENT)
        self._rx_counter += 1
        return data


class HttpHandler(BaseHTTPRequestHandler):
    server_version = f"BlueChat/{APP_VERSION}"
    sys_version = ""
    timeout = HTTP_TIMEOUT

    def do_GET(self) -> None:
        self._respond(include_body=True)

    def do_HEAD(self) -> None:
        self._respond(include_body=False)

    def _respond(self, include_body: bool) -> None:
        chat: ChatServer = self.server.chat
        client_ip = self.client_address[0]

        if chat.is_banned(client_ip):
            self._send(403, b"Forbidden", "text/plain; charset=utf-8", include_body)
            chat.notice(("http-banned", client_ip), f"Blocked web request from banned address {client_ip}")
            return

        path = urlsplit(self.path).path

        if path == "/ws" and include_body and self.headers.get("Upgrade", "").lower() == "websocket":
            self.close_connection = True
            chat.serve_websocket(self)
            return

        if path in ("/", "/index.html"):
            try:
                body = chat.html_path.read_bytes()
                status = 200
            except OSError:
                body = b"index.html is missing. Put it in the same folder as blue_chat.py."
                status = 500
                chat.log("index.html was not found next to blue_chat.py", "error")
            self._send(status, body, "text/html; charset=utf-8", include_body, policy=page_policy(body))
            if include_body and status == 200:
                chat.log(f"Page opened by {client_ip}")
        elif path == "/config":
            body = json.dumps(
                {
                    "web_port": chat.web_port,
                    "version": APP_VERSION,
                    "encryption": PROTOCOL_NAME,
                }
            ).encode("utf-8")
            self._send(200, body, "application/json", include_body)
        elif path == "/icon.svg":
            self._send(200, ICON_SVG.encode("utf-8"), "image/svg+xml", include_body)
        elif path == "/health":
            self._send(200, b"ok", "text/plain; charset=utf-8", include_body)
        else:
            self._send(404, b"Not found", "text/plain; charset=utf-8", include_body)
            chat.notice(
                ("http-404", client_ip, path),
                f"{client_ip} asked for {printable(path)}, which does not exist (404)",
            )

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        include_body: bool,
        policy: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        if policy:
            self.send_header("Content-Security-Policy", policy)
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, *_args) -> None:
        return


class QuietHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    chat: ChatServer

    def handle_error(self, request, client_address) -> None:
        error = sys.exc_info()[1]
        if isinstance(error, OSError):
            return
        self.chat.log(f"Web request from {client_address[0]} failed: {error!r}", "error")


class ChatServer:
    def __init__(self, events: queue.Queue, html_path: Path, history_max: int) -> None:
        self.events = events
        self.html_path = html_path
        self.history_max = history_max
        self.host_id = f"host-{secrets.token_hex(6)}"

        self._clients_lock = threading.Lock()
        self._clients: dict[socket.socket, Client] = {}
        self._history_lock = threading.Lock()
        self._history: list[dict] = []
        self._ban_lock = threading.Lock()
        self._bans: dict[str, dict] = load_bans()
        self.neighbours = NeighbourTable()
        self._count_lock = threading.Lock()
        self._message_count = 0
        self._notice_lock = threading.Lock()
        self._notices: dict[tuple, float] = {}
        self._departure_lock = threading.Lock()
        self._departures: dict[str, dict] = {}
        self._read_lock = threading.Lock()
        self._reads: dict[str, dict] = {}
        self._pending_lock = threading.Lock()
        self._pending = 0

        self.running = False
        self.bind = DEFAULT_SETTINGS["bind"]
        self.web_port: int | None = None
        self.started_at: float | None = None
        self._httpd: QuietHTTPServer | None = None
        self._stop_event: threading.Event | None = None

    @property
    def message_count(self) -> int:
        with self._count_lock:
            return self._message_count

    def display_host(self) -> str:
        return get_local_ip() if self.bind == "0.0.0.0" else self.bind

    def emit(self, kind: str, data: object = None) -> None:
        self.events.put((kind, data))

    def log(self, text: str, level: str = "info", color: str | None = None) -> None:
        self.emit("log", {"text": text, "level": level, "time": time.time(), "color": color})

    def notice(self, key: tuple, text: str, level: str = "warn") -> None:
        now = time.monotonic()
        with self._notice_lock:
            if now - self._notices.get(key, -NOTICE_INTERVAL) < NOTICE_INTERVAL:
                return
            if len(self._notices) > 1000:
                self._notices = {k: v for k, v in self._notices.items() if now - v < NOTICE_INTERVAL}
            self._notices[key] = now
        self.log(f"{text} (repeats hidden for {NOTICE_INTERVAL}s)", level)

    def status(self, kind: str, message: str, color: str | None = None) -> None:
        event = {"type": "system", "kind": kind, "msg": message, "ts": now_iso()}
        if color:
            event["color"] = color
        self.broadcast(event)

    @staticmethod
    def _port_candidates(port: int | None, port_range: tuple[int, int]) -> list[int]:
        if port:
            return [port]
        pool = list(range(port_range[0], port_range[1] + 1))
        random.shuffle(pool)
        return pool[:PORT_ATTEMPTS]

    def _bind_http(self, bind: str, port: int | None) -> tuple[QuietHTTPServer, int]:
        last_error: OSError | None = None
        for candidate in self._port_candidates(port, WEB_PORT_RANGE):
            try:
                httpd = QuietHTTPServer((bind, candidate), HttpHandler)
            except OSError as error:
                last_error = error
                continue
            httpd.chat = self
            return httpd, candidate
        raise OSError(f"Could not open the web port: {last_error}")

    def start(self, bind: str, web_port: int | None) -> None:
        if self.running:
            return

        httpd, chosen_web_port = self._bind_http(bind, web_port)
        self.bind = bind
        self._httpd = httpd
        self.web_port = chosen_web_port
        self._stop_event = threading.Event()
        self.started_at = time.time()
        self.running = True

        threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.5},
            name="http-serve",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._heartbeat_loop,
            args=(self._stop_event,),
            name="heartbeat",
            daemon=True,
        ).start()

        self.status("startup", "The server is online")
        self.log(f"{APP_NAME} {APP_VERSION} started on port {chosen_web_port}")
        self.log(f"Every chat connection is encrypted: {PROTOCOL_NAME}")
        if X25519PrivateKey is None:
            self.log(
                "Using the built-in encryption code. Installing python3-cryptography makes it faster",
                "warn",
            )
        if not self.html_path.exists():
            self.log(f"{self.html_path.name} was not found in {self.html_path.parent}", "warn")
        with self._ban_lock:
            ban_count = len(self._bans)
        if ban_count:
            self.log(
                f"{ban_count} banned device{'s' if ban_count != 1 else ''} will stay blocked "
                f"(saved in {BANS_PATH.name})"
            )
        self.emit("state")

    def stop(self) -> None:
        if not self.running:
            return

        self.status("shutdown", "The server is shutting down")
        self.running = False
        if self._stop_event is not None:
            self._stop_event.set()

        with self._clients_lock:
            clients = list(self._clients.values())
        for client in clients:
            client.try_send(encode_close(CLOSE_NORMAL))
            client.close()

        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

        self.started_at = None
        self.log("Server stopped")
        self.emit("state")

    def _origin_allowed(self, origin: str | None, host: str | None) -> bool:
        if not origin:
            return True
        try:
            parts = urlsplit(origin)
            port = parts.port or 80
            requested = urlsplit(f"//{host or ''}").hostname
        except ValueError:
            return False
        return (
            parts.scheme == "http"
            and port == self.web_port
            and parts.hostname is not None
            and requested is not None
            and parts.hostname.lower() == requested.lower()
        )

    def _refuse(self, handler: BaseHTTPRequestHandler, status: int, key: str, text: str) -> None:
        handler.send_response(status)
        if status == 426:
            handler.send_header("Sec-WebSocket-Version", "13")
        handler.send_header("Content-Length", "0")
        handler.send_header("Connection", "close")
        handler.end_headers()
        ip = handler.client_address[0]
        self.notice((key, ip), f"Refused chat connection from {ip}: {text}")

    def _upgrade(self, handler: BaseHTTPRequestHandler, client: Client) -> bool:
        headers = handler.headers
        key = headers.get("Sec-WebSocket-Key", "")
        connection_tokens = [token.strip().lower() for token in headers.get("Connection", "").split(",")]
        try:
            key_ok = len(base64.b64decode(key, validate=True)) == 16
        except ValueError:
            key_ok = False

        if not key_ok or "upgrade" not in connection_tokens:
            self._refuse(handler, 400, "ws-bad", "not a WebSocket request")
            return False
        if headers.get("Sec-WebSocket-Version") != "13":
            self._refuse(handler, 426, "ws-version", "unsupported WebSocket version")
            return False
        origin = headers.get("Origin")
        if not self._origin_allowed(origin, headers.get("Host")):
            self._refuse(handler, 403, "ws-origin", f"it came from another website ({printable(origin)})")
            return False
        with self._clients_lock:
            full = len(self._clients) >= MAX_CLIENTS
        if full:
            self._refuse(handler, 503, "ws-full", f"server is full ({MAX_CLIENTS})")
            return False

        claimed = parse_qs(urlsplit(handler.path).query).get("uid")
        if claimed:
            client.claim(claimed[0])

        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
        handler.protocol_version = "HTTP/1.1"
        handler.send_response_only(101)
        handler.send_header("Upgrade", "websocket")
        handler.send_header("Connection", "Upgrade")
        handler.send_header("Sec-WebSocket-Accept", accept)
        handler.end_headers()
        handler.wfile.flush()
        return True

    @staticmethod
    def _tune_socket(conn: socket.socket) -> None:
        for level, option in (
            (socket.IPPROTO_TCP, socket.TCP_NODELAY),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE),
        ):
            try:
                conn.setsockopt(level, option, 1)
            except (OSError, ValueError):
                pass
        conn.setblocking(False)

    def serve_websocket(self, handler: BaseHTTPRequestHandler) -> None:
        if not self.running:
            return
        if not self._reserve_handshake():
            self._refuse(handler, 503, "ws-busy", "too many connections are being set up at once")
            return

        conn = handler.connection
        client = Client(conn, handler.client_address)
        client.handshake_reserved = True
        try:
            if not self._upgrade(handler, client):
                return
            self._tune_socket(conn)
            client.channel = SecureChannel()
            client.deadline = time.monotonic() + KEX_TIMEOUT
            client.send_event(client.channel.offer())
            self._receive_loop(client)
        except OSError:
            pass
        finally:
            self._finish_handshake(client)
            self._drop(client)

    def _reserve_handshake(self) -> bool:
        with self._pending_lock:
            if self._pending >= MAX_PENDING_HANDSHAKES:
                return False
            self._pending += 1
            return True

    def _finish_handshake(self, client: Client) -> None:
        client.deadline = None
        with self._pending_lock:
            if client.handshake_reserved:
                client.handshake_reserved = False
                self._pending -= 1

    def _complete_key_exchange(self, client: Client, raw: bytes) -> bool:
        try:
            client.channel.accept(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError):
            self.notice(
                ("kex", client.ip),
                f"Closed a chat connection from {client.ip}: its encryption setup was invalid",
            )
            return False
        return self._admit(client)

    def _admit(self, client: Client) -> bool:
        if not self.running:
            return False
        with client.order_lock:
            with self._clients_lock:
                full = len(self._clients) >= MAX_CLIENTS
                if not full:
                    self._clients[client.conn] = client
                    roster = {
                        other.uid: other
                        for other in self._clients.values()
                        if other is not client and other.seen_hello
                    }
            if full:
                self.notice(
                    ("ws-full", client.ip), f"Refused chat connection from {client.ip}: server is full"
                )
                return False
            self._send_backlog(client, roster)
        self.emit("clients")
        return True

    def _send_backlog(self, client: Client, roster: dict[str, Client]) -> None:
        client.send_event({"type": "welcome", "user_id": client.uid, "ts": now_iso()})
        with self._history_lock:
            replay = self._history[-HISTORY_REPLAY:]
        for event in replay:
            client.send_event(event)
        for uid, other in roster.items():
            client.send_event(
                {
                    "type": "presence",
                    "event": "online",
                    "user_id": uid,
                    "username": other.username,
                    "color": other.color,
                    "ts": now_iso(),
                }
            )
        for position in self.read_positions():
            client.send_event(position)
        client.send_event({"type": "system", "msg": "connected", "client_id": client.id, "ts": now_iso()})

    def _receive_loop(self, client: Client) -> None:
        message = bytearray()
        message_opcode: int | None = None

        while True:
            frame = read_frame(client)
            if frame is None:
                return
            client.touch()
            fin, opcode, payload = frame
            if not client.allow_frame():
                self.notice(
                    ("flood", client.ip),
                    f"Closed a chat connection from {client.ip}: it was sending far too much data",
                )
                return

            if opcode == OP_CLOSE:
                client.try_send(encode_close(CLOSE_NORMAL))
                return
            if opcode == OP_PING:
                client.send_raw(encode_frame(OP_PONG, payload))
                continue
            if opcode == OP_PONG:
                continue

            if opcode == OP_CONTINUATION:
                if message_opcode is None:
                    return
                message += payload
            elif opcode in (OP_TEXT, OP_BINARY):
                if message_opcode is not None:
                    return
                message_opcode = opcode
                message = bytearray(payload)
            else:
                return

            if len(message) > MAX_MESSAGE_BYTES:
                return
            if not fin:
                continue

            raw = bytes(message)
            message = bytearray()
            channel_ready = client.channel is not None and client.channel.ready
            if message_opcode == OP_TEXT:
                if channel_ready:
                    return
                self._finish_handshake(client)
                if not self._complete_key_exchange(client, raw):
                    return
            elif not channel_ready:
                return
            else:
                try:
                    self._dispatch(client, client.channel.open(raw))
                except ValueError:
                    self.notice(
                        ("decrypt", client.ip),
                        f"Closed a chat connection from {client.ip}: a message failed its integrity check",
                    )
                    return
            message_opcode = None

    def _dispatch(self, client: Client, raw: bytes) -> None:
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return
        if isinstance(data, dict):
            self._handle(client, data)

    def _handle(self, client: Client, data: dict) -> None:
        kind = data.get("type")

        with self._clients_lock:
            if client.conn not in self._clients:
                return
            if "user_id" in data:
                client.claim(data["user_id"])
            previous_name = client.username
            previous_color = client.color
            if "username" in data:
                client.username = clean_name(data["username"]) or "Guest"
            if "color" in data:
                client.color = clean_color(data["color"])
            first_hello = kind == "hello" and not client.seen_hello
            if kind == "hello":
                client.seen_hello = True
            elif kind == "typing":
                client.typing = bool(data.get("typing", False))
            allowed = True
            warn_rate = False
            stopped_typing_on_send = False
            if kind == "message":
                allowed = client.allow_message()
                if not allowed and not client.warned_rate:
                    client.warned_rate = warn_rate = True
                if allowed and client.typing:
                    client.typing = False
                    stopped_typing_on_send = True
            went_away = came_back = stopped_typing = False
            away_for = 0.0
            if kind == "away" and client.seen_hello:
                wants_away = bool(data.get("away", False))
                if wants_away and not client.away:
                    client.away = True
                    client.away_since = time.time()
                    went_away = True
                    stopped_typing = client.typing
                    client.typing = False
                elif not wants_away and client.away:
                    away_for = time.time() - (client.away_since or time.time())
                    client.away = False
                    client.away_since = None
                    came_back = True
            known = client.seen_hello and not first_hello
            uid = client.uid
            name = client.username
            color = client.color

        renamed = known and name != previous_name
        recolored = known and color != previous_color

        if first_hello:
            self.broadcast(
                {
                    "type": "presence",
                    "event": "online",
                    "user_id": uid,
                    "username": name,
                    "color": color,
                    "ts": now_iso(),
                }
            )
            self._announce_arrival(client, name, color)
            if client.channel is not None:
                self.log(f"{name}'s security code is {client.channel.code}", color=color)
        if went_away:
            if stopped_typing:
                self.broadcast(
                    {"type": "typing", "user_id": uid, "typing": False, "ts": now_iso()},
                    exclude=client,
                )
            self.status("away", f"{name} stepped away (page in background)", color)
            self.log(f"{name} ({client.ip}) put the page in the background", color=color)
            self.emit("clients")
        if came_back:
            self.status("back", f"{name} is back after {format_duration(away_for)}", color)
            self.log(f"{name} ({client.ip}) returned after {format_duration(away_for)} away", color=color)
            self.emit("clients")
        if renamed:
            self.status("rename", f"{previous_name} has changed their username to {name}", color)
            self.log(f"{previous_name} changed their username to {name} ({client.ip})", color=color)
        if recolored:
            self.status("color", f"{name} has changed their colour to {color}", color)
            self.log(
                f"{name} changed their colour from {previous_color} to {color} ({client.ip})", color=color
            )
        if renamed:
            self._rename_reader(uid, name)
        if kind == "hello" or renamed or recolored:
            self.broadcast(
                {
                    "type": "identity",
                    "user_id": uid,
                    "username": name,
                    "color": color,
                    "ts": now_iso(),
                }
            )
            self.emit("clients")

        if kind == "message":
            if warn_rate:
                client.try_event(
                    {
                        "type": "system",
                        "kind": "limit",
                        "msg": "You're sending messages too quickly. Please wait a moment.",
                        "ts": now_iso(),
                    }
                )
                self.notice(
                    ("rate", uid),
                    f"{name} ({client.ip}) is sending messages too quickly; extra messages are being dropped",
                )
            if stopped_typing_on_send:
                self.broadcast(
                    {"type": "typing", "user_id": uid, "typing": False, "ts": now_iso()},
                    exclude=client,
                )
                self.emit("clients")
            text = clean_message(data.get("text")) if allowed else ""
            if text:
                self.broadcast(
                    {
                        "type": "message",
                        "seq": self._count_message(),
                        "user_id": uid,
                        "username": name,
                        "color": color,
                        "text": text,
                        "ts": now_iso(),
                    }
                )
        elif kind == "read" and client.seen_hello:
            self._record_read(uid, name, data.get("seq"))
        elif kind == "typing":
            self.broadcast(
                {
                    "type": "typing",
                    "user_id": uid,
                    "typing": bool(data.get("typing", False)),
                    "ts": now_iso(),
                },
                exclude=client,
            )
            self.emit("clients")

    def _count_message(self) -> int:
        with self._count_lock:
            self._message_count += 1
            return self._message_count

    def _record_read(self, uid: str, name: str, value: object) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            return
        with self._count_lock:
            latest = self._message_count
        if not 0 < value <= latest:
            return
        with self._read_lock:
            previous = self._reads.get(uid)
            if previous is not None and previous["seq"] >= value:
                return
            if len(self._reads) >= MAX_READERS and uid not in self._reads:
                oldest = min(self._reads, key=lambda key: self._reads[key]["seq"])
                del self._reads[oldest]
            self._reads[uid] = {"seq": value, "username": name}
        self.broadcast({"type": "read", "user_id": uid, "username": name, "seq": value, "ts": now_iso()})

    def _rename_reader(self, uid: str, name: str) -> None:
        with self._read_lock:
            if uid in self._reads:
                self._reads[uid]["username"] = name

    def read_positions(self) -> list[dict]:
        with self._read_lock:
            return [
                {"type": "read", "user_id": uid, "username": info["username"], "seq": info["seq"]}
                for uid, info in self._reads.items()
            ]

    def _announce_arrival(self, client: Client, name: str, color: str) -> None:
        now = time.time()
        with self._clients_lock:
            others = [
                other
                for other in self._clients.values()
                if other is not client and other.seen_hello and other.uid == client.uid
            ]
        stale = [other for other in others if other.away or time.monotonic() - other.last_seen > STALE_AFTER]
        with self._departure_lock:
            departure = self._departures.pop(client.uid, None)

        if stale:
            quiet_since = min(other.quiet_since() for other in stale)
            for other in stale:
                self._drop(other, announce=False, reason="replaced")
            self.status("back", f"{name} is back after {format_duration(now - quiet_since)}", color)
            self.log(
                f"{name} reconnected from {client.ip} and replaced a connection that had gone quiet",
                color=color,
            )
        elif others:
            self.status("join", f"{name} connected (another tab)", color)
            self.log(f"{name} opened another connection from {client.ip}", color=color)
        elif departure and now - departure["time"] <= RESUME_WINDOW:
            gone_for = format_duration(now - departure["since"])
            if departure["reason"] in ("timeout", "background"):
                self.status("back", f"{name} is back after {gone_for}", color)
            else:
                self.status("join", f"{name} reconnected after {gone_for}", color)
            self.log(
                f"{name} reconnected from {client.ip} after {gone_for} ({departure['reason']})",
                color=color,
            )
        else:
            self.status("join", f"{name} connected", color)
            self.log(f"{name} joined from {client.ip} with colour {color}", color=color)

    def _remember_departure(self, client: Client, reason: str) -> None:
        now = time.time()
        since = client.quiet_since() if reason in ("timeout", "background") else now
        with self._departure_lock:
            if len(self._departures) > 500:
                self._departures = {
                    uid: info for uid, info in self._departures.items() if now - info["time"] <= RESUME_WINDOW
                }
            self._departures[client.uid] = {"time": now, "since": since, "reason": reason}

    def _heartbeat_loop(self, stop_event: threading.Event) -> None:
        ping = encode_frame(OP_PING, b"bluechat")
        last_ping = 0.0
        while not stop_event.wait(HEARTBEAT_TICK):
            now = time.monotonic()
            with self._clients_lock:
                clients = list(self._clients.values())
            if now - last_ping >= PING_INTERVAL:
                last_ping = now
                for client in clients:
                    client.try_send(ping)
            for client in clients:
                if now - client.last_seen > IDLE_TIMEOUT:
                    self._time_out(client)

    def _time_out(self, client: Client) -> None:
        with self._clients_lock:
            if client.conn not in self._clients:
                return
            has_other = any(
                other is not client and other.seen_hello and other.uid == client.uid
                for other in self._clients.values()
            )
        if client.seen_hello and not has_other:
            if client.away:
                message = f"{client.username} timed out while the page was in the background"
            else:
                message = f"{client.username} timed out (no response for {format_duration(IDLE_TIMEOUT)})"
            self.status("timeout", message, client.color)
        self.log(
            f"{client.username} ({client.ip}) stopped responding, closed after "
            f"{format_duration(IDLE_TIMEOUT)} of silence",
            "warn",
            client.color,
        )
        client.try_send(encode_close(CLOSE_GOING_AWAY))
        self._drop(client, announce=False, reason="timeout")

    def _drop(self, client: Client, announce: bool = True, reason: str = "leave") -> None:
        with self._clients_lock:
            removed = self._clients.pop(client.conn, None)
            has_other = removed is not None and any(
                other.seen_hello and other.uid == client.uid for other in self._clients.values()
            )
        client.close()
        if removed is None:
            return

        if not has_other:
            self.broadcast({"type": "presence", "event": "offline", "user_id": client.uid, "ts": now_iso()})

        if client.seen_hello:
            duration = format_duration(time.time() - client.connected_at)
            if has_other:
                self.log(
                    f"{client.username} closed an extra connection ({client.ip}) after {duration}",
                    color=client.color,
                )
            else:
                if reason == "leave" and client.away:
                    reason = "background"
                if reason in ("leave", "background", "timeout"):
                    self._remember_departure(client, reason)
                if announce and self.running:
                    if reason == "background":
                        self.status(
                            "away", f"{client.username} disconnected (page in background)", client.color
                        )
                    else:
                        self.status("leave", f"{client.username} disconnected", client.color)
                self.log(f"{client.username} left ({client.ip}) after {duration}", color=client.color)
        self.emit("clients")

    def broadcast(self, event: dict, exclude: Client | None = None) -> None:
        with self._clients_lock:
            targets = [client for client in self._clients.values() if client is not exclude]

        unreachable = []
        for client in targets:
            try:
                client.send_event(event)
            except OSError:
                unreachable.append(client)

        event_type = event.get("type")
        if event_type in STORED_EVENT_TYPES:
            with self._history_lock:
                self._history.append(event)
                if len(self._history) > self.history_max:
                    del self._history[: -self.history_max]
        if event_type in CHAT_EVENT_TYPES:
            self.emit("chat", event)

        for client in unreachable:
            self._drop(client)

    def snapshot(self) -> list[dict]:
        with self._clients_lock:
            return [
                {
                    "id": client.id,
                    "name": client.username,
                    "color": client.color,
                    "ip": client.ip,
                    "since": client.connected_at,
                    "typing": client.typing,
                    "away": client.away,
                    "ready": client.seen_hello,
                }
                for client in self._clients.values()
            ]

    def announce(self, text: str) -> None:
        message = clean_message(text)
        if message:
            self.status("announcement", message)
            self.log(f"Announcement sent: {message}")

    def host_identity_changed(self, old_name: str, new_name: str, old_color: str, new_color: str) -> None:
        if not self.running:
            return
        if new_name != old_name:
            self.status("rename", f"{old_name} has changed their username to {new_name}", new_color)
            self.log(f"Host name changed from {old_name} to {new_name}", color=new_color)
        if new_color != old_color:
            self.status("color", f"{new_name} has changed their colour to {new_color}", new_color)
            self.log(f"Host colour changed from {old_color} to {new_color}", color=new_color)

    def send_as_host(self, text: str, name: str, color: str) -> None:
        message = clean_message(text)
        if not message:
            return
        self.broadcast(
            {
                "type": "message",
                "seq": self._count_message(),
                "user_id": self.host_id,
                "username": clean_name(name) or DEFAULT_HOST_NAME,
                "color": clean_color(color, DEFAULT_HOST_COLOR),
                "text": message,
                "ts": now_iso(),
            }
        )

    def kick(self, client_ids: set[str], kind: str = "kick") -> int:
        verb = "was banned by the host" if kind == "ban" else "was removed by the host"
        with self._clients_lock:
            targets = [client for client in self._clients.values() if client.id in client_ids]
        for client in targets:
            self.status(kind, f"{client.username} {verb}", client.color)
            self.log(f"{client.username} ({client.ip}) {verb}", "warn", client.color)
            client.try_send(encode_close(CLOSE_POLICY))
            self._drop(client, announce=False, reason=kind)
        return len(targets)

    def is_banned(self, ip: str) -> bool:
        with self._ban_lock:
            if not self._bans:
                return False
            if f"ip:{ip}" in self._bans:
                return True
            check_mac = any(entry["kind"] == "mac" for entry in self._bans.values())
        if not check_mac:
            return False
        mac = self.neighbours.mac_for(ip)
        if mac is None:
            return False
        with self._ban_lock:
            return f"mac:{mac}" in self._bans

    def banned(self) -> list[tuple[str, str]]:
        with self._ban_lock:
            entries = sorted(self._bans.items(), key=lambda item: item[1]["since"])
        return [(key, f"{entry['name']} · {entry['value']}") for key, entry in entries]

    def ban(self, people: list[tuple[str, str]]) -> None:
        added = []
        for name, ip in people:
            if not is_ipv4(ip):
                continue
            mac = self.neighbours.mac_for(ip, fresh=True)
            kind, value = ("mac", mac) if mac else ("ip", ip)
            entry = {
                "kind": kind,
                "value": value,
                "name": clean_name(name) or "Guest",
                "ip": ip,
                "since": now_iso(),
            }
            with self._ban_lock:
                self._bans[f"{kind}:{value}"] = entry
            added.append(entry)

        with self._clients_lock:
            remaining = list(self._clients.values())
        blocked = {client.id for client in remaining if self.is_banned(client.ip)}
        self.kick(blocked, "ban")

        with self._ban_lock:
            stored = save_bans(self._bans)
        for entry in added:
            if entry["kind"] == "mac":
                self.log(
                    f"Banned {entry['name']}'s device (hardware address {entry['value']}) until you unban it",
                    "warn",
                )
            else:
                self.log(
                    f"Banned {entry['name']} by IP address {entry['value']} until you unban it "
                    "(this device's hardware address isn't visible to the Pi)",
                    "warn",
                )
        if not stored:
            self.log(f"Could not save {BANS_PATH}, so bans will end when the app closes", "error")
        self.emit("clients")

    def unban(self, key: str) -> None:
        with self._ban_lock:
            entry = self._bans.pop(key, None)
            stored = entry is None or save_bans(self._bans)
        if entry is None:
            return
        self.log(f"Unbanned {entry['name']} ({entry['value']})")
        if not stored:
            self.log(f"Could not save {BANS_PATH}", "error")
        self.emit("clients")

    def clear_history(self) -> None:
        with self._history_lock:
            self._history.clear()
        with self._read_lock:
            self._reads.clear()
        self.log("Chat history cleared, new visitors start fresh")

    def history(self) -> list[dict]:
        with self._history_lock:
            return list(self._history)


BG = "#0f1115"
PANEL = "#161a22"
RAISED = "#1d2330"
HOVER = "#26304a"
FIELD = "#0f1218"
SELECT = "#2a3b5f"
BORDER = "#283143"
TEXT = "#e6eaf0"
MUTED = "#9aa4b2"
DISABLED = "#556070"
ACCENT = "#4a90e2"
ACCENT_HOVER = "#3b7fd0"
RED = "#d9534f"
PILL_OFF = "#2b3240"
AMBER = "#f0ad4e"
IDLE = "#7f93b5"
BACK = "#5cb88a"

FEED_MAX_LINES = 4000
LOG_MAX_LINES = 2000
PUMP_INTERVAL_MS = 100
PUMP_BATCH = 500
MODE_CHAT = "Chat message"
MODE_ANNOUNCE = "Announcement"
MESSAGE_GAP = "  "
TIME_FORMAT = "%H:%M:%S"
ICON_PNGS = {
    16: (
        "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACnElEQVR42p2SXUhUaRzGf+85R+ZDp840TmmWH5vDpPapKblC"
        "RRCbbBERtHu3JBVBVy2LN3URXUVXQdCFLWxZ0UVBl0Uu0ZfR3RKt6Vpg6s5gzaxOjs44533fc7pwdaVa+vhd/Xme//Pw8vKH"
        "BQRaj1fwCd7fMeants5QS7y8e2vHufb/C2/tONfeEi/vpq0zNKdZ827vmWx0c/fg9uZY91T27K95XzhhmGYZgKdk0u+8XfnD"
        "d5sO3X3y4jq9Z7IfFgADo5MjOphZEm/b/kuxHbWsIhMA6Whymde659mYMTA8MbQwY84NjUdu7o9WxU/HG1sDy8uiRvbNKN74"
        "K9zJNwghqI6tNoLLasS0NBsXx3YMjv1xY2C+wN5yamPt2uZr5asaInnHIz0yyK56wc8/buL71irkZJpHfSlmLJvFkWVBKZ1v"
        "U/lIj5PsTRkA5ZXVR0PRFVHpKJyColim2LOtjq6uC+zduw890U+JTDHnh8uqK8tqag/O/kH9sSX+UGQdwsIpKBAg8AD47eIl"
        "EokkmUyGht0n5n2ERbG9dD0bTtoWioDACjgFRQmanGcwY4S59bCfq1cuc6enB3/4G+79baMdhd9T5IwiTCtgM5UrsezSoKWU"
        "sqSjaTLT9BeKGFI2l+4nsa0shqhiIh1kXISpUePU+SS/y1KUkgG71LAsAK09HEdxC5tcNs3I4/OsqSymt+8lAOsbavlreJqZ"
        "tgMMhUoRQqOl+98daO0iHTUr+MJUNP+Em3+KLyIAcBetoqJlA6bPRjoa8NCut6BAuaSGn/8TDC/XTmHKFK5HzoixKFaLJwRj"
        "rgf5HPncNJY/pPMTCdNV/74gU0glSybHHmjp3X77engNn4EQxp+mKXZm5HhiVmk6XMSX8jWZj/EORPoXfu+MN/0AAAAASUVO"
        "RK5CYII="
    ),
    28: (
        "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"
    ),
    32: (
        "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAGMklEQVR42u2WXVBV1xXHf+fjnvsBBL2IXD6rIEEgAWwqCFYL"
        "LUbbxiHRPLSJjaNpnWmbTjt9SszYQELz0Ieo00kzqQ/WaR5CQk3MxLFJ0xaDgVAdHT+KxiRCUURFUCofl3vv3qsP93L1BrHR"
        "zHT6kD1zZq+1z17/9T97/c86B/5fx6yap5f/L7DMmW54XGZr/qrm9i+aPH9Vc7vHZbbeNgHLtHbXLymsyqtv6rvT5Hn1TX31"
        "1XdXWaa1+7YJTASDb/b0Xx1reWFjjr9ms/iXPVXyeRP7lz1V4q/ZLK9tfTyn59zw2EQw+OZMe41bAtVslmN7toAIdRu3jl4d"
        "mfiTYdopLrcnEAoGi7UKJwOYlmvU8bi7Q5OTA2g1OivV8/Dfd/4yGRHKHmxmuON5444IzF/5XMfaFYuqu/55jojpRTkpMid3"
        "nuHPyMbjdvD6vAgQnAgSDAa5cqGfS329YoWvGW4mqSzNofXdw50972ypuX0CtY32XMzu/OLSgsKyCjNnXh62CbYBhpEIIDFb"
        "S/QKazjb+y8+PnZE95zs/vQSUkJbY+TzEyhpdPK+kny6rHZV7rwFheacZBNEoplFCIVDHOv6B1cHBzAMg9T0TCoqK7EdJ2Hf"
        "0DicOX1KHW37c++5T86W8slvJ/87gfsafWledaXhp087U0teW/A5Bo4NF/p62Pd6C+sfXMLikkxE4GD3eXbu7mT19x8hI3c+"
        "obAwEYHxcDReRNjzYnN4+OK/Uz5LYhqBQP3zH9d9b9MCx+2NPwmGgYhw5Xwv1sAh3tj62E0PruHnuyCnktlZ8xJOAsMgODbK"
        "/paXT17425aSGV/DuXVNv8krrsi2bA9KCyqi43NocpLD77TOmBxgz/b1dO19lVAwNC3e5fGRXVSWNWfZM003J3DfJp/L5VlX"
        "ULHUq7VGRTTRWaG1pvfYQR5fU5WQcOu27RSXllG9dDkv/u4lAH64dgm9Jw5Oi1cRTdHiulSX272BksZ4ee0pY7bjb0hJC8xS"
        "SgBJUDcIoZGLVCwsj6+0te2n6dlfA/DHXTuxbZv33vsrXy3OZt/hY2ilE+Kn8JJnpfv8Y582DMPrCQTcSakNgYJSr1IaI1bz"
        "hJloOadG54ddcfvZ56JEqquXUPS1VYgIkRlwsu6uSLsyOFBPjEC8BDoSrnK5fWgl0WNTseOL+VZSOkdOnY8nXbSoIm6/336A"
        "99sPUFy8kMMn+7GS0qfFT/kuTxIGunaaBrSK+C2XD6UUSglK6dgc9TMKytnR2hlPWv+tb7L+sXVkZgbIzAzwg3WP8MB3v8Pv"
        "X+sgULhoWvyUbzteROu50zTg8iYNWY73rqgGNOkSYq4R4pI4DBoOGBYLlzbw0C928ca29di2zfZtLySIcvXP/kDpN9YgAkoJ"
        "6RKMYbgYNDyAYDk+XJ6k4WkEJkdH5mul47WqNQZJQXFNLFp0FiIa3+wsroomq66RHz1cRXlRNgBHP+rnpZYO7ln+EJ7UAFoJ"
        "Ippa6zLJEmEUm1cjgbgWJsdG8qcRAKLCAQThL/jJMENc1A4Rrq87qVkUr9jI28eP81bXkWgdfXMo//YmDNNCa0Fiqn9XzybT"
        "DDGgHTTX128cCQSizAXDgAGxuWC4EBF6Dr3F+NDZW3w3T9Pf3ZGw4vXnoipXcyFixxri9bdixk6o1PWmobWO+7ll94OaIHhm"
        "L0+uyeCJlckET+xIuJ5YmcyTazIIntkLapy8ivtnxJvxBJSSaT0cEQzDYkHdTxjoLuLDPoNkMwSphaBCsf83h94rDqNDHtIW"
        "/5jMe1cgYsbx4k8+hTsjgYiKbdKx75S+wbcIlKygNxImeO0yWcsKmRwbBMPA8aVxaCIdT0oagXvciBYU8pn4G/Bm1ICOqler"
        "MKblijHXCTOGhTc1gOeujJt2OhVRN42LhIPYLjcitypBRBMcG5bzR9+eNCxLza96NAmgp/OVcQHyqx/13ZHf9cqYKGVmlT/g"
        "8ST5jZsSsJ2kE8P93QtGzh4dGPqgOT9t2a8a+o/v2wkghmwAuGNfZMPQB817MO2e1Ox7M23Hdyr++z9ljPUuf1mSehjuaF4L"
        "MNG3/yNPztddOhTqvNz+zI4v6kcx27ZLcgFDB8x10CZ8Ob4cwH8ARi2fPpcbh8QAAAAASUVORK5CYII="
    ),
    48: (
        "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"
    ),
    64: (
        "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"
        "HqwAAAAASUVORK5CYII="
    ),
    128: (
        "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"
    ),
}
HEADER_ICON_SIZE = 28
ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <title>Blue Chat Server</title>
  <defs>
    <linearGradient id="body" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#6db3ff"/>
      <stop offset="1" stop-color="#2f6fd6"/>
    </linearGradient>
    <linearGradient id="horn" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#ffffff"/>
      <stop offset="1" stop-color="#c9d6ee"/>
    </linearGradient>
  </defs>
  <path d="M34 36 L26 8 L50 28 Z" fill="url(#horn)" stroke="#123a7a" stroke-width="4" stroke-linejoin="round"/>
  <path d="M94 36 L102 8 L78 28 Z" fill="url(#horn)" stroke="#123a7a" stroke-width="4" stroke-linejoin="round"/>
  <path d="M10 70 C10 38 34 22 64 22 C94 22 118 38 118 70 L118 104 C118 108 115 110 112 107 L104 100 L96 110 L88 100 L80 110 L72 100 L64 110 L56 100 L48 110 L40 100 L32 110 L24 100 L16 107 C13 110 10 108 10 104 Z" fill="url(#body)" stroke="#123a7a" stroke-width="4" stroke-linejoin="round"/>
  <ellipse cx="64" cy="34" rx="30" ry="7" fill="#ffffff" opacity="0.18"/>
  <circle cx="64" cy="56" r="21" fill="#ffffff" stroke="#123a7a" stroke-width="4"/>
  <circle cx="68" cy="58" r="10" fill="#0f1115"/>
  <circle cx="72" cy="54" r="3.5" fill="#ffffff"/>
  <path d="M38 82 C46 96 82 96 90 82 Z" fill="#0f1115" stroke="#123a7a" stroke-width="3" stroke-linejoin="round"/>
  <path d="M48 85 L52 92 L56 86 Z" fill="#ffffff"/>
  <path d="M72 86 L76 92 L80 85 Z" fill="#ffffff"/>
  <ellipse cx="30" cy="74" rx="6" ry="4" fill="#ff8fb3" opacity="0.55"/>
  <ellipse cx="98" cy="74" rx="6" ry="4" fill="#ff8fb3" opacity="0.55"/>
</svg>
"""
FONT_SIZE = 10
MONO_FAMILIES = (
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Noto Sans Mono",
    "Ubuntu Mono",
    "Menlo",
    "Consolas",
    "Courier New",
    "Courier",
)
NAMED_FONTS = (
    "TkDefaultFont",
    "TkTextFont",
    "TkFixedFont",
    "TkMenuFont",
    "TkHeadingFont",
    "TkCaptionFont",
    "TkSmallCaptionFont",
    "TkIconFont",
    "TkTooltipFont",
)
TAB_TITLES = ("Chat", "Server log", "Settings")
WHEEL_EVENTS = ("<MouseWheel>", "<Button-4>", "<Button-5>")
SIDE_WHEEL_EVENTS = ("<Shift-MouseWheel>", "<Shift-Button-4>", "<Shift-Button-5>")
SIDE_WHEEL_STEP = 40


class App:
    def __init__(self, root: tk.Tk, server: ChatServer, events: queue.Queue, settings: dict) -> None:
        self.root = root
        self.server = server
        self.events = events
        self.settings = settings
        self.url = ""
        self._closing = False
        self._picking_color = False
        self._picker: ColorPicker | None = None
        self._ban_keys: list[str] = []

        root.title(APP_NAME)
        root.configure(bg=BG)
        root.geometry("1040x700")
        root.minsize(760, 460)
        self._maximize()

        self._load_icons()
        self._create_fonts()
        self._create_style()
        self._build()

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(PUMP_INTERVAL_MS, self._pump)
        root.after(1000, self._tick)
        self._set_running(False)

        if self.settings["autostart"]:
            root.after(200, self.start_server)

    def _load_icons(self) -> None:
        self._icons: dict[int, tk.PhotoImage] = {}
        for size, data in ICON_PNGS.items():
            try:
                self._icons[size] = tk.PhotoImage(master=self.root, data=data, format="png")
            except tk.TclError:
                continue
        window_icons = [
            self._icons[size] for size in sorted(self._icons, reverse=True) if size != HEADER_ICON_SIZE
        ]
        if window_icons:
            try:
                self.root.iconphoto(True, *window_icons)
            except tk.TclError:
                pass

    def _maximize(self) -> None:
        try:
            self.root.state("zoomed")
            return
        except tk.TclError:
            pass
        try:
            self.root.attributes("-zoomed", True)
            return
        except tk.TclError:
            pass
        self.root.geometry(f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}+0+0")

    def _create_fonts(self) -> None:
        available = {family.lower() for family in tkfont.families(self.root)}
        family = next(
            (name for name in MONO_FAMILIES if name.lower() in available),
            tkfont.nametofont("TkFixedFont").actual("family"),
        )
        for name in NAMED_FONTS:
            try:
                tkfont.nametofont(name).configure(
                    family=family, size=FONT_SIZE, weight="normal", slant="roman"
                )
            except tk.TclError:
                pass

        base = tkfont.nametofont("TkDefaultFont")
        self.font_base = base
        self.font_bold = base.copy()
        self.font_bold.configure(weight="bold")
        self.font_title = base.copy()
        self.font_title.configure(size=FONT_SIZE + 5, weight="bold")
        self.font_big = base.copy()
        self.font_big.configure(size=FONT_SIZE + 3, weight="bold")
        self.font_small = base.copy()
        self.font_small.configure(size=FONT_SIZE - 1)
        self.font_italic = base.copy()
        self.font_italic.configure(slant="italic")

    def _create_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(
            ".",
            background=PANEL,
            foreground=TEXT,
            fieldbackground=FIELD,
            bordercolor=BORDER,
            lightcolor=PANEL,
            darkcolor=PANEL,
            troughcolor=BG,
            focuscolor=ACCENT,
            selectbackground=SELECT,
            selectforeground=TEXT,
            insertcolor=TEXT,
        )
        style.configure("Root.TFrame", background=BG)
        style.configure("Muted.TLabel", foreground=MUTED)
        style.configure("Small.TLabel", foreground=MUTED, font=self.font_small)
        style.configure("Title.TLabel", font=self.font_title)
        style.configure("Stat.TLabel", font=self.font_big)

        style.configure("TButton", background=RAISED, padding=(12, 6), bordercolor=BORDER)
        style.map(
            "TButton",
            background=[("disabled", PANEL), ("active", HOVER)],
            foreground=[("disabled", DISABLED)],
        )
        style.configure("Accent.TButton", background=ACCENT, foreground="white")
        style.map("Accent.TButton", background=[("disabled", "#22304a"), ("active", ACCENT_HOVER)])

        style.configure("TEntry", fieldbackground=FIELD, foreground=TEXT, padding=5)
        style.configure("Url.TEntry", padding=6)
        style.configure("TSpinbox", fieldbackground=FIELD, foreground=TEXT, arrowcolor=TEXT, padding=4)
        style.map("TSpinbox", fieldbackground=[("disabled", PANEL)], foreground=[("disabled", DISABLED)])
        style.configure("TCombobox", fieldbackground=FIELD, foreground=TEXT, arrowcolor=TEXT, padding=4)
        style.map("TCombobox", fieldbackground=[("readonly", FIELD)], foreground=[("readonly", TEXT)])
        style.configure("TCheckbutton", background=PANEL, foreground=TEXT, indicatorbackground=FIELD)
        style.map(
            "TCheckbutton",
            background=[("active", PANEL)],
            indicatorbackground=[("selected", ACCENT)],
        )

        style.configure(
            "Treeview",
            background=FIELD,
            fieldbackground=FIELD,
            foreground=TEXT,
            rowheight=28,
            bordercolor=BORDER,
        )
        style.configure("Treeview.Heading", background=RAISED, foreground=MUTED, relief="flat", padding=4)
        style.map("Treeview", background=[("selected", SELECT)])
        style.map("Treeview.Heading", background=[("active", HOVER)])

        style.configure("TLabelframe", background=PANEL, bordercolor=BORDER)
        style.configure("TLabelframe.Label", background=PANEL, foreground=MUTED, font=self.font_bold)
        style.configure("TPanedwindow", background=BG)
        for scrollbar_style in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
            style.configure(
                scrollbar_style,
                background=RAISED,
                troughcolor=FIELD,
                arrowcolor=MUTED,
                bordercolor=FIELD,
                lightcolor=RAISED,
                darkcolor=RAISED,
                gripcount=0,
            )
            style.map(scrollbar_style, background=[("active", HOVER)])

        self.root.option_add("*TCombobox*Listbox.background", FIELD)
        self.root.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.root.option_add("*TCombobox*Listbox.selectBackground", SELECT)

    def _scrolled_text(self, parent: tk.Misc, **options) -> tuple[tk.Text, ttk.Scrollbar]:
        text = tk.Text(
            parent,
            bg=FIELD,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
            padx=10,
            pady=8,
            state="disabled",
            **options,
        )
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        return text, scrollbar

    def _build(self) -> None:
        outer = ttk.Frame(self.root, style="Root.TFrame", padding=10)
        outer.pack(fill="both", expand=True)

        self._build_header(outer)
        self._build_info(outer)

        pane = ttk.Panedwindow(outer, orient="horizontal")
        pane.pack(fill="both", expand=True, pady=(10, 0))
        pane.add(self._build_people(pane), weight=2)

        pane.add(self._build_tabs(pane), weight=3)

    def _build_tabs(self, parent: tk.Misc) -> ttk.Frame:
        container = ttk.Frame(parent, style="Root.TFrame")
        container.rowconfigure(1, weight=1)
        container.columnconfigure(0, weight=1)

        bar = tk.Frame(container, bg=BG)
        bar.grid(row=0, column=0, sticky="w")

        body = ttk.Frame(container)
        body.grid(row=1, column=0, sticky="nsew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        builders = (self._build_chat, self._build_log, self._build_settings)
        width = max(len(title) for title in TAB_TITLES) + 2
        self._tabs: list[tuple[tk.Frame, tk.Label, tk.Misc]] = []
        self._active_tab = 0

        for index, (title, builder) in enumerate(zip(TAB_TITLES, builders)):
            page = builder(body)
            page.grid(row=0, column=0, sticky="nsew")

            tab = tk.Frame(bar, bg=PANEL, padx=6, pady=5, cursor="hand2")
            tab.pack(side="left", padx=(0, 4))
            label = tk.Label(
                tab,
                text=title,
                width=width,
                bg=PANEL,
                fg=MUTED,
                font=self.font_base,
                padx=4,
                pady=2,
                highlightthickness=1,
                highlightbackground=PANEL,
                highlightcolor=PANEL,
            )
            label.pack()

            for widget in (tab, label):
                widget.bind("<Button-1>", lambda _event, i=index: self.select_tab(i))
                widget.bind("<Enter>", lambda _event, i=index: self._hover_tab(i, True))
                widget.bind("<Leave>", lambda _event, i=index: self._hover_tab(i, False))
            self._tabs.append((tab, label, page))

        self.root.bind("<Control-Tab>", lambda _event: self.select_tab(self._active_tab + 1))
        self.root.bind("<Control-ISO_Left_Tab>", lambda _event: self.select_tab(self._active_tab - 1))
        self.select_tab(0)
        return container

    def select_tab(self, index: int) -> str:
        self._active_tab = index % len(self._tabs)
        for position, (tab, label, page) in enumerate(self._tabs):
            active = position == self._active_tab
            background = RAISED if active else PANEL
            border = ACCENT if active else background
            tab.configure(bg=background)
            label.configure(
                bg=background,
                fg=TEXT if active else MUTED,
                highlightbackground=border,
                highlightcolor=border,
            )
            if active:
                page.tkraise()
        return "break"

    def _hover_tab(self, index: int, inside: bool) -> None:
        if index != self._active_tab:
            self._tabs[index][1].configure(fg=TEXT if inside else MUTED)

    def _build_header(self, parent: tk.Misc) -> None:
        header = ttk.Frame(parent, padding=(14, 10))
        header.pack(fill="x")

        logo = self._icons.get(HEADER_ICON_SIZE)
        if logo is not None:
            ttk.Label(header, image=logo).pack(side="left", padx=(0, 10))
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
        self.status_pill = tk.Label(
            header, text="Stopped", bg=PILL_OFF, fg=MUTED, font=self.font_bold, padx=12, pady=3
        )
        self.status_pill.pack(side="left", padx=12)

        self.button_restart = ttk.Button(header, text="Restart", command=self.restart_server)
        self.button_restart.pack(side="right")
        self.button_stop = ttk.Button(header, text="Stop", command=self.stop_server)
        self.button_stop.pack(side="right", padx=6)
        self.button_start = ttk.Button(header, text="Start", command=self.start_server)
        self.button_start.pack(side="right")

    def _build_info(self, parent: tk.Misc) -> None:
        info = ttk.Frame(parent, padding=(14, 4, 14, 12))
        info.pack(fill="x")
        info.columnconfigure(0, weight=1)

        ttk.Label(info, text="Open this address on any device on your network:", style="Muted.TLabel").grid(
            row=0, column=0, columnspan=3, sticky="w"
        )

        self.url_var = tk.StringVar(value="Server is stopped")
        ttk.Entry(
            info, textvariable=self.url_var, state="readonly", font=self.font_big, style="Url.TEntry"
        ).grid(row=1, column=0, sticky="ew", pady=(4, 2))
        self.button_copy = ttk.Button(info, text="Copy", command=self.copy_url)
        self.button_copy.grid(row=1, column=1, padx=(8, 0))
        self.button_open = ttk.Button(info, text="Open in browser", command=self.open_browser)
        self.button_open.grid(row=1, column=2, padx=(6, 0))

        self.alt_url_var = tk.StringVar()
        ttk.Label(info, textvariable=self.alt_url_var, style="Muted.TLabel").grid(row=2, column=0, sticky="w")

        stats = ttk.Frame(info)
        stats.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self.stat_vars: dict[str, tk.StringVar] = {}
        for column, (key, label) in enumerate(
            [
                ("online", "Online"),
                ("messages", "Messages"),
                ("uptime", "Uptime"),
                ("security", "Encryption"),
            ]
        ):
            box = ttk.Frame(stats)
            box.grid(row=0, column=column, padx=(0, 34), sticky="w")
            ttk.Label(box, text=label, style="Small.TLabel").pack(anchor="w")
            variable = tk.StringVar(value="-")
            ttk.Label(box, textvariable=variable, style="Stat.TLabel").pack(anchor="w")
            self.stat_vars[key] = variable

    def _build_people(self, parent: tk.Misc) -> ttk.Labelframe:
        frame = ttk.Labelframe(parent, text="People online", padding=8)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        columns = (
            ("name", "Name", "Guest", True),
            ("ip", "Address", "255.255.255.255", False),
            ("since", "Since", "00:00", False),
            ("status", "Status", "connecting", False),
        )
        self.tree = ttk.Treeview(
            frame, columns=[c[0] for c in columns], show="headings", selectmode="extended"
        )
        for key, label, sample, stretch in columns:
            width = max(self.font_base.measure(sample), self.font_base.measure(label)) + 12
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, minwidth=width, stretch=stretch)
        tree_scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        tree_side_scroll = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(
            yscrollcommand=tree_scroll.set,
            xscrollcommand=lambda first, last: self._fit_side_scroll(tree_side_scroll, first, last),
        )
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll.grid(row=0, column=1, sticky="ns")
        tree_side_scroll.grid(row=1, column=0, sticky="ew")
        tree_side_scroll.grid_remove()
        self.tree.bind("<Delete>", lambda _event: self.kick_selected())
        for sequence in SIDE_WHEEL_EVENTS:
            self.tree.bind(sequence, self._scroll_people_sideways)

        buttons = ttk.Frame(frame)
        buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        buttons.columnconfigure((0, 1), weight=1, uniform="people_actions")
        ttk.Button(buttons, text="Kick", command=self.kick_selected).grid(
            row=0, column=0, sticky="ew", padx=(0, 3)
        )
        ttk.Button(buttons, text="Ban device", command=self.ban_selected).grid(
            row=0, column=1, sticky="ew", padx=(3, 0)
        )

        hint = ttk.Label(
            frame,
            text=(
                "Kicked people can rejoin straight away. Banned devices stay blocked, even after a restart, "
                "until you unban them. Some phones can change their hardware address in their Wi-Fi settings."
            ),
            style="Small.TLabel",
            wraplength=200,
            justify="left",
        )
        hint.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        hint.bind("<Configure>", lambda event: hint.configure(wraplength=max(event.width - 10, 100)))

        ttk.Label(frame, text="Banned devices", style="Muted.TLabel").grid(
            row=4, column=0, sticky="w", pady=(10, 2)
        )
        self.ban_list = tk.Listbox(
            frame,
            height=3,
            bg=FIELD,
            fg=TEXT,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=BORDER,
            selectbackground=SELECT,
            selectforeground=TEXT,
            selectmode="extended",
            activestyle="none",
        )
        self.ban_list.grid(row=5, column=0, columnspan=2, sticky="ew")
        ttk.Button(frame, text="Unban", command=self.unban_selected).grid(
            row=6, column=0, columnspan=2, sticky="ew", pady=(6, 0)
        )
        return frame

    def _scroll_people_sideways(self, event: tk.Event) -> str:
        first, last = self.tree.xview()
        if first > 0 or last < 1:
            backwards = event.num == 4 or getattr(event, "delta", 0) > 0
            self.tree.xview_scroll(-SIDE_WHEEL_STEP if backwards else SIDE_WHEEL_STEP, "units")
        return "break"

    @staticmethod
    def _fit_side_scroll(scrollbar: ttk.Scrollbar, first: str, last: str) -> None:
        scrollbar.set(first, last)
        if float(first) <= 0.0 and float(last) >= 1.0:
            scrollbar.grid_remove()
        else:
            scrollbar.grid()

    def _build_chat(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)

        self.feed, feed_scroll = self._scrolled_text(frame, height=10)
        self.feed.grid(row=0, column=0, columnspan=3, sticky="nsew")
        feed_scroll.grid(row=0, column=3, sticky="ns")
        self.feed.tag_configure("time", foreground=MUTED, font=self.font_small)
        self.feed.tag_configure("system", foreground=MUTED, font=self.font_italic)
        self.feed.tag_configure("system_alert", foreground=AMBER, font=self.font_italic)
        self.feed.tag_configure("system_idle", foreground=IDLE, font=self.font_italic)
        self.feed.tag_configure("system_back", foreground=BACK, font=self.font_italic)
        self.feed.tag_configure("body", foreground=TEXT)

        self.mode_var = tk.StringVar(value=MODE_CHAT)
        mode = ttk.Combobox(
            frame,
            textvariable=self.mode_var,
            state="readonly",
            width=14,
            values=(MODE_CHAT, MODE_ANNOUNCE),
        )
        mode.grid(row=1, column=0, sticky="w", pady=(8, 0))
        mode.bind("<<ComboboxSelected>>", lambda _event: self._update_send_hint())

        self.say_var = tk.StringVar()
        say = ttk.Entry(frame, textvariable=self.say_var)
        say.grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        say.bind("<Return>", lambda _event: self.host_send())
        say.bind("<KP_Enter>", lambda _event: self.host_send())

        ttk.Button(frame, text="Send", style="Accent.TButton", command=self.host_send).grid(
            row=1, column=2, columnspan=2, sticky="e", pady=(8, 0)
        )

        self.send_hint_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.send_hint_var, style="Small.TLabel").grid(
            row=2, column=0, columnspan=4, sticky="w", pady=(4, 0)
        )
        self._update_send_hint()
        return frame

    def _build_log(self, parent: tk.Misc) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=8)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.log_text, log_scroll = self._scrolled_text(frame, height=10)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.tag_configure("time", foreground=MUTED)
        self.log_text.tag_configure("info", foreground=TEXT)
        self.log_text.tag_configure("warn", foreground=AMBER)
        self.log_text.tag_configure("error", foreground=RED)

        ttk.Button(frame, text="Clear log", command=lambda: self._clear_text(self.log_text)).grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        return frame

    def _build_settings(self, parent: tk.Misc) -> ttk.Frame:
        outer = ttk.Frame(parent)
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        canvas = tk.Canvas(outer, bg=PANEL, highlightthickness=0, borderwidth=0, yscrollincrement=20)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        frame = ttk.Frame(canvas, padding=14)
        frame.columnconfigure(0, weight=1)
        window = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))

        def resize(event: tk.Event) -> None:
            canvas.itemconfigure(window, width=event.width)
            if frame.winfo_reqheight() <= event.height:
                canvas.yview_moveto(0)

        canvas.bind("<Configure>", resize)

        self._fill_settings(frame)
        self._bind_wheel(canvas, canvas)
        return outer

    def _bind_wheel(self, widget: tk.Misc, canvas: tk.Canvas) -> None:
        def scroll(event: tk.Event) -> str:
            first, last = canvas.yview()
            if first > 0 or last < 1:
                if event.num == 4 or getattr(event, "delta", 0) > 0:
                    canvas.yview_scroll(-3, "units")
                elif event.num == 5 or getattr(event, "delta", 0) < 0:
                    canvas.yview_scroll(3, "units")
            return "break"

        for sequence in WHEEL_EVENTS:
            widget.bind(sequence, scroll)
        for child in widget.winfo_children():
            self._bind_wheel(child, canvas)

    def _fill_settings(self, frame: ttk.Frame) -> None:
        settings = self.settings

        self.var_bind = tk.StringVar(value=settings["bind"])
        self.var_web_auto = tk.BooleanVar(value=settings["web_port_auto"])
        self.var_web_port = tk.StringVar(value=str(settings["web_port"]))
        self.var_history = tk.StringVar(value=str(settings["history_max"]))
        self.var_host_name = tk.StringVar(value=settings["host_name"])
        self.var_host_color = tk.StringVar(value=settings["host_color"])
        self.var_autostart = tk.BooleanVar(value=settings["autostart"])
        self.var_open_browser = tk.BooleanVar(value=settings["open_browser"])

        network = ttk.Labelframe(frame, text="Network (applies on restart)", padding=10)
        network.grid(row=0, column=0, sticky="ew")

        ttk.Label(network, text="Listen on").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Combobox(
            network,
            textvariable=self.var_bind,
            width=16,
            values=("0.0.0.0", get_local_ip(), "127.0.0.1"),
        ).grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(network, text="0.0.0.0 = whole network", style="Muted.TLabel").grid(
            row=0, column=2, sticky="w"
        )

        self._port_row(network, 1, "Web page port", self.var_web_auto, self.var_web_port, WEB_PORT_RANGE)
        tip = ttk.Label(
            network,
            text="Tip: fixed ports give everyone an address that stays the same, so they can bookmark it.",
            style="Small.TLabel",
            justify="left",
        )
        tip.grid(row=3, column=0, columnspan=3, sticky="w", pady=(6, 0))
        network.bind(
            "<Configure>", lambda event: tip.configure(wraplength=max(event.width - 30, 200)), add="+"
        )

        security = ttk.Labelframe(frame, text="Security", padding=10)
        security.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        security.columnconfigure(1, weight=1)

        ttk.Label(security, text="Status").grid(row=0, column=0, sticky="w", pady=3)
        self.security_status_var = tk.StringVar(value="Server is stopped")
        ttk.Label(security, textvariable=self.security_status_var).grid(
            row=0, column=1, columnspan=2, sticky="w", padx=8
        )

        self.security_tip_var = tk.StringVar()
        security_tip = ttk.Label(
            security,
            textvariable=self.security_tip_var,
            style="Small.TLabel",
            justify="left",
        )
        security_tip.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        security.bind(
            "<Configure>",
            lambda event: security_tip.configure(wraplength=max(event.width - 30, 200)),
            add="+",
        )

        chat = ttk.Labelframe(frame, text="Chat", padding=10)
        chat.grid(row=2, column=0, sticky="ew", pady=10)

        ttk.Label(chat, text="Messages kept").grid(row=0, column=0, sticky="w", pady=3)
        ttk.Spinbox(
            chat,
            from_=HISTORY_LIMITS[0],
            to=HISTORY_LIMITS[1],
            increment=10,
            textvariable=self.var_history,
            width=8,
        ).grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(chat, text=f"New visitors see the last {HISTORY_REPLAY}", style="Muted.TLabel").grid(
            row=0, column=2, sticky="w"
        )

        ttk.Label(chat, text="Your host name").grid(row=1, column=0, sticky="w", pady=3)
        ttk.Entry(chat, textvariable=self.var_host_name, width=18).grid(row=1, column=1, sticky="w", padx=8)
        self.color_swatch = tk.Label(
            chat,
            text="   ",
            bg=clean_color(self.var_host_color.get(), DEFAULT_HOST_COLOR),
            relief="flat",
            cursor="hand2",
        )
        self.color_swatch.grid(row=1, column=2, sticky="w")
        self.color_swatch.bind("<Button-1>", lambda _event: self.pick_color())

        history_buttons = ttk.Frame(chat)
        history_buttons.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(history_buttons, text="Clear chat history", command=self.clear_history).pack(side="left")
        ttk.Button(history_buttons, text="Export history...", command=self.export_history).pack(
            side="left", padx=6
        )

        app = ttk.Labelframe(frame, text="App", padding=10)
        app.grid(row=3, column=0, sticky="ew")
        ttk.Checkbutton(app, text="Start the server when the app opens", variable=self.var_autostart).grid(
            row=0, column=0, sticky="w", pady=2
        )
        ttk.Checkbutton(app, text="Open the chat in a browser on start", variable=self.var_open_browser).grid(
            row=1, column=0, sticky="w", pady=2
        )

        actions = ttk.Frame(frame)
        actions.grid(row=4, column=0, sticky="w", pady=(12, 0))
        ttk.Button(actions, text="Save", command=self.save_settings_clicked).pack(side="left")
        ttk.Button(
            actions,
            text="Save & restart",
            style="Accent.TButton",
            command=lambda: self.save_settings_clicked(restart=True),
        ).pack(side="left", padx=6)

    @staticmethod
    def _port_row(
        parent: tk.Misc,
        row: int,
        label: str,
        auto_var: tk.BooleanVar,
        port_var: tk.StringVar,
        port_range: tuple[int, int],
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        spinbox = ttk.Spinbox(parent, from_=PORT_LIMITS[0], to=PORT_LIMITS[1], textvariable=port_var, width=8)
        spinbox.grid(row=row, column=1, sticky="w", padx=8)

        def sync() -> None:
            spinbox.state(["disabled"] if auto_var.get() else ["!disabled"])

        ttk.Checkbutton(
            parent,
            text=f"Random ({port_range[0]}-{port_range[1]})",
            variable=auto_var,
            command=sync,
        ).grid(row=row, column=2, sticky="w")
        sync()

    def _pump(self) -> None:
        refresh = False
        try:
            for _ in range(PUMP_BATCH):
                try:
                    kind, data = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    if kind == "log":
                        self._append_log(data)
                    elif kind == "chat":
                        self._append_chat(data)
                    elif kind == "clients":
                        refresh = True
                    elif kind == "state":
                        self._set_running(self.server.running)
                        refresh = True
                except tk.TclError:
                    continue
            if refresh:
                self._refresh_people()
        except tk.TclError:
            pass
        finally:
            if not self._closing:
                self.root.after(PUMP_INTERVAL_MS, self._pump)

    def _tick(self) -> None:
        try:
            started = self.server.started_at
            if self.server.running and started:
                hours, remainder = divmod(int(time.time() - started), 3600)
                minutes, seconds = divmod(remainder, 60)
                uptime = f"{hours}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes}:{seconds:02d}"
            else:
                uptime = "-"
            self.stat_vars["uptime"].set(uptime)
            self.stat_vars["online"].set(str(sum(1 for person in self.server.snapshot() if person["ready"])))
            self.stat_vars["messages"].set(str(self.server.message_count))
        except tk.TclError:
            pass
        finally:
            if not self._closing:
                self.root.after(1000, self._tick)

    @staticmethod
    def _insert(widget: tk.Text, text: str, *tags: str) -> None:
        try:
            widget.insert("end", text, tags)
        except tk.TclError:
            widget.insert("end", "".join(ch if ord(ch) <= 0xFFFF else "�" for ch in text), tags)

    @staticmethod
    def _hanging_tag(widget: tk.Text, indent: int) -> str:
        tag = f"hang{indent}"
        widget.tag_configure(tag, lmargin1=0, lmargin2=indent)
        return tag

    @staticmethod
    def _insert_swatch(widget: tk.Text, color: object, *tags: str) -> None:
        if not isinstance(color, str) or not HEX_COLOR.fullmatch(color):
            return
        swatch_tag = f"swatch{color[1:].lower()}"
        widget.tag_configure(swatch_tag, background=color)
        widget.insert("end", " ", tags)
        widget.insert("end", "  ", (*tags, swatch_tag))

    @staticmethod
    def _trim(widget: tk.Text, max_lines: int) -> None:
        lines = int(widget.index("end-1c").split(".")[0])
        if lines > max_lines:
            widget.delete("1.0", f"{lines - max_lines + 1}.0")

    @staticmethod
    def _clear_text(widget: tk.Text) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.configure(state="disabled")

    def _append_chat(self, event: dict) -> None:
        stick_to_bottom = self.feed.yview()[1] > 0.98
        stamp_text = f"{format_local_time(event.get('ts'), TIME_FORMAT)}  "

        self.feed.configure(state="normal")
        if event.get("type") == "system":
            style = KIND_STYLES.get(str(event.get("kind")), "system")
            hang = self._hanging_tag(self.feed, self.font_small.measure(stamp_text))
            self._insert(self.feed, stamp_text, "time", hang)
            self._insert(self.feed, str(event.get("msg", "")), style, hang)
            self._insert_swatch(self.feed, event.get("color"), style, hang)
            self._insert(self.feed, "\n", style, hang)
        else:
            color = clean_color(event.get("color"))
            name = str(event.get("username") or "Guest")
            name_tag = f"user{color[1:]}"
            self.feed.tag_configure(name_tag, foreground=color, font=self.font_bold)

            indent = (
                self.font_small.measure(stamp_text)
                + self.font_bold.measure(name)
                + self.font_base.measure(MESSAGE_GAP)
            )
            first_line_tag = self._hanging_tag(self.feed, indent)
            next_line_tag = f"indent{indent}"
            self.feed.tag_configure(next_line_tag, lmargin1=indent, lmargin2=indent)

            first, *rest = str(event.get("text", "")).split("\n")
            self._insert(self.feed, stamp_text, "time", first_line_tag)
            self._insert(self.feed, name, name_tag, first_line_tag)
            self._insert(self.feed, f"{MESSAGE_GAP}{first}\n", "body", first_line_tag)
            for line in rest:
                self._insert(self.feed, f"{line}\n", "body", next_line_tag)
        self._trim(self.feed, FEED_MAX_LINES)
        self.feed.configure(state="disabled")

        if stick_to_bottom:
            self.feed.see("end")

    def _append_log(self, entry: dict) -> None:
        level = entry["level"] if entry["level"] in ("info", "warn", "error") else "info"
        self.log_text.configure(state="normal")
        stamp_text = f"{datetime.fromtimestamp(entry['time']).strftime(TIME_FORMAT)}  "
        hang = self._hanging_tag(self.log_text, self.font_base.measure(stamp_text))
        self._insert(self.log_text, stamp_text, "time", hang)
        self._insert(self.log_text, str(entry["text"]), level, hang)
        self._insert_swatch(self.log_text, entry.get("color"), level, hang)
        self._insert(self.log_text, "\n", level, hang)
        self._trim(self.log_text, LOG_MAX_LINES)
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _refresh_people(self) -> None:
        people = sorted(self.server.snapshot(), key=lambda person: (person["name"].lower(), person["id"]))
        wanted = {person["id"] for person in people}

        for item in self.tree.get_children():
            if item not in wanted:
                self.tree.delete(item)

        for index, person in enumerate(people):
            tag = f"user{person['color'][1:]}"
            self.tree.tag_configure(tag, foreground=person["color"])
            if person["away"]:
                status = "away"
            elif person["typing"]:
                status = "typing..."
            elif person["ready"]:
                status = "online"
            else:
                status = "connecting"
            values = (
                person["name"],
                person["ip"],
                time.strftime("%H:%M", time.localtime(person["since"])),
                status,
            )
            if self.tree.exists(person["id"]):
                self.tree.item(person["id"], values=values, tags=(tag,))
            else:
                self.tree.insert("", "end", iid=person["id"], values=values, tags=(tag,))
            self.tree.move(person["id"], "", index)

        banned = self.server.banned()
        if self._ban_keys != [key for key, _ in banned]:
            self._ban_keys = [key for key, _ in banned]
            self.ban_list.delete(0, "end")
            for _, label in banned:
                self.ban_list.insert("end", label)

    def _set_running(self, running: bool) -> None:
        self.status_pill.configure(
            text="Running" if running else "Stopped",
            bg=ACCENT if running else PILL_OFF,
            fg="white" if running else MUTED,
        )

        self.button_start.state(["disabled"] if running else ["!disabled"])
        for button in (self.button_stop, self.button_restart, self.button_copy, self.button_open):
            button.state(["!disabled"] if running else ["disabled"])

        if running:
            host = self.server.display_host()
            port = self.server.web_port
            self.url = f"http://{host}:{port}"
            self.url_var.set(self.url)
            if self.server.bind == "0.0.0.0":
                self.alt_url_var.set(
                    f"or http://{socket.gethostname()}.local:{port}   ·   on this Pi: http://127.0.0.1:{port}"
                )
            else:
                self.alt_url_var.set("")
            self.stat_vars["security"].set(ENCRYPTION_SHORT)
        else:
            self.url = ""
            self.url_var.set("Server is stopped")
            self.alt_url_var.set("")
            self.stat_vars["security"].set("-")
        self._update_security(running)

    def _update_security(self, running: bool) -> None:
        if not running:
            self.security_status_var.set("Server is stopped")
            self.security_tip_var.set("")
            return
        self.security_status_var.set(PROTOCOL_NAME)
        self.security_tip_var.set(
            "Every device makes its own one-time keys when it connects, so nobody else on your network can "
            "read the chat, including anyone recording it to decrypt later with a quantum computer. No "
            "certificates or warnings are needed. Each person sees a security code under the version number "
            "in their sidebar, and the Server log shows the same code when they join. If the two codes "
            "differ, someone may be interfering with your network."
        )

    def _update_send_hint(self) -> None:
        if self.mode_var.get() == MODE_ANNOUNCE:
            self.send_hint_var.set("Shows as a centred notice for everyone")
        else:
            self.send_hint_var.set(f"Sends as “{self.settings['host_name']}” (change in Settings)")

    def _ask(self, title: str, message: str) -> bool:
        return messagebox.askyesno(title, message, parent=self.root)

    def _info(self, title: str, message: str) -> None:
        messagebox.showinfo(title, message, parent=self.root)

    def _error(self, title: str, message: str) -> None:
        messagebox.showerror(title, message, parent=self.root)

    def _selected_people(self) -> tuple[str, ...]:
        return self.tree.selection()

    def start_server(self) -> None:
        settings = self.settings
        self.server.history_max = settings["history_max"]
        try:
            self.server.start(
                settings["bind"],
                None if settings["web_port_auto"] else settings["web_port"],
            )
        except OSError as error:
            self.server.log(str(error), "error")
            self._error(
                "Couldn't start the server",
                f"{error}\n\nIf you set fixed ports, another program may already be using them.",
            )
            return
        if settings["open_browser"]:
            self.root.after(600, self.open_browser)

    def stop_server(self) -> None:
        if self.server.snapshot() and not self._ask(
            "Stop server",
            "People are connected. Stop the server and disconnect them?",
        ):
            return
        self.server.stop()

    def restart_server(self) -> None:
        self.server.stop()
        self.start_server()

    def copy_url(self) -> None:
        if self.url:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.url)
            self.server.log("Address copied to the clipboard")

    def open_browser(self) -> None:
        if self.url:
            threading.Thread(target=webbrowser.open, args=(self.url,), daemon=True).start()

    def host_send(self) -> None:
        text = self.say_var.get().strip()
        if not text:
            return
        if not self.server.running:
            self._info("Server stopped", "Start the server to send messages.")
            return
        if self.mode_var.get() == MODE_ANNOUNCE:
            self.server.announce(text)
        else:
            self.server.send_as_host(text, self.settings["host_name"], self.settings["host_color"])
        self.say_var.set("")

    def kick_selected(self) -> None:
        selection = self._selected_people()
        if not selection:
            self._info("Kick", "Select someone in the list first.")
            return
        self.server.kick(set(selection))

    def ban_selected(self) -> None:
        selection = self._selected_people()
        if not selection:
            self._info("Ban", "Select someone in the list first.")
            return

        people = [(self.tree.set(item, "name"), self.tree.set(item, "ip")) for item in selection]
        addresses = {ip for _, ip in people}
        names = sorted(f"{name} ({ip})" for name, ip in people)
        own_addresses = {"127.0.0.1", get_local_ip()}
        if own_addresses.intersection(addresses) and not self._ask(
            "Ban",
            "One of these is this Pi itself. Ban it anyway?",
        ):
            return
        if not self._ask(
            "Ban",
            "Ban these devices until you unban them? This lasts after restarts.\n\n" + "\n".join(names),
        ):
            return
        self.server.ban(people)

    def unban_selected(self) -> None:
        keys = [
            self._ban_keys[index] for index in self.ban_list.curselection() if index < len(self._ban_keys)
        ]
        if not keys:
            self._info("Unban", "Select a banned device in the list first.")
            return
        for key in keys:
            self.server.unban(key)

    def pick_color(self) -> None:
        if self._picking_color:
            return
        self._picking_color = True
        current = clean_color(self.var_host_color.get(), DEFAULT_HOST_COLOR)
        outcome: dict[str, tuple[bool, str | None]] = {}

        picker = ColorPicker()
        self._picker = picker

        def work() -> None:
            outcome["result"] = picker.choose(current, "Host name colour")

        worker = threading.Thread(target=work, name="color-picker", daemon=True)
        worker.start()

        def finish() -> None:
            if worker.is_alive():
                self.root.after(100, finish)
                return
            self._picking_color = False
            self._picker = None
            if self._closing:
                return
            available, color = outcome.get("result", (False, None))
            if not available:
                self._show_palette(current)
            elif color:
                self._apply_host_color(color)

        finish()

    def _apply_host_color(self, color: str) -> None:
        value = clean_color(color, DEFAULT_HOST_COLOR)
        self.var_host_color.set(value)
        self.color_swatch.configure(bg=value)

    def _show_palette(self, current: str) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Host name colour")
        dialog.configure(bg=PANEL)
        dialog.transient(self.root)
        dialog.resizable(False, False)

        frame = ttk.Frame(dialog, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Choose a colour").grid(
            row=0, column=0, columnspan=PALETTE_COLUMNS, sticky="w", pady=(0, 10)
        )

        def choose(color: str) -> None:
            dialog.destroy()
            self._apply_host_color(color)

        for index, color in enumerate(PRESET_COLORS):
            row, column = divmod(index, PALETTE_COLUMNS)
            ring = TEXT if color == current else PANEL
            swatch = tk.Label(
                frame,
                bg=color,
                width=4,
                height=2,
                cursor="hand2",
                highlightthickness=2,
                highlightbackground=ring,
                highlightcolor=ring,
            )
            swatch.grid(row=row + 1, column=column, padx=3, pady=3)
            swatch.bind("<Button-1>", lambda _event, value=color: choose(value))

        rows = (len(PRESET_COLORS) + PALETTE_COLUMNS - 1) // PALETTE_COLUMNS
        ttk.Button(frame, text="Cancel", command=dialog.destroy).grid(
            row=rows + 1, column=0, columnspan=PALETTE_COLUMNS, sticky="ew", pady=(10, 0)
        )
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.wait_visibility()
        dialog.grab_set()
        dialog.focus_set()

    def clear_history(self) -> None:
        if self._ask(
            "Clear history",
            "Clear the stored chat history?\n\nPeople already in the chat keep what's on their screen.",
        ):
            self.server.clear_history()
            self._clear_text(self.feed)

    def export_history(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export chat history",
            defaultextension=".txt",
            initialfile=f"blue-chat-{datetime.now():%Y%m%d-%H%M}.txt",
            filetypes=[("Text", "*.txt"), ("JSON", "*.json")],
        )
        if not path:
            return

        entries = [event for event in self.server.history() if event.get("type") in CHAT_EVENT_TYPES]
        try:
            if path.lower().endswith(".json"):
                content = json.dumps(entries, indent=2, ensure_ascii=False)
            else:
                lines = []
                for event in entries:
                    stamp = format_local_time(event.get("ts"), f"%Y-%m-%d {TIME_FORMAT}")
                    if event["type"] == "system":
                        lines.append(f"[{stamp}] * {event.get('msg', '')}")
                    else:
                        lines.append(f"[{stamp}] {event.get('username', 'Guest')}: {event.get('text', '')}")
                content = "\n".join(lines) + "\n"
            Path(path).write_text(content, encoding="utf-8")
        except OSError as error:
            self._error("Export failed", str(error))
            return
        self.server.log(f"Exported {len(entries)} entries to {path}")

    def _read_settings_form(self) -> dict | None:
        try:
            web_port = int(self.var_web_port.get())
            history_max = int(self.var_history.get())
        except ValueError:
            self._error("Settings", "The port and messages kept must be whole numbers.")
            return None

        low, high = PORT_LIMITS
        if not low <= web_port <= high:
            self._error("Settings", f"The port must be between {low} and {high}.")
            return None
        if not HISTORY_LIMITS[0] <= history_max <= HISTORY_LIMITS[1]:
            self._error(
                "Settings", f"Messages kept must be between {HISTORY_LIMITS[0]} and {HISTORY_LIMITS[1]}."
            )
            return None

        bind = self.var_bind.get().strip()
        if not is_ipv4(bind):
            self._error("Settings", "Listen on must be an IPv4 address such as 0.0.0.0.")
            return None

        return {
            "bind": bind,
            "web_port_auto": self.var_web_auto.get(),
            "web_port": web_port,
            "history_max": history_max,
            "host_name": clean_name(self.var_host_name.get()) or DEFAULT_HOST_NAME,
            "host_color": clean_color(self.var_host_color.get(), DEFAULT_HOST_COLOR),
            "autostart": self.var_autostart.get(),
            "open_browser": self.var_open_browser.get(),
        }

    def save_settings_clicked(self, restart: bool = False) -> None:
        values = self._read_settings_form()
        if values is None:
            return

        old_name = self.settings["host_name"]
        old_color = self.settings["host_color"]
        self.settings.update(values)
        self.var_host_name.set(values["host_name"])
        self.server.host_identity_changed(old_name, values["host_name"], old_color, values["host_color"])
        self.server.history_max = values["history_max"]
        self._update_send_hint()

        if save_settings(self.settings):
            self.server.log("Settings saved")
        else:
            self.server.log(f"Could not write {SETTINGS_PATH}", "error")
        if restart:
            self.restart_server()

    def on_close(self) -> None:
        if self.server.snapshot() and not self._ask(
            "Quit",
            "People are connected. Stop the server and quit?",
        ):
            return
        self.shutdown()

    def shutdown(self) -> None:
        if self._closing:
            return
        self._closing = True
        if self._picker is not None:
            self._picker.cancel()
        self.server.stop()
        self.root.destroy()


def desktop_quote(value: str) -> str:
    escaped = "".join("\\" + ch if ch in '"`$\\' else ch for ch in value)
    return '"' + escaped.replace("%", "%%") + '"'


def desktop_entry() -> str:
    command = f"{desktop_quote(sys.executable)} {desktop_quote(str(Path(__file__).resolve()))}"
    return "\n".join(
        [
            "[Desktop Entry]",
            "Type=Application",
            f"Name={APP_NAME}",
            "Comment=Chat server for your local network",
            f"Exec={command}",
            f"Path={APP_DIR}",
            f"Icon={APP_DESKTOP_ID}",
            f"StartupWMClass={APP_CLASS}",
            "Terminal=false",
            "Categories=Network;Chat;",
            "",
        ]
    )


def write_if_changed(path: Path, content: bytes) -> bool:
    if path.exists() and path.read_bytes() == content:
        return False
    atomic_write(path, content)
    return True


def install_desktop_integration() -> tuple[bool, str]:
    if not sys.platform.startswith("linux"):
        return False, "Taskbar icon setup is only needed on Linux"

    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    icons = data_home / "icons" / "hicolor"
    applications = data_home / "applications"

    files: dict[Path, bytes] = {
        icons / "scalable" / "apps" / f"{APP_DESKTOP_ID}.svg": ICON_SVG.encode("utf-8"),
        applications / f"{APP_DESKTOP_ID}.desktop": desktop_entry().encode("utf-8"),
    }
    for size, data in ICON_PNGS.items():
        if size != HEADER_ICON_SIZE:
            files[icons / f"{size}x{size}" / "apps" / f"{APP_DESKTOP_ID}.png"] = base64.b64decode(data)

    try:
        changed = [path for path, content in files.items() if write_if_changed(path, content)]
    except OSError as error:
        return False, f"Could not set up the taskbar icon: {error}"

    if not changed:
        return True, "Taskbar icon is set up"

    commands = [["update-desktop-database", "-q", str(applications)]]
    if (icons / "icon-theme.cache").exists():
        commands.append(["gtk-update-icon-cache", "-q", "-t", "-f", str(icons)])
    for command in commands:
        executable = shutil.which(command[0])
        if executable:
            try:
                subprocess.run([executable, *command[1:]], capture_output=True, timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                pass
    return True, f"Taskbar icon installed in {data_home}"


def run_headless(server: ChatServer, events: queue.Queue, settings: dict) -> int:
    def terminate(*_args) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    server.history_max = settings["history_max"]
    try:
        server.start(
            settings["bind"],
            None if settings["web_port_auto"] else settings["web_port"],
        )
    except OSError as error:
        print(f"Could not start: {error}", file=sys.stderr)
        return 1

    host = get_local_ip() if settings["bind"] == "0.0.0.0" else settings["bind"]
    print(f"CHAT:       http://{host}:{server.web_port}", flush=True)
    print(f"ENCRYPTION: {PROTOCOL_NAME}", flush=True)
    print("Press Ctrl+C to stop.", flush=True)

    try:
        while True:
            try:
                kind, data = events.get(timeout=0.5)
            except queue.Empty:
                continue
            stamp = datetime.now().strftime("%H:%M:%S")
            if kind == "log":
                print(f"{stamp}  {data['text']}", flush=True)
            elif kind == "chat" and data.get("type") == "message":
                print(f"{stamp}  <{data.get('username')}> {data.get('text')}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def port_argument(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a whole number") from error
    if not PORT_LIMITS[0] <= port <= PORT_LIMITS[1]:
        raise argparse.ArgumentTypeError(f"must be between {PORT_LIMITS[0]} and {PORT_LIMITS[1]}")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description="Blue Chat LAN chat server")
    parser.add_argument("--headless", action="store_true", help="run without the GUI")
    parser.add_argument("--web-port", type=port_argument, help="fixed web port (overrides settings)")
    args = parser.parse_args()

    settings = load_settings()
    if args.web_port:
        settings.update(web_port_auto=False, web_port=args.web_port)

    events: queue.Queue = queue.Queue()
    server = ChatServer(events, HTML_PATH, settings["history_max"])

    if args.headless:
        return run_headless(server, events, settings)
    if tk is None:
        print("Tkinter is not installed (sudo apt install python3-tk). Running headless.", flush=True)
        return run_headless(server, events, settings)

    integrated, integration_message = install_desktop_integration()

    try:
        root = tk.Tk(className=APP_DESKTOP_ID)
    except tk.TclError:
        print("No display found. Running headless.", flush=True)
        return run_headless(server, events, settings)

    app = App(root, server, events, settings)
    server.log(integration_message, "info" if integrated else "warn")
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, lambda *_args: root.after_idle(app.shutdown))
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
