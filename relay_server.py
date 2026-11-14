#!/usr/bin/env python3
"""
Minimal, Private 1-to-1 Relay Server for Render (Strict & Hardened)
Connects a single Android Companion phone app to a single Termux CLI client.

Zero persistence, zero payload logging, fail-closed single-owner security.
Strict defense against:
- Brute-force scanning and dictionary attacks (IP ban jail)
- Slowloris and connection hanging (15s initial handshake timeout)
- Message and ping flooding (per-socket token bucket rate limiter)
- Memory ballooning (capped 64-request queue capacity)
- Directory traversal and path manipulation on HTTP endpoints
- MIME confusion, clickjacking, and header injection (Enterprise Security Headers)
- Log injection, log forging, and ANSI escape code attacks (CWE-117)
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import sys
import time
import uuid
from typing import Optional, Union, Dict, Any, Set, List
from aiohttp import web, WSMsgType

# -----------------------------------------------------------------------------
# Configuration & Strict Fail-Closed Startup Checks
# -----------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", 10000))
HOST = "0.0.0.0"
MAX_PAYLOAD_SIZE = 16 * 1024 * 1024       # 16 MB max for screenshots/files
REQUEST_TIMEOUT_HTTP = 25.0               # Seconds to wait for phone HTTP-RPC reply
REQUEST_TIMEOUT_PENDING = 30.0            # Seconds before pending request TTL cleanup
HEARTBEAT_INTERVAL = 25.0                # Seconds between idle keepalive pings to phone
HANDSHAKE_TIMEOUT = 15.0                 # Max seconds to receive first message (Slowloris guard)
IDLE_CLI_TIMEOUT = 180.0                 # Max seconds of inactivity on CLI socket
PROBE_BAN_THRESHOLD = 10                  # Failed probes per minute to trigger ban
PROBE_BAN_DURATION = 300.0                # Ban duration in seconds (5 minutes)
MAX_GLOBAL_PENDING = 64                  # Maximum concurrent requests in memory
WS_MSG_RATE_LIMIT = 40                   # Max WebSocket messages/sec per client
WS_PING_RATE_LIMIT = 5                   # Max WebSocket PING frames/sec per client

PHONE_KEY = os.environ.get("PHONE_KEY", "").strip()
CLI_KEY = os.environ.get("CLI_KEY", "").strip()
SERVER_START_TIME = time.time()


def validate_key(name: str, key: str) -> None:
    """Enforces minimum length, character safety, and basic entropy."""
    if not key or len(key) < 24:
        sys.stderr.write(f"[FATAL] {name} is missing or shorter than 24 characters. Server exiting.\n")
        sys.exit(1)
    if any(c in key for c in (" ", "\t", "\n", "\r", "/", "\\", "?", "#", "&", "\0")):
        sys.stderr.write(f"[FATAL] {name} contains forbidden whitespace or delimiter characters. Server exiting.\n")
        sys.exit(1)
    if len(set(key)) < 8:
        sys.stderr.write(f"[FATAL] {name} has insufficient entropy (too repetitive). Server exiting.\n")
        sys.exit(1)


validate_key("PHONE_KEY", PHONE_KEY)
validate_key("CLI_KEY", CLI_KEY)

if hmac.compare_digest(PHONE_KEY.encode("utf-8"), CLI_KEY.encode("utf-8")):
    sys.stderr.write("[FATAL] PHONE_KEY and CLI_KEY must be distinct keys. Server exiting.\n")
    sys.exit(1)


# -----------------------------------------------------------------------------
# Zero-Sensitive Logging & Sanitization (CWE-117 Protection)
# -----------------------------------------------------------------------------
def sanitize_log_string(val: Any) -> str:
    """Strips newlines, control characters, and ANSI escape codes to prevent log poisoning."""
    s = str(val)
    s = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', s)
    s = re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', ' ', s)
    if len(s) > 100:
        s = s[:97] + "..."
    return s


class RedactingLogFormatter(logging.Formatter):
    """Sanitizes log messages to ensure secrets/tokens never leak to stdout."""
    def format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        if PHONE_KEY and PHONE_KEY in s:
            s = s.replace(PHONE_KEY, "[REDACTED_PHONE_KEY]")
        if CLI_KEY and CLI_KEY in s:
            s = s.replace(CLI_KEY, "[REDACTED_CLI_KEY]")
        return s


logger = logging.getLogger("private_relay")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(RedactingLogFormatter("[%(asctime)s] [%(levelname)s] %(message)s"))
logger.addHandler(_handler)
logger.propagate = False


# -----------------------------------------------------------------------------
# Constant-Time Authentication & In-Memory Threat Shield
# -----------------------------------------------------------------------------
def check_phone_key(candidate: str) -> bool:
    """Validates candidate against PHONE_KEY using constant-time comparison."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), PHONE_KEY.encode("utf-8"))


def check_cli_key(candidate: str) -> bool:
    """Validates candidate against CLI_KEY using constant-time comparison."""
    if not candidate:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), CLI_KEY.encode("utf-8"))


def get_client_ip(request: web.Request) -> str:
    """Extracts client IP safely from proxy headers or socket remote."""
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            ip = parts[0]
            if ":" in ip and not ip.startswith("[") and ip.count(":") == 1:
                ip = ip.split(":")[0]
            if re.match(r"^[0-9a-fA-F.:]+$", ip):
                return ip
    if request.headers.get("X-Real-IP"):
        ip = request.headers["X-Real-IP"].strip()
        if re.match(r"^[0-9a-fA-F.:]+$", ip):
            return ip
    if request.remote and re.match(r"^[0-9a-fA-F.:]+$", request.remote):
        return request.remote
    return "127.0.0.1"


class SlidingRateLimiter:
    """Sliding-window rate limiter per socket or IP."""
    __slots__ = ("limit", "window", "timestamps")

    def __init__(self, limit: int, window: float = 1.0):
        self.limit = limit
        self.window = window
        self.timestamps: List[float] = []

    def allow(self, now: float) -> bool:
        cutoff = now - self.window
        self.timestamps = [t for t in self.timestamps if t > cutoff]
        if len(self.timestamps) >= self.limit:
            return False
        self.timestamps.append(now)
        return True


class ProbeShield:
    """In-memory sliding window brute-force tracker. Jails IPs with >10 failed probes for 5 mins."""
    def __init__(self):
        self.failed_probes: Dict[str, List[float]] = {}
        self.banned_ips: Dict[str, float] = {}
        self.health_probes: Dict[str, List[float]] = {}

    def is_banned(self, ip: str, now: Optional[float] = None) -> bool:
        now = now or time.time()
        expiry = self.banned_ips.get(ip)
        if expiry is None:
            return False
        if now < expiry:
            return True
        self.banned_ips.pop(ip, None)
        self.failed_probes.pop(ip, None)
        return False

    def record_failure(self, ip: str, now: Optional[float] = None) -> None:
        now = now or time.time()
        cutoff = now - 60.0
        attempts = self.failed_probes.setdefault(ip, [])
        self.failed_probes[ip] = [t for t in attempts if t > cutoff]
        self.failed_probes[ip].append(now)

        if len(self.failed_probes[ip]) > PROBE_BAN_THRESHOLD:
            self.banned_ips[ip] = now + PROBE_BAN_DURATION
            logger.warning("IP blocked for 5 minutes due to excessive failed probes")

    def check_health_rate(self, ip: str, now: Optional[float] = None) -> bool:
        now = now or time.time()
        cutoff = now - 60.0
        probes = self.health_probes.setdefault(ip, [])
        self.health_probes[ip] = [t for t in probes if t > cutoff]
        if len(self.health_probes[ip]) >= 60:
            return False
        self.health_probes[ip].append(now)
        return True

    def cleanup(self, now: Optional[float] = None) -> None:
        now = now or time.time()
        cutoff = now - 60.0
        for ip in list(self.failed_probes.keys()):
            if ip not in self.banned_ips:
                rem = [t for t in self.failed_probes[ip] if t > cutoff]
                if rem:
                    self.failed_probes[ip] = rem
                else:
                    self.failed_probes.pop(ip, None)
        for ip, expiry in list(self.banned_ips.items()):
            if now >= expiry:
                self.banned_ips.pop(ip, None)
        for ip in list(self.health_probes.keys()):
            rem = [t for t in self.health_probes[ip] if t > cutoff]
            if rem:
                self.health_probes[ip] = rem
            else:
                self.health_probes.pop(ip, None)


# -----------------------------------------------------------------------------
# 1-to-1 Private Relay State
# -----------------------------------------------------------------------------
class PendingRequest:
    __slots__ = ("request_id", "alt_id", "requester", "created_at")

    def __init__(
        self,
        request_id: str,
        alt_id: Optional[str],
        requester: Union[web.WebSocketResponse, asyncio.Future]
    ):
        self.request_id = request_id
        self.alt_id = alt_id
        self.requester = requester
        self.created_at = time.time()


class PrivateRelay:
    """Manages the single phone connection and up to 2 CLI client connections."""
    def __init__(self, shield: ProbeShield):
        self.shield = shield
        self.phone_ws: Optional[web.WebSocketResponse] = None
        self.last_phone_activity: float = 0.0
        self.active_cli_sockets: Set[web.WebSocketResponse] = set()
        self.pending_requests: Dict[str, PendingRequest] = {}
        self.heartbeat_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None

    async def register_phone(self, ws: web.WebSocketResponse) -> None:
        """Registers the sole phone socket, cleanly replacing any stale connection."""
        if self.phone_ws is not None and self.phone_ws is not ws and not self.phone_ws.closed:
            try:
                await self.phone_ws.close(code=1000, message=b"Replaced by new phone connection")
            except Exception:
                pass
        self.phone_ws = ws
        now = time.time()
        self.last_phone_activity = now
        logger.info("Phone connected")

    def unregister_phone(self, ws: web.WebSocketResponse) -> None:
        if self.phone_ws is ws:
            self.phone_ws = None
            logger.info("Phone disconnected")

    def register_cli_precheck(self) -> bool:
        """Allows up to 2 concurrent CLI sockets."""
        return len(self.active_cli_sockets) < 2

    def unregister_cli(self, ws: web.WebSocketResponse) -> None:
        self.active_cli_sockets.discard(ws)
        to_del = [k for k, v in list(self.pending_requests.items()) if v.requester is ws]
        for k in to_del:
            self.pending_requests.pop(k, None)
        logger.info("CLI client disconnected")

    def register_request(
        self,
        request_id: str,
        requester: Union[web.WebSocketResponse, asyncio.Future],
        alt_id: Optional[str] = None
    ) -> bool:
        """Enforces maximum queue capacity (64) to prevent memory exhaustion."""
        if len(self.pending_requests) >= MAX_GLOBAL_PENDING:
            return False
        entry = PendingRequest(request_id, alt_id, requester)
        self.pending_requests[request_id] = entry
        if alt_id and alt_id != request_id:
            self.pending_requests[alt_id] = entry
        return True

    def pop_pending(self, request_id: Optional[str], alt_id: Optional[str] = None) -> Optional[PendingRequest]:
        for k in (request_id, alt_id):
            if k and k in self.pending_requests:
                entry = self.pending_requests.pop(k)
                if entry.alt_id and entry.alt_id in self.pending_requests:
                    self.pending_requests.pop(entry.alt_id, None)
                if entry.request_id and entry.request_id in self.pending_requests:
                    self.pending_requests.pop(entry.request_id, None)
                return entry
        return None

    async def deliver_phone_response(self, data: Dict[str, Any], raw_text: str) -> None:
        req_id = data.get("requestId") or data.get("reqId")
        alt_id = data.get("reqId") if data.get("requestId") else None
        entry = self.pop_pending(req_id, alt_id)
        if not entry:
            return

        requester = entry.requester
        if isinstance(requester, asyncio.Future):
            if not requester.done():
                requester.set_result(data)
        elif isinstance(requester, web.WebSocketResponse):
            if not requester.closed:
                try:
                    await requester.send_str(raw_text)
                except Exception:
                    pass

    async def start_tasks(self) -> None:
        self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop_tasks(self) -> None:
        for t in (self.heartbeat_task, self.cleanup_task):
            if t and not t.done():
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

    async def _heartbeat_loop(self) -> None:
        """Sends keepalive every 25s on idle phone_ws so Render proxy doesn't drop connection."""
        while True:
            try:
                await asyncio.sleep(5.0)
                now = time.time()
                if self.phone_ws is not None and not self.phone_ws.closed:
                    if (now - self.last_phone_activity) >= HEARTBEAT_INTERVAL:
                        ping_pkt = {
                            "type": "PING",
                            "pingId": f"hb_{uuid.uuid4().hex[:6]}",
                            "sessionId": "relay_hb",
                            "timestamp": int(now * 1000)
                        }
                        try:
                            await self.phone_ws.send_str(json.dumps(ping_pkt))
                            self.last_phone_activity = now
                        except Exception:
                            pass
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _cleanup_loop(self) -> None:
        """Cleans up stale requests older than 30s and expired bans."""
        while True:
            try:
                await asyncio.sleep(5.0)
                now = time.time()
                stale = [
                    k for k, v in list(self.pending_requests.items())
                    if now - v.created_at > REQUEST_TIMEOUT_PENDING
                ]
                for k in stale:
                    entry = self.pending_requests.pop(k, None)
                    if entry and isinstance(entry.requester, asyncio.Future) and not entry.requester.done():
                        entry.requester.set_exception(asyncio.TimeoutError("Pending request timed out"))
                self.shield.cleanup(now)
            except asyncio.CancelledError:
                break
            except Exception:
                pass


# -----------------------------------------------------------------------------
# Middleware: Brute-Force Ban & Anti-Sniff Headers
# -----------------------------------------------------------------------------
@web.middleware
async def single_owner_middleware(request: web.Request, handler) -> web.StreamResponse:
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)

    if shield.is_banned(ip):
        return web.Response(status=404, text="Not Found")

    response = await handler(request)

    if not response.prepared:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Server"] = "Relay"

    return response


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
async def handle_health(request: web.Request) -> web.Response:
    """Public health probe: 200 OK with zero internal state or connection metrics leaked."""
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)
    if not shield.check_health_rate(ip):
        return web.Response(status=429, text="Too Many Requests")
    return web.json_response({"status": "UP"}, status=200)


async def handle_cli_health(request: web.Request) -> web.Response:
    """
    Authenticated CLI health & bridge diagnostics probe.
    Requires valid CLI_KEY.
    Returns relay uptime, phone WebSocket connectivity, and active sessions.
    """
    key = request.match_info.get("key", "")
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)

    if not check_cli_key(key):
        shield.record_failure(ip)
        return web.Response(status=404, text="Not Found")

    relay: PrivateRelay = request.app["relay"]
    now = time.time()
    phone_online = (relay.phone_ws is not None and not relay.phone_ws.closed)
    phone_last_seen = round(now - relay.last_phone_activity, 1) if relay.last_phone_activity > 0 else None

    return web.json_response(
        {
            "status": "UP",
            "role": "cli",
            "phone_connected": phone_online,
            "phone_last_seen_sec": phone_last_seen,
            "active_cli_count": len([ws for ws in relay.active_cli_sockets if not ws.closed]),
            "uptime_sec": int(now - SERVER_START_TIME),
            "pending_requests_count": len(relay.pending_requests),
            "timestamp": now,
        },
        status=200
    )


async def handle_phone_health(request: web.Request) -> web.Response:
    """
    Authenticated Phone health probe.
    Requires valid PHONE_KEY.
    """
    key = request.match_info.get("key", "")
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)

    if not check_phone_key(key):
        shield.record_failure(ip)
        return web.Response(status=404, text="Not Found")

    now = time.time()
    return web.json_response(
        {
            "status": "UP",
            "role": "phone",
            "uptime_sec": int(now - SERVER_START_TIME),
            "timestamp": now,
        },
        status=200
    )


async def handle_phone_ws(request: web.Request) -> web.WebSocketResponse:
    """
    Dedicated Phone-Only WebSocket: /p/{PHONE_KEY}/ws and /p/{PHONE_KEY}
    Only this entrypoint can register phone_ws.
    Hardened with slowloris timeout, ping flood protection, and strict packet routing.
    """
    key = request.match_info.get("key", "")
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)

    if not check_phone_key(key):
        shield.record_failure(ip)
        return web.Response(status=404, text="Not Found")

    relay: PrivateRelay = request.app["relay"]
    ws = web.WebSocketResponse(
        max_msg_size=MAX_PAYLOAD_SIZE,
        heartbeat=HEARTBEAT_INTERVAL,
        autoping=True
    )
    await ws.prepare(request)
    await relay.register_phone(ws)

    msg_limiter = SlidingRateLimiter(limit=WS_MSG_RATE_LIMIT, window=1.0)
    ping_limiter = SlidingRateLimiter(limit=WS_PING_RATE_LIMIT, window=1.0)
    has_received_first = False

    try:
        while True:
            # Slowloris guard on initial message
            if not has_received_first:
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=HANDSHAKE_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning("Phone socket timed out waiting for initial message (slowloris mitigation)")
                    await ws.close(code=1008, message=b"Handshake timeout")
                    break
                has_received_first = True
            else:
                msg = await ws.receive()

            now = time.time()

            if not msg_limiter.allow(now):
                logger.warning("Message flood detected from phone socket. Dropping.")
                await ws.close(code=1008, message=b"Policy Violation: Message rate limit exceeded")
                break

            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    if not isinstance(data, dict):
                        continue
                except (json.JSONDecodeError, RecursionError, ValueError, Exception):
                    continue

                msg_type = str(data.get("type", ""))
                relay.last_phone_activity = now

                # PING -> PONG
                if msg_type == "PING":
                    if not ping_limiter.allow(now):
                        logger.warning("Ping flood detected on phone socket. Dropping.")
                        await ws.close(code=1008, message=b"Policy Violation: Ping flood")
                        break

                    now_ms = int(now * 1000)
                    pong = {
                        "type": "PONG",
                        "timestamp": now_ms,
                        "sessionId": sanitize_log_string(data.get("sessionId", "")),
                        "pingId": sanitize_log_string(data.get("pingId", "")),
                        "requestTimestamp": data.get("timestamp", now_ms)
                    }
                    await ws.send_str(json.dumps(pong))
                    continue

                if msg_type in ("PONG", "HELLO"):
                    continue

                # Response packets from phone
                is_response = (
                    msg_type.endswith("_RESULT")
                    or msg_type in (
                        "AUTH_REQUIRED",
                        "AUTH_SUCCESS",
                        "AUTH_FAILED",
                        "REGISTER_SUCCESS",
                        "REGISTER_FAILED",
                    )
                )

                if is_response:
                    await relay.deliver_phone_response(data, msg.data)
                elif msg_type == "ACCESSIBILITY_SCREEN_UPDATE":
                    # Never broadcast unsolicited screen updates
                    pass
                else:
                    # Unsolicited alerts: forward strictly to active CLI sockets
                    for cli in list(relay.active_cli_sockets):
                        if not cli.closed:
                            try:
                                await cli.send_str(msg.data)
                            except Exception:
                                pass

            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                break

    except Exception:
        pass
    finally:
        relay.unregister_phone(ws)

    return ws


async def handle_cli_ws(request: web.Request) -> web.WebSocketResponse:
    """
    Dedicated CLI-Only WebSocket: /c/{CLI_KEY}/ws and /c/{CLI_KEY}
    Max 2 concurrent sockets; cannot impersonate phone_ws.
    Hardened with slowloris timeout, ping flood protection, and command dispatch.
    """
    key = request.match_info.get("key", "")
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)

    if not check_cli_key(key):
        shield.record_failure(ip)
        return web.Response(status=404, text="Not Found")

    relay: PrivateRelay = request.app["relay"]
    if not relay.register_cli_precheck():
        return web.Response(status=429, text="Too Many Requests")

    ws = web.WebSocketResponse(
        max_msg_size=MAX_PAYLOAD_SIZE,
        heartbeat=HEARTBEAT_INTERVAL,
        autoping=True
    )
    await ws.prepare(request)
    relay.active_cli_sockets.add(ws)
    logger.info("CLI client connected")

    msg_limiter = SlidingRateLimiter(limit=WS_MSG_RATE_LIMIT, window=1.0)
    ping_limiter = SlidingRateLimiter(limit=WS_PING_RATE_LIMIT, window=1.0)
    has_received_first = False

    try:
        while True:
            # Slowloris guard on initial message
            if not has_received_first:
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=HANDSHAKE_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.warning("CLI socket timed out waiting for initial message (slowloris mitigation)")
                    await ws.close(code=1008, message=b"Handshake timeout")
                    break
                has_received_first = True
            else:
                try:
                    msg = await asyncio.wait_for(ws.receive(), timeout=IDLE_CLI_TIMEOUT)
                except asyncio.TimeoutError:
                    logger.info("Reaping inactive CLI socket after timeout")
                    await ws.close(code=1000, message=b"Idle timeout")
                    break

            now = time.time()

            if not msg_limiter.allow(now):
                logger.warning("Message flood detected from CLI socket. Dropping.")
                await ws.close(code=1008, message=b"Policy Violation: Message rate limit exceeded")
                break

            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    if not isinstance(data, dict):
                        continue
                except (json.JSONDecodeError, RecursionError, ValueError, Exception):
                    continue

                msg_type = str(data.get("type", ""))

                # PING -> PONG
                if msg_type == "PING":
                    if not ping_limiter.allow(now):
                        logger.warning("Ping flood detected on CLI socket. Dropping.")
                        await ws.close(code=1008, message=b"Policy Violation: Ping flood")
                        break

                    now_ms = int(now * 1000)
                    pong = {
                        "type": "PONG",
                        "timestamp": now_ms,
                        "sessionId": sanitize_log_string(data.get("sessionId", "")),
                        "pingId": sanitize_log_string(data.get("pingId", "")),
                        "requestTimestamp": data.get("timestamp", now_ms)
                    }
                    await ws.send_str(json.dumps(pong))
                    continue

                # CLI Command Packet
                req_id = data.get("requestId") or data.get("reqId")
                if not req_id:
                    req_id = f"req_{uuid.uuid4().hex[:8]}"
                    data["requestId"] = req_id
                    data["reqId"] = req_id
                    raw_text = json.dumps(data)
                else:
                    raw_text = msg.data

                # Check phone availability
                if relay.phone_ws is None or relay.phone_ws.closed:
                    err_reply = {
                        "type": "HTTP_RPC_RESULT",
                        "requestId": req_id,
                        "reqId": req_id,
                        "success": False,
                        "error": "Phone offline"
                    }
                    await ws.send_str(json.dumps(err_reply))
                    continue

                alt_id = data.get("reqId") if data.get("requestId") else None
                registered = relay.register_request(req_id, ws, alt_id=alt_id)
                if not registered:
                    err_reply = {
                        "type": "HTTP_RPC_RESULT",
                        "requestId": req_id,
                        "reqId": req_id,
                        "success": False,
                        "error": "Server busy"
                    }
                    await ws.send_str(json.dumps(err_reply))
                    continue

                try:
                    await relay.phone_ws.send_str(raw_text)
                    relay.last_phone_activity = now
                except Exception:
                    relay.pop_pending(req_id, alt_id)
                    err_reply = {
                        "type": "HTTP_RPC_RESULT",
                        "requestId": req_id,
                        "reqId": req_id,
                        "success": False,
                        "error": "Phone offline"
                    }
                    await ws.send_str(json.dumps(err_reply))

            elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED, WSMsgType.ERROR):
                break

    except Exception:
        pass
    finally:
        relay.unregister_cli(ws)

    return ws


async def handle_cli_http(request: web.Request) -> web.Response:
    """
    Dedicated CLI HTTP REST Bridge: /c/{CLI_KEY}/api/{endpoint:.*} (GET & POST)
    Hardened against directory traversal, method injection, and queue exhaustion.
    """
    key = request.match_info.get("key", "")
    shield: ProbeShield = request.app["shield"]
    ip = get_client_ip(request)

    if not check_cli_key(key):
        shield.record_failure(ip)
        return web.Response(status=404, text="Not Found")

    if request.method not in ("GET", "POST"):
        return web.Response(status=405, text="Method Not Allowed")

    endpoint = request.match_info.get("endpoint", "").lstrip("/")

    # Strict directory traversal and character whitelist check
    if endpoint:
        if ".." in endpoint or "//" in endpoint or "\\" in endpoint or "\0" in endpoint:
            return web.json_response(
                {"success": False, "error": "Invalid endpoint: directory traversal not allowed"},
                status=400
            )
        if not re.match(r"^[a-zA-Z0-9_\-\/]+$", endpoint):
            return web.json_response(
                {"success": False, "error": "Invalid endpoint: contains forbidden characters"},
                status=400
            )

    full_endpoint = f"/api/{endpoint}" if endpoint else "/api/"

    # Extract Auth Token
    extracted_token = ""
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        extracted_token = auth_header[7:].strip()
    elif "X-API-Key" in request.headers:
        extracted_token = request.headers["X-API-Key"].strip()
    elif "token" in request.query:
        extracted_token = request.query["token"].strip()

    # Extract Payload
    payload: Dict[str, Any] = {}
    if request.method == "POST":
        try:
            if request.can_read_body:
                body = await request.json()
                if isinstance(body, dict):
                    payload = body
        except Exception:
            payload = {}
    else:
        payload = dict(request.query)
        payload.pop("token", None)

    relay: PrivateRelay = request.app["relay"]

    if relay.phone_ws is None or relay.phone_ws.closed:
        return web.json_response({"success": False, "error": "Phone offline"}, status=503)

    req_id = f"req_{uuid.uuid4().hex[:12]}"
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[Dict[str, Any]] = loop.create_future()

    registered = relay.register_request(req_id, fut, alt_id=req_id)
    if not registered:
        return web.json_response({"success": False, "error": "Server busy"}, status=429)

    rpc_msg: Dict[str, Any] = {
        "type": "HTTP_RPC",
        "endpoint": full_endpoint,
        "requestId": req_id,
        "reqId": req_id,
        "token": extracted_token,
        **payload
    }
    rpc_msg["type"] = "HTTP_RPC"
    rpc_msg["endpoint"] = full_endpoint
    rpc_msg["requestId"] = req_id
    rpc_msg["reqId"] = req_id
    rpc_msg["token"] = extracted_token

    try:
        await relay.phone_ws.send_str(json.dumps(rpc_msg))
        relay.last_phone_activity = time.time()
    except Exception:
        relay.pop_pending(req_id)
        return web.json_response({"success": False, "error": "Phone offline"}, status=503)

    try:
        result = await asyncio.wait_for(fut, timeout=REQUEST_TIMEOUT_HTTP)
    except asyncio.TimeoutError:
        relay.pop_pending(req_id)
        return web.json_response({"success": False, "error": "Gateway Timeout: Phone offline"}, status=504)

    err = str(result.get("error", ""))
    rtype = str(result.get("type", ""))

    if err == "UNAUTHORIZED_DEVICE" or rtype == "AUTH_REQUIRED":
        status_code = 401
    else:
        status_code = 200

    return web.json_response(result, status=status_code)


# -----------------------------------------------------------------------------
# Application Setup & Entrypoint
# -----------------------------------------------------------------------------
async def on_startup(app: web.Application) -> None:
    relay: PrivateRelay = app["relay"]
    await relay.start_tasks()
    logger.info("Server started on port %d", PORT)


async def on_cleanup(app: web.Application) -> None:
    relay: PrivateRelay = app["relay"]
    await relay.stop_tasks()
    if relay.phone_ws and not relay.phone_ws.closed:
        try:
            await relay.phone_ws.close(code=1001)
        except Exception:
            pass


def create_app() -> web.Application:
    shield = ProbeShield()
    relay = PrivateRelay(shield)

    app = web.Application(
        client_max_size=MAX_PAYLOAD_SIZE,
        middlewares=[single_owner_middleware]
    )
    app["shield"] = shield
    app["relay"] = relay
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    # 1. Public Health Check (Render, Uptime monitors - zero metadata leaked)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/health/", handle_health)
    app.router.add_get("/healthz", handle_health)
    app.router.add_get("/healthz/", handle_health)
    app.router.add_get("/ping", handle_health)
    app.router.add_get("/ping/", handle_health)

    # 2. Authenticated CLI Health & Diagnostics (/c/{CLI_KEY}/health)
    app.router.add_get(r"/c/{key}/health", handle_cli_health)
    app.router.add_get(r"/c/{key}/health/", handle_cli_health)
    app.router.add_get(r"/c/{key}/status", handle_cli_health)
    app.router.add_get(r"/c/{key}/status/", handle_cli_health)
    app.router.add_get(r"/c/{key}/ping", handle_cli_health)
    app.router.add_get(r"/c/{key}/ping/", handle_cli_health)
    app.router.add_get(r"/c/{key}/api/health", handle_cli_health)
    app.router.add_get(r"/c/{key}/api/health/", handle_cli_health)

    # 3. Authenticated Phone Health (/p/{PHONE_KEY}/health)
    app.router.add_get(r"/p/{key}/health", handle_phone_health)
    app.router.add_get(r"/p/{key}/health/", handle_phone_health)
    app.router.add_get(r"/p/{key}/ping", handle_phone_health)
    app.router.add_get(r"/p/{key}/ping/", handle_phone_health)
    app.router.add_get(r"/p/{key}/status", handle_phone_health)
    app.router.add_get(r"/p/{key}/status/", handle_phone_health)

    # 4. Phone-Only WebSocket (/p/{PHONE_KEY}/ws)
    app.router.add_get(r"/p/{key}/ws", handle_phone_ws)
    app.router.add_get(r"/p/{key}/ws/", handle_phone_ws)
    app.router.add_get(r"/p/{key}", handle_phone_ws)
    app.router.add_get(r"/p/{key}/", handle_phone_ws)

    # 3. CLI-Only WebSocket (/c/{CLI_KEY}/ws)
    app.router.add_get(r"/c/{key}/ws", handle_cli_ws)
    app.router.add_get(r"/c/{key}/ws/", handle_cli_ws)
    app.router.add_get(r"/c/{key}", handle_cli_ws)
    app.router.add_get(r"/c/{key}/", handle_cli_ws)

    # 4. CLI-Only HTTP REST-to-WS Bridge (/c/{CLI_KEY}/api/{endpoint:.*})
    app.router.add_get(r"/c/{key}/api/{endpoint:.*}", handle_cli_http)
    app.router.add_post(r"/c/{key}/api/{endpoint:.*}", handle_cli_http)
    app.router.add_get(r"/c/{key}/api", handle_cli_http)
    app.router.add_post(r"/c/{key}/api", handle_cli_http)

    return app


def main() -> None:
    app = create_app()
    web.run_app(
        app,
        host=HOST,
        port=PORT,
        access_log=None
    )


if __name__ == "__main__":
    main()
