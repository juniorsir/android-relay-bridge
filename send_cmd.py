#!/usr/bin/env python3
"""
CLI Controller for Termux AIOS & Android Automation Bridge
Sends commands over localhost WebSocket or HTTP REST to the Android device.

Features:
- List installed applications (with search filter & system app toggle)
- Open / Launch applications by name, package name, or URL
- Inspect on-screen UI hierarchy (Accessibility tree)
- Tap elements by label or coordinates
- Dispatch gestures (swipe, click, scroll next)
- Trigger system actions (Back, Home, Recents, Notifications)
- Display live toast messages
- Seamless auto-fallback to HTTP REST (Port 8080) if WebSocket server (Port 8000) is offline

Usage:
    python send_cmd.py apps [filter] [--system] [--json]
    python send_cmd.py open <appName | packageName | url>
    python send_cmd.py inspect [delay_sec]
    python send_cmd.py click <x> <y>
    python send_cmd.py tap <label>
    python send_cmd.py swipe <x1> <y1> <x2> <y2> [duration_ms]
    python send_cmd.py next
    python send_cmd.py back | home | recents | notifications
    python send_cmd.py toast <text>
"""

import asyncio
import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

CLOUDFLARE_TUNNEL_URL = "https://private-relay-bridge.onrender.com"
CLOUDFLARE_WS_URL = "wss://private-relay-bridge.onrender.com/ws"
LOCAL_HTTP_URL = "http://127.0.0.1:8080"
LOCAL_WS_URL = "ws://127.0.0.1:8000/ws"
BUNDLED_MASTER_TOKEN = ""

WS_SERVER_URL = os.environ.get("AURA_WS_URL", CLOUDFLARE_WS_URL)
HTTP_SERVER_URL = os.environ.get("AURA_HTTP_URL", CLOUDFLARE_TUNNEL_URL)

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False


def parse_center(bounds_str):
    try:
        nums = [int(n) for n in re.findall(r'\d+', bounds_str)]
        if len(nums) == 4:
            return (nums[0] + nums[2]) // 2, (nums[1] + nums[3]) // 2
    except Exception:
        pass
    return None


def print_tree(nodes, depth=0, find_text=None, matched_targets=None):
    if not isinstance(nodes, list):
        nodes = [nodes]

    for node in nodes:
        indent = "  " * depth
        class_name = node.get("className", "").split(".")[-1]
        text = node.get("text", "") or ""
        desc = node.get("contentDescription", "") or ""
        clickable = node.get("isClickable", False)
        bounds = node.get("boundsInScreen", "")

        center = parse_center(bounds)
        cx, cy = center if center else (0, 0)
        coord_str = f" -> click {cx} {cy}" if (clickable and center) else ""

        if find_text and matched_targets is not None:
            clean_search = find_text.strip().lower()
            if (clean_search in text.lower() or clean_search in desc.lower()) and center:
                matched_targets.append((text or desc or class_name, cx, cy))

        info = []
        if text:
            info.append(f'"{text}"')
        if desc and desc != text:
            info.append(f'desc="{desc}"')
        if not info and clickable:
            info.append("(clickable area)")

        label = " ".join(info) if info else ""
        marker = "•" if (clickable or text or desc) else "·"
        print(f"{indent}{marker} [{class_name}] {label}{coord_str}")

        children = node.get("children", [])
        if children:
            print_tree(children, depth + 1, find_text, matched_targets)


# ---------------------------------------------------------------------------
# HTTP REST Fallback Helpers & Security Shield (Zero external dependencies)
# ---------------------------------------------------------------------------

TOKEN_FILE = os.path.expanduser("~/.aura_token")
LOCAL_TOKEN_FILE = os.path.join(os.path.dirname(__file__), ".aura_token")
SDCARD_TOKEN_FILES = [
    "/sdcard/Download/AeroShare/.aura_token",
    "/sdcard/Download/.aura_token",
    "/storage/emulated/0/Download/AeroShare/.aura_token",
    "/storage/emulated/0/Download/.aura_token"
]

def load_stored_token():
    if os.environ.get("AURA_API_TOKEN"):
        return os.environ.get("AURA_API_TOKEN").strip()
    if os.environ.get("AERO_TOKEN"):
        return os.environ.get("AERO_TOKEN").strip()
    for candidate in [TOKEN_FILE, LOCAL_TOKEN_FILE] + SDCARD_TOKEN_FILES:
        if os.path.exists(candidate):
            try:
                with open(candidate, "r") as f:
                    val = f.read().strip()
                    if val:
                        return val
            except Exception:
                pass
    if BUNDLED_MASTER_TOKEN:
        return BUNDLED_MASTER_TOKEN.strip()
    return ""

def save_stored_token(token):
    clean = (token or "").strip()
    for path in [TOKEN_FILE, LOCAL_TOKEN_FILE]:
        try:
            if clean:
                with open(path, "w") as f:
                    f.write(clean)
            elif os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

TARGET_URL_FILE = os.path.expanduser("~/.aura_target_url")

def load_stored_target_url():
    if os.environ.get("AURA_HTTP_URL"):
        return os.environ.get("AURA_HTTP_URL").strip().rstrip("/")
    if os.path.exists(TARGET_URL_FILE):
        try:
            with open(TARGET_URL_FILE, "r") as f:
                val = f.read().strip().rstrip("/")
                if val.startswith("http"):
                    return val
        except Exception:
            pass
    return ""

def save_stored_target_url(url):
    try:
        with open(TARGET_URL_FILE, "w") as f:
            f.write(url.strip().rstrip("/"))
    except Exception:
        pass

STORED_TARGET_URL = load_stored_target_url()
if STORED_TARGET_URL:
    HTTP_SERVER_URL = STORED_TARGET_URL
    if STORED_TARGET_URL.startswith(("http://127.", "http://192.168.", "http://10.", "http://172.")):
        LOCAL_HTTP_URL = STORED_TARGET_URL
    WS_SERVER_URL = STORED_TARGET_URL.replace("http://", "ws://").replace("https://", "wss://").replace(":8080", ":8000") + "/ws"

AUTH_TOKEN = load_stored_token()

def get_http_headers():
    headers = {
        "User-Agent": "AuraTermuxCLI/3.0",
        "Accept": "application/json"
    }
    if AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
        headers["X-API-Key"] = AUTH_TOKEN
    return headers


def check_unauthorized_response(res):
    global AUTH_TOKEN
    if isinstance(res, dict) and (res.get("error") == "UNAUTHORIZED_DEVICE" or res.get("action") == "AUTHENTICATION_REQUIRED"):
        AUTH_TOKEN = ""
        save_stored_token("")
        print("\n" + "=" * 68)
        print(" 🔒 ACCESS DENIED: UNAUTHORIZED DEVICE")
        print("=" * 68)
        print(" 401 Unauthorized: This device is not authenticated with AeroShare.")
        print(" Please run the login command to authenticate on your phone:")
        print("   python send_cmd.py login")
        print(" Approve with Face, Fingerprint, or PIN when prompted.")
        print("=" * 68 + "\n")
        return True
    return False


def normalize_api_error(err_dict_or_str, status_code=None, reason=None):
    if isinstance(err_dict_or_str, dict):
        if err_dict_or_str.get("cloudflare_error") or err_dict_or_str.get("status") in [502, 503, 504] or status_code in [502, 503, 504]:
            detail = err_dict_or_str.get("detail") or err_dict_or_str.get("title") or "Bad gateway"
            code = err_dict_or_str.get("status") or status_code or 502
            return f"Cloudflare {code} ({detail}): Phone origin server is unreachable or offline. Ensure AeroShare is running on device (Port 8080)."
        if err_dict_or_str.get("server") == "termux-aios" and not err_dict_or_str.get("success", False):
            return "Connected to WebSocket relay on Port 8000 instead of AeroShare REST on Port 8080. Start AeroShare on the device or ensure mock_server.py is running."
        if err_dict_or_str.get("error"):
            return err_dict_or_str.get("error")
        if err_dict_or_str.get("message"):
            return err_dict_or_str.get("message")
        if err_dict_or_str.get("detail"):
            return err_dict_or_str.get("detail")
    if status_code:
        return f"HTTP {status_code}: {reason or 'Server Error'}"
    return str(err_dict_or_str) if err_dict_or_str else "Unknown error"


async def _ws_rpc_async(endpoint, payload=None):
    if not HAS_WEBSOCKETS:
        return None
    req_id = f"req_{uuid.uuid4().hex[:8]}"
    p = dict(payload) if isinstance(payload, dict) else {}
    ws_msg = {"requestId": req_id, "reqId": req_id, "token": AUTH_TOKEN}

    if endpoint == "/api/auth/login":
        ws_msg.update({"type": "AUTH_LOGIN", **p})
        expected = ["AUTH_LOGIN_RESULT", "HTTP_RPC_RESULT"]
    elif endpoint == "/api/auth/poll":
        ws_msg.update({"type": "AUTH_POLL", **p})
        expected = ["AUTH_POLL_RESULT", "HTTP_RPC_RESULT"]
    elif endpoint in ["/api/auth/pair", "/api/pair/verify"]:
        ws_msg.update({"type": "REGISTER_REQUEST", **p})
        expected = ["REGISTER_SUCCESS", "REGISTER_FAILED", "HTTP_RPC_RESULT"]
    elif endpoint == "/api/shell/exec":
        ws_msg.update({"type": "SHELL_EXEC", **p})
        expected = ["SHELL_EXEC_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint == "/api/system/status":
        ws_msg.update({"type": "SYSTEM_STATUS", **p})
        expected = ["SYSTEM_STATUS_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint == "/api/system/toggle":
        ws_msg.update({"type": "SYSTEM_TOGGLE", **p})
        expected = ["SYSTEM_TOGGLE_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint == "/api/screen/capture":
        ws_msg.update({"type": "SCREEN_CAPTURE", **p})
        expected = ["SCREEN_CAPTURE_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint == "/api/ui/tree":
        ws_msg.update({"type": "UI_TREE", **p})
        expected = ["ACCESSIBILITY_INSPECT_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint == "/api/ui/action":
        ws_msg.update({"type": "UI_ACTION", **p})
        expected = ["UI_ACTION_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint.startswith("/api/fs/"):
        op = endpoint.split("/api/fs/")[-1].strip("/")
        ws_msg.update({"type": "FS_OP", "op": op, **p})
        expected = ["FS_OP_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint.startswith("/api/clipboard/"):
        op = endpoint.split("/api/clipboard/")[-1].strip("/")
        ws_msg.update({"type": "CLIPBOARD_OP", "op": op, **p})
        expected = ["CLIPBOARD_RESULT", "HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    elif endpoint.startswith("/api/"):
        ws_msg.update({"type": "HTTP_RPC", "endpoint": endpoint, **p})
        expected = ["HTTP_RPC_RESULT", "AUTH_REQUIRED"]
    else:
        return None

    ws_targets = []
    if WS_SERVER_URL:
        ws_targets.append(WS_SERVER_URL)
    for local_target in [LOCAL_WS_URL, "ws://127.0.0.1:8080/ws"]:
        if local_target not in ws_targets:
            ws_targets.append(local_target)

    base_timeout = 18.0 if (endpoint in ["/api/shell/exec", "/api/screen/capture"] or "/uninstall" in endpoint or "/snap" in endpoint or "/apk/" in endpoint) else 4.5
    for ws_url in ws_targets:
        is_remote = not ws_url.startswith(("ws://127.0.0.1", "ws://localhost"))
        open_to = 15.0 if is_remote else 1.5
        recv_to = max(base_timeout, 25.0) if is_remote else base_timeout
        connect_url = ws_url
        if ws_url.startswith(("ws://127.0.0.1:8080", "ws://localhost:8080")) and AUTH_TOKEN and "token=" not in ws_url:
            sep = "&" if "?" in ws_url else "?"
            connect_url = f"{ws_url}{sep}token={urllib.parse.quote(AUTH_TOKEN)}"
        try:
            async with websockets.connect(connect_url, open_timeout=open_to, max_size=16 * 1024 * 1024) as ws:
                await ws.send(json.dumps(ws_msg))
                deadline = time.time() + recv_to
                while time.time() < deadline:
                    rem = max(0.2, deadline - time.time())
                    raw = await asyncio.wait_for(ws.recv(), timeout=rem)
                    resp = json.loads(raw)
                    rtype = resp.get("type", "")
                    resp_rids = [resp.get("requestId"), resp.get("reqId"), resp.get("id")]
                    if rtype in expected and (not req_id or req_id in resp_rids):
                        if rtype == "AUTH_REQUIRED":
                            resp["error"] = "UNAUTHORIZED_DEVICE"
                        return resp
        except Exception:
            continue
    return None


def ws_rpc_fallback(endpoint, payload=None):
    if not HAS_WEBSOCKETS:
        return None

    def _runner():
        return asyncio.run(_ws_rpc_async(endpoint, payload))

    try:
        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False

        if not in_loop:
            return _runner()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(_runner).result(timeout=35.0)
    except Exception:
        return None


def http_get(path_and_query):
    parts = path_and_query.split("?", 1)
    endpoint = parts[0]
    query_payload = {}
    if len(parts) > 1 and parts[1]:
        for k, v in urllib.parse.parse_qsl(parts[1]):
            query_payload[k] = v

    last_error = None
    is_remote_http = bool(HTTP_SERVER_URL and not HTTP_SERVER_URL.startswith(("http://127.", "http://localhost")))

    # 1. Try remote HTTP tunnel first if configured for remote bridge (fast ~150ms round-trip)
    if is_remote_http:
        remote_url = f"{HTTP_SERVER_URL}{path_and_query}"
        try:
            req = urllib.request.Request(remote_url, headers=get_http_headers())
            with urllib.request.urlopen(req, timeout=25.0) as resp:
                data = resp.read().decode("utf-8")
                parsed = json.loads(data)
                if isinstance(parsed, dict) and not parsed.get("success", False) and not parsed.get("error"):
                    parsed["error"] = normalize_api_error(parsed, resp.status, resp.reason)
                return parsed
        except urllib.error.HTTPError as e:
            try:
                err_data = e.read().decode("utf-8")
                parsed = json.loads(err_data)
                if check_unauthorized_response(parsed):
                    return parsed
                if isinstance(parsed, dict):
                    if not parsed.get("error"):
                        parsed["error"] = normalize_api_error(parsed, e.code, e.reason)
                    return parsed
            except Exception:
                pass
        except Exception as e:
            err_str = str(e)
            if not last_error or ("No address associated with hostname" not in err_str and "Name or service not known" not in err_str):
                last_error = err_str

    # 2. Try local loopback HTTP server on port 8080 (fast 1.5s check)
    local_url = f"{LOCAL_HTTP_URL}{path_and_query}"
    try:
        req = urllib.request.Request(local_url, headers=get_http_headers())
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = resp.read().decode("utf-8")
            parsed = json.loads(data)
            if isinstance(parsed, dict) and not parsed.get("success", False) and not parsed.get("error"):
                parsed["error"] = normalize_api_error(parsed, resp.status, resp.reason)
            return parsed
    except urllib.error.HTTPError as e:
        try:
            err_data = e.read().decode("utf-8")
            parsed = json.loads(err_data)
            if check_unauthorized_response(parsed):
                return parsed
            if isinstance(parsed, dict):
                if not parsed.get("error"):
                    parsed["error"] = normalize_api_error(parsed, e.code, e.reason)
                return parsed
        except Exception:
            pass
        return {"success": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        last_error = str(e)

    # 3. Try WebSocket RPC via ws_relay.py (ws://127.0.0.1:8000/ws or Cloudflare WSS)
    ws_res = ws_rpc_fallback(endpoint, query_payload)
    if isinstance(ws_res, dict):
        check_unauthorized_response(ws_res)
        return ws_res

    # 4. Fallback to remote HTTP URL if not already tried above
    if not is_remote_http and HTTP_SERVER_URL and HTTP_SERVER_URL != LOCAL_HTTP_URL:
        remote_url = f"{HTTP_SERVER_URL}{path_and_query}"
        try:
            req = urllib.request.Request(remote_url, headers=get_http_headers())
            with urllib.request.urlopen(req, timeout=25.0) as resp:
                data = resp.read().decode("utf-8")
                parsed = json.loads(data)
                if isinstance(parsed, dict) and not parsed.get("success", False) and not parsed.get("error"):
                    parsed["error"] = normalize_api_error(parsed, resp.status, resp.reason)
                return parsed
        except urllib.error.HTTPError as e:
            try:
                err_data = e.read().decode("utf-8")
                parsed = json.loads(err_data)
                if check_unauthorized_response(parsed):
                    return parsed
                if isinstance(parsed, dict):
                    if not parsed.get("error"):
                        parsed["error"] = normalize_api_error(parsed, e.code, e.reason)
                    return parsed
            except Exception:
                pass
        except Exception as e:
            err_str = str(e)
            if not last_error or ("No address associated with hostname" not in err_str and "Name or service not known" not in err_str):
                last_error = err_str

    return {"success": False, "error": last_error or "Connection failed to AeroShare bridge (ensure AeroShare is open on phone)"}


def http_post(endpoint, payload):
    data_bytes = json.dumps(payload).encode("utf-8")
    headers = get_http_headers()
    headers["Content-Type"] = "application/json"

    timeout_sec = 18.0 if ("/shell" in endpoint or "/screen" in endpoint or "/fs/" in endpoint or "/uninstall" in endpoint or "/snap" in endpoint or "/apk/" in endpoint) else 2.5
    last_error = None
    is_remote_http = bool(HTTP_SERVER_URL and not HTTP_SERVER_URL.startswith(("http://127.", "http://localhost")))

    # 1. Try remote HTTP tunnel first if configured for remote bridge (fast ~150ms round-trip)
    if is_remote_http:
        remote_url = f"{HTTP_SERVER_URL}{endpoint}"
        try:
            req = urllib.request.Request(remote_url, data=data_bytes, headers=headers)
            with urllib.request.urlopen(req, timeout=max(timeout_sec, 25.0)) as resp:
                data = resp.read().decode("utf-8")
                parsed = json.loads(data)
                if isinstance(parsed, dict) and not parsed.get("success", False) and not parsed.get("error"):
                    parsed["error"] = normalize_api_error(parsed, resp.status, resp.reason)
                return parsed
        except urllib.error.HTTPError as e:
            try:
                err_data = e.read().decode("utf-8")
                parsed = json.loads(err_data)
                if endpoint not in ["/api/auth/login", "/api/auth/poll"]:
                    if check_unauthorized_response(parsed):
                        return parsed
                if isinstance(parsed, dict):
                    if not parsed.get("error"):
                        parsed["error"] = normalize_api_error(parsed, e.code, e.reason)
                    return parsed
            except Exception:
                pass
        except Exception as e:
            err_str = str(e)
            if not last_error or ("No address associated with hostname" not in err_str and "Name or service not known" not in err_str):
                last_error = err_str

    # 2. Try local loopback HTTP server on port 8080
    local_url = f"{LOCAL_HTTP_URL}{endpoint}"
    try:
        req = urllib.request.Request(local_url, data=data_bytes, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            data = resp.read().decode("utf-8")
            parsed = json.loads(data)
            if isinstance(parsed, dict) and not parsed.get("success", False) and not parsed.get("error"):
                parsed["error"] = normalize_api_error(parsed, resp.status, resp.reason)
            return parsed
    except urllib.error.HTTPError as e:
        try:
            err_data = e.read().decode("utf-8")
            parsed = json.loads(err_data)
            if endpoint not in ["/api/auth/login", "/api/auth/poll"]:
                if check_unauthorized_response(parsed):
                    return parsed
            if isinstance(parsed, dict):
                if not parsed.get("error"):
                    parsed["error"] = normalize_api_error(parsed, e.code, e.reason)
                return parsed
        except Exception:
            pass
        return {"success": False, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        last_error = str(e)

    # 3. Try WebSocket RPC via ws_relay.py (ws://127.0.0.1:8000/ws or Cloudflare WSS)
    ws_res = ws_rpc_fallback(endpoint, payload)
    if isinstance(ws_res, dict):
        if endpoint not in ["/api/auth/login", "/api/auth/poll"]:
            check_unauthorized_response(ws_res)
        return ws_res

    # 4. Fallback to remote HTTP URL if not already tried above
    if not is_remote_http and HTTP_SERVER_URL and HTTP_SERVER_URL != LOCAL_HTTP_URL:
        remote_url = f"{HTTP_SERVER_URL}{endpoint}"
        try:
            req = urllib.request.Request(remote_url, data=data_bytes, headers=headers)
            with urllib.request.urlopen(req, timeout=max(timeout_sec, 25.0)) as resp:
                data = resp.read().decode("utf-8")
                parsed = json.loads(data)
                if isinstance(parsed, dict) and not parsed.get("success", False) and not parsed.get("error"):
                    parsed["error"] = normalize_api_error(parsed, resp.status, resp.reason)
                return parsed
        except urllib.error.HTTPError as e:
            try:
                err_data = e.read().decode("utf-8")
                parsed = json.loads(err_data)
                if endpoint not in ["/api/auth/login", "/api/auth/poll"]:
                    if check_unauthorized_response(parsed):
                        return parsed
                if isinstance(parsed, dict):
                    if not parsed.get("error"):
                        parsed["error"] = normalize_api_error(parsed, e.code, e.reason)
                    return parsed
            except Exception:
                pass
        except Exception as e:
            err_str = str(e)
            if not last_error or ("No address associated with hostname" not in err_str and "Name or service not known" not in err_str):
                last_error = err_str

    return {"success": False, "error": last_error or "Connection failed to AeroShare bridge (ensure AeroShare is open on phone)"}


def execute_relay_health(as_json=False):
    target = HTTP_SERVER_URL or CLOUDFLARE_TUNNEL_URL
    if not target:
        print("[ERROR] No relay target URL configured.")
        return
    health_url = f"{target.rstrip('/')}/health"
    try:
        req = urllib.request.Request(health_url, headers=get_http_headers())
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = resp.read().decode("utf-8")
            parsed = json.loads(data)
            if as_json:
                print(json.dumps(parsed, indent=2))
                return
            status = parsed.get("status", "UNKNOWN")
            phone_conn = parsed.get("phone_connected", False)
            phone_seen = parsed.get("phone_last_seen_sec", None)
            uptime = parsed.get("uptime_sec", 0)
            print("\n" + "=" * 60)
            print(" 📡 RELAY BRIDGE STATUS")
            print("=" * 60)
            print(f" Relay Server URL  : {target}")
            print(f" Server Status     : {status}")
            print(f" Phone Connected   : {'✅ YES' if phone_conn else '❌ NO (Phone offline)'}")
            if phone_seen is not None:
                print(f" Phone Last Seen   : {phone_seen}s ago")
            print(f" Relay Uptime      : {uptime}s")
            print("=" * 60 + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to reach relay bridge: {e}")


def execute_login(client_name="Termux Bridge", as_json=False):
    global AUTH_TOKEN
    sec_dev_id = f"SEC-DEV-{uuid.uuid4().hex[:8].upper()}"

    payload = {
        "clientName": client_name,
        "securityDeviceId": sec_dev_id,
        "deviceId": sec_dev_id
    }

    res = http_post("/api/auth/login", payload)
    if not res.get("success", False):
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            err_msg = res.get("error", "Unknown error")
            print(f"\n[ERROR] Login request failed: {err_msg}")
            if "lockdown" in str(err_msg).lower():
                print("Hint: Panic Lockdown is active on the phone. Unlock it inside the app UI first.\n")
            else:
                print("Hint: Ensure AeroShare is running on your phone and retry.\n")
        return

    req_id = res.get("requestId", "")
    if as_json and not sys.stdout.isatty():
        pass

    print("\n" + "=" * 68)
    print(" 🔐 AUTHENTICATION REQUIRED: PENDING ON-DEVICE VERIFICATION")
    print("=" * 68)
    print(f" Security Device ID : {sec_dev_id}")
    print(f" Client Name        : {client_name}")
    print(f" Notification       : Sent to Android phone notification drawer!")
    print(f" Status             : Waiting for Face, Fingerprint, or PIN on phone...")
    print("-" * 68)
    print(" 📱 Action Required On Phone:")
    print(" 1. Look at your Android phone screen (or tap the incoming notification).")
    print(" 2. Confirm verification using Face, Fingerprint, or PIN/Pattern.")
    print("=" * 68)
    print(" Polling for verification (press Ctrl+C to cancel)", end="", flush=True)

    start_time = time.time()
    poll_payload = {
        "requestId": req_id,
        "securityDeviceId": sec_dev_id,
        "deviceId": sec_dev_id
    }

    consecutive_consumed_errors = 0
    while time.time() - start_time < 90:
        time.sleep(1.2)
        print(".", end="", flush=True)
        poll_res = http_post("/api/auth/poll", poll_payload)
        if poll_res.get("success", False):
            consecutive_consumed_errors = 0
            status = poll_res.get("status", "")
            if status == "APPROVED":
                token = (poll_res.get("clientToken") or "").strip()
                if not token:
                    print("\n\n[ERROR] Phone approved login but returned an empty token (already consumed). Retrying login...")
                    save_stored_token("")
                    AUTH_TOKEN = ""
                    return
                save_stored_token(token)
                AUTH_TOKEN = token
                verify_res = http_get("/api/security/status")
                if not isinstance(verify_res, dict) or not verify_res.get("success", False):
                    err_detail = verify_res.get("error", "Verification failed") if isinstance(verify_res, dict) else "No response"
                    if err_detail != "UNAUTHORIZED_DEVICE":
                        print(f"\n\n[ERROR] Token received but verification check failed: {err_detail}\n")
                    save_stored_token("")
                    AUTH_TOKEN = ""
                    return
                print("\n\n" + "=" * 68)
                print(" ✅ VERIFIED! ACCESS GRANTED TO TERMUX")
                print("=" * 68)
                print(f" Security Device ID : {sec_dev_id}")
                print(f" Authorized Token   : {token[:16]}... (Saved to ~/.aura_token)")
                print(f" Status             : FULLY AUTHORIZED")
                print("-" * 68)
                print(" You can now execute commands from Termux freely!")
                print(" Example: python send_cmd.py apps")
                print("=" * 68 + "\n")
                return
            elif status == "DENIED":
                save_stored_token("")
                AUTH_TOKEN = ""
                print("\n\n" + "=" * 68)
                print(" ❌ ACCESS DENIED: Verification was rejected or cancelled on phone.")
                print("=" * 68 + "\n")
                return
        elif poll_res.get("error") and "consumed" in str(poll_res.get("error")).lower():
            consecutive_consumed_errors += 1
            if consecutive_consumed_errors >= 3:
                save_stored_token("")
                AUTH_TOKEN = ""
                print(f"\n\n[ERROR] {poll_res.get('error')}\n")
                return

    save_stored_token("")
    AUTH_TOKEN = ""
    print("\n\n[TIMEOUT] Verification timed out after 90 seconds. Try running 'python send_cmd.py login' again.\n")


# ---------------------------------------------------------------------------
# App Listing & Formatting
# ---------------------------------------------------------------------------

def display_apps(apps_list, filter_query="", as_json=False):
    if as_json:
        print(json.dumps(apps_list, indent=2))
        return

    if not apps_list:
        if filter_query:
            print(f"\n[!] No installed applications found matching '{filter_query}'.")
            print("    Try running without a filter: python send_cmd.py apps")
        else:
            print("\n[!] No installed applications found.")
        return

    print("\n" + "=" * 80)
    title = f" INSTALLED APPLICATIONS ({len(apps_list)} found)"
    if filter_query:
        title += f" [Filter: '{filter_query}']"
    print(title)
    print("=" * 80)
    print(f" {'#':<4} {'APP NAME':<28} {'PACKAGE NAME':<34} {'TYPE':<8}")
    print("-" * 80)

    for idx, app in enumerate(apps_list, start=1):
        name = app.get("appName", "Unknown")[:26]
        pkg = app.get("packageName", "")[:33]
        is_sys = app.get("isSystemApp", False)
        app_type = "[System]" if is_sys else "[User]"
        print(f" {idx:<4} {name:<28} {pkg:<34} {app_type:<8}")

    print("=" * 80)
    print("💡 Tip: To launch an app, run:")
    print("   python send_cmd.py open <appName | packageName | url>")
    print("   Example: python send_cmd.py open Termux\n")


# ---------------------------------------------------------------------------
# App List & Launch Execution (HTTP REST Port 8080)
# ---------------------------------------------------------------------------

async def execute_list_apps(include_system=False, filter_query="", as_json=False, force_http=False):
    return run_http_list_apps(include_system, filter_query, as_json)


def run_http_list_apps(include_system=False, filter_query="", as_json=False):
    params = []
    if include_system:
        params.append("includeSystem=true")
    if filter_query:
        params.append(f"filter={urllib.parse.quote(filter_query)}")
    q_str = "?" + "&".join(params) if params else ""

    res = http_get(f"/api/app/list{q_str}")
    if res.get("success", False):
        apps = res.get("apps", [])
        if filter_query and not q_str:
            q = filter_query.lower()
            apps = [a for a in apps if q in a.get("appName", "").lower() or q in a.get("packageName", "").lower()]
        display_apps(apps, filter_query, as_json)
        return True
    else:
        err = res.get("error", "Unknown error")
        if err != "UNAUTHORIZED_DEVICE":
            print(f"[ERROR] Could not fetch apps via HTTP: {err}")
            print("Ensure AeroShare is running on the device (HTTP REST active on port 8080).")
        return False


async def execute_launch_app(target, force_http=False):
    clean_target = target.strip()
    is_url = clean_target.startswith(("http://", "https://", "www."))
    return run_http_launch_app(clean_target, is_url)


def run_http_launch_app(clean_target, is_url):
    payload = {
        "packageName": clean_target if not is_url else None,
        "url": clean_target if is_url else None
    }
    res = http_post("/api/app/launch", payload)
    if res.get("success", False):
        target_name = res.get("target") or clean_target
        print(f"✓ Successfully launched: '{target_name}'")
        return True
    else:
        err = res.get("error", "Target not found or launch failed")
        print(f"✗ Failed to launch '{clean_target}': {err}")
        print("  💡 Run 'python send_cmd.py apps' to view installed applications.")
        return False


# ---------------------------------------------------------------------------
# AeroShare Peer-to-Peer File Transfer & Local Device Discovery
# ---------------------------------------------------------------------------

def execute_devices(as_json=False):
    res = http_get("/api/share/devices")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    if not res.get("success", False):
        print(f"[ERROR] Could not fetch devices: {res.get('error', 'Unknown')}")
        return

    local_name = res.get("localDeviceName", "Android Device")
    local_ip = res.get("localIp", "Unknown")
    is_radar = res.get("isRadarActive", True)
    devices = res.get("devices", [])

    print("\n" + "=" * 80)
    print(f" AEROSHARE LOCAL RADAR & PEER DISCOVERY")
    print(f" Local Device: {local_name} ({local_ip}) | Radar: {'[ON - Scanning]' if is_radar else '[OFF]'}")
    print("=" * 80)
    if not devices:
        print(" [!] No nearby AeroShare peers discovered yet.")
        print("     • Ensure devices are connected to the same Wi-Fi or Hotspot.")
        print("     • You can manually beam to any device IP via: python send_cmd.py share <file> <IP>")
    else:
        print(f" {'#':<4} {'DEVICE NAME':<28} {'IP ADDRESS':<18} {'PORT':<8} {'TYPE':<10} {'SIGNAL':<8}")
        print("-" * 80)
        for idx, dev in enumerate(devices, start=1):
            name = dev.get("name", "Peer")[:26]
            ip = dev.get("ip", "")[:16]
            port = dev.get("port", 8080)
            dtype = dev.get("deviceType", "PHONE")[:8]
            rssi = f"{dev.get('rssi', -50)}dBm"
            print(f" {idx:<4} {name:<28} {ip:<18} {port:<8} {dtype:<10} {rssi:<8}")
    print("=" * 80 + "\n")


def execute_share(target_input, peer_ip="", as_json=False):
    if not target_input:
        print("[ERROR] Please specify a file path or text snippet to share.")
        print("Usage: python send_cmd.py share <filePath | text> [targetDeviceIp]")
        return

    is_file = os.path.exists(target_input) and os.path.isfile(target_input)
    payload = {}
    if is_file:
        payload["filePath"] = os.path.abspath(target_input)
    else:
        payload["text"] = target_input

    if peer_ip:
        payload["ip"] = peer_ip

    res = http_post("/api/share/send", payload)
    if as_json:
        print(json.dumps(res, indent=2))
        return

    if res.get("success", False):
        if is_file:
            print(f"✓ Started AeroShare transfer of '{res.get('fileName')}' ({res.get('sizeBytes', 0)} bytes)")
            print(f"  Transfer ID : {res.get('transferId')}")
            print(f"  Target Peer : {res.get('targetIp')}")
            print("  Run 'python send_cmd.py transfers' to inspect live progress.")
        else:
            print(f"✓ Sent text snippet to {res.get('targetIp')}: \"{res.get('text')}\"")
    else:
        print(f"✗ Failed to initiate transfer: {res.get('error', 'Unknown error')}")


def execute_transfers(as_json=False):
    res = http_get("/api/share/transfers")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    transfers = res.get("transfers", [])
    print("\n" + "=" * 80)
    print(f" AEROSHARE ACTIVE TRANSFERS ({len(transfers)} active)")
    print("=" * 80)
    if not transfers:
        print(" No active transfers currently running.")
    else:
        for tx in transfers:
            fn = tx.get("fileName", "file")
            pct = tx.get("progressPct", 0)
            status = tx.get("status", "TRANSFERRING")
            speed = tx.get("speedBytesPerSec", 0) / (1024 * 1024)
            eta = tx.get("etaSeconds", 0)
            direction = tx.get("direction", "SEND")
            peer = tx.get("peerName", tx.get("peerIp", "Peer"))
            tx_id = tx.get("id", "")
            bar_len = 20
            filled = int(bar_len * pct / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            print(f" [{direction}] {fn} -> {peer}")
            print(f"   [{bar}] {pct}% | {speed:.2f} MB/s | ETA: {eta}s | Status: {status} | ID: {tx_id}")
    print("=" * 80 + "\n")


def execute_history(as_json=False):
    res = http_get("/api/share/history")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    history = res.get("history", [])
    print("\n" + "=" * 80)
    print(f" AEROSHARE TRANSFER HISTORY ({len(history)} items)")
    print("=" * 80)
    if not history:
        print(" No completed transfers recorded.")
    else:
        print(f" {'FILE NAME':<30} {'STATUS':<12} {'DIR':<8} {'PEER':<20}")
        print("-" * 80)
        for item in history[:20]:
            fn = item.get("fileName", "file")[:28]
            status = item.get("status", "DONE")[:10]
            direction = item.get("direction", "SEND")[:6]
            peer = item.get("peerName", "Peer")[:18]
            print(f" {fn:<30} {status:<12} {direction:<8} {peer:<20}")
    print("=" * 80 + "\n")


def execute_cancel(transfer_id):
    if not transfer_id:
        print("[ERROR] Missing transfer ID to cancel.")
        return
    res = http_post("/api/share/cancel", {"id": transfer_id})
    if res.get("success", False):
        print(f"✓ Cancelled transfer: {transfer_id}")
    else:
        print(f"✗ Could not cancel transfer: {transfer_id}")


def execute_clip(text=None, as_json=False):
    if text:
        res = http_post("/api/share/clip", {"text": text})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"✓ Beamed clipboard snippet: \"{text}\"")
    else:
        res = http_get("/api/share/clip")
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            clip_text = res.get("clipboardText", "")
            print(f"Clipboard Content: {clip_text}")


def execute_radar(enable=None, as_json=False):
    payload = {}
    if enable is not None:
        payload["enabled"] = enable
    res = http_post("/api/share/radar", payload)
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        status_str = "ACTIVE (Scanning)" if res.get("isRadarActive", True) else "PAUSED"
        print(f"✓ AeroShare Radar is now: {status_str}")


def execute_battery(as_json=False):
    res = http_get("/api/battery")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    pct = res.get("batteryPct", 0)
    charging = "⚡ Charging" if res.get("isCharging", False) else "Discharging"
    temp = res.get("batteryTempC", 0.0)
    uptime_sec = res.get("uptimeSeconds", 0)
    uptime_str = f"{uptime_sec // 3600}h {(uptime_sec % 3600) // 60}m"
    is_opt = res.get("isIgnoringBatteryOptimizations", False)
    print("\n" + "=" * 55)
    print(" 🔋 DEVICE BATTERY & POWER STATUS")
    print("=" * 55)
    print(f" Level:           {pct}% [{charging}]")
    print(f" Temperature:     {temp}°C")
    print(f" Throttling:      {'Yes ⚠️' if res.get('isThermalThrottling', False) else 'Normal'}")
    print(f" Background Mode: {'✓ UNRESTRICTED (Exempt from Doze)' if is_opt else '⚠️ OPTIMIZED (Restricted in Doze)'}")
    print(f" Uptime:          {uptime_str}")
    print("=" * 55 + "\n")


def execute_location(as_json=False):
    res = http_get("/api/location")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    print("\n" + "=" * 68)
    print(" 📍 DEVICE GPS & LOCATION TELEMETRY")
    print("=" * 68)
    if res.get("success", False):
        lat = res.get("latitude", 0.0)
        lon = res.get("longitude", 0.0)
        acc = res.get("accuracy", 0.0)
        alt = res.get("altitude", 0.0)
        spd = res.get("speed", 0.0)
        spd_kmh = res.get("speedKmh", spd * 3.6)
        spd_mph = res.get("speedMph", spd * 2.23694)
        bearing = res.get("bearing", 0.0)
        compass = res.get("bearingCompass", "")
        prov = res.get("provider", "GPS")
        is_live = res.get("isLiveTracking", False)
        up_cnt = res.get("updateCount", 0)
        maps_url = res.get("mapsUrl", f"https://maps.google.com/?q={lat},{lon}")

        print(f" Status           : {'🟢 LIVE REALTIME STREAMING (1s Active)' if is_live else '🔵 Fixed Snapshot'}")
        print(f" Latitude         : {lat:.6f}")
        print(f" Longitude        : {lon:.6f}")
        print(f" Coordinates      : {lat:.6f}, {lon:.6f}")
        print(f" Accuracy         : ±{acc:.1f} meters")
        print(f" Speed            : {spd_kmh:.1f} km/h ({spd_mph:.1f} mph | {spd:.2f} m/s)")
        if compass:
            print(f" Heading/Bearing  : {compass} ({bearing:.0f}°)")
        print(f" Altitude         : {alt:.1f} meters")
        print(f" Provider         : {prov.upper()}")
        if up_cnt > 0:
            print(f" Fix Counter      : Update #{up_cnt}")
        print(f" Google Maps URL  : {maps_url}")
        print("-" * 68)
        print(" 💡 Tip: For continuous real-time live GPS streaming, run:")
        print("    python send_cmd.py location --live")
    else:
        print(f" [!] {res.get('error', 'Location unavailable')}")
        print(" 💡 Tip: Ensure Location is enabled on the phone and AeroShare has Location permission.")
    print("=" * 68 + "\n")


def execute_live_location(interval_sec=1.0, as_json=False):
    # Activate live location tracking on phone
    start_res = http_post("/api/location/live", {"action": "START", "intervalMs": int(interval_sec * 1000)})
    if not start_res.get("success", False):
        err = start_res.get("error", "Unknown error")
        print(f"\n[ERROR] Could not start live GPS tracking: {err}")
        print("Ensure Location is enabled in phone settings and AeroShare has Location permission.\n")
        return

    print("\n" + "=" * 80)
    print(" 🛰️  REAL-TIME GPS TELEMETRY STREAM (Continuous 1-Second Updates)")
    print("=" * 80)
    print(f" Provider : High-Accuracy Fused GPS + Network Provider")
    print(f" Interval : {interval_sec}s updates")
    print(f" Controls : Press Ctrl+C at any time to stop streaming")
    print("-" * 80)
    print(f" {'TIME':<10} {'FIX#':<7} {'LATITUDE':<12} {'LONGITUDE':<12} {'ACCURACY':<10} {'SPEED':<14} {'HEADING':<10}")
    print("-" * 80)

    try:
        last_count = -1
        while True:
            res = http_get("/api/location")
            if as_json:
                print(json.dumps(res))
            elif res.get("success", False) and res.get("hasCoordinates", False):
                now_str = time.strftime("%H:%M:%S")
                fix_num = res.get("updateCount", 0)
                lat = res.get("latitude", 0.0)
                lon = res.get("longitude", 0.0)
                acc = res.get("accuracy", 0.0)
                spd_kmh = res.get("speedKmh", res.get("speed", 0.0) * 3.6)
                bearing = res.get("bearing", 0.0)
                compass = res.get("bearingCompass", "")
                head_str = f"{compass} {int(bearing)}°" if compass else f"{int(bearing)}°"

                prefix = "🟢" if fix_num != last_count else "  "
                print(f" {prefix} {now_str:<8} #{fix_num:<5} {lat:<12.6f} {lon:<12.6f} ±{acc:<7.1f}m {spd_kmh:<7.1f} km/h {head_str:<10}")
                last_count = fix_num
            else:
                now_str = time.strftime("%H:%M:%S")
                msg = res.get("statusMessage", res.get("error", "Acquiring GPS fix..."))
                print(f"    {now_str:<8} [ACQUIRING] {msg}")

            time.sleep(interval_sec)
    except KeyboardInterrupt:
        print("\n\n" + "-" * 80)
        print(" ⏹️  Stopping live GPS telemetry on device...")
        http_post("/api/location/live", {"action": "STOP"})
        print(" ✓ Live GPS stream stopped. Device returned to standby.")
        print("=" * 80 + "\n")


def execute_battery_opt(action="STATUS", as_json=False):
    res = http_post("/api/battery/optimization", {"action": action.upper()})
    if as_json:
        print(json.dumps(res, indent=2))
        return
    status = res.get("status", "OPTIMIZED")
    print("\n" + "=" * 60)
    print(f" ⚡ BATTERY OPTIMIZATION & BACKGROUND EXECUTION: [{status}]")
    print("=" * 60)
    if status == "UNRESTRICTED":
        print(" ✓ App is UNRESTRICTED. Background transfers & radar run uninterrupted.")
    else:
        print(" ⚠️ App is OPTIMIZED. Android Doze may pause background transfers.")
        print(f" 💡 {res.get('hint', '')}")
    if res.get("actionRequested", False):
        print(" ✓ System authorization intent dispatched to phone screen.")
    print("=" * 60 + "\n")


def execute_sensors(as_json=False):
    res = http_get("/api/sensors")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    print("\n" + "=" * 60)
    print(" 📡 LIVE HARDWARE SENSORS SNAPSHOT")
    print("=" * 60)
    if "ambientLightLux" in res:
        print(f" Ambient Light:    {res['ambientLightLux']:.1f} lux")
    if "proximityCm" in res:
        is_near = " (NEAR)" if res.get("isNear", False) else " (FAR)"
        print(f" Proximity:        {res['proximityCm']:.1f} cm{is_near}")
    if "compassHeadingDegrees" in res:
        cardinal = res.get("compassCardinal", "")
        print(f" Compass:          {res['compassHeadingDegrees']:.1f}° ({cardinal})")
    if "pressureHpa" in res:
        print(f" Barometer:        {res['pressureHpa']:.1f} hPa")
    if "stepCount" in res:
        print(f" Step Counter:     {int(res['stepCount'])} steps")
    if "accelerometer" in res:
        acc = res["accelerometer"]
        print(f" Accelerometer:    X={acc.get('x', 0):.2f}, Y={acc.get('y', 0):.2f}, Z={acc.get('z', 0):.2f} m/s²")
    if "gyroscope" in res:
        gyro = res["gyroscope"]
        print(f" Gyroscope:        X={gyro.get('x', 0):.2f}, Y={gyro.get('y', 0):.2f}, Z={gyro.get('z', 0):.2f} rad/s")
    print("=" * 60 + "\n")


def execute_torch(enable=True, as_json=False):
    res = http_post("/api/torch", {"enabled": enable})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        state_str = "ON 🔦" if enable else "OFF"
        print(f"✓ Camera Torch set to: {state_str}")


def execute_vibrate(duration_ms=200, preset=None, as_json=False):
    payload = {"durationMs": duration_ms}
    if preset:
        payload["preset"] = preset
    res = http_post("/api/vibrate", payload)
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"✓ Triggered haptic vibration ({duration_ms}ms)")


def execute_tts(text, pitch=1.0, rate=1.0, as_json=False):
    if not text:
        print("[ERROR] Missing text to speak.")
        return
    res = http_post("/api/tts", {"text": text, "pitch": pitch, "rate": rate})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"✓ Spoke aloud: \"{text}\"")


def execute_volume(level=None, stream="MEDIA", as_json=False):
    if level is not None:
        try:
            vol_int = int(level)
            res = http_post("/api/volume", {"stream": stream.upper(), "volume": vol_int})
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                print(f"✓ Set {stream.upper()} volume to: {vol_int}")
        except ValueError:
            print(f"[ERROR] Invalid volume level: {level}")
    else:
        res = http_get("/api/volume")
        if as_json:
            print(json.dumps(res, indent=2))
            return
        print("\n" + "=" * 50)
        print(" 🔊 AUDIO STREAMS & VOLUME STATUS")
        print("=" * 50)
        print(f" Ringer Mode: {res.get('ringerMode', 'NORMAL')}")
        print("-" * 50)
        for s in res.get("streams", []):
            st = s.get("stream", "STREAM")
            cur = s.get("volume", 0)
            max_v = s.get("max", 15)
            pct = s.get("percentage", 0)
            print(f" {st:<16} {cur:>2}/{max_v:<2} ({pct}%)")
        print("=" * 50 + "\n")


def execute_tone(freq_hz=440, duration_ms=500, as_json=False):
    res = http_post("/api/audio/tone", {"frequency": freq_hz, "durationMs": duration_ms})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"✓ Played audio tone ({freq_hz} Hz for {duration_ms}ms)")


def execute_hud(text, title="⚡ Termux HUD", as_json=False):
    res = http_post("/api/floating", {"title": title, "text": text, "type": "HUD", "isDraggable": True})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        if res.get("displayedAsToast", False):
            print(f"✓ HUD displayed as Toast (overlay permission pending): \"{text}\"")
        else:
            print(f"✓ Floating HUD displayed: \"{text}\"")


def execute_notify(title, message, as_json=False):
    res = http_post("/api/notification", {"title": title, "message": message})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"✓ System notification posted: [{title}] {message}")


def execute_media(action="PLAY_PAUSE", as_json=False):
    res = http_post("/api/media/control", {"command": action})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"✓ Media action '{action.upper()}' dispatched")


def execute_storage(folder="DOWNLOADS", limit=30, as_json=False):
    res = http_post("/api/storage/files", {"folder": folder, "limit": limit})
    if as_json:
        print(json.dumps(res, indent=2))
        return
    files = res.get("files", [])
    directory = res.get("directory", folder)
    print("\n" + "=" * 80)
    print(f" 📁 STORAGE FILE EXPLORER: {directory} ({len(files)} files)")
    print("=" * 80)
    print(f" {'#':<4} {'NAME':<38} {'SIZE':<12} {'TYPE':<8}")
    print("-" * 80)
    for idx, f in enumerate(files, start=1):
        name = f.get("name", "")[:36]
        sz_bytes = f.get("sizeBytes", 0)
        is_dir = f.get("isDirectory", False)
        if is_dir:
            sz_str = "<DIR>"
            ftype = "[DIR]"
        else:
            if sz_bytes > 1024 * 1024:
                sz_str = f"{sz_bytes / (1024 * 1024):.1f} MB"
            elif sz_bytes > 1024:
                sz_str = f"{sz_bytes / 1024:.1f} KB"
            else:
                sz_str = f"{sz_bytes} B"
            ftype = "[FILE]"
        print(f" {idx:<4} {name:<38} {sz_str:<12} {ftype:<8}")
    print("=" * 80)
    print("💡 Tip: Share any file instantly:")
    print("   python send_cmd.py share <filePath>\n")


def execute_sms(phone, message="", as_json=False):
    if not phone:
        print("[ERROR] Missing phone number.")
        return
    res = http_post("/api/sms/compose", {"phone": phone, "message": message})
    if as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"✓ SMS Composer opened for: {phone}")


def execute_shell(cmd_str, timeout_ms=15000, cwd=None, as_json=False):
    if not cmd_str:
        print("[ERROR] Missing shell command.")
        print("Usage: python send_cmd.py shell <command>")
        return
    payload = {"cmd": cmd_str, "timeout_ms": timeout_ms}
    if cwd:
        payload["cwd"] = cwd
    res = http_post("/api/shell/exec", payload)
    if as_json:
        print(json.dumps(res, indent=2))
        return
    exit_code = res.get("exit_code", -1)
    dur = res.get("duration_ms", 0)
    stdout = res.get("stdout", "")
    stderr = res.get("stderr", "")
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if stderr:
        print(stderr, file=sys.stderr, end="" if stderr.endswith("\n") else "\n")
    if not res.get("success", False) and not stdout and not stderr:
        print(f"[ERROR] Shell execution failed: {res.get('error', 'Unknown error')}")
    else:
        print(f"[exit={exit_code} | {dur}ms]")


def execute_screenshot(out_path="screenshot.jpg", quality=80, as_json=False):
    res = http_post("/api/screen/capture", {"quality": quality, "maxDimension": 1440})
    if as_json:
        print(json.dumps(res, indent=2))
        return
    if res.get("success", False) and res.get("base64"):
        import base64
        raw_bytes = base64.b64decode(res["base64"])
        with open(out_path, "wb") as f:
            f.write(raw_bytes)
        w = res.get("width", 0)
        h = res.get("height", 0)
        print(f"✓ Screenshot saved to '{out_path}' ({w}x{h}, {len(raw_bytes) // 1024} KB)")
    else:
        print(f"✗ Screenshot failed: {res.get('error', 'Unknown error')}")


def execute_system_toggle(target, state="toggle", extra=None, as_json=False):
    payload = {"target": target, "state": state}
    if extra:
        payload.update(extra)
    res = http_post("/api/system/toggle", payload)
    if as_json:
        print(json.dumps(res, indent=2))
        return
    if res.get("success", False):
        print(f"✓ System toggle '{target}' -> {json.dumps({k: v for k, v in res.items() if k not in ['success', 'target']})}")
    else:
        print(f"✗ System toggle '{target}' failed: {res.get('error', 'Unknown error')}")


def execute_system_status(as_json=False):
    res = http_get("/api/system/status")
    if as_json:
        print(json.dumps(res, indent=2))
        return
    if not res.get("success", False):
        print(f"[ERROR] {res.get('error', 'Failed to fetch system status')}")
        return
    print("\n" + "=" * 60)
    print(" 📱 AEROSHARE SYSTEM & BRIDGE STATUS")
    print("=" * 60)
    print(f" Flashlight (Torch) : {'ON 🔦' if res.get('torchEnabled') else 'OFF'}")
    print(f" Do Not Disturb     : {'ACTIVE 🔕' if res.get('dndEnabled') else 'NORMAL'}")
    print(f" Wi-Fi              : {'ENABLED' if res.get('wifiEnabled') else 'DISABLED'} ({res.get('wifiSsid') or 'No SSID'})")
    print(f" Local IPv4         : {res.get('localIp', '127.0.0.1')}")
    print(f" Bluetooth          : {'ENABLED' if res.get('bluetoothEnabled') else 'DISABLED'}")
    print(f" Media Volume       : {res.get('mediaVolume', 0)}/{res.get('mediaMaxVolume', 15)} [{res.get('ringerMode', 'NORMAL')}]")
    print(f" Screen Brightness  : {res.get('brightness', 0)}/255")
    print(f" UI Accessibility   : {'READY ✓' if res.get('accessibilityEnabled') else 'DISABLED ⚠️'}")
    print(f" Clipboard Preview  : {res.get('clipboardPreview', '')[:50]}")
    print("=" * 60 + "\n")


def execute_fs_op(op, path="", extra=None, as_json=False):
    payload = {"path": path}
    if extra:
        payload.update(extra)
    res = http_post(f"/api/fs/{op}", payload)
    if as_json:
        print(json.dumps(res, indent=2))
        return res
    if not res.get("success", False):
        print(f"✗ File '{op}' failed: {res.get('error', 'Unknown error')}")
        return res
    if op == "list":
        files = res.get("files", [])
        print(f"\n📁 Directory: {res.get('path')} ({len(files)} entries)")
        print("-" * 72)
        for item in files:
            marker = "[DIR] " if item.get("isDirectory") else "[FILE]"
            sz = item.get("sizeBytes", 0)
            sz_str = "<DIR>" if item.get("isDirectory") else f"{sz} B"
            print(f" {marker} {item.get('name', ''):<42} {sz_str:>12}")
        print("-" * 72 + "\n")
    elif op == "read":
        if res.get("encoding") == "base64":
            print(f"[Binary file: {res.get('sizeBytes', 0)} bytes, base64 encoded]")
        else:
            content = res.get("content", "")
            print(content, end="" if content.endswith("\n") else "\n")
    elif op == "write":
        print(f"✓ Wrote {res.get('writtenBytes', 0)} bytes to {res.get('path')}")
    elif op == "delete":
        print(f"✓ Deleted {res.get('path')}")
    elif op == "stat":
        print(json.dumps(res, indent=2))
    return res


def execute_ui_http(action, payload, as_json=False):
    body = {"action": action}
    body.update(payload)
    res = http_post("/api/ui/action", body)
    if as_json:
        print(json.dumps(res, indent=2))
    elif res.get("success", False):
        print(f"✓ UI action '{action}' succeeded")
    else:
        print(f"✗ UI action '{action}' failed: {res.get('error', 'Unknown error')}")
    return res


# ---------------------------------------------------------------------------
# Hardware Stations & Interactive Permissions Hub
# ---------------------------------------------------------------------------

def execute_permissions(subcmd="list", target=None, as_json=False):
    subcmd = (subcmd or "list").lower()
    if subcmd in ["list", "status", "overview", "ls"]:
        res = http_get("/api/permissions")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        perms = res.get("permissions", [])
        print("\n" + "=" * 80)
        print(f" 🛡️ ANDROID PERMISSIONS & HARDWARE STATIONS OVERVIEW ({len(perms)} monitored)")
        print("=" * 80)
        print(f" {'#':<3} {'ID':<20} {'NAME':<18} {'STATUS':<12} {'PERMISSION'}")
        print("-" * 80)
        for idx, p in enumerate(perms, start=1):
            pid = p.get("id", "")
            pname = p.get("name", "")
            granted = p.get("isGranted", False)
            status_str = "✅ GRANTED" if granted else "❌ DENIED"
            perm_str = p.get("permission", "").replace("android.permission.", "")
            print(f" {idx:<3} {pid:<20} {pname:<18} {status_str:<12} {perm_str}")
        print("=" * 80)
        print("💡 Tip: Request permission or open settings:")
        print("   python send_cmd.py permissions request <camera|mic|notif|storage|location>")
        print("   python send_cmd.py permissions settings <camera|mic|notif|storage|location>\n")
        return res

    elif subcmd in ["request", "ask", "grant", "prompt"]:
        if not target:
            print("[ERROR] Missing target permission.")
            print("Usage: python send_cmd.py permissions request <camera|mic|notif|storage|location>")
            return
        res = http_post("/api/permissions/request", {"idOrName": target, "openSettings": False})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"✓ Requested '{target}' permission on device! Alert dispatched to phone screen.")
        return res

    elif subcmd in ["settings", "open", "config"]:
        target = target or "app"
        res = http_post("/api/permissions/request", {"idOrName": target, "openSettings": True})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"✓ Opened Android Settings for '{target}' on device display.")
        return res

    else:
        print(f"[ERROR] Unknown permissions subcommand: '{subcmd}'. Available: list, request, settings")


def execute_camera(subcmd="status", as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info", "details"]:
        res = http_get("/api/camera/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        granted = res.get("isGranted", False)
        status_str = "✅ GRANTED" if granted else "❌ DENIED"
        cameras = res.get("cameras", [])
        print("\n" + "=" * 70)
        print(" 📸 CAMERA HARDWARE STATION")
        print("=" * 70)
        print(f" Permission Status  : {status_str}")
        print(f" Total Cameras      : {res.get('cameraCount', len(cameras))}")
        print(f" Back Facing        : {res.get('backCameras', 0)}")
        print(f" Front Facing       : {res.get('frontCameras', 0)}")
        print(f" Flash Available    : {'YES' if res.get('hasFlash') else 'NO'}")
        if cameras:
            print("-" * 70)
            print(f" {'ID':<6} {'FACING':<12} {'FLASH':<10}")
            for c in cameras:
                print(f" {c.get('id', ''):<6} {c.get('facing', ''):<12} {'YES' if c.get('hasFlash') else 'NO':<10}")
        print("=" * 70)
        print("💡 Tip: Test or manage camera:")
        print("   python send_cmd.py camera test      # Launch camera capture on phone")
        print("   python send_cmd.py camera perm      # Trigger on-screen permission prompt")
        print("   python send_cmd.py camera settings  # Open camera settings\n")
        return res

    elif subcmd in ["test", "capture", "shot", "snap"]:
        res = http_post("/api/camera/test", {})
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            print("✓ Camera capture activity launched successfully on device!")
        else:
            print(f"✗ Camera test failed: {res.get('error', 'Camera not accessible')}")
        return res

    elif subcmd in ["perm", "request", "grant"]:
        return execute_permissions("request", "camera", as_json=as_json)

    elif subcmd in ["settings", "open"]:
        return execute_permissions("settings", "camera", as_json=as_json)

    else:
        print(f"[ERROR] Unknown camera subcommand: '{subcmd}'. Available: status, test, perm, settings")


def execute_mic(subcmd="status", duration_sec=3, as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info", "details"]:
        res = http_get("/api/mic/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        granted = res.get("isGranted", False)
        status_str = "✅ GRANTED" if granted else "❌ DENIED"
        has_hw = res.get("hasMicrophoneHardware", True)
        is_muted = res.get("isMicrophoneMuted", False)
        sample_rate = res.get("sampleRateHz", "44100")
        print("\n" + "=" * 70)
        print(" 🎙️ MICROPHONE HARDWARE STATION")
        print("=" * 70)
        print(f" Permission Status  : {status_str}")
        print(f" Hardware Available : {'YES' if has_hw else 'NO'}")
        print(f" Microphone Muted   : {'YES' if is_muted else 'NO'}")
        print(f" Output Sample Rate : {sample_rate} Hz")
        print("=" * 70)
        print("💡 Tip: Record audio or manage mic:")
        print("   python send_cmd.py mic --live       # Real-time continuous audio recording & live VU meter")
        print("   python send_cmd.py mic test [sec]   # Record test audio clip (default 3s)")
        print("   python send_cmd.py mic play <file>  # Play back audio file on device")
        print("   python send_cmd.py mic perm         # Trigger on-screen permission prompt")
        print("   python send_cmd.py mic settings     # Open microphone settings\n")
        return res

    elif subcmd in ["live", "--live", "-l", "stream", "record-live", "realtime", "start"]:
        return execute_live_mic(as_json=as_json)

    elif subcmd in ["stop", "unrecord", "finish"]:
        res = http_post("/api/mic/live/stop", {})
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            print(f"✓ Real-time recording stopped: {res.get('filePath')}")
        else:
            print(f"✗ Failed to stop recording: {res.get('error', 'No active recording')}")
        return res

    elif subcmd in ["play", "listen"]:
        path = target_arg or ""
        res = http_post("/api/mic/play", {"filePath": path})
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            print(f"✓ Playing audio on phone: {path}")
        else:
            print(f"✗ Playback failed: {res.get('error', 'Could not play audio')}")
        return res

    elif subcmd in ["test", "record", "rec", "sample"]:
        print(f"🎙️ Recording {duration_sec}s audio sample on device...")
        res = http_post("/api/audio/test_record", {"durationSec": duration_sec})
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            print("\n" + "=" * 70)
            print(" 🎙️ MICROPHONE TEST RECORDING COMPLETE")
            print("=" * 70)
            print(f" Duration        : {res.get('durationSec', duration_sec)}s")
            print(f" Sample Rate     : {res.get('sampleRate', 44100)} Hz")
            print(f" Channels        : {res.get('channels', 1)}")
            print(f" Peak Amplitude  : {res.get('maxAmplitude', 0)}")
            print(f" Total Bytes     : {res.get('sizeBytes', 0):,} bytes")
            print("=" * 70 + "\n")
        else:
            print(f"✗ Microphone recording failed: {res.get('error', 'Microphone not accessible')}")
        return res

    elif subcmd in ["perm", "request", "grant"]:
        return execute_permissions("request", "record_audio", as_json=as_json)

    elif subcmd in ["settings", "open"]:
        return execute_permissions("settings", "record_audio", as_json=as_json)

    else:
        print(f"[ERROR] Unknown mic subcommand: '{subcmd}'. Available: --live, test, stop, play, perm, settings")


def execute_live_mic(as_json=False):
    res = http_post("/api/mic/live/start", {})
    if as_json:
        print(json.dumps(res, indent=2))
        return res
    if not res.get("success", False):
        print(f"✗ Failed to start real-time recording: {res.get('error', 'Microphone error')}")
        return res

    file_path = res.get("filePath", "")
    print("\n" + "=" * 76)
    print(" 🎙️ REAL-TIME LIVE AUDIO RECORDING STARTED")
    print("=" * 76)
    print(f" Target File   : {file_path}")
    print(" Live VU Meter : Streaming audio telemetry (Press Ctrl+C to stop & save)...")
    print("-" * 76)

    try:
        while True:
            time.sleep(0.12)
            st = http_get("/api/mic/live/status")
            if not st.get("isRecording", False):
                break
            dur_ms = st.get("durationMs", 0)
            sec = dur_ms // 1000
            min_part = sec // 60
            sec_part = sec % 60
            tenth = (dur_ms % 1000) // 100
            time_str = f"{min_part:02d}:{sec_part:02d}.{tenth}"

            bytes_rec = st.get("bytesRecorded", 0)
            kb_str = f"{bytes_rec / 1024.0:.1f} KB"
            rms = int(st.get("rms", 0))
            db = st.get("decibels", -60.0)

            norm_db = max(0.0, min(60.0, db + 60.0))
            bar_len = int((norm_db / 60.0) * 20)
            meter_bar = "█" * bar_len + "░" * (20 - bar_len)

            sys.stdout.write(f"\r 🔴 [{time_str}] | {kb_str:>9} | RMS:{rms:>5} | {db:>5.1f} dB [{meter_bar}] ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        print("\n\nStopping real-time recording and finalizing WAV audio header...")
        stop_res = http_post("/api/mic/live/stop", {})
        if as_json:
            print(json.dumps(stop_res, indent=2))
        elif stop_res.get("success", False):
            print("\n" + "=" * 76)
            print(" ✅ REAL-TIME AUDIO RECORDING SAVED")
            print("=" * 76)
            print(f" Duration       : {stop_res.get('durationSec', 0)}s ({stop_res.get('durationMs', 0)} ms)")
            print(f" Total Size     : {stop_res.get('sizeBytes', 0) / 1024.0:.1f} KB")
            print(f" Sample Rate    : {stop_res.get('sampleRate', 44100)} Hz")
            print(f" Saved File     : {stop_res.get('filePath', file_path)}")
            print("=" * 76)
            print("💡 Tip: Play back recording on phone:")
            print(f"   python send_cmd.py mic play \"{stop_res.get('filePath', file_path)}\"\n")
        else:
            print(f"✗ Failed to stop recording: {stop_res.get('error', 'Unknown error')}")


def execute_notif(subcmd="status", text=None, as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info", "details"]:
        res = http_get("/api/notif/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        granted = res.get("isGranted", False)
        status_str = "✅ GRANTED" if granted else "❌ DENIED"
        are_enabled = res.get("areNotificationsEnabled", False)
        can_dnd = res.get("canBypassDnd", False)
        channels = res.get("channels", [])
        print("\n" + "=" * 70)
        print(" 🔔 NOTIFICATIONS HARDWARE STATION")
        print("=" * 70)
        print(f" Permission Status  : {status_str}")
        print(f" System Enabled     : {'YES' if are_enabled else 'NO'}")
        print(f" Can Bypass DND     : {'YES' if can_dnd else 'NO'}")
        print(f" Active Channels    : {res.get('channelCount', len(channels))}")
        if channels:
            print("-" * 70)
            print(f" {'ID':<28} {'NAME':<24} {'IMPORTANCE'}")
            for ch in channels:
                print(f" {ch.get('id', ''):<28} {ch.get('name', ''):<24} {ch.get('importance', '')}")
        print("=" * 70)
        print("💡 Tip: Test notifications:")
        print("   python send_cmd.py notif test [msg] # Send test notification to phone")
        print("   python send_cmd.py notif perm       # Trigger on-screen permission prompt")
        print("   python send_cmd.py notif settings   # Open notification settings\n")
        return res

    elif subcmd in ["test", "send", "alert", "dispatch"]:
        msg = text or "Hardware station test notification from Termux CLI!"
        res = http_post("/api/notif/test", {"title": "🔔 Hardware Station Test", "message": msg})
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            print(f"✓ Dispatched high-priority test notification to phone: '{msg}'")
        else:
            print(f"✗ Failed to dispatch notification: {res.get('error', 'Notification dispatch error')}")
        return res

    elif subcmd in ["perm", "request", "grant"]:
        return execute_permissions("request", "post_notifications", as_json=as_json)

    elif subcmd in ["settings", "open"]:
        return execute_permissions("settings", "post_notifications", as_json=as_json)

    else:
        print(f"[ERROR] Unknown notif subcommand: '{subcmd}'. Available: status, test, perm, settings")


def execute_storage_station(subcmd="status", as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info", "details"]:
        res = http_get("/api/storage/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        granted = res.get("isGranted", False)
        status_str = "✅ GRANTED" if granted else "❌ DENIED"
        media_img = res.get("mediaImagesGranted", False)
        all_files = res.get("allFilesAccessGranted", False)
        total_gb = res.get("totalSpaceGb", "0.0")
        free_gb = res.get("freeSpaceGb", "0.0")
        used_gb = res.get("usedSpaceGb", "0.0")
        used_pct = res.get("usedPercent", 0)
        pics_cnt = res.get("picturesCount", 0)
        dls_cnt = res.get("downloadsCount", 0)
        print("\n" + "=" * 70)
        print(" 💾 STORAGE & MEDIA HARDWARE STATION")
        print("=" * 70)
        print(f" Permission Status  : {status_str}")
        print(f" Media Images Access: {'YES' if media_img else 'NO'}")
        print(f" All Files Access   : {'YES' if all_files else 'NO'}")
        print(f" Total Capacity     : {total_gb} GB")
        print(f" Used Space         : {used_gb} GB ({used_pct}% used)")
        print(f" Free Available     : {free_gb} GB")
        print(f" Indexed Pictures   : {pics_cnt}")
        print(f" Indexed Downloads  : {dls_cnt}")
        print("=" * 70)
        print("💡 Tip: Storage actions:")
        print("   python send_cmd.py storage test     # Run storage access check")
        print("   python send_cmd.py storage files    # Browse storage files")
        print("   python send_cmd.py storage perm     # Trigger on-screen permission prompt")
        print("   python send_cmd.py storage settings # Open storage settings\n")
        return res

    elif subcmd in ["test", "check", "bench"]:
        res = http_post("/api/storage/test", {})
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            print("\n" + "=" * 70)
            print(" 💾 STORAGE ACCESS TEST: PASSED")
            print("=" * 70)
            print(f" Total Space    : {res.get('totalSpaceGb', '0.0')} GB")
            print(f" Free Space     : {res.get('freeSpaceGb', '0.0')} GB")
            print(f" Test Status    : {res.get('testStatus', 'ACCESSIBLE')}")
            print("=" * 70 + "\n")
        else:
            print(f"✗ Storage test failed: {res.get('error', 'Storage not accessible')}")
        return res

    elif subcmd in ["perm", "request", "grant"]:
        return execute_permissions("request", "storage", as_json=as_json)

    elif subcmd in ["settings", "open"]:
        return execute_permissions("settings", "storage", as_json=as_json)

    else:
        print(f"[ERROR] Unknown storage subcommand: '{subcmd}'. Available: status, test, perm, settings")


def execute_api_help(as_json=False):
    res = http_get("/api/help")
    if as_json:
        print(json.dumps(res, indent=2))
        return res
    if not res.get("success", False):
        print(f"[ERROR] Could not fetch API help: {res.get('error', 'Unknown error')}")
        return res

    print("\n" + "=" * 80)
    print(" 📖 AERO HARDWARE BRIDGE API DOCUMENTATION & DIRECTORY (/api/help)")
    print("=" * 80)
    print(f" Service     : {res.get('service', 'Aero Hardware Bridge API')}")
    print(f" Port        : {res.get('port', 8080)}")
    print(f" Auth Header : {res.get('authHeader', 'X-API-Key or Bearer')}")
    print("-" * 80)
    print(" 🛠️ HARDWARE STATIONS SUITE:")
    stations = res.get("hardwareStations", {})
    for st_name, st_info in stations.items():
        print(f"\n  [{st_name.upper()}]")
        for k, v in st_info.items():
            print(f"    • {k:<22}: {v}")
    print("-" * 80)
    print(" 📡 AVAILABLE ENDPOINTS:")
    endpoints = res.get("availableEndpoints", [])
    for ep in endpoints:
        print(f"    {ep}")
    print("=" * 80 + "\n")
    return res


def execute_battery_station(subcmd="status", as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info"]:
        res = http_get("/api/battery/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        pct = res.get("percent", 100)
        charging = res.get("isCharging", False)
        status = res.get("status", "UNKNOWN")
        plug = res.get("plugType", "NONE")
        health = res.get("health", "GOOD")
        temp = res.get("temperatureC", 25.0)
        volt = res.get("voltageMv", 0)
        doze = res.get("isIgnoringBatteryOptimizations", False)
        print("\n" + "=" * 70)
        print(" 🔋 BATTERY HARDWARE STATION")
        print("=" * 70)
        print(f" Level          : {pct}% {'⚡ (Charging)' if charging else ''}")
        print(f" Status         : {status} via {plug}")
        print(f" Health         : {health}")
        print(f" Temperature    : {temp} °C")
        print(f" Voltage        : {volt} mV")
        print(f" Doze Exemption : {'ACTIVE (Unrestricted)' if doze else 'Optimized'}")
        print("=" * 70 + "\n")
        return res
    elif subcmd in ["opt", "optimization", "doze", "exempt"]:
        res = http_post("/api/battery/optimization", {"action": "REQUEST"})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Battery Optimization Request: {res.get('status', 'OK')}")
        return res
    else:
        print(f"[ERROR] Unknown battery subcommand: '{subcmd}'. Available: status, doze")


def execute_sensors_station(as_json=False):
    res = http_get("/api/sensors/status")
    if as_json:
        print(json.dumps(res, indent=2))
        return res
    accel = res.get("accelerometer", {})
    gyro = res.get("gyroscope", {})
    mag = res.get("magnetometer", {})
    count = res.get("sensorCount", 0)
    lux = res.get("lightLux", 0.0)
    prox = res.get("proximityCm", 5.0)
    print("\n" + "=" * 70)
    print(f" 🧭 SENSORS HARDWARE STATION ({count} Sensors Registered)")
    print("=" * 70)
    print(f" Accelerometer  : X={accel.get('x', 0):.2f}, Y={accel.get('y', 0):.2f}, Z={accel.get('z', 9.8):.2f} m/s²")
    print(f" Gyroscope      : X={gyro.get('x', 0):.2f}, Y={gyro.get('y', 0):.2f}, Z={gyro.get('z', 0):.2f} rad/s")
    print(f" Ambient Light  : {lux:.1f} Lux")
    print(f" Proximity      : {prox:.1f} cm")
    print(f" Magnetometer   : X={mag.get('x', 0):.1f}, Y={mag.get('y', 0):.1f}, Z={mag.get('z', 0):.1f} µT")
    print("=" * 70 + "\n")
    return res


def execute_display_station(subcmd="status", val=None, as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info"]:
        res = http_get("/api/display/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        w = res.get("widthPixels", 1080)
        h = res.get("heightPixels", 2400)
        hz = res.get("refreshRateHz", 60.0)
        b = res.get("currentBrightness", 128)
        auto = res.get("isAutoBrightness", False)
        timeout = res.get("screenTimeoutSec", 60)
        wl = res.get("isWakeLockHeld", False)
        can_write = res.get("canWriteSystemSettings", False)
        print("\n" + "=" * 70)
        print(" 🖥️ DISPLAY HARDWARE STATION")
        print("=" * 70)
        print(f" Resolution     : {w}x{h} @ {hz} Hz")
        print(f" Brightness     : {b} / 255 (Auto={'ON' if auto else 'OFF'})")
        print(f" Screen Timeout : {timeout} seconds")
        print(f" WakeLock Held  : {'YES (Screen Awake)' if wl else 'NO'}")
        print(f" WRITE_SETTINGS : {'GRANTED' if can_write else 'REQUIRED'}")
        print("=" * 70 + "\n")
        return res
    elif subcmd in ["brightness", "bright", "set-brightness"]:
        level = int(val) if val and val.isdigit() else 128
        res = http_post("/api/display/brightness", {"brightness": level})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Display brightness set to {level}: {'OK' if res.get('success') else res.get('error')}")
        return res
    elif subcmd in ["auto", "auto-brightness"]:
        enabled = val.lower() in ["true", "1", "on", "yes"] if val else True
        res = http_post("/api/display/auto_brightness", {"enabled": enabled})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Auto brightness: {'ENABLED' if enabled else 'DISABLED'}")
        return res
    elif subcmd in ["timeout", "screen-timeout"]:
        sec = int(val) if val and val.isdigit() else 60
        res = http_post("/api/display/timeout", {"seconds": sec})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Screen timeout set to {sec}s: {'OK' if res.get('success') else res.get('error')}")
        return res
    elif subcmd in ["wakelock", "wake"]:
        enable = val.lower() in ["true", "1", "on", "yes"] if val else True
        res = http_post("/api/display/wakelock", {"enable": enable})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Screen WakeLock: {'ACTIVE' if enable else 'RELEASED'}")
        return res
    else:
        print(f"[ERROR] Unknown display subcommand: '{subcmd}'. Available: status, brightness <0-255>, auto <on|off>, timeout <sec>, wakelock <on|off>")


def execute_network_station(as_json=False):
    res = http_get("/api/network/status")
    if as_json:
        print(json.dumps(res, indent=2))
        return res
    transport = res.get("activeTransport", "OFFLINE")
    connected = res.get("isConnected", False)
    metered = res.get("isMetered", False)
    wifi = res.get("wifi")
    cell = res.get("cellular")
    ips = res.get("localIpv4Addresses", [])
    print("\n" + "=" * 70)
    print(" 🌐 NETWORK HARDWARE STATION")
    print("=" * 70)
    print(f" Transport      : {transport} ({'CONNECTED' if connected else 'OFFLINE'})")
    print(f" Metered        : {'YES' if metered else 'NO (Unlimited)'}")
    if wifi:
        print(f" Wi-Fi SSID     : {wifi.get('ssid')} (BSSID: {wifi.get('bssid')})")
        print(f" Wi-Fi Signal   : {wifi.get('rssiDbm')} dBm • {wifi.get('linkSpeedMbps')} Mbps • {wifi.get('wifiStandard')}")
    if cell:
        print(f" Cellular       : {cell.get('carrierName')} ({cell.get('networkType')}) • Roaming={cell.get('isRoaming')}")
    if ips:
        print(" Local IPv4     : " + ", ".join(ips))
    print("=" * 70 + "\n")
    return res


def execute_audio_station(subcmd="status", param1=None, param2=None, as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info"]:
        res = http_get("/api/audio/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        ringer = res.get("ringerMode", "NORMAL")
        music = res.get("isMusicActive", False)
        streams = res.get("streams", [])
        rt = res.get("realtimeRecording", {})
        print("\n" + "=" * 70)
        print(" 🔊 AUDIO & MIXER HARDWARE STATION")
        print("=" * 70)
        print(f" Ringer Mode    : {ringer}")
        print(f" Music Active   : {'YES' if music else 'NO'}")
        if streams:
            print("\n Volume Streams:")
            for s in streams:
                print(f"   • {s.get('stream', 'STREAM'):<12}: {s.get('percentage', 0):>3}% (Level: {s.get('current')}/{s.get('max')})")
        if rt and rt.get("isRecording", False):
            print(f"\n 🔴 Real-time Recording: ACTIVE (Duration: {rt.get('durationMs', 0)} ms)")
        print("=" * 70 + "\n")
        return res
    elif subcmd in ["volume", "vol"]:
        stream = param1.upper() if param1 else "MEDIA"
        pct = int(param2) if param2 and param2.isdigit() else 50
        res = http_post("/api/audio/volume", {"stream": stream, "percent": pct})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Set {stream} volume to {pct}%: {'OK' if res.get('success') else res.get('error')}")
        return res
    elif subcmd in ["ringer", "ringer-mode", "mode"]:
        mode = param1.upper() if param1 else "NORMAL"
        res = http_post("/api/audio/ringer_mode", {"mode": mode})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Set ringer mode to {mode}: {'OK' if res.get('success') else res.get('error')}")
        return res
    elif subcmd in ["record-live", "stream-start", "live-start"]:
        res = http_post("/api/audio/realtime/start", {})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Live Recording Started: {res.get('filePath') or res.get('message') or 'OK'}")
        return res
    elif subcmd in ["stop-live", "stream-stop", "live-stop"]:
        res = http_post("/api/audio/realtime/stop", {})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Live Recording Stopped: {res.get('filePath')} ({res.get('durationSec')}s, {res.get('sizeBytes')} bytes)")
        return res
    elif subcmd in ["status-live", "live-status"]:
        res = http_get("/api/audio/realtime/status")
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Recording: {'YES' if res.get('isRecording') else 'NO'} • Duration: {res.get('durationSec', 0)}s • RMS: {res.get('rms', 0)} • dB: {res.get('decibels', -60)}")
        return res
    elif subcmd in ["play", "play-file"]:
        path = param1 or ""
        res = http_post("/api/audio/play_file", {"filePath": path})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"Play Audio File: {'OK' if res.get('success') else res.get('error')}")
        return res
    else:
        print(f"[ERROR] Unknown audio subcommand: '{subcmd}'. Available: status, volume <stream> <0-100>, ringer <NORMAL|VIBRATE|SILENT>, record-live, stop-live, status-live, play <path>")


def execute_network_moderation(subcmd="status", target=None, extra=None, as_json=False):
    subcmd = (subcmd or "status").lower()
    if subcmd in ["status", "info"]:
        res = http_get("/api/network/moderation/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        vpn = res.get("isVpnActive", False)
        tot = res.get("totalIntercepted", 0)
        blk = res.get("totalBlocked", 0)
        d_cnt = res.get("blacklistedDomainsCount", 0)
        ip_cnt = res.get("blacklistedIpsCount", 0)
        last_t = res.get("lastBlockedTarget", "")
        print("\n" + "=" * 75)
        print(" 🛡️ NETWORK MODERATION & DNS FILTER STATUS")
        print("=" * 75)
        print(f" VPN DNS Filter     : {'🟢 ACTIVE (Filtering queries)' if vpn else '⚪ INACTIVE (Pass-through)'}")
        print(f" Total Intercepted  : {tot}")
        print(f" Total Blocked      : {blk}")
        print(f" Blacklisted Domains: {d_cnt}")
        print(f" Blacklisted IPs    : {ip_cnt}")
        pdns_mode = res.get("privateDnsMode", "opportunistic")
        pdns_spec = res.get("privateDnsSpecifier", "")
        pdns_fam = res.get("privateDnsFamilyProtected", False)
        pdns_label = f"{pdns_mode} ({pdns_spec})" if pdns_spec else pdns_mode
        print(f" OS Private DNS     : {pdns_label} {'[🛡️ FAMILY PROTECTED]' if pdns_fam else ''}")
        if last_t:
            print(f" Last Blocked Target: {last_t}")
        print("=" * 75)
        print("Commands: block <domain|ip>, unblock <domain|ip>, list, logs, dns <family|adguard-family|auto|off>, start, stop\n")
        return res

    elif subcmd in ["block", "add"]:
        if not target:
            print("[ERROR] Missing domain, URL, or IP to block.")
            print("Usage: python send_cmd.py block-site <domain_or_url> [domain2 ...]")
            print("   or: python send_cmd.py net-filter block <domain_or_ip>")
            return
        targets = [t.strip() for t in str(target).replace(",", " ").split() if t.strip()]
        last_res = None
        # Ensure VPN DNS filter is active so DNS + Browser URL guard enforce immediately
        http_post("/api/network/moderation/service", {"action": "start"})
        for tgt in targets:
            is_ip = tgt.replace(".", "").isdigit() and tgt.count(".") == 3
            payload = {"ip": tgt} if is_ip else {"domain": tgt}
            res = http_post("/api/network/moderation/block", payload)
            last_res = res
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                dom_clean = res.get("domain") or res.get("ip") or tgt
                comps = res.get("companionDomainsBlocked", [])
                comp_str = f" (+ companion CDNs: {', '.join(comps)})" if comps else ""
                print(f"🚫 Blocked site/target '{dom_clean}': {res.get('action', 'OK')}{comp_str} [Total blocked: {res.get('totalBlacklistedDomains', 0)}]")
        return last_res

    elif subcmd in ["unblock", "remove", "del", "rm", "clear"]:
        if not target:
            print("[ERROR] Missing domain or IP to unblock (or pass 'all' to clear all custom blocked sites).")
            print("Usage: python send_cmd.py unblock-site <domain_or_url | all>")
            return
        targets = [t.strip() for t in str(target).replace(",", " ").split() if t.strip()]
        last_res = None
        for tgt in targets:
            is_ip = tgt.replace(".", "").isdigit() and tgt.count(".") == 3
            payload = {"ip": tgt} if is_ip else {"domain": tgt}
            res = http_post("/api/network/moderation/unblock", payload)
            last_res = res
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                dom_clean = res.get("domain") or res.get("ip") or tgt
                print(f"✓ Unblocked site/target '{dom_clean}': {res.get('action', 'OK')} [Total blocked: {res.get('totalBlacklistedDomains', 0)}]")
        return last_res

    elif subcmd in ["list", "rules", "blacklist"]:
        res = http_get("/api/network/moderation/rules")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        domains = res.get("domains", [])
        auto_learned = res.get("autoLearnedDomains", {}) or {}
        ips = res.get("ips", [])
        enabled_cats = res.get("enabledCategories", [])
        cat_domains_map = res.get("enabledCategoryDomains", {})
        blocked_apps = res.get("blockedApps", [])
        eff_total = res.get("effectiveTotalBlockedDomains", len(domains))

        print("\n" + "=" * 78)
        print(f" 🚫 BLOCKED SITES, CATEGORIES & APPS (Effective Blocked Domains: {eff_total})")
        print("=" * 78)
        print(f"Custom & Auto-Learned Blacklisted Domains ({len(domains)}):")
        if domains:
            for d in domains:
                auto_tag = auto_learned.get(d, "")
                badge = f"  🤖 [{auto_tag}]" if auto_tag else ""
                print(f"  • {d}{badge}")
        else:
            print("  (None added yet — use: python send_cmd.py block-site <domain>)")

        print(f"\nEnabled Category Presets ({len(enabled_cats)}):")
        if enabled_cats:
            for cat in enabled_cats:
                c_doms = cat_domains_map.get(cat, [])
                if c_doms:
                    preview = ", ".join(c_doms[:6]) + (f" ... (+{len(c_doms) - 6} more)" if len(c_doms) > 6 else "")
                    print(f"  • [{cat:<8}] ({len(c_doms):>2} domains): {preview}")
                else:
                    print(f"  • [{cat}]")
        else:
            print("  (No categories enabled)")

        if blocked_apps:
            print(f"\nBlocked Apps — App Firewall ({len(blocked_apps)}):")
            for app_pkg in blocked_apps:
                print(f"  • 🚫 {app_pkg}")

        print(f"\nBlacklisted IPs ({len(ips)}):")
        for ip in ips:
            print(f"  • {ip}")
        print("=" * 75 + "\n")
        return res

    elif subcmd in ["logs", "audit", "events"]:
        limit = int(target) if target and target.isdigit() else 30
        res = http_get(f"/api/network/moderation/logs?limit={limit}")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        logs = res.get("logs", [])
        print("\n" + "=" * 80)
        print(f" 📜 NETWORK AUDIT & BLOCK LOGS (Last {len(logs)} Events)")
        print("=" * 80)
        for lg in logs:
            action = lg.get("action", "ALLOWED")
            action_tag = "🔴 BLOCKED" if action == "BLOCKED" else "🟢 ALLOWED"
            print(f" {action_tag} | {lg.get('domain', 'N/A'):<32} | {lg.get('reason', '')}")
        print("=" * 80 + "\n")
        return res

    elif subcmd in ["start", "enable", "on"]:
        res = http_post("/api/network/moderation/service", {"action": "start"})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success"):
            print("\n" + "=" * 76)
            print(f" 🛡️ AERO NETWORK MODERATOR & DNS FIREWALL: {res.get('action', 'STARTED')}")
            print("=" * 76)
            print(f" Status  : 🟢 ACTIVE")
            print(f" Message : {res.get('message', 'Aero Network Moderator VPN & DNS Firewall started.')}")
            print("=" * 76 + "\n")
        else:
            print(f"✗ Aero Network Moderator VPN failed: {res.get('error')}")
        return res

    elif subcmd in ["stop", "disable", "off"]:
        res = http_post("/api/network/moderation/service", {"action": "stop"})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("✓ Aero Network Moderator VPN & DNS Firewall: STOPPED")
        return res

    elif subcmd in ["category", "categories", "cat"]:
        cat_action = (target or "list").lower()
        if cat_action in ["list", "status", "ls"]:
            res = http_get("/api/network/moderation/categories")
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            print("\n" + "=" * 75)
            print(" 🗂️ DNS CATEGORY BLOCKLIST PRESETS")
            print("=" * 75)
            for c in res.get("categories", []):
                st = "🟢 ENABLED " if c.get("enabled") else "⚪ DISABLED"
                print(f" {st} | {c.get('category', ''):<10} | {c.get('domainCount', 0):>3} domains | {c.get('blockedHits', 0)} blocked hits")
            print("=" * 75)
            print("Usage: python send_cmd.py net-filter category <enable|disable> <ADS|TRACKERS|MALWARE|ADULT|SOCIAL|GAMBLING>\n")
            return res
        elif cat_action in ["enable", "on", "disable", "off"] and extra:
            en = cat_action in ["enable", "on"]
            if en:
                http_post("/api/network/moderation/service", {"action": "start"})
            res = http_post("/api/network/moderation/category", {"category": extra.upper(), "enabled": en})
            if as_json:
                print(json.dumps(res, indent=2))
            elif res.get("success"):
                print(f"🛡️ Category '{extra.upper()}' -> {'ENABLED' if en else 'DISABLED'} (Effective blocked domains: {res.get('effectiveTotalBlockedDomains')})")
                pdns_auto = res.get("privateDnsAutoUpdate")
                if pdns_auto:
                    method = pdns_auto.get("methodUsed", "NONE")
                    host = pdns_auto.get("targetHostname", "")
                    if pdns_auto.get("appliedDirectly"):
                        print(f"🔒 System Private DNS auto-updated -> {host} ({method}) [Active even if VPN is OFF]")
                    elif pdns_auto.get("uiAutomationDispatched"):
                        print(f"🤖 Dispatched Accessibility UI automation to set System Private DNS -> {host}")
            else:
                print(f"[ERROR] {res.get('error')}")
            return res
        else:
            print("Usage: python send_cmd.py net-filter category [list | enable <CAT> | disable <CAT>]")
            return

    elif subcmd in ["inspect", "inspect-site", "check-site", "metadata", "scan-site"]:
        if not target:
            print("[ERROR] Missing domain or URL to inspect.")
            print("Usage: python send_cmd.py inspect-site <domain_or_url>")
            return
        res = http_post("/api/network/moderation/inspect-site", {"target": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        is_adult = res.get("isAdult", False)
        score = res.get("confidenceScore", 0)
        trig = res.get("triggerSource", "CLEAN")
        title = res.get("pageTitle") or "(None)"
        desc = res.get("metaDescription") or "(None)"
        kws = res.get("metaKeywords") or "(None)"
        rta = res.get("rtaRating") or "(None)"
        fam_dns = res.get("familyDnsBlocked", False)
        indicators = res.get("matchedIndicators", []) or []

        print("\n" + "=" * 80)
        print(f" 🔍 SITE METADATA & ADULT CONTENT CLASSIFIER: {res.get('domain', target)}")
        print("=" * 80)
        print(f" Verdict            : {'🚫 ADULT / RESTRICTED (AUTO-BLACKLISTED)' if is_adult else '🟢 CLEAN / SAFE'}")
        print(f" Confidence Score   : {score}/100 (Trigger: {trig})")
        print(f" Root Domain        : {res.get('rootDomain', '')}")
        print(f" Family DNS 1.1.1.3 : {'🚫 SINKHOLED (0.0.0.0)' if fam_dns else '🟢 Allowed'}")
        print(f" RTA Adult Meta Tag : {rta}")
        print(f" HTML <title>       : {title}")
        print(f" <meta description> : {desc}")
        print(f" <meta keywords>    : {kws}")
        if indicators:
            print("-" * 80)
            print(" Matched Detection Indicators:")
            for ind in indicators:
                print(f"   • {ind}")
        print("=" * 80 + "\n")
        return res

    elif subcmd in ["analytics", "stats", "top", "frequency"]:
        top_n = int(target) if target and target.isdigit() else 20
        res = http_get(f"/api/network/moderation/analytics?top={top_n}")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("\n" + "=" * 78)
        print(" 📊 PER-DOMAIN QUERY FREQUENCY & TRAFFIC ANALYTICS")
        print("=" * 78)
        print(f" Total Queries : {res.get('totalQueries', 0)}  |  Blocked: {res.get('totalBlocked', 0)} ({res.get('blockRatePercent', 0.0)}%)  |  Unique Domains: {res.get('uniqueDomainsQueried', 0)}")
        print("-" * 78)
        print(" Top Queried Domains:")
        for item in res.get("topQueriedDomains", [])[:10]:
            st_icon = "🔴" if item.get("status") == "BLOCKED" else "🟢"
            print(f"   {st_icon} {item.get('domain', ''):<36} | Queries: {item.get('queries', 0):<5} | Blocked: {item.get('blocked', 0)}")
        print("-" * 78)
        print(" Top Blocked Domains:")
        for item in res.get("topBlockedDomains", [])[:10]:
            print(f"   🚫 {item.get('domain', ''):<36} | Blocked Hits: {item.get('blockedCount', 0)}")
        print("=" * 78 + "\n")
        return res

    elif subcmd in ["dns", "private-dns", "dns-protect", "auto-dns", "system-dns"]:
        preset = (target or "status").strip()
        res = http_post("/api/network/moderation/private-dns", {"preset": preset})
        if not res.get("success") and "Unknown API endpoint" in str(res.get("error", "")):
            # Backward-compatibility fallback to category route if running prior APK build
            if preset.lower() in ["status", "get", "info"]:
                res = http_get("/api/network/moderation/categories")
            else:
                res = http_post("/api/network/moderation/category", {"category": f"DNS:{preset.upper()}", "enabled": True})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if not res.get("success"):
            print(f"[ERROR] Could not reach AeroShare DNS engine: {res.get('error', 'Unknown error')}")
            print("Tip: If Android Private DNS was set to a hostname blocked by your ISP, open Settings -> Private DNS -> Automatic, or open the AeroShare app once (it will auto-heal).")
            return res
        if preset.lower() in ["status", "get", "info"]:
            mode = res.get("mode", "smart-engine")
            spec = res.get("specifier") or res.get("upstreamResolvers") or "(Automatic)"
            fam = res.get("isFamilyProtected", False)
            adblk = res.get("isAdBlockProtected", False)
            vpn_on = res.get("isVpnActive", False)
            acc_on = res.get("accessibilityGuardActive", False)
            tot_blk = res.get("effectiveTotalBlockedDomains", 0)
            print("\n" + "=" * 78)
            print(" 🛡️ SMART DNS & BROWSER METADATA GUARD STATUS")
            print("=" * 78)
            print(f" Active DNS Engine Mode   : {mode}")
            print(f" Upstream DNS Resolvers   : {spec}")
            print(f" Family Adult Filter      : {'🟢 ACTIVE (1.1.1.3 + 94.140.14.15 + Metadata)' if fam else '⚪ INACTIVE'}")
            print(f" AdGuard Ad/Tracker Filter: {'🟢 ACTIVE' if adblk else '⚪ INACTIVE'}")
            print(f" Local DNS Firewall VPN   : {'🟢 ACTIVE (Auto-Started)' if vpn_on else '⚪ OFF (Using Browser URL + 1.1.1.3 Guard)'}")
            print(f" Live Browser URL Guard   : {'🟢 ACTIVE (1.1.1.3 + HTML Metadata Scanner)' if acc_on else '⚪ INACTIVE'}")
            print(f" Effective Blocked Domains: {tot_blk}")
            print("-" * 78)
            print(" Available Presets:")
            for k, desc in (res.get("availablePresets") or {}).items():
                print(f"   • {k:<15} : {desc}")
            print("=" * 78)
            print("Usage: python send_cmd.py dns-protect <family | adguard-family | adguard | security | auto | off>\n")
        else:
            print(f"🛡️ Smart DNS Protection -> {res.get('presetDescription', preset)}")
            print(f"   Active Mode / DNS  : {res.get('targetMode')} / {res.get('targetHostname') or '(Auto)'}")
            print(f"   Engine Method      : {res.get('methodUsed')}")
            print(f"   Effective Blocked  : {res.get('effectiveTotalBlockedDomains', 0)} domains (Categories: {', '.join(res.get('enabledCategories', []))})")
        return res

    elif subcmd in ["export", "dump", "save-logs", "export-logs"]:
        fmt = (extra or target or "csv").strip().lower()
        if fmt.startswith("--format="):
            fmt = fmt.split("=", 1)[1].strip().lower()
        elif fmt in ["--json", "-j"]:
            fmt = "json"
        elif fmt in ["--csv", "-c"]:
            fmt = "csv"
        clean_fmt = "json" if "json" in fmt else "csv"
        res = http_post("/api/network/moderation/export", {"format": clean_fmt, "includeAllowed": True, "limit": 2000})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success"):
            print("\n" + "=" * 78)
            print(" 📁 DNS & NETWORK AUDIT LOG EXPORT")
            print("=" * 78)
            print(f" Format         : {res.get('format', clean_fmt).upper()}")
            print(f" Total Exported : {res.get('exportedCount', 0)} log entries")
            print(f" File Name      : {res.get('fileName')}")
            print(f" Saved Path     : {res.get('filePath')}")
            print(f" File Size      : {res.get('fileSizeBytes', 0)} bytes")
            print("-" * 78)
            print(" Preview (first few lines):")
            for line in res.get("preview", "").splitlines()[:8]:
                print(f"   {line}")
            print("=" * 78 + "\n")
        else:
            print(f"[ERROR] Failed to export DNS logs: {res.get('error')}")
        return res

    elif subcmd in ["block-screen", "overlay-block", "blockscreen", "warning-screen"]:
        action = (target or "").strip().lower()
        if action in ["on", "enable", "1", "true"]:
            res = http_post("/api/network/moderation/block-screen", {"enabled": True})
        elif action in ["off", "disable", "0", "false"]:
            res = http_post("/api/network/moderation/block-screen", {"enabled": False})
        elif action in ["test", "trigger", "preview", "show", "pop"]:
            dom = extra or "restricted-site.com"
            res = http_post("/api/network/moderation/block-screen", {"test": True, "domain": dom})
            if not res or not res.get("previewTriggered"):
                q_res = http_get(f"/api/network/moderation/block-screen?test=true&domain={urllib.parse.quote(dom)}")
                if q_res and isinstance(q_res, dict):
                    res = q_res
        elif action in ["hide", "close", "clear", "dismiss-now"]:
            res = http_post("/api/network/moderation/block-screen", {"hide": True})
        elif action in ["msg", "message", "text"] and extra:
            clean_msg = extra.strip()
            res = http_post("/api/network/moderation/block-screen", {"message": clean_msg, "test": True})
            if not res or (res.get("customMessage") or "").strip() != clean_msg:
                q_res = http_get(f"/api/network/moderation/block-screen?message={urllib.parse.quote(clean_msg)}&test=true")
                if q_res and isinstance(q_res, dict):
                    res = q_res
        elif action in ["dismiss", "sec", "timer"] and extra and extra.isdigit():
            res = http_post("/api/network/moderation/block-screen", {"autoDismissSeconds": int(extra)})
        elif target and target not in ["status", "info", "get", ""]:
            # If user ran: python send_cmd.py block-screen "Restricted content is not allowed" directly
            msg_text = f"{target} {extra}".strip() if extra else target.strip()
            res = http_post("/api/network/moderation/block-screen", {"message": msg_text, "test": True})
            if not res or (res.get("customMessage") or "").strip() != msg_text:
                q_res = http_get(f"/api/network/moderation/block-screen?message={urllib.parse.quote(msg_text)}&test=true")
                if q_res and isinstance(q_res, dict):
                    res = q_res
        else:
            res = http_get("/api/network/moderation/block-screen")
        if as_json:
            print(json.dumps(res, indent=2))
            return res

        if not res or (isinstance(res, dict) and not res.get("success", True) and res.get("error")):
            err_msg = res.get("error") if isinstance(res, dict) else "No response from AeroShare server"
            print("\n" + "=" * 78)
            print(" ❌ RESTRICTED SITE BLOCK SCREEN: ACTION FAILED")
            print("=" * 78)
            print(f" Error   : {err_msg}")
            if isinstance(res, dict) and (res.get("error") == "UNAUTHORIZED_DEVICE" or res.get("action") == "AUTHENTICATION_REQUIRED"):
                print(" Reason  : Device authorization required.")
                print(" Fix     : Run 'python send_cmd.py login' in Termux to approve on phone.")
            print("=" * 78 + "\n")
            return res

        print("\n" + "=" * 78)
        print(" 🛡️ VISUAL RESTRICTED SITE BLOCK SCREEN CONFIG & STATUS")
        print("=" * 78)
        en = res.get("enabled", True)
        msg_disp = res.get("customMessage") or "Restricted content is not allowed on this device"
        has_overlay_perm = res.get("hasOverlayPermission", True)
        print(f" Block Screen Status  : {'🟢 ENABLED' if en else '⚪ DISABLED'}")
        print(f" Warning Message      : {msg_disp}")
        print(f" Auto-Dismiss Timer   : {res.get('autoDismissSeconds', 6)}s (0 = stays until tapped)")
        print(f" Foreground Activity  : 🟢 Active (BlockScreenActivity pops up on top)")
        print(f" Overlay Permission   : {'🟢 Granted' if has_overlay_perm else '⚠️ Not Granted (Settings -> Display over other apps)'}")
        if res.get("previewTriggered") or action in ["test", "trigger", "preview", "show", "pop", "msg", "message", "text"]:
            print(" Visual Warning State : 🚀 POPPED UP ON PHONE SCREEN (BlockScreenActivity Active)!")
        print("=" * 78)
        print("Commands:")
        print("   python send_cmd.py block-screen test             # Pop up block screen immediately on phone")
        print("   python send_cmd.py block-screen msg <text>       # Set custom warning message & preview on phone")
        print("   python send_cmd.py block-screen hide             # Dismiss active overlay")
        print("   python send_cmd.py block-screen [on | off]       # Enable / disable visual block overlay")
        print("   python send_cmd.py block-screen dismiss <sec>    # Set auto-dismiss countdown timer\n")
        return res

    else:
        print(f"[ERROR] Unknown net-filter subcommand: '{subcmd}'. Available: status, block, unblock, list, logs, category, inspect, dns, export, block-screen, analytics, start, stop")


def execute_network_speed(live=False, as_json=False):
    if not live:
        res = http_get("/api/network/speed")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("\n" + "=" * 72)
        print(" 🚀 LIVE NETWORK BANDWIDTH & DATA USAGE SPEED METER")
        print("=" * 72)
        print(f" Download Speed : {res.get('downloadKBps', 0.0)} KB/s ({res.get('downloadMbps', 0.0)} Mbps)")
        print(f" Upload Speed   : {res.get('uploadKBps', 0.0)} KB/s ({res.get('uploadMbps', 0.0)} Mbps)")
        print(f" Total Boot Rx  : {res.get('totalBootRxMB', 0.0)} MB  (Wi-Fi: {res.get('wifiRxMB', 0.0)} MB | Mobile: {res.get('mobileRxMB', 0.0)} MB)")
        print(f" Total Boot Tx  : {res.get('totalBootTxMB', 0.0)} MB  (Wi-Fi: {res.get('wifiTxMB', 0.0)} MB | Mobile: {res.get('mobileTxMB', 0.0)} MB)")
        print(f" Packets Rx/Tx  : {res.get('totalRxPackets', 0)} Rx / {res.get('totalTxPackets', 0)} Tx")
        print("=" * 72 + "\n")
        return res
    else:
        print("🚀 Streaming Live Bandwidth Speed Meter (Ctrl+C to stop)...")
        try:
            while True:
                res = http_get("/api/network/speed")
                if as_json:
                    print(json.dumps(res))
                else:
                    dl_kb = res.get("downloadKBps", 0.0)
                    ul_kb = res.get("uploadKBps", 0.0)
                    rx_mb = res.get("totalBootRxMB", 0.0)
                    tx_mb = res.get("totalBootTxMB", 0.0)
                    sys.stdout.write(f"\r ⬇️  DL: {dl_kb:>7.1f} KB/s  |  ⬆️  UL: {ul_kb:>7.1f} KB/s  |  Total Rx: {rx_mb} MB / Tx: {tx_mb} MB   ")
                    sys.stdout.flush()
                time.sleep(0.8)
        except KeyboardInterrupt:
            print("\n[✓] Stopped live bandwidth speed stream.")


def execute_network_diag(subcmd="ping", target=None, extra=None, as_json=False):
    subcmd = (subcmd or "ping").lower()
    if subcmd == "ping":
        host = target or "8.8.8.8"
        cnt = int(extra) if extra and extra.isdigit() else 3
        res = http_post("/api/network/diag/ping", {"host": host, "count": cnt})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("\n" + "=" * 72)
        print(f" 📡 PING DIAGNOSTIC: {host} ({cnt} packets)")
        print("=" * 72)
        print(f" Status  : {'🟢 REACHABLE' if res.get('success') else '🔴 UNREACHABLE'}")
        print(f" Latency : min={res.get('minRttMs', -1)} ms | avg={res.get('avgRttMs', -1)} ms | max={res.get('maxRttMs', -1)} ms")
        if res.get("rawOutput"):
            print("-" * 72)
            print(res.get("rawOutput"))
        print("=" * 72 + "\n")
        return res
    elif subcmd in ["dns", "nslookup", "resolve"]:
        domain = target or "google.com"
        res = http_post("/api/network/diag/dns", {"domain": domain})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("\n" + "=" * 72)
        print(f" 🔍 DNS LOOKUP & MODERATION VERDICT: {domain}")
        print("=" * 72)
        print(f" Lookup Time       : {res.get('lookupTimeMs', 0)} ms")
        print(f" Moderation Policy : {'🔴 BLOCKED (' + str(res.get('moderationVerdict')) + ')' if res.get('blockedByModerationPolicy') else '🟢 ALLOWED'}")
        print(f" IPv4 Records      : {', '.join(res.get('ipv4Addresses', [])) or 'None'}")
        print(f" IPv6 Records      : {', '.join(res.get('ipv6Addresses', [])) or 'None'}")
        print("=" * 72 + "\n")
        return res
    elif subcmd in ["port", "tcp", "port-check"]:
        host = target or "127.0.0.1"
        port = int(extra) if extra and extra.isdigit() else 80
        res = http_post("/api/network/diag/port", {"host": host, "port": port})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        is_open = res.get("open", False)
        print(f"\n🔌 TCP PORT CHECK {host}:{port} -> {'🟢 OPEN' if is_open else '🔴 CLOSED'} (RTT: {res.get('connectRttMs', 0)} ms)")
        if not is_open and res.get("reason"):
            print(f"   Reason: {res.get('reason')}")
        print()
        return res
    else:
        print(f"[ERROR] Unknown net-diag subcommand '{subcmd}'. Available: ping <host>, dns <domain>, port <host> <port>")


def _render_all_apps_network_table(res):
    apps = res.get("apps", []) or []
    fg_app = res.get("foregroundAppName") or res.get("foregroundPackage") or "None"
    vpn_on = res.get("isVpnFirewallActive", False)
    blocked_cnt = res.get("blockedAppsCount", 0)
    print("\n" + "=" * 96)
    print(f" 🌐 PER-APP LIVE INTERNET TRAFFIC & DOMAIN MONITOR ({len(apps)} active apps)")
    print("=" * 96)
    print(f" Foreground App : {fg_app:<30} | VPN DNS Inspector: {'🟢 ACTIVE' if vpn_on else '⚪ STANDBY (Run: net-filter start)'}")
    print(f" Net-Blocked    : {blocked_cnt} app(s)")
    print("-" * 96)
    print(f" {'APP NAME':<20} {'STATUS':<11} {'⬇️ DL KB/s':>10} {'⬆️ UL KB/s':>10} {'TOTAL RX/TX':>15} {'SOCK':>5}  {'LATEST DOMAIN / URL'}")
    print("-" * 96)
    if not apps:
        print(" No per-app network traffic recorded yet.")
    for a in apps[:22]:
        aname = (a.get("appName") or a.get("packageName") or "")[:19]
        if a.get("isForeground"):
            aname = ("*" + aname)[:19]
        st = "🚫 BLOCKED" if a.get("isNetworkBlocked") else "🟢 ONLINE "
        dl = a.get("downloadKBps", 0.0)
        ul = a.get("uploadKBps", 0.0)
        rx = a.get("totalRxMB", 0.0)
        tx = a.get("totalTxMB", 0.0)
        tot_str = f"{rx:.1f}/{tx:.1f}M"
        socks = a.get("activeSocketsCount", 0)
        dom = (a.get("latestDomainOrUrl") or "-")[:26]
        print(f" {aname:<20} {st:<11} {dl:>10.1f} {ul:>10.1f} {tot_str:>15} {socks:>5}  {dom}")
    print("=" * 96)
    print("💡 Inspect specific app : python send_cmd.py net-app <appName|pkg> [--live]")
    print("💡 Block app internet   : python send_cmd.py net-app block <appName|pkg>")
    print("💡 Live browsing stream : python send_cmd.py browsing --live\n")


def _render_single_app_network_panel(res):
    aname = res.get("appName", "")
    pkg = res.get("packageName", "")
    uid = res.get("uid", -1)
    is_blk = res.get("isNetworkBlocked", False)
    is_fg = res.get("isForeground", False)
    dl = res.get("downloadKBps", 0.0)
    ul = res.get("uploadKBps", 0.0)
    rx_mb = res.get("totalRxMB", 0.0)
    tx_mb = res.get("totalTxMB", 0.0)
    rx_pkts = res.get("rxPackets", 0)
    tx_pkts = res.get("txPackets", 0)
    active_url = res.get("activeBrowserUrl", "")
    conns = res.get("activeConnections", []) or []
    doms = res.get("visitedDomains", []) or []

    print("\n" + "=" * 88)
    print(f" 📡 APP INTERNET TRAFFIC & LIVE BROWSING INSPECTOR: {aname} ({pkg})")
    print("=" * 88)
    print(f" UID & State      : UID {uid}  |  {'🟢 IN FOREGROUND' if is_fg else '⚫ BACKGROUND'}  |  Firewall: {'🚫 INTERNET BLOCKED' if is_blk else '🟢 INTERNET ALLOWED'}")
    print(f" Live Speed       : ⬇️  DL: {dl:>7.1f} KB/s   |   ⬆️  UL: {ul:>7.1f} KB/s")
    print(f" Total Data Used  : Rx: {rx_mb} MB ({rx_pkts} pkts)  |  Tx: {tx_mb} MB ({tx_pkts} pkts)")
    if active_url:
        print(f" Active Tab / URL : 🌐 {active_url}")

    print("-" * 88)
    print(f" 🔌 ACTIVE SOCKET CONNECTIONS & REMOTE IPs ({len(conns)} active):")
    if not conns:
        print("   No active open sockets detected for this app right now.")
    else:
        for c in conns[:12]:
            proto = c.get("protocol", "TCP")
            rem_ep = c.get("remoteEndpoint", "")
            svc = c.get("remoteService", "")
            st = c.get("state", "")
            rdom = c.get("resolvedDomain", "")
            dom_tag = f" -> {rdom}" if rdom else ""
            print(f"   • [{proto:<4}] {rem_ep:<22} ({svc:<16}) [{st}]{dom_tag}")

    print("-" * 88)
    print(f" 🌍 VISITED DOMAINS & BROWSING URLS ({len(doms)} recent):")
    if not doms:
        print("   No domains/URLs captured for this app yet. (Start VPN via 'net-filter start' or open browser)")
    else:
        for d in doms[:15]:
            act = d.get("action", "ALLOWED")
            icon = "🚫" if act == "BLOCKED" else ("🌐" if d.get("source") == "BROWSER_URL_BAR" else "🟢")
            t_str = d.get("formattedTime", "")
            src = d.get("source", "DNS")
            url_val = d.get("domainOrUrl", "")
            title = d.get("pageTitle", "")
            title_tag = f" ({title[:35]})" if title else ""
            print(f"   {icon} [{t_str}] [{src:<15}] {url_val}{title_tag}")
    print("=" * 88 + "\n")


def execute_per_app_network(mode="all", target=None, live=False, as_json=False):
    if mode == "block":
        if not target:
            print("[ERROR] Usage: python send_cmd.py net-app block <appName | packageName>")
            return
        res = http_post("/api/network/app/block", {"target": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success"):
            print("\n" + "=" * 76)
            print(f" 🚫 APP INTERNET ACCESS BLOCKED: {res.get('appName')} ({res.get('packageName')})")
            print("=" * 76)
            print(f" App UID          : {res.get('uid')}")
            print(f" Net-Blocked Apps : {res.get('blockedAppsCount', 1)}")
            print(f" Message          : {res.get('message')}")
            print("=" * 76 + "\n")
        else:
            print(f"✗ Failed to block app network: {res.get('error')}")
        return res

    elif mode == "unblock":
        tgt = target or "all"
        res = http_post("/api/network/app/unblock", {"target": tgt, "all": tgt.lower() in ["all", "*"]})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success"):
            if res.get("action") == "UNBLOCKED_ALL_APP_NETWORKS":
                print(f"✓ Restored internet access for all apps ({res.get('clearedCount', 0)} unblocked).")
            else:
                print(f"✓ Restored internet access for: {res.get('appName')} ({res.get('packageName')})")
        else:
            print(f"✗ Failed to unblock app network: {res.get('error')}")
        return res

    elif mode == "single":
        if not target:
            print("[ERROR] Missing app name or package name.")
            print("Usage: python send_cmd.py net-app <appName | packageName> [--live]")
            return
        if not live:
            res = http_post("/api/network/app/inspect", {"target": target, "limit": 35})
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            if not res.get("success"):
                print(f"✗ Could not inspect network for '{target}': {res.get('error', 'App not found')}")
                return res
            _render_single_app_network_panel(res)
            return res
        else:
            print(f"📡 Streaming Live Network Traffic, Sockets & Browsing for '{target}' (Ctrl+C to stop)...")
            try:
                while True:
                    res = http_post("/api/network/app/inspect", {"target": target, "limit": 15})
                    if as_json:
                        print(json.dumps(res))
                    elif res.get("success"):
                        sys.stdout.write("\033[2J\033[H")
                        _render_single_app_network_panel(res)
                        print(" [Live Watch Active — Refreshing every 1.2s | Press Ctrl+C to exit]")
                        sys.stdout.flush()
                    else:
                        print(f"✗ {res.get('error', 'App not found')}")
                        break
                    time.sleep(1.2)
            except KeyboardInterrupt:
                print("\n[✓] Stopped single-app live network monitor.")
            return

    elif mode == "browsing":
        if not live:
            res = http_post("/api/network/browsing", {"limit": 40})
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            tabs = res.get("activeBrowserTabs", []) or []
            feed = res.get("browsingFeed", []) or []
            socks = res.get("activeRemoteSockets", []) or []
            print("\n" + "=" * 88)
            print(" 🌐 CURRENT WEB BROWSING, ACTIVE URLS & LIVE DOMAIN STREAM")
            print("=" * 88)
            print(f" Foreground App    : {res.get('foregroundAppName', 'None')} ({res.get('foregroundPackage', '')})")
            if res.get("foregroundActiveUrl"):
                print(f" Active Browser URL: 🔗 {res.get('foregroundActiveUrl')}")
            print(f" VPN DNS Monitor   : {'🟢 ACTIVE' if res.get('isVpnDnsMonitorActive') else '⚪ STANDBY (Run: python send_cmd.py net-filter start)'}")
            print(f" Browser URL Reader: {'🟢 ACTIVE' if res.get('isAccessibilityUrlReaderActive') else '⚪ STANDBY (Enable Accessibility for full URL bar capture)'}")
            if tabs:
                print("-" * 88)
                print(" Active Browser Tabs:")
                for t in tabs:
                    fg_mark = " [FOREGROUND]" if t.get("isForeground") else ""
                    print(f"   🌐 {t.get('appName')} ({t.get('packageName')}){fg_mark}: {t.get('activeUrl')}")
            print("-" * 88)
            print(f" Recent Browsing & App Domain Requests ({len(feed)} events):")
            if not feed:
                print("   No browsing/domain activity recorded yet.")
            for item in feed[:25]:
                act = item.get("action", "ALLOWED")
                icon = "🚫" if act == "BLOCKED" else ("🌐" if item.get("source") == "BROWSER_URL_BAR" else "🟢")
                print(f"   {icon} [{item.get('formattedTime')}] {item.get('appName', ''):<18} | {item.get('domainOrUrl')}")
            if socks:
                print("-" * 88)
                print(f" Active Remote Socket Connections ({len(socks)}):")
                for s in socks[:12]:
                    rdom = f" ({s.get('resolvedDomain')})" if s.get("resolvedDomain") else ""
                    print(f"   🔌 {s.get('appName', ''):<18} -> {s.get('remoteEndpoint'):<21} [{s.get('remoteService')}]{rdom}")
            print("=" * 88 + "\n")
            return res
        else:
            print("🌐 Streaming Live Browsing URLs & Per-App Domain Requests (Ctrl+C to stop)...")
            seen_keys = set()
            first_batch = True
            try:
                while True:
                    res = http_post("/api/network/browsing", {"limit": 30})
                    feed = res.get("browsingFeed", []) if isinstance(res, dict) else []
                    if first_batch:
                        for item in reversed(feed[:10]):
                            k = f"{item.get('timestampMs')}_{item.get('domainOrUrl')}"
                            seen_keys.add(k)
                            act = item.get("action", "ALLOWED")
                            icon = "🚫" if act == "BLOCKED" else ("🌐" if item.get("source") == "BROWSER_URL_BAR" else "🟢")
                            rsn = item.get("reason", "")
                            rsn_tag = f" [{rsn}]" if act == "BLOCKED" and rsn else ""
                            print(f" {icon} [{item.get('formattedTime')}] {item.get('appName', ''):<18} -> {item.get('domainOrUrl')}{rsn_tag}")
                        first_batch = False
                    else:
                        for item in reversed(feed):
                            k = f"{item.get('timestampMs')}_{item.get('domainOrUrl')}"
                            if k not in seen_keys:
                                seen_keys.add(k)
                                if as_json:
                                    print(json.dumps(item))
                                else:
                                    act = item.get("action", "ALLOWED")
                                    icon = "🚫" if act == "BLOCKED" else ("🌐" if item.get("source") == "BROWSER_URL_BAR" else "🟢")
                                    rsn = item.get("reason", "")
                                    rsn_tag = f" [{rsn}]" if act == "BLOCKED" and rsn else ""
                                    print(f" {icon} [{item.get('formattedTime')}] {item.get('appName', ''):<18} -> {item.get('domainOrUrl')}{rsn_tag}")
                    time.sleep(1.0)
            except KeyboardInterrupt:
                print("\n[✓] Stopped live browsing stream.")
            return

    else:
        if not live:
            res = http_post("/api/network/apps", {"top": 30})
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            _render_all_apps_network_table(res)
            return res
        else:
            print("🚀 Streaming Per-App Live Bandwidth & Domain Activity Table (Ctrl+C to stop)...")
            try:
                while True:
                    res = http_post("/api/network/apps", {"top": 20})
                    if as_json:
                        print(json.dumps(res))
                    elif isinstance(res, dict) and res.get("success"):
                        sys.stdout.write("\033[2J\033[H")
                        _render_all_apps_network_table(res)
                        print(" [Live Stream Active — Refreshing every 1.2s | Press Ctrl+C to exit]")
                        sys.stdout.flush()
                    time.sleep(1.2)
            except KeyboardInterrupt:
                print("\n[✓] Stopped per-app live traffic stream.")
            return


def start_internet_tunnel_for_port(port=8080):
    """
    Starts or reuses a background HTTPS public tunnel (Cloudflare Quick Tunnel or SSH localhost.run)
    pointing to the active Android device's HTTP server (whether 127.0.0.1:8080 on the same device
    or <Device-A-LAN-IP>:8080 when the app is on another device) so temporary screen share URLs
    work from anywhere over the internet.
    """
    import subprocess
    import shutil
    tunnel_cache_file = os.path.expanduser("~/.aero_public_tunnel_url")

    # Determine target host & port (supports App on Device A + Termux on Device B)
    target_host = "127.0.0.1"
    target_port = port
    for candidate_url in [LOCAL_HTTP_URL, HTTP_SERVER_URL]:
        if candidate_url and candidate_url.startswith("http://") and "trycloudflare" not in candidate_url:
            parsed = urllib.parse.urlparse(candidate_url)
            if parsed.hostname:
                target_host = parsed.hostname
                target_port = parsed.port or port
                break

    # If HTTP_SERVER_URL is ALREADY an internet HTTPS tunnel (e.g. Device A has its own Cloudflare/lhr tunnel), use it directly!
    if HTTP_SERVER_URL.startswith("https://") and ("trycloudflare.com" in HTTP_SERVER_URL or "lhr.life" in HTTP_SERVER_URL or "ngrok" in HTTP_SERVER_URL):
        try:
            req = urllib.request.Request(f"{HTTP_SERVER_URL}/health", headers=get_http_headers())
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if resp.status == 200:
                    return HTTP_SERVER_URL.rstrip("/")
        except Exception:
            pass

    # 1. Try cloudflared if installed on Termux device (tunnels to target_host:target_port)
    if shutil.which("cloudflared"):
        print(f"🌐 Launching Cloudflare HTTPS Quick Tunnel for {target_host}:{target_port}...")
        log_path = os.path.expanduser("~/.aero_cloudflared.log")
        proc = subprocess.Popen(
            ["cloudflared", "tunnel", "--no-autoupdate", "--url", f"http://{target_host}:{target_port}"],
            stdout=open(log_path, "w"),
            stderr=subprocess.STDOUT,
            start_new_session=True
        )
        for _ in range(24):
            time.sleep(0.5)
            try:
                with open(log_path, "r") as f:
                    txt = f.read()
                m = re.search(r"https://[a-zA-Z0-9\-]+\.trycloudflare\.com", txt)
                if m:
                    pub_url = m.group(0)
                    with open(tunnel_cache_file, "w") as cf:
                        cf.write(pub_url)
                    return pub_url
            except Exception:
                pass

    # 2. Fallback to zero-install SSH reverse tunnel via localhost.run (tunnels to target_host:target_port)
    if shutil.which("ssh"):
        print(f"🌐 Launching zero-install SSH HTTPS Tunnel (localhost.run) for {target_host}:{target_port}...")
        log_path = os.path.expanduser("~/.aero_ssh_tunnel.log")
        proc = subprocess.Popen(
            [
                "ssh", "-o", "StrictHostKeyChecking=no", "-o", "ServerAliveInterval=30",
                "-R", f"80:{target_host}:{target_port}", "nokey@localhost.run"
            ],
            stdout=open(log_path, "w"),
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True
        )
        for _ in range(24):
            time.sleep(0.5)
            try:
                with open(log_path, "r") as f:
                    txt = f.read()
                m = re.search(r"https://[a-zA-Z0-9\-]+\.lhr\.life", txt)
                if m:
                    pub_url = m.group(0)
                    with open(tunnel_cache_file, "w") as cf:
                        cf.write(pub_url)
                    return pub_url
            except Exception:
                pass

    # 3. Check cached/configured public URL
    # 3. Check cached/configured public URL or active CLOUDFLARE_TUNNEL_URL
    if os.path.exists(tunnel_cache_file):
        try:
            with open(tunnel_cache_file, "r") as cf:
                cached = cf.read().strip()
                if cached.startswith("http"):
                    return cached
        except Exception:
            pass
    if CLOUDFLARE_TUNNEL_URL and CLOUDFLARE_TUNNEL_URL.startswith("https://"):
        return CLOUDFLARE_TUNNEL_URL.rstrip("/")
    return ""


def execute_app_guard(subcmd="status", target=None, raw_args=None, as_json=False):
    raw_args = raw_args or []
    subcmd = (subcmd or "status").lower()

    if subcmd in ["block", "lock", "ban", "deny"]:
        if not target:
            print("[ERROR] Missing app name or package name to block.")
            print("Usage: python send_cmd.py app-guard block <appName | packageName>")
            return
        res = http_post("/api/apps/guard/block", {"target": target, "packageName": target, "package": target, "app": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print("\n" + "=" * 72)
            print(f" 🚫 APP BLOCKED: {res.get('appName')} ({res.get('packageName')})")
            print("=" * 72)
            print(f" Active Blocked Apps     : {res.get('blockedCount', 1)}")
            print(f" Accessibility Enforcer  : {'🟢 ACTIVE (Instant Home Redirect)' if res.get('isAccessibilityEnforcementActive') else '⚠️ Background Monitor Active (Enable Accessibility for instant intercept)'}")
            print("=" * 72 + "\n")
        else:
            print(f"✗ Failed to block '{target}': {res.get('error', 'Unknown error')}")
        return res

    elif subcmd in ["unblock", "unlock", "allow"]:
        tgt = target or "all"
        res = http_post("/api/apps/guard/unblock", {"target": tgt, "packageName": tgt, "package": tgt, "all": (tgt.lower() == "all")})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            if res.get("action") == "UNBLOCKED_ALL":
                print(f"✓ Unblocked all apps ({res.get('clearedCount', 0)} cleared).")
            else:
                print(f"✓ Unblocked app: {res.get('appName', tgt)} ({res.get('packageName', tgt)})")
        else:
            print(f"✗ Failed to unblock '{tgt}': {res.get('error', 'Unknown error')}")
        return res

    elif subcmd in ["uninstall", "remove", "delete", "rm"]:
        if not target:
            print("[ERROR] Missing app name or package name to uninstall.")
            print("Usage: python send_cmd.py uninstall <appName | packageName>")
            return
        res = http_post("/api/apps/guard/uninstall", {"target": target, "packageName": target, "package": target, "app": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            auto_confirmed = res.get("autoConfirmed", False)
            acc_active = res.get("accessibilityActive", False)
            clicked_btns = res.get("clickedButtons", [])
            header_title = "ZERO-CONFIRMATION UNINSTALL COMPLETE" if auto_confirmed else "UNINSTALL TRIGGERED"
            print("\n" + "=" * 72)
            print(f" 🗑️ {header_title}: {res.get('appName')} ({res.get('packageName')})")
            print("=" * 72)
            print(f" Action         : {res.get('action')}")
            if auto_confirmed:
                btns_str = ", ".join(clicked_btns) if clicked_btns else "Silent Shell / Auto-Click"
                print(f" Auto-Confirmed : ✅ YES ({btns_str})")
            elif acc_active:
                print(f" Auto-Confirmed : ⚡ Accessibility Watcher Armed (Auto-clicking dialog...)")
            else:
                print(f" Auto-Confirmed : ⚠️ Manual Confirm Required (Accessibility service is OFF)")
            print(f" Message        : {res.get('message')}")
            if not acc_active and not auto_confirmed:
                print("-" * 72)
                print(" 💡 Tip: To make all future uninstalls 100% automatic with ZERO confirmation:")
                print("    1. Run: python send_cmd.py permissions settings accessibility")
                print("    2. Enable 'AI Companion / AeroShare' in Accessibility Settings once.")
            elif res.get("isSystemApp"):
                print("-" * 72)
                print(f" 💡 Note: '{res.get('appName')}' is a pre-installed [System] app and has also been")
                print("    automatically blocked in App Guard & force-stopped.")
            print("=" * 72 + "\n")
        else:
            print(f"✗ Uninstall failed for '{target}': {res.get('error', 'App not found')}")
        return res

    elif subcmd in ["force-stop", "forcestop", "kill", "stop"]:
        if not target:
            print("[ERROR] Missing app name or package name to force-stop.")
            print("Usage: python send_cmd.py force-stop <appName | packageName>")
            return
        res = http_post("/api/apps/guard/force-stop", {"target": target, "packageName": target, "package": target, "app": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print(f"✓ Force-stopped {res.get('appName')} ({res.get('packageName')})")
        else:
            print(f"✗ Could not force-stop '{target}': {res.get('error', 'App not found')}")
        return res

    elif subcmd in ["settings", "app-settings", "open-settings"]:
        if not target:
            print("[ERROR] Missing app name or package name.")
            print("Usage: python send_cmd.py app-guard settings <appName | packageName>")
            return
        res = http_post("/api/apps/guard/settings", {"target": target, "packageName": target, "package": target, "app": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print(f"✓ Opened system App Info on phone for: {res.get('appName')} ({res.get('packageName')})")
        else:
            print(f"✗ Failed opening App Info: {res.get('error', 'Unknown error')}")
        return res

    elif subcmd in ["info", "inspect", "details", "verify"]:
        if not target:
            print("[ERROR] Missing app name, package name, or APK file path to inspect.")
            print("Usage: python send_cmd.py app-info <appName | packageName | /path/to/file.apk>")
            return
        res = http_post("/api/apps/guard/info", {"target": target, "packageName": target, "package": target, "app": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if not res.get("success", False):
            print(f"✗ App / APK verification failed: {res.get('error', 'Target not found')}")
            return res
        print_app_verification_report(res)
        return res

    elif subcmd in ["events", "history", "logs", "alerts"]:
        if target and target.lower() in ["clear", "reset", "clean"]:
            res = http_post("/api/apps/guard/events/clear", {})
            if as_json:
                print(json.dumps(res, indent=2))
            else:
                print("✓ Cleared App Guard package event history.")
            return res
        res = http_get("/api/apps/guard/events")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        events = res.get("events", [])
        print("\n" + "=" * 80)
        print(f" 🔔 APP INSTALLATION, UNINSTALLATION & BLOCK EVENT LOG ({len(events)} events)")
        print("=" * 80)
        if not events:
            print("  No package events recorded yet.")
        for evt in events:
            etype = evt.get("eventType", "EVENT")
            icon = "🟢" if etype == "INSTALLED" else ("🔄" if etype == "UPDATED" else ("🗑️" if etype == "UNINSTALLED" else "🚫"))
            t_str = evt.get("formattedTime", "")
            aname = evt.get("appName", "")
            pkg = evt.get("packageName", "")
            det = evt.get("details") or evt.get("installerSource") or ""
            print(f" {icon} [{t_str}] {etype:<15} | {aname} ({pkg})")
            if det:
                print(f"    ↳ {det}")
        print("=" * 80 + "\n")
        return res

    elif subcmd in ["policy", "config"]:
        payload = {}
        for a in raw_args:
            if a.startswith("--alert-install="):
                payload["alertOnInstall"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
            elif a.startswith("--alert-uninstall="):
                payload["alertOnUninstall"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
            elif a.startswith("--alert-blocked="):
                payload["alertOnBlockedLaunch"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
            elif a.startswith("--auto-block="):
                payload["autoBlockNewInstalls"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
        if target in ["auto-block-on", "lockdown"]:
            payload["autoBlockNewInstalls"] = True
        elif target in ["auto-block-off", "unlockdown"]:
            payload["autoBlockNewInstalls"] = False
        res = http_post("/api/apps/guard/policy", payload)
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("✓ Updated App Guard policy:")
        print(f"  • Alert on Installation   : {'ON' if res.get('alertOnInstall') else 'OFF'}")
        print(f"  • Alert on Uninstallation : {'ON' if res.get('alertOnUninstall') else 'OFF'}")
        print(f"  • Auto-Block New Installs : {'ON' if res.get('autoBlockNewInstalls') else 'OFF'}")
        return res

    elif subcmd in ["watch", "live", "--live", "monitor"]:
        print("🛡️ Watching live App Installation, Update, Uninstallation & Block events (Ctrl+C to stop)...")
        seen_ids = set()
        first_poll = True
        try:
            while True:
                res = http_get("/api/apps/guard/events")
                events = res.get("events", []) if isinstance(res, dict) else []
                if first_poll:
                    for e in events:
                        seen_ids.add(e.get("id"))
                    first_poll = False
                else:
                    for e in reversed(events):
                        eid = e.get("id")
                        if eid and eid not in seen_ids:
                            seen_ids.add(eid)
                            if as_json:
                                print(json.dumps(e))
                            else:
                                etype = e.get("eventType", "EVENT")
                                print(f"🔔 [{e.get('formattedTime')}] {etype}: {e.get('appName')} ({e.get('packageName')}) - {e.get('details')}")
                time.sleep(1.5)
        except KeyboardInterrupt:
            print("\n[✓] Stopped live App Guard monitor.")
        return

    else:
        res = http_get("/api/apps/guard/status")
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        blocked = res.get("blockedApps", [])
        events = res.get("recentEvents", [])
        print("\n" + "=" * 78)
        print(" 🛡️ AEROSHARE APP GUARD & PACKAGE CONTROL STATUS")
        print("=" * 78)
        print(f" Real-Time Package Monitor : {'🟢 ACTIVE' if res.get('monitoringActive', True) else '🔴 INACTIVE'}")
        print(f" Alert on App Install      : {'🔔 ON' if res.get('alertOnInstall', True) else '🔕 OFF'}")
        print(f" Alert on App Uninstall    : {'🔔 ON' if res.get('alertOnUninstall', True) else '🔕 OFF'}")
        print(f" Auto-Block New Installs   : {'🛡️ ON (Lockdown)' if res.get('autoBlockNewInstalls', False) else '⚪ OFF'}")
        print(f" Accessibility Enforcer    : {'🟢 READY' if res.get('isAccessibilityBlockerActive') else '⚠️ Fallback Mode'}")
        print(f" Blocked Apps ({res.get('blockedCount', len(blocked))})          : " + (", ".join(f"{b.get('appName')} ({b.get('packageName')})" for b in blocked) if blocked else "None"))
        if events:
            print("-" * 78)
            print(" Recent Package Activity:")
            for evt in events[:8]:
                print(f"   • [{evt.get('formattedTime')}] {evt.get('eventType'):<14} {evt.get('appName')} ({evt.get('packageName')})")
        print("=" * 78)
        print("💡 Quick Commands:")
        print("   python send_cmd.py block-app <appName|pkg>    # Block any app from launching")
        print("   python send_cmd.py unblock-app <appName|all>  # Unblock an app or all apps")
        print("   python send_cmd.py uninstall <appName|pkg>    # Uninstall an app from phone")
        print("   python send_cmd.py force-stop <appName|pkg>   # Force-stop running app")
        print("   python send_cmd.py app-info <appName|pkg>     # Deep inspect permissions & SDK")
        print("   python send_cmd.py app-guard watch            # Stream live install/uninstall alerts\n")
        return res


# ---------------------------------------------------------------------------
# Suite 1: App Usage Time Limits & Daily Screen-Time Analytics
# ---------------------------------------------------------------------------

def execute_screen_time(subcmd="stats", target=None, minutes=0, as_json=False):
    subcmd = (subcmd or "stats").lower()
    if subcmd in ["set", "limit", "add"]:
        if not target or minutes <= 0:
            print("[ERROR] Usage: python send_cmd.py usage-limit set <appName|packageName> <minutes_per_day>")
            return
        res = http_post("/api/apps/usage/limit/set", {"target": target, "dailyLimitMinutes": int(minutes)})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print("\n" + "=" * 74)
            print(f" ⏳ DAILY USAGE LIMIT CONFIGURED: {res.get('appName')} ({res.get('packageName')})")
            print("=" * 74)
            print(f" Daily Limit       : {res.get('dailyLimitMinutes')} minutes/day")
            print(f" Used Today        : {res.get('usedTodayMinutes', 0)} minutes")
            print(f" Quota Status      : {'🚫 EXCEEDED (Auto-Blocked)' if res.get('isQuotaExceeded') else '🟢 WITHIN QUOTA'}")
            print("=" * 74 + "\n")
        else:
            print(f"✗ Failed to set usage limit: {res.get('error', 'Unknown error')}")
        return res

    elif subcmd in ["remove", "rm", "clear", "unlimit", "delete"]:
        tgt = target or "all"
        is_all = tgt.lower() in ["all", "*"]
        res = http_post("/api/apps/usage/limit/remove", {"target": tgt, "all": is_all})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            if is_all:
                print(f"✓ Cleared all daily app usage limits ({res.get('removedCount', 0)} removed).")
            else:
                print(f"✓ Removed daily usage limit for {res.get('appName')} ({res.get('packageName')}).")
        else:
            print(f"✗ Failed to remove usage limit: {res.get('error', 'Unknown error')}")
        return res

    else:
        top_n = int(target) if (target and str(target).isdigit()) else 25
        res = http_post("/api/apps/usage/stats", {"top": top_n})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if not res.get("success", False):
            print(f"✗ Could not fetch screen-time analytics: {res.get('error', 'Unknown error')}")
            return res

        quotas = res.get("quotas", [])
        apps = res.get("apps", [])
        has_perm = res.get("usageAccessPermissionGranted", False)
        print("\n" + "=" * 82)
        print(f" 📊 DAILY SCREEN-TIME ANALYTICS & APP QUOTAS ({res.get('date', 'Today')})")
        print("=" * 82)
        print(f" Total Screen Time Today : {res.get('totalScreenTimeFormatted', '0m')} ({res.get('totalScreenTimeMinutes', 0)} mins)")
        print(f" Usage Access Permission : {'🟢 GRANTED' if has_perm else '⚠️ NOT GRANTED (Run: python send_cmd.py permissions settings usage)'}")
        print(f" Active App Quotas       : {len(quotas)}")
        if quotas:
            print("-" * 82)
            print(" Active Daily Quotas:")
            for q in quotas:
                st = "🚫 BLOCKED (Quota Reached)" if q.get("isQuotaExceeded") else f"🟢 {q.get('remainingMinutes')}m remaining"
                print(f"   • {q.get('appName'):<24} ({q.get('packageName')}) : {q.get('usedTodayMinutes')}m / {q.get('dailyLimitMinutes')}m  [{st}]")
        print("-" * 82)
        if not apps:
            print(" No foreground app usage recorded yet today.")
        else:
            print(f" {'#':<3} {'APP NAME':<24} {'PACKAGE NAME':<30} {'TIME USED':<12} {'QUOTA':<10}")
            print("-" * 82)
            for idx, a in enumerate(apps, 1):
                aname = a.get("appName", "")[:22]
                pkg = a.get("packageName", "")[:28]
                dur = a.get("formattedDuration", "0m")
                lim = a.get("dailyLimitMinutes", 0)
                q_str = f"{lim}m/day" if lim > 0 else "-"
                if a.get("isBlocked"):
                    q_str += " [🚫]"
                print(f" {idx:<3} {aname:<24} {pkg:<30} {dur:<12} {q_str:<10}")
        print("=" * 82)
        print("💡 Set a daily time limit: python send_cmd.py usage-limit set <appName|pkg> <minutes>\n")
        return res


# ---------------------------------------------------------------------------
# Suite 2: Intruder & Device Unlock Monitor with Security Alerts
# ---------------------------------------------------------------------------

def execute_unlock_monitor(subcmd="status", target=None, raw_args=None, as_json=False):
    raw_args = raw_args or []
    subcmd = (subcmd or "status").lower()
    if subcmd in ["snap", "photo", "capture", "selfie"]:
        lens = target if target in ["front", "back"] else "front"
        res = http_post("/api/security/unlock/snap", {"lens": lens})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print("\n" + "=" * 74)
            print(f" 📸 INTRUDER SECURITY SNAPSHOT CAPTURED ({lens.upper()} CAMERA)")
            print("=" * 74)
            print(f" Saved File Path : {res.get('filePath')}")
            print(f" File Size       : {res.get('fileSize', 0)} bytes")
            print("=" * 74 + "\n")
        else:
            print(f"✗ Intruder snapshot failed: {res.get('error', 'Camera unavailable')}")
        return res

    elif subcmd in ["clear", "reset", "clean"]:
        res = http_post("/api/security/unlock/clear", {})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print("✓ Cleared device unlock & intruder security logs.")
        return res

    elif subcmd in ["policy", "config", "settings"]:
        payload = {}
        for a in raw_args:
            if a.startswith("--enabled="):
                payload["enabled"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
            elif a.startswith("--alert="):
                payload["alertOnUnlock"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
            elif a.startswith("--photo=") or a.startswith("--snap="):
                payload["capturePhotoOnUnlock"] = a.split("=", 1)[1].lower() in ["1", "true", "on", "yes"]
        if target in ["photo-on", "snap-on"]:
            payload["capturePhotoOnUnlock"] = True
        elif target in ["photo-off", "snap-off"]:
            payload["capturePhotoOnUnlock"] = False
        res = http_post("/api/security/unlock/policy", payload)
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print("✓ Updated Unlock & Intruder Monitor policy:")
        print(f"  • Unlock Monitor Enabled        : {'ON' if res.get('unlockMonitorEnabled') else 'OFF'}")
        print(f"  • Real-Time Unlock Alert        : {'ON' if res.get('alertOnUnlock') else 'OFF'}")
        print(f"  • Front-Camera Photo on Unlock  : {'ON' if res.get('capturePhotoOnUnlock') else 'OFF'}")
        return res

    else:
        res = http_post("/api/security/unlock/status", {"limit": 40})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        events = res.get("events", [])
        print("\n" + "=" * 80)
        print(" 🔐 INTRUDER & DEVICE UNLOCK MONITOR")
        print("=" * 80)
        print(f" Monitor Status          : {'🟢 ACTIVE' if res.get('unlockMonitorEnabled', True) else '🔴 DISABLED'}")
        print(f" Screen Currently On     : {'🟢 YES' if res.get('isScreenCurrentlyOn') else '⚫ NO (Screen Off)'}")
        print(f" Real-Time Unlock Alerts : {'🔔 ON' if res.get('alertOnUnlock', True) else '🔕 OFF'}")
        print(f" Auto-Selfie on Unlock   : {'📸 ON' if res.get('capturePhotoOnUnlock', False) else '⚪ OFF'}")
        print(f" Total Unlocks Recorded  : {res.get('totalUnlockCountRecorded', 0)} (Total events: {len(events)})")
        if events:
            print("-" * 80)
            print(" Recent Screen & Unlock Security Events:")
            for e in events[:15]:
                et = e.get("eventType", "EVENT")
                icon = "🔓" if et == "DEVICE_UNLOCKED" else ("📸" if et == "INTRUDER_SNAP" else ("💡" if et == "SCREEN_ON" else "🔒"))
                line = f" {icon} [{e.get('formattedTime')}] {et:<16} | App: {e.get('foregroundAppName', 'Screen')} | Batt: {e.get('batteryPercent', 0)}%"
                print(line)
                if e.get("photoPath"):
                    print(f"    📸 Snapshot: {e.get('photoPath')}")
        print("=" * 80)
        print("💡 Commands:")
        print("   python send_cmd.py unlock-monitor snap [front|back]")
        print("   python send_cmd.py unlock-monitor policy --photo=on --alert=on\n")
        return res


# ---------------------------------------------------------------------------
# Suite 3: Clipboard & Notification History Logger + Keyword Watch Alerts
# ---------------------------------------------------------------------------

def execute_history_keyword_watch(mode="clip", subcmd="", target="", as_json=False):
    if mode == "clip":
        if subcmd in ["clear", "reset", "clean"]:
            res = http_post("/api/history/clear", {"target": "clipboard"})
            print("✓ Cleared clipboard history.")
            return res
        q = " ".join([p for p in [subcmd, target] if p]).strip()
        res = http_post("/api/history/clipboard", {"query": q, "limit": 50})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        entries = res.get("entries", [])
        kws = res.get("watchedKeywords", [])
        print("\n" + "=" * 80)
        print(f" 📋 CLIPBOARD HISTORY LOG ({len(entries)} / {res.get('totalEntries', 0)} entries)" + (f" [Filter: '{q}']" if q else ""))
        print(f" Watched Keywords: {', '.join(kws) if kws else 'None'}")
        print("=" * 80)
        if not entries:
            print(" No clipboard entries recorded matching query.")
        for item in entries:
            matched = item.get("matchedKeywords", [])
            kw_tag = f"  🚨 MATCHED: {matched}" if matched else ""
            print(f" • [{item.get('formattedTime')}] ({item.get('length', 0)} chars){kw_tag}")
            print(f"   {item.get('text', '')[:200]}")
        print("=" * 80 + "\n")
        return res

    elif mode == "notif":
        if subcmd in ["clear", "reset", "clean"]:
            res = http_post("/api/history/clear", {"target": "notifications"})
            print("✓ Cleared notification history.")
            return res
        q = " ".join([p for p in [subcmd, target] if p]).strip()
        res = http_post("/api/history/notifications", {"query": q, "limit": 60})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        entries = res.get("entries", [])
        kws = res.get("watchedKeywords", [])
        print("\n" + "=" * 82)
        print(f" 🔔 NOTIFICATION HISTORY LOG ({len(entries)} / {res.get('totalEntries', 0)} entries)" + (f" [Filter: '{q}']" if q else ""))
        print(f" Watched Keywords: {', '.join(kws) if kws else 'None'}")
        print("=" * 82)
        if not entries:
            print(" No historical notifications recorded matching query.")
        for item in entries:
            matched = item.get("matchedKeywords", [])
            kw_tag = f" 🚨 MATCHED: {matched}" if matched else ""
            print(f" • [{item.get('formattedTime')}] {item.get('appName')} ({item.get('packageName')}){kw_tag}")
            print(f"   {item.get('title')}: {item.get('text', '')[:180]}")
        print("=" * 82 + "\n")
        return res

    else:
        sub = (subcmd or "list").lower()
        if sub in ["add", "watch", "set"]:
            if not target:
                print("[ERROR] Usage: python send_cmd.py keyword-watch add <keyword>")
                return
            res = http_post("/api/history/keywords/add", {"keyword": target})
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            print(f"✓ Added watched keyword '{target}'. Active keywords: {', '.join(res.get('watchedKeywords', []))}")
            return res
        elif sub in ["remove", "rm", "del", "clear"]:
            tgt = target or ("all" if sub == "clear" else "")
            if not tgt:
                print("[ERROR] Usage: python send_cmd.py keyword-watch remove <keyword|all>")
                return
            res = http_post("/api/history/keywords/remove", {"keyword": tgt, "all": tgt.lower() == "all"})
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            print(f"✓ Updated watched keywords: {', '.join(res.get('watchedKeywords', [])) or 'None'}")
            return res
        else:
            res = http_post("/api/history/keywords/list", {})
            if as_json:
                print(json.dumps(res, indent=2))
                return res
            kws = res.get("watchedKeywords", [])
            print("\n" + "=" * 74)
            print(f" 🔍 KEYWORD WATCH ALERT ENGINE ({len(kws)} active keywords)")
            print("=" * 74)
            print(" Watched Keywords : " + (", ".join(kws) if kws else "None configured"))
            print("-" * 74)
            print(" Any clipboard copy or status bar notification containing a watched")
            print(" keyword immediately fires a KEYWORD_MATCH_ALERT to Termux & phone.")
            print(" Commands:")
            print("   python send_cmd.py keyword-watch add <word>")
            print("   python send_cmd.py keyword-watch remove <word|all>")
            print("=" * 74 + "\n")
            return res


# ---------------------------------------------------------------------------
# Suite 4: Scheduled & Event-Driven Automation Rules Engine
# ---------------------------------------------------------------------------

def execute_automation_rules(subcmd="list", target=None, raw_args=None, as_json=False):
    raw_args = raw_args or []
    sub = (subcmd or "list").lower()
    if sub in ["add", "create", "new"]:
        when_spec = ""
        do_spec = ""
        cooldown = 15
        for a in raw_args:
            if a.startswith("--when=") or a.startswith("--trigger="):
                when_spec = a.split("=", 1)[1]
            elif a.startswith("--do=") or a.startswith("--action="):
                do_spec = a.split("=", 1)[1]
            elif a.startswith("--cooldown="):
                val = a.split("=", 1)[1]
                if val.isdigit():
                    cooldown = int(val)
        rule_name = target or f"{when_spec} -> {do_spec}"
        if not when_spec or not do_spec:
            print("[ERROR] Missing --when=<trigger:value> or --do=<action:value>.")
            print("Examples:")
            print("  python send_cmd.py rules add \"Low Battery DND\" --when=battery_below:20 --do=dnd:on")
            print("  python send_cmd.py rules add \"Night Mode\" --when=time_daily:23:00 --do=brightness:15")
            print("  python send_cmd.py rules add \"Unlock Voice\" --when=device_unlocked:true --do=tts:Welcome_back")
            return
        res = http_post("/api/automation/rules/add", {
            "name": rule_name,
            "trigger": when_spec,
            "action": do_spec,
            "cooldownMinutes": cooldown
        })
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            r = res.get("rule", {})
            print("\n" + "=" * 74)
            print(f" ⚡ AUTOMATION RULE CREATED: {r.get('name')} (ID: {r.get('id')})")
            print("=" * 74)
            print(f" Trigger  : {r.get('triggerSpec')}")
            print(f" Action   : {r.get('actionSpec')}")
            print(f" Cooldown : {r.get('cooldownMinutes')} minutes")
            print("=" * 74 + "\n")
        else:
            print(f"✗ Failed to add rule: {res.get('error', 'Unknown error')}")
        return res

    elif sub in ["remove", "rm", "del", "delete", "clear"]:
        tgt = target or ("all" if sub == "clear" else "")
        if not tgt:
            print("[ERROR] Usage: python send_cmd.py rules remove <ruleId|ruleName|all>")
            return
        res = http_post("/api/automation/rules/remove", {"target": tgt, "all": tgt.lower() == "all"})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        print(f"✓ Removed {res.get('removedCount', 0)} automation rule(s).")
        return res

    elif sub in ["toggle", "enable", "disable"]:
        if not target:
            print("[ERROR] Usage: python send_cmd.py rules toggle <ruleId|name> [on|off]")
            return
        parts = target.split()
        rid = parts[0]
        en = True
        if sub == "disable" or (len(parts) > 1 and parts[1].lower() in ["off", "false", "0"]):
            en = False
        res = http_post("/api/automation/rules/toggle", {"target": rid, "enabled": en})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            r = res.get("rule", {})
            print(f"✓ Rule '{r.get('name')}' ({r.get('id')}) -> {'ENABLED' if r.get('enabled') else 'DISABLED'}")
        else:
            print(f"✗ {res.get('error', 'Rule not found')}")
        return res

    elif sub in ["test", "run", "fire"]:
        if not target:
            print("[ERROR] Usage: python send_cmd.py rules test <ruleId|ruleName>")
            return
        res = http_post("/api/automation/rules/test", {"target": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            r = res.get("rule", {})
            print(f"⚡ Executed rule '{r.get('name')}' ({r.get('actionSpec')}) -> {res.get('executionResult')}")
        else:
            print(f"✗ {res.get('error', 'Rule not found')}")
        return res

    else:
        res = http_post("/api/automation/rules/list", {})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        rules = res.get("rules", [])
        print("\n" + "=" * 84)
        print(f" ⚡ SCHEDULED & EVENT-DRIVEN AUTOMATION RULES ({len(rules)} rules)")
        print("=" * 84)
        if not rules:
            print(" No automation rules configured yet.")
        else:
            for r in rules:
                st = "🟢 ON " if r.get("enabled") else "⚪ OFF"
                print(f" {st} [{r.get('id')}] {r.get('name'):<24} | WHEN {r.get('triggerSpec'):<22} -> DO {r.get('actionSpec')}")
                print(f"        Fired: {r.get('triggerCount', 0)}x | Last: {r.get('lastTriggeredFormatted', 'Never')} | Cooldown: {r.get('cooldownMinutes', 15)}m")
        print("=" * 84)
        print("💡 Triggers: battery_below:20, battery_above:80, charging:true, wifi_connected:true, time_daily:23:00, app_opened:<pkg>, device_unlocked:true")
        print("💡 Actions : torch:on|off, dnd:on|off, brightness:0-255, volume:0-100, tts:<text>, notify:<text>, block_app:<pkg>, force_stop:<pkg>, shell:<cmd>\n")
        return res


# ---------------------------------------------------------------------------
# Suite 5: APK Backup Extractor & Remote APK Installer
# ---------------------------------------------------------------------------

def print_app_verification_report(res):
    if not isinstance(res, dict) or not res.get("success", False):
        return
    src_type = res.get("sourceType", "INSTALLED_APP")
    header_badge = "🔍 PRE-INSTALL APK VERIFIER & CAPABILITY REPORT" if src_type == "APK_FILE" else "📦 APP DEVELOPER VERIFIER & CAPABILITY REPORT"
    dev = res.get("developerInfo", {}) or {}
    sec = res.get("securityAssessment", {}) or {}
    upg = dev.get("upgradeCheck", {}) or {}
    caps = res.get("capabilities", []) or []
    comps = res.get("components", {}) or {}

    print("\n" + "=" * 84)
    print(f" {header_badge}")
    print("=" * 84)
    print(f" App Name           : {res.get('appName')}  [{res.get('category', 'Application')}]")
    print(f" Package Name       : {res.get('packageName')}")
    print(f" Version            : v{res.get('versionName')} (Version Code: {res.get('versionCode')})")
    print(f" Source / Status    : {res.get('installerSource')}  |  {'🚫 BLOCKED' if res.get('isBlocked') else ('SYSTEM APP' if res.get('isSystemApp') else 'USER APP')}")
    print(f" Android SDK        : targetSdk={res.get('targetSdk')} | minSdk={res.get('minSdk')}")
    print(f" APK Size & Path    : {res.get('apkSizeMb', 0.0)} MB ({res.get('sourceApkPath', '')})")
    if res.get("apkSha256"):
        print(f" APK File SHA-256   : {res.get('apkSha256')}")

    # Section 1: What Does This App Do?
    print("-" * 84)
    print(" 📖 WHAT DOES THIS APP DO? (PURPOSE & FUNCTIONAL SUMMARY)")
    print("-" * 84)
    what_it_does = res.get("whatAppDoes", "General Android application.")
    print(f"   {what_it_does}")
    if comps:
        print(f"   • Manifest Components : {comps.get('activitiesCount', 0)} Screens (Activities) | {comps.get('servicesCount', 0)} Background Services | {comps.get('receiversCount', 0)} Event Receivers | {comps.get('providersCount', 0)} Content Providers")

    # Section 2: Developer & Signing Certificate Verifier
    print("-" * 84)
    print(" 🔏 DEVELOPER IDENTITY & SIGNING CERTIFICATE VERIFICATION")
    print("-" * 84)
    pub_badge = "✅ TRUSTED" if dev.get("isTrustedPublisher") else ("⚠️ DEBUG KEY" if dev.get("isDebugCertificate") else "ℹ️ CUSTOM SIGNER")
    print(f"   Developer / Signer : {dev.get('developerName', 'Unknown')}  [{pub_badge}]")
    print(f"   Verified Publisher : {dev.get('verifiedPublisher', 'Independent Developer')}")
    print(f"   Organization (O)   : {dev.get('organization', 'N/A')}  |  Unit (OU): {dev.get('organizationalUnit', 'N/A')}")
    if dev.get("location") and dev.get("location") != "N/A":
        print(f"   Developer Location : {dev.get('location')}")
    print(f"   Cert Subject DN    : {dev.get('subjectDn', 'N/A')}")
    print(f"   Crypto Signature   : {dev.get('signatureAlgorithm', 'N/A')} ({dev.get('publicKeyAlgorithm', 'N/A')})")
    print(f"   Certificate Valid  : {dev.get('validFrom', 'N/A')} -> {dev.get('validUntil', 'N/A')}" + (" [🚨 EXPIRED]" if dev.get("isExpired") else " [🟢 VALID]"))
    print(f"   Cert SHA-256       : {dev.get('sha256Fingerprint', 'N/A')}")
    print(f"   Cert SHA-1         : {dev.get('sha1Fingerprint', 'N/A')}")
    if upg:
        print(f"   Upgrade Check      : {upg.get('summary', 'N/A')}")

    # Section 3: Plain-English Capabilities ("What This App Can Do")
    print("-" * 84)
    print(f" ⚡ DEVICE CAPABILITIES & BEHAVIORS ({len(caps)} functional areas, {res.get('totalPermissionsCount', 0)} raw permissions)")
    print("-" * 84)
    if not caps:
        print("   🟢 No sensitive hardware, network, or private data capabilities requested.")
    else:
        for c in caps:
            risk = c.get("risk", "LOW")
            r_tag = "🔴 HIGH" if risk == "HIGH" else ("🟡 MOD " if risk == "MODERATE" else "🟢 LOW ")
            perms_str = ", ".join(c.get("permissions", [])[:5])
            print(f"   {c.get('icon', '•')} [{r_tag}] {c.get('title')}")
            print(f"      ↳ What it does : {c.get('whatItDoes')}")
            print(f"      ↳ Permissions  : {perms_str}")

    # Section 4: Security & Trust Verdict
    print("-" * 84)
    print(" 🛡️ SECURITY & PRE-INSTALL TRUST VERDICT")
    print("-" * 84)
    print(f"   Verdict            : {sec.get('verdict', 'N/A')}")
    print(f"   Trust Score        : {sec.get('trustScore', 0)}/100  (Risk Level: {sec.get('riskLevel', 'UNKNOWN')})")
    pos_list = sec.get("positiveSignals", []) or []
    for p in pos_list:
        print(f"   ✓ {p}")
    warn_list = sec.get("warnings", []) or []
    for w in warn_list:
        print(f"   ⚠️ {w}")
    print("=" * 84 + "\n")


def execute_apk_ops(mode="backup", target=None, force=False, as_json=False):
    if mode == "verify":
        if not target:
            print("[ERROR] Missing APK file path or installed app name/package to verify.")
            print("Usage: python send_cmd.py verify </sdcard/Download/app.apk | appName | packageName>")
            return
        res = http_post("/api/apps/apk/verify", {"target": target, "path": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print_app_verification_report(res)
        else:
            print(f"✗ Verification failed for '{target}': {res.get('error', 'Target not found')}")
        return res

    elif mode == "backup":
        if not target:
            print("[ERROR] Missing app name or package name to back up.")
            print("Usage: python send_cmd.py apk-backup <appName | packageName>")
            return
        res = http_post("/api/apps/apk/backup", {"target": target})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        if res.get("success", False):
            print("\n" + "=" * 78)
            print(f" 💾 APK BACKUP EXTRACTED: {res.get('appName')} v{res.get('versionName')}")
            print("=" * 78)
            print(f" Package Name    : {res.get('packageName')}")
            print(f" Backup File     : {res.get('backupFilePath')}")
            print(f" APK Size        : {res.get('sizeMb')} MB ({res.get('sizeBytes')} bytes)")
            print(f" SHA-256 Digest  : {res.get('sha256')}")
            print("=" * 78 + "\n")
        else:
            print(f"✗ APK backup failed: {res.get('error', 'App not found')}")
        return res

    elif mode == "install":
        if not target:
            print("[ERROR] Missing APK file path on device or backup filename.")
            print("Usage: python send_cmd.py apk-install </sdcard/Download/file.apk | backup_file.apk> [--force]")
            return
        res = http_post("/api/apps/apk/install", {"path": target, "force": force})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        verification = res.get("verification")
        if isinstance(verification, dict) and verification.get("success", False):
            print_app_verification_report(verification)
        if res.get("success", False):
            print("=" * 84)
            print(f" 📲 APK INSTALLATION STATUS: {res.get('action')}")
            print("=" * 84)
            print(f" App      : {res.get('appName', '')} ({res.get('packageName', '')})")
            print(f" APK Path : {res.get('apkFilePath')}")
            print(f" Message  : {res.get('message')}")
            print("=" * 84 + "\n")
        else:
            print(f"✗ APK install blocked or failed: {res.get('error', 'File not found')}")
        return res

    else:
        res = http_post("/api/apps/apk/backups", {})
        if as_json:
            print(json.dumps(res, indent=2))
            return res
        backups = res.get("backups", [])
        print("\n" + "=" * 82)
        print(f" 💾 EXTRACTED APK BACKUPS ({len(backups)} files in {res.get('backupDirectory', '/sdcard/Download/AeroShare/backups')})")
        print("=" * 82)
        if not backups:
            print(" No APK backups extracted yet. Run: python send_cmd.py apk-backup <appName|pkg>")
        else:
            for idx, b in enumerate(backups, 1):
                print(f" {idx:<3} {b.get('fileName'):<44} {b.get('sizeMb', 0.0):>6} MB | {b.get('lastModified')}")
        print("=" * 82 + "\n")
        return res


# ---------------------------------------------------------------------------
# Main CLI Router
# ---------------------------------------------------------------------------

def print_help():
    print("""
================================================================================
  AeroShare Clean Command Center & Device Bridge CLI (send_cmd.py)
================================================================================

APP GUARD, DEVELOPER VERIFIER, APP BLOCKER & ZERO-CONFIRM UNINSTALLER:
  python send_cmd.py verify <apkPath|appName|pkg>             # Verify developer signature & see what app does
  python send_cmd.py app-info <appName|packageName|apkPath>   # Deep inspect developer cert, capabilities & risk
  python send_cmd.py app-guard [status|events|watch]          # Live install/uninstall monitor & alerts
  python send_cmd.py block-app <appName|packageName>          # Block any app from opening on phone
  python send_cmd.py unblock-app <appName|packageName|all>    # Unblock a blocked app (or 'all')
  python send_cmd.py uninstall <appName|packageName>          # Zero-confirmation uninstall / disable app
  python send_cmd.py force-stop <appName|packageName>         # Force-stop & kill background app processes
  python send_cmd.py app-guard policy [--auto-block=on|off] [--alert-install=on|off]

SCREEN-TIME ANALYTICS, APP USAGE LIMITS & APK BACKUP / INSTALLER:
  python send_cmd.py screen-time [top_n]                      # Daily foreground screen-time analytics & quotas
  python send_cmd.py usage-limit set <appName|pkg> <minutes>  # Auto-block app when daily usage reaches limit
  python send_cmd.py usage-limit remove <appName|pkg|all>     # Remove daily app time limit
  python send_cmd.py apk-backup <appName|packageName>         # Extract installed app APK to Download/AeroShare/backups
  python send_cmd.py apk-backups                              # List all backed-up APK files & sizes
  python send_cmd.py apk-install <apkPath|backupFileName>     # Install APK silently or via package installer

SECURITY UNLOCK MONITOR, CLIPBOARD/NOTIFICATION HISTORY & AUTOMATION RULES:
  python send_cmd.py unlock-monitor [status|snap [front|back]|clear]
  python send_cmd.py unlock-monitor policy [--photo=on|off] [--alert=on|off]
  python send_cmd.py clip-history [search_query|clear]        # Searchable clipboard history log
  python send_cmd.py notif-history [search_query|clear]       # Searchable notification history log
  python send_cmd.py keyword-watch [list|add <kw>|remove <kw|all>]
  python send_cmd.py rules [list|add <name> --when=<trig> --do=<act>|remove <id|all>|test <id>]

HARDWARE STATIONS & PERMISSIONS HUB:
  python send_cmd.py permissions [list|request|settings <id>] # Interactive Android permission manager
  python send_cmd.py camera [status|test|perm|settings]       # Camera hardware station & capture test
  python send_cmd.py mic [--live|test|stop|play|perm]          # Real-time continuous recording & live VU meter
  python send_cmd.py notif [status|test [msg]|perm|settings]  # Notification manager & alert test
  python send_cmd.py storage [status|test|perm|settings|files]# Storage capacity, test & file explorer

SHELL & REMOTE EXECUTION:
  python send_cmd.py shell <cmd>               # Execute direct sh -c command on device
  python send_cmd.py status                    # Full hardware, network & bridge status

SCREEN CAPTURE & UI AUTOMATION:
  python send_cmd.py screenshot [out.jpg]      # Capture live device screen to JPEG
  python send_cmd.py inspect [delay_sec]       # Dump interactive UI node hierarchy
  python send_cmd.py tap <label>               # Find UI element by text/desc and tap it
  python send_cmd.py click <x> <y>             # Tap exact screen coordinates
  python send_cmd.py swipe <x1> <y1> <x2> <y2> # Perform drag or swipe gesture
  python send_cmd.py type <text>               # Input text into focused/editable field
  python send_cmd.py key <BACK|HOME|RECENTS|LOCK_SCREEN|QUICK_SETTINGS>

INTERNET CONTROLLER, DNS FILTER & NETWORK DIAGNOSTICS:
  python send_cmd.py net-speed [--live]                        # Live Rx/Tx bandwidth speed & data meter
  python send_cmd.py net-filter [status|block|unblock|list|logs|start|stop]
  python send_cmd.py net-filter category [list|enable|disable] <ADS|TRACKERS|MALWARE|ADULT|SOCIAL|GAMBLING>
  python send_cmd.py net-filter analytics [top_n]              # Per-domain query frequency & block stats
  python send_cmd.py net-diag [ping <host>|dns <domain>|port <host> <port>]

SYSTEM HARDWARE TOGGLES:
  python send_cmd.py torch [on|off|toggle]     # Toggle camera flashlight
  python send_cmd.py dnd [on|off|toggle]       # Toggle Do Not Disturb mode
  python send_cmd.py wifi                      # Open Wi-Fi quick panel & view SSID/IP
  python send_cmd.py bluetooth                 # Open Bluetooth settings & view status
  python send_cmd.py volume [0-15|up|down|mute]# View or control audio stream volumes
  python send_cmd.py brightness <0-255>        # Set screen brightness level
  python send_cmd.py media <play|next|prev>    # Control system media playback

GPS & LIVE TELEMETRY:
  python send_cmd.py location                  # Get current device GPS fix & telemetry
  python send_cmd.py location --live [sec]     # Real-time continuous GPS stream (default 1s)
  python send_cmd.py track [sec]               # Live GPS telemetry radar (Ctrl+C to stop)

DEVICE FILE MANAGER & CLIPBOARD SYNC:
  python send_cmd.py fs-ls [path]              # List directory contents on device
  python send_cmd.py cat <remote_path>         # Read text file from device
  python send_cmd.py put <local> <remote_path> # Upload local file to device path
  python send_cmd.py rm <remote_path>          # Delete file or folder on device
  python send_cmd.py stat <remote_path>        # Inspect file metadata
  python send_cmd.py clip [text]               # Read or set Android system clipboard

APPLICATION & P2P CONTROLS:
  python send_cmd.py login [client_name]       # Authenticate CLI via Biometrics/PIN on phone
  python send_cmd.py apps [filter] [--system]  # List installed applications (shows [BLOCKED] status)
  python send_cmd.py open <appName|pkg|url>    # Launch app or URL on device
  python send_cmd.py devices                   # Discover nearby AeroShare peers
  python send_cmd.py share <file|text> [ip]    # Beam file or text to peer

FLAGS & URL CONFIGURATION:
  python send_cmd.py set-url <new_url>     Update tunnel/server URL in scripts & config
  --url <http_or_ws_url>                   Override target server URL
  --ip <phone_lan_ip>                      Connect to another device on Wi-Fi/Hotspot
  --http                                   Force HTTP REST execution
  --json                                   Output raw JSON response
================================================================================
""")


def execute_app_visibility(action="status", as_json=False):
    act = (action or "status").strip().lower()
    if act in ["hide", "hidden", "on", "true", "enable", "stealth"]:
        res = http_post("/api/app/visibility", {"hidden": True})
    elif act in ["show", "unhide", "visible", "off", "false", "disable"]:
        res = http_post("/api/app/visibility", {"hidden": False})
    else:
        res = http_get("/api/app/visibility")

    if as_json:
        print(json.dumps(res, indent=2))
        return res

    if not res or (isinstance(res, dict) and not res.get("success", True) and res.get("error")):
        err_msg = res.get("error") if isinstance(res, dict) else "No response from AeroShare server"
        print(f"[ERROR] App visibility failed: {err_msg}")
        return res

    hidden = res.get("hidden", False)
    synthetic = res.get("osSyntheticIconFallback", False)
    fully_hidden = res.get("fullyHidden", hidden and not synthetic)
    adb_cmd = res.get("adbHideCommand", "adb shell settings put global show_hidden_icon_apps_enabled 0")
    adb_grant = res.get("adbGrantCommand", f"adb shell pm grant {res.get('packageName', 'com.aistudio.aicompanion.bseft')} android.permission.WRITE_SECURE_SETTINGS")
    print("\n" + "=" * 78)
    print(" 🕵️  AEROSHARE LAUNCHER VISIBILITY")
    print("=" * 78)
    if fully_hidden:
        status_label = "🙈 FULLY HIDDEN (Removed from launcher & apps list)"
    elif hidden and synthetic:
        status_label = "⚠️ ALIAS DISABLED (Android 10+ still shows App Info icon)"
    elif hidden:
        status_label = "🙈 HIDDEN (Launcher alias disabled)"
    else:
        status_label = "👁️ VISIBLE (Shown in apps list)"
    print(f" Apps List Status : {status_label}")
    print(f" Package          : {res.get('packageName')}")
    print(f" Launcher Entries : {res.get('launcherEntriesCount', 0 if hidden else 1)} active")
    print(f" MainActivity     : 🟢 Enabled (Direct launch & background bridge active)")
    if hidden and synthetic:
        print(" Android 10+ Note : Stock Android blocks non-root apps from hiding completely.")
        print(" Tap Behavior     : Tapping icon opens System App Info (not AI Companion).")
        print(f" Full Hide (ADB)  : {adb_cmd}")
        print(f" Auto-Hide Grant  : {adb_grant}")
    print(f" Reopen / Unhide  : {res.get('reopenHint')}")
    print("=" * 78 + "\n")
    return res


def execute_set_url(raw_url, as_json=False):
    if not raw_url:
        print("[ERROR] Usage: python send_cmd.py set-url <https://private-relay-bridge.onrender.com/c/YOUR_CLI_KEY>")
        return
    clean = raw_url.strip().rstrip("/")
    if clean.endswith("/ws"):
        clean = clean[:-3].rstrip("/")
    if clean.startswith("wss://"):
        http_url = "https://" + clean[6:]
        ws_url = clean + "/ws"
    elif clean.startswith("ws://"):
        http_url = "http://" + clean[5:]
        ws_url = clean + "/ws"
    elif clean.startswith("http://"):
        http_url = clean
        ws_url = "ws://" + clean[7:] + "/ws"
    elif clean.startswith("https://"):
        http_url = clean
        ws_url = "wss://" + clean[8:] + "/ws"
    else:
        if "onrender.com" in clean or "trycloudflare.com" in clean or "lhr.life" in clean or "ngrok" in clean:
            http_url = "https://" + clean
            ws_url = "wss://" + clean + "/ws"
        else:
            http_url = f"http://{clean}:8080" if ":" not in clean else f"http://{clean}"
            ws_url = f"ws://{clean.split(':')[0]}:8000/ws"

    # 1. Update send_cmd.py (and any .py scripts in the same directory) in-place
    script_dir = os.path.dirname(os.path.abspath(__file__))
    updated_files = []
    for fname in os.listdir(script_dir):
        if fname.endswith(".py"):
            fpath = os.path.join(script_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                new_content = re.sub(
                    r'^CLOUDFLARE_TUNNEL_URL\s*=\s*".*"',
                    f'CLOUDFLARE_TUNNEL_URL = "{http_url}"',
                    content,
                    flags=re.MULTILINE
                )
                new_content = re.sub(
                    r'^CLOUDFLARE_WS_URL\s*=\s*".*"',
                    f'CLOUDFLARE_WS_URL = "{ws_url}"',
                    new_content,
                    flags=re.MULTILINE
                )
                if new_content != content:
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    updated_files.append(fname)
            except Exception:
                pass

    # 2. Save persistent target URL & public tunnel URL files
    save_stored_target_url(http_url)
    try:
        with open(os.path.expanduser("~/.aero_public_tunnel_url"), "w", encoding="utf-8") as f:
            f.write(http_url)
    except Exception:
        pass

    # 3. Notify phone server if reachable
    if AUTH_TOKEN:
        try:
            http_post("/api/screen/tunnel", {"publicUrl": http_url})
        except Exception:
            pass

    if as_json:
        print(json.dumps({
            "success": True,
            "httpUrl": http_url,
            "wsUrl": ws_url,
            "updatedScripts": updated_files
        }, indent=2))
    else:
        print(f"✓ Updated URL in scripts ({', '.join(updated_files) if updated_files else 'config saved'}):")
        print(f"  HTTP URL      : {http_url}")
        print(f"  WebSocket URL : {ws_url}")


async def main():
    global AUTH_TOKEN, HTTP_SERVER_URL, WS_SERVER_URL
    raw_args = sys.argv[1:]
    if not raw_args or raw_args[0] in ["-h", "--help", "help"]:
        print_help()
        return

    # Extract global flags
    force_http = "--http" in raw_args
    include_system = "--system" in raw_args or "-s" in raw_args
    as_json = "--json" in raw_args

    # Check for --token <val>, --key <val>, or --url <val>
    cleaned_args = []
    skip_next = False
    for i, a in enumerate(raw_args):
        if skip_next:
            skip_next = False
            continue
        if a in ["--token", "--key", "-k"] and i + 1 < len(raw_args):
            AUTH_TOKEN = raw_args[i + 1]
            skip_next = True
            continue
        if a.startswith("--token="):
            AUTH_TOKEN = a.split("=", 1)[1]
            continue
        if a.startswith("--key="):
            AUTH_TOKEN = a.split("=", 1)[1]
            continue
        if a in ["--url", "-u"] and i + 1 < len(raw_args):
            custom_url = raw_args[i + 1].rstrip("/")
            if not custom_url.startswith("http"):
                custom_url = f"http://{custom_url}:8080" if ":" not in custom_url else f"http://{custom_url}"
            HTTP_SERVER_URL = custom_url
            LOCAL_HTTP_URL = custom_url
            WS_SERVER_URL = custom_url.replace("http://", "ws://").replace("https://", "wss://") + ("/ws" if not custom_url.endswith("/ws") else "")
            save_stored_target_url(custom_url)
            skip_next = True
            continue
        if a.startswith("--url="):
            custom_url = a.split("=", 1)[1].rstrip("/")
            if not custom_url.startswith("http"):
                custom_url = f"http://{custom_url}:8080" if ":" not in custom_url else f"http://{custom_url}"
            HTTP_SERVER_URL = custom_url
            LOCAL_HTTP_URL = custom_url
            WS_SERVER_URL = custom_url.replace("http://", "ws://").replace("https://", "wss://") + ("/ws" if not custom_url.endswith("/ws") else "")
            save_stored_target_url(custom_url)
            continue
        if a in ["--ip", "--host"] and i + 1 < len(raw_args):
            ip_val = raw_args[i + 1].strip()
            custom_url = f"http://{ip_val}:8080" if ":" not in ip_val else f"http://{ip_val}"
            HTTP_SERVER_URL = custom_url
            LOCAL_HTTP_URL = custom_url
            WS_SERVER_URL = f"ws://{ip_val.split(':')[0]}:8000/ws"
            save_stored_target_url(custom_url)
            skip_next = True
            continue
        if a.startswith("--ip=") or a.startswith("--host="):
            ip_val = a.split("=", 1)[1].strip()
            custom_url = f"http://{ip_val}:8080" if ":" not in ip_val else f"http://{ip_val}"
            HTTP_SERVER_URL = custom_url
            LOCAL_HTTP_URL = custom_url
            WS_SERVER_URL = f"ws://{ip_val.split(':')[0]}:8000/ws"
            save_stored_target_url(custom_url)
            continue
        if a not in ["--http", "--system", "-s", "--json"]:
            cleaned_args.append(a)

    args = cleaned_args
    if not args:
        print_help()
        return

    cmd = args[0].lower()

    # Quick URL updater command (works before or after login)
    if cmd in ["set-url", "seturl", "url", "update-url"]:
        target_u = args[1] if len(args) > 1 else ""
        execute_set_url(target_u, as_json=as_json)
        return

    # Authentication (Face Scan on Android Device)
    if cmd in ["login", "auth", "pair"]:
        cname = args[1] if len(args) > 1 else "Termux-Workstation"
        execute_login(cname, as_json=as_json)
        return

    # Relay Health Check (unauthenticated endpoint check)
    if cmd in ["health", "relay-health", "ping"]:
        execute_relay_health(as_json=as_json)
        return

    # ZERO-TRUST ACCESS GATE: Termux MUST be authenticated before executing ANY command
    if not AUTH_TOKEN:
        print("\n" + "=" * 72)
        print(" 🔒 ACCESS DENIED: TERMINAL NOT AUTHORIZED")
        print("=" * 72)
        print(" AeroShare requires on-device biometric or PIN authorization.")
        print(" Termux has not been authorized, or authorization was rejected.")
        print()
        print(" To authorize this terminal, run:")
        print("   python send_cmd.py login")
        print()
        print(" Then confirm with Face, Fingerprint, or PIN on your phone.")
        print("=" * 72 + "\n")
        return

    # Direct Shell Execution Bridge
    if cmd in ["shell", "sh", "exec", "cmd"]:
        shell_cmd = " ".join(args[1:])
        execute_shell(shell_cmd, as_json=as_json)
        return

    # System Status Snapshot
    if cmd in ["status", "sys-status", "info"]:
        execute_system_status(as_json=as_json)
        return

    # Live Screenshot Capture
    if cmd in ["screenshot", "screencap", "shot", "capture"]:
        out_file = args[1] if len(args) > 1 else "screenshot.jpg"
        execute_screenshot(out_file, as_json=as_json)
        return

    # System Toggles (DND, Wi-Fi, Bluetooth, Brightness)
    if cmd in ["dnd", "donotdisturb"]:
        st = args[1] if len(args) > 1 else "toggle"
        execute_system_toggle("dnd", state=st, as_json=as_json)
        return

    if cmd in ["wifi", "wi-fi"]:
        execute_system_toggle("wifi", as_json=as_json)
        return

    if cmd in ["bluetooth", "bt"]:
        execute_system_toggle("bluetooth", as_json=as_json)
        return

    if cmd in ["brightness", "bright"]:
        lvl = int(args[1]) if len(args) > 1 and args[1].isdigit() else 128
        execute_system_toggle("brightness", extra={"brightness": lvl}, as_json=as_json)
        return

    # File Manager Operations (fs-ls, cat, put, rm, stat)
    if cmd in ["fs-ls", "ls-dir"]:
        path = args[1] if len(args) > 1 else "/sdcard"
        execute_fs_op("list", path=path, as_json=as_json)
        return

    if cmd in ["cat", "read-file", "fs-read"]:
        if len(args) < 2:
            print("[ERROR] Usage: python send_cmd.py cat <remote_path>")
            return
        execute_fs_op("read", path=args[1], as_json=as_json)
        return

    if cmd in ["put", "upload", "fs-write"]:
        if len(args) < 3:
            print("[ERROR] Usage: python send_cmd.py put <local_file_or_text> <remote_path>")
            return
        src = args[1]
        dst = args[2]
        import base64
        if os.path.exists(src) and os.path.isfile(src):
            with open(src, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            execute_fs_op("write", path=dst, extra={"base64": b64}, as_json=as_json)
        else:
            execute_fs_op("write", path=dst, extra={"content": src}, as_json=as_json)
        return

    if cmd in ["rm", "del", "delete", "fs-rm"]:
        if len(args) < 2:
            print("[ERROR] Usage: python send_cmd.py rm <remote_path>")
            return
        execute_fs_op("delete", path=args[1], as_json=as_json)
        return

    if cmd in ["stat", "file-info"]:
        if len(args) < 2:
            print("[ERROR] Usage: python send_cmd.py stat <remote_path>")
            return
        execute_fs_op("stat", path=args[1], as_json=as_json)
        return

    # Clipboard Get / Set
    if cmd in ["clip-get"]:
        res = http_get("/api/clipboard/get")
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(res.get("text", ""))
        return

    if cmd in ["clip-set"]:
        txt = " ".join(args[1:])
        res = http_post("/api/clipboard/set", {"text": txt})
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            print(f"✓ Clipboard updated ({len(txt)} chars)")
        return

    # UI Text Input & Key Events over HTTP
    if cmd in ["type", "input", "input-text"]:
        if len(args) < 2:
            print("[ERROR] Usage: python send_cmd.py type <text>")
            return
        execute_ui_http("INPUT_TEXT", {"text": " ".join(args[1:])}, as_json=as_json)
        return

    if cmd in ["key", "keyevent"]:
        key_name = args[1].upper() if len(args) > 1 else "BACK"
        execute_ui_http("KEY", {"key": key_name}, as_json=as_json)
        return

    if cmd in ["ui-tree"]:
        res = http_get("/api/ui/tree")
        if as_json:
            print(json.dumps(res, indent=2))
        elif res.get("success", False):
            nodes = res.get("nodes", [])
            print("\n" + "=" * 60)
            print(f" PHONE SCREEN UI MAP ({len(nodes)} root node(s)):")
            print("=" * 60)
            print_tree(nodes)
            print("=" * 60 + "\n")
        else:
            print(f"✗ UI Tree inspection failed: {res.get('error', 'Accessibility service disabled')}")
        return

    # AeroShare P2P & File Sharing Controls
    if cmd in ["devices", "peers", "nearby"]:
        execute_devices(as_json=as_json)
        return

    if cmd in ["share", "send"]:
        if len(args) < 2:
            print("[ERROR] Missing file path or text to share.")
            print("Usage: python send_cmd.py share <filePath | text> [targetDeviceIp]")
            return
        target_input = args[1]
        peer_ip = args[2] if len(args) > 2 else ""
        execute_share(target_input, peer_ip, as_json=as_json)
        return

    if cmd in ["transfers", "tx"]:
        execute_transfers(as_json=as_json)
        return

    if cmd in ["history", "transfers-history"]:
        execute_history(as_json=as_json)
        return

    if cmd in ["cancel", "abort"]:
        if len(args) < 2:
            print("[ERROR] Missing transfer ID to cancel.")
            print("Usage: python send_cmd.py cancel <transferId>")
            return
        execute_cancel(args[1])
        return

    if cmd in ["clip", "clipboard"]:
        text_arg = " ".join(args[1:]) if len(args) > 1 else None
        execute_clip(text_arg, as_json=as_json)
        return

    if cmd in ["radar"]:
        enable_arg = None
        if len(args) > 1:
            enable_arg = args[1].lower() in ["on", "true", "start", "enable"]
        execute_radar(enable_arg, as_json=as_json)
        return

    # Hardware Stations & Interactive Permissions Hub
    if cmd in ["permissions", "permission", "perms", "perm"]:
        if len(args) > 1 and args[1].lower() in ["request", "ask", "grant", "settings", "open", "config", "list", "status", "ls"]:
            sub = args[1].lower()
            tgt = args[2] if len(args) > 2 else None
        elif len(args) > 1:
            sub = "request"
            tgt = args[1]
        else:
            sub = "list"
            tgt = None
        execute_permissions(sub, tgt, as_json=as_json)
        return

    if cmd in ["camera", "cam"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        execute_camera(sub, as_json=as_json)
        return

    if cmd in ["mic", "microphone", "audio-station", "record", "rec"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        dur = int(args[2]) if len(args) > 2 and args[2].isdigit() else (int(args[1]) if len(args) > 1 and args[1].isdigit() else 3)
        tgt = args[2] if len(args) > 2 else (args[1] if len(args) > 1 and sub in ["play", "listen"] else None)
        execute_mic(sub, duration_sec=dur, target_arg=tgt, as_json=as_json)
        return

    if cmd in ["notif", "notification-station", "notifications"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        txt = " ".join(args[2:]) if len(args) > 2 else None
        execute_notif(sub, text=txt, as_json=as_json)
        return

    if cmd in ["storage-station", "disk"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        execute_storage_station(sub, as_json=as_json)
        return

    # Hardware & Diagnostics
    if cmd in ["battery", "batt", "power"]:
        execute_battery(as_json=as_json)
        return

    if cmd in ["battery-opt", "battery-optimization", "doze", "unrestricted"]:
        action_arg = args[1] if len(args) > 1 else "STATUS"
        execute_battery_opt(action_arg, as_json=as_json)
        return

    if cmd in ["sensors", "sensor"]:
        execute_sensors(as_json=as_json)
        return

    if cmd in ["location", "gps", "loc", "where", "coords", "track", "live-location"]:
        sub = args[1].lower() if len(args) > 1 else ""
        if sub in ["settings", "open"]:
            execute_system_toggle("location", as_json=as_json)
        elif sub in ["live", "--live", "-l", "stream", "track", "watch", "start"]:
            interval = float(args[2]) if len(args) > 2 and args[2].replace('.', '', 1).isdigit() else 1.0
            execute_live_location(interval_sec=interval, as_json=as_json)
        elif sub in ["stop", "untrack"]:
            http_post("/api/location/live", {"action": "STOP"})
            print("[✓] Live GPS stream stopped on phone.")
        elif cmd in ["track", "live-location"]:
            interval = float(args[1]) if len(args) > 1 and args[1].replace('.', '', 1).isdigit() else 1.0
            execute_live_location(interval_sec=interval, as_json=as_json)
        else:
            execute_location(as_json=as_json)
        return

    if cmd in ["torch", "flash", "flashlight"]:
        if len(args) > 1 and args[1].lower() == "toggle":
            execute_system_toggle("torch", state="toggle", as_json=as_json)
            return
        enable = True
        if len(args) > 1 and args[1].lower() in ["off", "false", "0", "disable"]:
            enable = False
        execute_torch(enable, as_json=as_json)
        return

    if cmd in ["vibrate", "vib", "haptic"]:
        duration = int(args[1]) if len(args) > 1 and args[1].isdigit() else 200
        execute_vibrate(duration, as_json=as_json)
        return

    if cmd in ["tts", "speak", "voice"]:
        if len(args) < 2:
            print("[ERROR] Missing text to speak.")
            print("Usage: python send_cmd.py tts <text>")
            return
        execute_tts(" ".join(args[1:]), as_json=as_json)
        return

    if cmd in ["tone", "beep"]:
        freq = int(args[1]) if len(args) > 1 and args[1].isdigit() else 440
        dur = int(args[2]) if len(args) > 2 and args[2].isdigit() else 500
        execute_tone(freq, dur, as_json=as_json)
        return

    if cmd in ["volume", "vol"]:
        if len(args) > 1 and args[1].lower() in ["up", "down", "mute", "unmute"]:
            execute_system_toggle("volume", state=args[1].lower(), as_json=as_json)
            return
        level = args[1] if len(args) > 1 else None
        stream = args[2] if len(args) > 2 else "MEDIA"
        execute_volume(level, stream, as_json=as_json)
        return

    if cmd in ["hud", "floating"]:
        if len(args) < 2:
            print("[ERROR] Missing text for HUD overlay.")
            print("Usage: python send_cmd.py hud <text> [title]")
            return
        title = args[2] if len(args) > 2 else "⚡ Termux HUD"
        execute_hud(args[1], title, as_json=as_json)
        return

    if cmd in ["notify", "notification"]:
        if len(args) < 2:
            print("[ERROR] Missing message for notification.")
            print("Usage: python send_cmd.py notify <title> <message>")
            return
        title = args[1] if len(args) > 2 else "Aura Alert"
        msg = " ".join(args[2:]) if len(args) > 2 else args[1]
        execute_notify(title, msg, as_json=as_json)
        return

    # Comprehensive Hardware Station Suite CLI Router
    if cmd in ["api-help", "api_help", "api-docs", "apidocs", "help-api"]:
        execute_api_help(as_json=as_json)
        return

    if cmd in ["hide-app", "hide_app", "stealth-on"]:
        execute_app_visibility("hide", as_json=as_json)
        return

    if cmd in ["show-app", "show_app", "unhide-app", "unhide_app", "stealth-off"]:
        execute_app_visibility("show", as_json=as_json)
        return

    if cmd in ["app-visibility", "app_visibility", "visibility", "stealth"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        execute_app_visibility(sub, as_json=as_json)
        return

    if cmd in ["battery", "batt", "power"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        execute_battery_station(sub, as_json=as_json)
        return

    if cmd in ["sensors", "sensor", "telemetry-sensors"]:
        execute_sensors_station(as_json=as_json)
        return

    if cmd in ["display", "screen"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        val = args[2] if len(args) > 2 else None
        execute_display_station(sub, val, as_json=as_json)
        return

    if cmd in ["network", "net", "wifi-cell"]:
        execute_network_station(as_json=as_json)
        return

    # Network Moderation & DNS Filter Suite
    if cmd in ["net-filter", "network-filter", "moderation", "dns-block", "firewall", "filter"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        tgt = args[2] if len(args) > 2 else None
        extra = args[3] if len(args) > 3 else None
        execute_network_moderation(sub, tgt, extra, as_json=as_json)
        return

    # Live Bandwidth & Speed Meter
    if cmd in ["net-speed", "speed", "bandwidth", "traffic"]:
        is_live = "--live" in raw_args or "-l" in raw_args or (len(args) > 1 and args[1].lower() in ["live", "--live", "watch"])
        execute_network_speed(live=is_live, as_json=as_json)
        return

    # Per-App Live Network Traffic, Single-App Watch, App Firewall & Live Browsing
    if cmd in ["net-apps", "app-traffic", "net-top", "traffic-apps"]:
        is_live = "--live" in raw_args or "-l" in raw_args or (len(args) > 1 and args[1].lower() in ["live", "watch"])
        execute_per_app_network("all", live=is_live, as_json=as_json)
        return

    if cmd in ["net-app", "app-net", "watch-net"]:
        is_live = "--live" in raw_args or "-l" in raw_args
        clean_rest = [a for a in args[1:] if a not in ["--live", "-l", "live", "watch"]]
        if not clean_rest:
            execute_per_app_network("all", live=is_live, as_json=as_json)
            return
        sub_first = clean_rest[0].lower()
        if sub_first in ["block", "deny", "cut", "off"]:
            tgt = " ".join(clean_rest[1:]) if len(clean_rest) > 1 else None
            execute_per_app_network("block", target=tgt, as_json=as_json)
        elif sub_first in ["unblock", "allow", "on", "restore"]:
            tgt = " ".join(clean_rest[1:]) if len(clean_rest) > 1 else "all"
            execute_per_app_network("unblock", target=tgt, as_json=as_json)
        else:
            tgt = " ".join(clean_rest)
            execute_per_app_network("single", target=tgt, live=is_live, as_json=as_json)
        return

    if cmd in ["inspect-site", "check-site", "site-info", "site-meta", "scan-site"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_network_moderation("inspect", tgt, as_json=as_json)
        return

    if cmd in ["dns-protect", "private-dns", "auto-dns", "system-dns"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else "status"
        execute_network_moderation("dns", tgt, as_json=as_json)
        return

    if cmd in ["dns-export", "export-dns", "export-logs", "dump-dns"]:
        tgt = args[1] if len(args) > 1 else "csv"
        execute_network_moderation("export", tgt, as_json=as_json)
        return

    if cmd in ["block-screen", "blockscreen", "warning-screen"]:
        tgt = args[1] if len(args) > 1 else "status"
        extra = " ".join(args[2:]) if len(args) > 2 else None
        execute_network_moderation("block-screen", tgt, extra, as_json=as_json)
        return

    if cmd in ["block-site", "site-block", "block-domain", "block-url"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_network_moderation("block", tgt, as_json=as_json)
        return

    if cmd in ["unblock-site", "site-unblock", "unblock-domain", "unblock-url"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else "all"
        execute_network_moderation("unblock", tgt, as_json=as_json)
        return

    if cmd in ["blocked-sites", "sites", "blocklist"]:
        execute_network_moderation("list", as_json=as_json)
        return

    if cmd in ["net-block", "block-net", "cut-net"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        if tgt and (
            tgt.startswith("http://") or tgt.startswith("https://") or
            ("." in tgt and not tgt.startswith(("com.", "org.", "net.", "io.", "in.", "de.", "uk.")))
        ):
            execute_network_moderation("block", tgt, as_json=as_json)
        else:
            execute_per_app_network("block", target=tgt, as_json=as_json)
        return

    if cmd in ["net-unblock", "unblock-net", "allow-net"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else "all"
        if tgt and tgt.lower() != "all" and (
            tgt.startswith("http://") or tgt.startswith("https://") or
            ("." in tgt and not tgt.startswith(("com.", "org.", "net.", "io.", "in.", "de.", "uk.")))
        ):
            execute_network_moderation("unblock", tgt, as_json=as_json)
        else:
            execute_per_app_network("unblock", target=tgt, as_json=as_json)
        return

    if cmd in ["browsing", "live-browsing", "current-browsing", "connections", "sockets"]:
        is_live = "--live" in raw_args or "-l" in raw_args or (len(args) > 1 and args[1].lower() in ["live", "watch"])
        execute_per_app_network("browsing", live=is_live, as_json=as_json)
        return

    # Active Network Diagnostics (Ping, DNS Lookup, TCP Port Check)
    if cmd in ["net-diag", "diag", "ping", "nslookup", "dns-lookup", "port-check"]:
        if cmd == "ping":
            sub = "ping"
            tgt = args[1] if len(args) > 1 else "8.8.8.8"
            extra = args[2] if len(args) > 2 else "3"
        elif cmd in ["nslookup", "dns-lookup"]:
            sub = "dns"
            tgt = args[1] if len(args) > 1 else "google.com"
            extra = None
        elif cmd == "port-check":
            sub = "port"
            tgt = args[1] if len(args) > 1 else "127.0.0.1"
            extra = args[2] if len(args) > 2 else "80"
        else:
            sub = args[1].lower() if len(args) > 1 else "ping"
            tgt = args[2] if len(args) > 2 else None
            extra = args[3] if len(args) > 3 else None
        execute_network_diag(sub, tgt, extra, as_json=as_json)
        return

    # App Guard: Real-Time Installation Monitor, App Blocker, Uninstaller & Deep Package Controls
    if cmd in ["app-guard", "appguard", "guard", "pkg-guard"]:
        sub = args[1].lower() if len(args) > 1 and not args[1].startswith("--") else "status"
        tgt = " ".join(args[2:]) if len(args) > 2 else None
        execute_app_guard(sub, target=tgt, raw_args=raw_args, as_json=as_json)
        return

    if cmd in ["block-app", "blockapp", "lock-app"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_app_guard("block", target=tgt, raw_args=raw_args, as_json=as_json)
        return

    if cmd in ["unblock-app", "unblockapp", "unlock-app"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else "all"
        execute_app_guard("unblock", target=tgt, raw_args=raw_args, as_json=as_json)
        return

    if cmd in ["uninstall", "uninstall-app", "remove-app", "pkg-uninstall"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_app_guard("uninstall", target=tgt, raw_args=raw_args, as_json=as_json)
        return

    if cmd in ["force-stop", "forcestop", "kill-app", "stop-app"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_app_guard("force-stop", target=tgt, raw_args=raw_args, as_json=as_json)
        return

    if cmd in ["app-info", "appinfo", "pkg-info", "inspect-app", "what-is", "app-details", "verify-app"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_app_guard("info", target=tgt, raw_args=raw_args, as_json=as_json)
        return

    if cmd in ["verify", "apk-verify", "verify-apk", "apk-info", "check-apk", "check-app"]:
        tgt = " ".join([a for a in args[1:] if not a.startswith("--")]) if len(args) > 1 else None
        execute_apk_ops("verify", target=tgt, as_json=as_json)
        return

    if cmd in ["app-events", "install-log", "pkg-events"]:
        tgt = args[1] if len(args) > 1 else None
        execute_app_guard("events", target=tgt, raw_args=raw_args, as_json=as_json)
        return

    # Suite 1: Screen-Time Analytics & Daily App Usage Limits
    if cmd in ["screen-time", "screentime", "app-usage", "usage-stats"]:
        top_arg = args[1] if len(args) > 1 else "25"
        execute_screen_time("stats", target=top_arg, as_json=as_json)
        return

    if cmd in ["usage-limit", "app-limit", "time-limit", "quota"]:
        sub = args[1].lower() if len(args) > 1 else "stats"
        if sub in ["set", "add", "limit"]:
            tgt = args[2] if len(args) > 2 else None
            mins = int(args[3]) if len(args) > 3 and args[3].isdigit() else 0
            execute_screen_time("set", target=tgt, minutes=mins, as_json=as_json)
        elif sub in ["remove", "rm", "clear", "unlimit", "delete"]:
            tgt = args[2] if len(args) > 2 else "all"
            execute_screen_time("remove", target=tgt, as_json=as_json)
        elif len(args) >= 3 and args[2].isdigit():
            execute_screen_time("set", target=args[1], minutes=int(args[2]), as_json=as_json)
        else:
            execute_screen_time("stats", target="25", as_json=as_json)
        return

    # Suite 2: Intruder & Device Unlock Monitor
    if cmd in ["unlock-monitor", "intruder", "unlock-log", "unlock-logs", "security-monitor"]:
        sub = args[1].lower() if len(args) > 1 and not args[1].startswith("--") else ("policy" if any(a.startswith("--") for a in raw_args[1:]) else "status")
        tgt = args[2] if len(args) > 2 else None
        execute_unlock_monitor(sub, target=tgt, raw_args=raw_args, as_json=as_json)
        return

    # Suite 3: Clipboard & Notification History + Keyword Watch Alerts
    if cmd in ["clip-history", "clipboard-history", "clip-log"]:
        sub = args[1] if len(args) > 1 else ""
        tgt = " ".join(args[2:]) if len(args) > 2 else ""
        execute_history_keyword_watch("clip", subcmd=sub, target=tgt, as_json=as_json)
        return

    if cmd in ["notif-history", "notification-history", "notif-log"]:
        sub = args[1] if len(args) > 1 else ""
        tgt = " ".join(args[2:]) if len(args) > 2 else ""
        execute_history_keyword_watch("notif", subcmd=sub, target=tgt, as_json=as_json)
        return

    if cmd in ["keyword-watch", "keywords", "watch-keyword", "kw-watch"]:
        sub = args[1].lower() if len(args) > 1 else "list"
        tgt = " ".join(args[2:]) if len(args) > 2 else ""
        execute_history_keyword_watch("keywords", subcmd=sub, target=tgt, as_json=as_json)
        return

    # Suite 4: Scheduled & Event-Driven Automation Rules Engine
    if cmd in ["rules", "automation", "rule", "auto-rules"]:
        sub = args[1].lower() if len(args) > 1 and not args[1].startswith("--") else "list"
        non_flag_rest = [a for a in args[2:] if not a.startswith("--")]
        tgt = " ".join(non_flag_rest) if non_flag_rest else None
        execute_automation_rules(sub, target=tgt, raw_args=raw_args, as_json=as_json)
        return

    # Suite 5: APK Backup Extractor & Remote APK Installer
    if cmd in ["apk-backup", "backup-apk", "extract-apk"]:
        tgt = " ".join(args[1:]) if len(args) > 1 else None
        execute_apk_ops("backup", target=tgt, as_json=as_json)
        return

    if cmd in ["apk-backups", "list-backups", "backups"]:
        execute_apk_ops("list", as_json=as_json)
        return

    if cmd in ["apk-install", "install-apk"]:
        force_flag = "--force" in raw_args or "-f" in raw_args
        clean_parts = [a for a in args[1:] if a not in ["--force", "-f"]]
        tgt = " ".join(clean_parts) if clean_parts else None
        execute_apk_ops("install", target=tgt, force=force_flag, as_json=as_json)
        return

    if cmd in ["audio", "sound", "mixer"]:
        sub = args[1].lower() if len(args) > 1 else "status"
        p1 = args[2] if len(args) > 2 else None
        p2 = args[3] if len(args) > 3 else None
        execute_audio_station(sub, p1, p2, as_json=as_json)
        return

    if cmd in ["media", "player", "music"]:
        action = args[1].upper() if len(args) > 1 else "PLAY_PAUSE"
        execute_media(action, as_json=as_json)
        return

    if cmd in ["files", "storage", "ls-files", "dir"]:
        if cmd == "storage":
            if len(args) > 1 and args[1].lower() in ["status", "info", "details", "test", "check", "bench", "perm", "settings", "request"]:
                execute_storage_station(args[1].lower(), as_json=as_json)
                return
            elif len(args) == 1:
                execute_storage_station("status", as_json=as_json)
                return
            elif len(args) > 1 and args[1].lower() == "files":
                folder = args[2] if len(args) > 2 else "DOWNLOADS"
                limit = int(args[3]) if len(args) > 3 and args[3].isdigit() else 30
                execute_storage(folder, limit, as_json=as_json)
                return
        folder = args[1] if len(args) > 1 else "DOWNLOADS"
        limit = int(args[2]) if len(args) > 2 and args[2].isdigit() else 30
        execute_storage(folder, limit, as_json=as_json)
        return

    if cmd in ["sms", "text"]:
        if len(args) < 2:
            print("[ERROR] Missing phone number.")
            print("Usage: python send_cmd.py sms <phone_number> [message_text]")
            return
        phone = args[1]
        msg = " ".join(args[2:]) if len(args) > 2 else ""
        execute_sms(phone, msg, as_json=as_json)
        return

    # 1. LIST APPS: apps, list-apps, list_apps, list, ls
    if cmd in ["apps", "list-apps", "list_apps", "list", "ls"]:
        filter_query = " ".join(args[1:]) if len(args) > 1 else ""
        await execute_list_apps(include_system=include_system, filter_query=filter_query, as_json=as_json, force_http=force_http)
        return

    # 2. OPEN / LAUNCH APPS: open, launch, run, start
    if cmd in ["open", "launch", "run", "start"]:
        if len(args) < 2:
            print("[ERROR] Missing app name, package name, or URL.")
            print("Usage: python send_cmd.py open <appName | packageName | url>")
            return
        target = " ".join(args[1:])
        await execute_launch_app(target, force_http=force_http)
        return

    # HTTP REST Fallback for UI / Gesture commands when --http is specified or websockets is missing
    if force_http or not HAS_WEBSOCKETS:
        if cmd in ["back", "home", "recents", "notifications", "quick_settings", "lock_screen"]:
            execute_ui_http("KEY", {"key": cmd.upper()}, as_json=as_json)
            return
        if cmd == "inspect":
            delay = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0
            if delay > 0:
                time.sleep(delay)
            res = http_get("/api/ui/tree")
            if as_json:
                print(json.dumps(res, indent=2))
            elif res.get("success", False):
                nodes = res.get("nodes", [])
                print_tree(nodes)
            else:
                print(f"[ERROR] {res.get('error', 'Inspect failed')}")
            return
        if cmd == "tap" and len(args) >= 2:
            execute_ui_http("CLICK_TEXT", {"text": " ".join(args[1:])}, as_json=as_json)
            return
        if cmd == "click" and len(args) >= 3:
            execute_ui_http("TAP", {"x": float(args[1]), "y": float(args[2])}, as_json=as_json)
            return
        if cmd == "swipe" and len(args) >= 5:
            dur = int(args[5]) if len(args) > 5 else 300
            execute_ui_http("SWIPE", {
                "x1": float(args[1]), "y1": float(args[2]),
                "x2": float(args[3]), "y2": float(args[4]),
                "durationMs": dur
            }, as_json=as_json)
            return
        if cmd == "next":
            execute_ui_http("SCROLL", {"direction": "DOWN"}, as_json=as_json)
            return
        if cmd == "toast" and len(args) >= 2:
            res = http_post("/api/toast", {"message": " ".join(args[1:])})
            print(f"✓ Dispatched toast: '{' '.join(args[1:])}'")
            return

    if not HAS_WEBSOCKETS:
        print("[ERROR] The 'websockets' library is required for streaming WebSocket operations.")
        print("Install via: pip install websockets (or pass --http to use HTTP REST)")
        return

    now_ms = int(time.time() * 1000)

    candidate_ws_urls = []
    if WS_SERVER_URL:
        candidate_ws_urls.append(WS_SERVER_URL)
    for fallback_ws in ["ws://127.0.0.1:8080/ws", LOCAL_WS_URL]:
        if fallback_ws not in candidate_ws_urls:
            candidate_ws_urls.append(fallback_ws)

    ws = None
    connected_ws_url = None
    for ws_url in candidate_ws_urls:
        is_remote = not ws_url.startswith(("ws://127.0.0.1", "ws://localhost"))
        open_to = 15.0 if is_remote else 2.0
        connect_url = ws_url
        if ws_url.startswith(("ws://127.0.0.1:8080", "ws://localhost:8080")) and AUTH_TOKEN and "token=" not in ws_url:
            sep = "&" if "?" in ws_url else "?"
            connect_url = f"{ws_url}{sep}token={urllib.parse.quote(AUTH_TOKEN)}"
        try:
            ws = await asyncio.wait_for(websockets.connect(connect_url, open_timeout=open_to), timeout=open_to + 2.0)
            connected_ws_url = ws_url
            break
        except Exception:
            continue

    if not ws:
        print(f"[ERROR] Could not connect to WebSocket at {WS_SERVER_URL} or ws://127.0.0.1:8080/ws")
        return

    is_remote_ws = bool(connected_ws_url and not connected_ws_url.startswith(("ws://127.0.0.1", "ws://localhost")))

    async def await_ack_or_auth_error(req_id=None, wait_sec=2.0):
        deadline = time.time() + wait_sec
        while time.time() < deadline:
            rem = max(0.15, deadline - time.time())
            try:
                raw_reply = await asyncio.wait_for(ws.recv(), timeout=rem)
                reply_data = json.loads(raw_reply)
                rtype = str(reply_data.get("type", "")).upper()
                if rtype in ["HELLO", "PING", "PONG", "ACCESSIBILITY_SCREEN_UPDATE", "HEARTBEAT"]:
                    continue
                if rtype == "AUTH_REQUIRED":
                    check_unauthorized_response({"error": "UNAUTHORIZED_DEVICE"})
                    return reply_data
                resp_rid = reply_data.get("requestId") or reply_data.get("reqId")
                if not req_id or not resp_rid or resp_rid == req_id:
                    return reply_data
            except asyncio.TimeoutError:
                break
            except Exception:
                break
        return None

    try:
        async with ws:
            try:
                await asyncio.wait_for(ws.recv(), timeout=0.6)
            except asyncio.TimeoutError:
                pass

            if cmd in ["back", "home", "recents", "notifications"]:
                packet = {
                    "type": "ACCESSIBILITY_GESTURE",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "gestureId": f"{cmd}-{now_ms}",
                    "gestureType": cmd.upper(),
                    "startX": 0.0,
                    "startY": 0.0,
                    "durationMs": 50,
                    "token": AUTH_TOKEN
                }
                await ws.send(json.dumps(packet))
                print(f"Dispatched system action: {cmd.upper()}")

            elif cmd == "inspect":
                delay = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0
                if delay > 0:
                    print(f"Switch to target app! Inspecting in {delay}s...")
                    for i in range(delay, 0, -1):
                        print(f" {i}...", end="", flush=True)
                        await asyncio.sleep(1)
                    print(" Inspecting!")

                packet = {
                    "type": "ACCESSIBILITY_INSPECT",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "target": "active_window",
                    "token": AUTH_TOKEN
                }
                print("Sent ACCESSIBILITY_INSPECT -> Waiting for screen nodes...")
                await ws.send(json.dumps(packet))

                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=8.0)
                    data = json.loads(msg)
                    if data.get("type") == "ACCESSIBILITY_INSPECT_RESULT":
                        nodes = data.get("nodes", [])
                        print("\n" + "=" * 60)
                        print(f" PHONE SCREEN UI MAP ({len(nodes)} root node(s)):")
                        print("=" * 60)
                        print_tree(nodes)
                        print("=" * 60 + "\n")
                        break

            elif cmd == "tap" and len(args) >= 2:
                target_label = " ".join(args[1:])
                packet = {
                    "type": "ACCESSIBILITY_INSPECT",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "target": "active_window",
                    "token": AUTH_TOKEN
                }
                print(f"Searching screen for '{target_label}'...")
                await ws.send(json.dumps(packet))

                matched_targets = []
                while True:
                    msg = await asyncio.wait_for(ws.recv(), timeout=8.0)
                    data = json.loads(msg)
                    if data.get("type") == "ACCESSIBILITY_INSPECT_RESULT":
                        nodes = data.get("nodes", [])
                        print_tree(nodes, depth=0, find_text=target_label, matched_targets=matched_targets)
                        break

                if matched_targets:
                    found_name, tx, ty = matched_targets[0]
                    click_packet = {
                        "type": "ACCESSIBILITY_GESTURE",
                        "timestamp": now_ms,
                        "sessionId": "cli-" + str(now_ms),
                        "gestureId": f"click-{now_ms}",
                        "gestureType": "CLICK",
                        "action": "CLICK",
                        "startX": float(tx),
                        "startY": float(ty),
                        "x": int(tx),
                        "y": int(ty),
                        "durationMs": 100,
                        "token": AUTH_TOKEN
                    }
                    await ws.send(json.dumps(click_packet))
                    print(f"✓ Tapped '{found_name}' at ({tx}, {ty})")
                else:
                    print(f"✗ Could not find element matching '{target_label}' on screen.")
                    print("  Try running 'python send_cmd.py inspect' to see full UI structure.")

            elif cmd == "click" and len(args) >= 3:
                x, y = int(args[1]), int(args[2])
                packet = {
                    "type": "ACCESSIBILITY_GESTURE",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "gestureId": f"click-{now_ms}",
                    "gestureType": "CLICK",
                    "action": "CLICK",
                    "startX": float(x),
                    "startY": float(y),
                    "x": x,
                    "y": y,
                    "durationMs": 100,
                    "token": AUTH_TOKEN
                }
                await ws.send(json.dumps(packet))
                print(f"Dispatched CLICK at ({x}, {y})")

            elif cmd == "swipe" and len(args) >= 5:
                x1, y1 = int(args[1]), int(args[2])
                x2, y2 = int(args[3]), int(args[4])
                dur = int(args[5]) if len(args) > 5 else 300
                packet = {
                    "type": "ACCESSIBILITY_GESTURE",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "gestureId": f"swipe-{now_ms}",
                    "gestureType": "SWIPE",
                    "action": "SWIPE",
                    "startX": float(x1),
                    "startY": float(y1),
                    "endX": float(x2),
                    "endY": float(y2),
                    "x": x1,
                    "y": y1,
                    "durationMs": dur,
                    "token": AUTH_TOKEN
                }
                await ws.send(json.dumps(packet))
                print(f"Dispatched SWIPE from ({x1}, {y1}) to ({x2}, {y2}) [{dur}ms]")

            elif cmd == "next":
                packet = {
                    "type": "ACCESSIBILITY_GESTURE",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "gestureId": f"next-{now_ms}",
                    "gestureType": "SWIPE",
                    "action": "SWIPE",
                    "startX": 500.0,
                    "startY": 1400.0,
                    "endX": 500.0,
                    "endY": 300.0,
                    "durationMs": 250,
                    "token": AUTH_TOKEN
                }
                await ws.send(json.dumps(packet))
                print("Dispatched scroll to next item")

            elif cmd == "toast" and len(args) >= 2:
                msg = " ".join(args[1:])
                req_id = f"msg_{now_ms}"
                packet = {
                    "type": "AI_STREAM",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "requestId": req_id,
                    "reqId": req_id,
                    "textChunk": msg,
                    "isFinal": True,
                    "token": AUTH_TOKEN
                }
                await ws.send(json.dumps(packet))
                ack = await await_ack_or_auth_error(req_id, wait_sec=5.0 if is_remote_ws else 1.5)
                if not ack or ack.get("type") != "AUTH_REQUIRED":
                    print(f"Dispatched toast: '{msg}'")

            else:
                prompt_text = " ".join(args)
                req_id = f"msg_{now_ms}"
                packet = {
                    "type": "AI_STREAM",
                    "timestamp": now_ms,
                    "sessionId": "cli-" + str(now_ms),
                    "requestId": req_id,
                    "reqId": req_id,
                    "textChunk": prompt_text,
                    "isFinal": True,
                    "token": AUTH_TOKEN
                }
                await ws.send(json.dumps(packet))
                ack = await await_ack_or_auth_error(req_id, wait_sec=6.0 if is_remote_ws else 2.0)
                if ack and ack.get("type") == "AUTH_REQUIRED":
                    pass
                elif ack and ack.get("success", False):
                    print(f"✓ Delivered to phone: '{prompt_text}'")
                elif is_remote_ws:
                    print(f"[!] Sent '{prompt_text}' to relay, but phone did not confirm receipt.")
                    print("    Ensure the AeroShare app is connected to wss://private-relay-bridge.onrender.com/p/<PHONE_KEY>/ws")
                else:
                    print(f"Dispatched message: '{prompt_text}'")

    except ConnectionRefusedError:
        print(f"[!] Could not connect to WebSocket at {WS_SERVER_URL}.")
        print("    If Termux relay is offline, start it with: python mock_server.py")
        print("    Or pass --http to execute directly against port 8080.")
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
