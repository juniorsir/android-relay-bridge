# Private 1-to-1 Android ⇄ Termux Relay Server (Strict & Hardened)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/juniorsir/android-relay-bridge)

A minimal, private 1-to-1 cloud bridge designed for deployment on Render. Its sole purpose is connecting a single Android Companion phone app to a single Termux CLI client (`send_cmd.py`) over the internet with zero persistence, zero payload logging, and fail-closed key isolation.

---

## ⚡ 3-Step Setup

### Step 1: Deploy on Render
1. Push this repository to GitHub or GitLab.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** → **Blueprint** and connect this repository.
3. Render automatically provisions the web service using [render.yaml](file:///data/data/com.termux/files/home/render.yaml) and generates two distinct 256-bit secret keys:
   - `PHONE_KEY` (Phone-only WebSocket gateway)
   - `CLI_KEY` (Termux CLI WebSocket & HTTP REST gateway)
4. Once deployed, copy `PHONE_KEY` and `CLI_KEY` from your Render service **Environment** tab.

### Step 2: Configure Android Companion App
In the Android Companion app settings, set the outbound WebSocket URL:

```text
wss://<your-render-app>.onrender.com/p/<PHONE_KEY>/ws
```

*The phone connects outbound, sends `HELLO`, and keeps the live tunnel open for commands.*

### Step 3: Configure Termux CLI (`send_cmd.py`)
In Termux, point `send_cmd.py` to your private CLI endpoint:

```bash
python send_cmd.py set-url https://<your-render-app>.onrender.com/c/<CLI_KEY>
```

Authenticate and execute commands:

```bash
# Authenticate CLI with device biometric/PIN
python send_cmd.py login Termux-Workstation

# Run commands over the internet
python send_cmd.py apps
python send_cmd.py toast "Connected via Private Relay"
python send_cmd.py inspect
```

---

## 🔒 Strict Security Hardening Overview

* **Zero Public Attack Surface**: Only `GET /health` (`/healthz`, `/ping`) is public (returns `200 OK` `{"status": "UP"}` with zero metadata, rate-limited to 60 req/min).
* **Authenticated Diagnostics & Health**:
  * **CLI Health** (`GET /c/{CLI_KEY}/health` or `/c/{CLI_KEY}/status`): Returns real-time relay uptime, phone WebSocket connectivity status (`phone_connected: true/false`), phone last-seen elapsed seconds, and active CLI session counts.
  * **Phone Health** (`GET /p/{PHONE_KEY}/health`): Returns relay health for the phone client.
* **Strict Role Isolation**:
  * **Phone WebSocket** (`/p/{PHONE_KEY}/ws`): Max 1 connection; cannot act as CLI requester. Replaces stale phone connections cleanly on reconnect.
  * **CLI Gateway** (`/c/{CLI_KEY}/ws` and `/c/{CLI_KEY}/api/...`): Max 2 concurrent sockets (rejects excess with `429 Too Many Requests`); cannot impersonate the phone.
  * Every other path returns `404 Not Found` immediately before upgrading WebSockets or touching memory.
* **Fail-Closed Key Validation**:
  * Minimum length 24 characters.
  * Forbidden character checks (blocks whitespace, control characters, URL delimiters).
  * Entropy validation (requires at least 8 unique characters; blocks repeating patterns).
  * Fails closed (`exit(1)`) on startup if `PHONE_KEY == CLI_KEY` or invalid.
* **Brute-Force Auto-Jail**: Any IP making >10 failed `/p/` or `/c/` probes per minute is blocked with `404 Not Found` for 5 minutes.
* **Slowloris & Inactivity Mitigations**:
  * 15-second initial handshake timeout: sockets that fail to send a valid first message within 15 seconds are terminated immediately.
  * Idle reaper drops inactive CLI connections after 180 seconds.
* **Anti-Flooding Frame Throttling**:
  * Capped at 40 messages/second and 5 PINGs/second per socket.
  * Violating sockets are terminated with WebSocket code `1008` (Policy Violation).
* **Directory Traversal Protection**:
  * All `/c/{CLI_KEY}/api/{endpoint}` paths are strictly sanitized against `..`, `//`, `\`, and null bytes (returns `400 Bad Request` if invalid).
* **Enterprise Security Headers**:
  * `X-Content-Type-Options: nosniff`
  * `X-Frame-Options: DENY`
  * `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  * `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  * `Referrer-Policy: no-referrer`
  * `Cache-Control: no-store, no-cache, must-revalidate, private`
  * `Server: Relay`
* **Zero Persistence & Zero Payload Logging**:
  * Never writes to disk.
  * Access logging disabled (`access_log=None`).
  * Log inputs are sanitized to strip ANSI codes, newlines, and control characters (CWE-117 protection).
  * Never logs keys, tokens, command parameters, URLs, or device data.
* **Queue Capacity & High Throughput**:
  * Maximum 64 concurrent requests in memory (prevents memory exhaustion).
  * 16 MB maximum message and body limits for screenshots and file transfers.
