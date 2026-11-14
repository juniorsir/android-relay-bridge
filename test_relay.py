#!/usr/bin/env python3
"""
Test Suite for Strict & Hardened Private 1-to-1 Relay Server
Verifies:
1. Public health check: GET /health returns 200 with {"status": "UP"} and security headers.
2. Fail-closed role isolation between /p/{PHONE_KEY} and /c/{CLI_KEY}.
3. Rejection of cross-key access (phone key on CLI route or CLI key on phone route).
4. Offline phone handling (WebSocket error packet and HTTP 503).
5. Phone registration and targeted PING/PONG heartbeats.
6. 1-to-1 Command routing: CLI WebSocket -> Relay -> Phone -> Relay -> CLI.
7. HTTP-over-WS REST bridge: POST /c/{CLI_KEY}/api/... -> Phone -> HTTP 200.
8. Phone socket replacement on reconnect (clean close of old socket).
9. CLI connection limit (max 2 concurrent CLI sockets, 3rd gets 429).
10. Brute-force probe jail: >10 failed probes triggers 5-minute ban (404).
11. Screen update dropping: ACCESSIBILITY_SCREEN_UPDATE is never sent to CLI.
12. Directory traversal prevention: ../ or // in endpoint returns 400 Bad Request.
13. Anti-flooding defense: sending rapid pings (>5/sec) closes socket with code 1008.
"""

import asyncio
import json
import os
import sys
import unittest
from aiohttp import web, WSServerHandshakeError
from aiohttp.test_utils import AioHTTPTestCase

TEST_PHONE_KEY = "phone_secret_key_abcdef_1234567890"
TEST_CLI_KEY = "cli_secret_key_zyxwvu_0987654321"

os.environ["PHONE_KEY"] = TEST_PHONE_KEY
os.environ["CLI_KEY"] = TEST_CLI_KEY
os.environ["PORT"] = "10000"

import relay_server


class TestPrivateRelay(AioHTTPTestCase):
    async def get_application(self) -> web.Application:
        return relay_server.create_app()

    async def test_01_health_check_zero_leak_and_headers(self):
        """GET /health, /healthz, /ping return 200 OK with ok, phoneConnected, cliClients and security headers."""
        for path in ("/health", "/health/", "/healthz", "/healthz/", "/ping", "/ping/"):
            resp = await self.client.get(path)
            self.assertEqual(resp.status, 200)
            data = await resp.json()
            self.assertTrue(data.get("ok"))
            self.assertIn("phoneConnected", data)
            self.assertIn("cliClients", data)
            self.assertEqual(data.get("status"), "UP")

            # Enterprise security headers
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
            self.assertIn("default-src 'none'", resp.headers.get("Content-Security-Policy", ""))
            self.assertIn("max-age=31536000", resp.headers.get("Strict-Transport-Security", ""))
            self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")
            self.assertEqual(resp.headers.get("Server"), "Relay")

        # HEAD /health
        head_resp = await self.client.head("/health")
        self.assertEqual(head_resp.status, 200)

    async def test_01b_authenticated_health_checks(self):
        """Authenticated CLI and Phone health endpoints report detailed diagnostics."""
        # 1. Unauthenticated or wrong key -> 401 or 404
        self.assertIn((await self.client.get("/c/invalid_key_123456789012345/health")).status, (401, 404))
        self.assertIn((await self.client.get("/p/invalid_key_123456789012345/health")).status, (401, 404))

        # 2. CLI health when phone is offline
        resp_cli = await self.client.get(f"/c/{TEST_CLI_KEY}/health")
        self.assertEqual(resp_cli.status, 200)
        cli_data = await resp_cli.json()
        self.assertEqual(cli_data.get("status"), "UP")
        self.assertEqual(cli_data.get("role"), "cli")
        self.assertFalse(cli_data.get("phone_connected"))
        self.assertIsNone(cli_data.get("phone_last_seen_sec"))
        self.assertIn("uptime_sec", cli_data)

        # Also test /c/{key}/status and /c/{key}/api/health
        resp_status = await self.client.get(f"/c/{TEST_CLI_KEY}/status")
        self.assertEqual(resp_status.status, 200)
        resp_api_health = await self.client.get(f"/c/{TEST_CLI_KEY}/api/health")
        self.assertEqual(resp_api_health.status, 200)

        # 3. Phone connects, CLI health reflects phone_connected: True
        phone_ws = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone_ws.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        resp_cli_online = await self.client.get(f"/c/{TEST_CLI_KEY}/health")
        self.assertEqual(resp_cli_online.status, 200)
        online_data = await resp_cli_online.json()
        self.assertTrue(online_data.get("phone_connected"))
        self.assertIsNotNone(online_data.get("phone_last_seen_sec"))

        # 4. Phone health endpoint
        resp_phone = await self.client.get(f"/p/{TEST_PHONE_KEY}/health")
        self.assertEqual(resp_phone.status, 200)
        phone_data = await resp_phone.json()
        self.assertEqual(phone_data.get("status"), "UP")
        self.assertEqual(phone_data.get("role"), "phone")

        await phone_ws.close()

    async def test_02_strict_role_and_key_isolation(self):
        """Phone key cannot access CLI routes; CLI key cannot access phone routes."""
        self.assertEqual((await self.client.get("/")).status, 404)
        self.assertIn((await self.client.get("/ws")).status, (401, 404))

        # Phone key attempting CLI routes -> 401 or 404
        resp1 = await self.client.get(f"/c/{TEST_PHONE_KEY}/api/security/status")
        self.assertIn(resp1.status, (401, 404))

        with self.assertRaises(WSServerHandshakeError) as ctx1:
            await self.client.ws_connect(f"/c/{TEST_PHONE_KEY}/ws")
        self.assertIn(ctx1.exception.status, (401, 404))

        # CLI key attempting Phone routes -> 401 or 404
        with self.assertRaises(WSServerHandshakeError) as ctx2:
            await self.client.ws_connect(f"/p/{TEST_CLI_KEY}/ws")
        self.assertIn(ctx2.exception.status, (401, 404))

    async def test_03_offline_phone_error_handling(self):
        """When phone is offline, HTTP returns 503 and CLI WebSocket gets error reply."""
        resp = await self.client.post(
            f"/c/{TEST_CLI_KEY}/api/system/status",
            json={"action": "check"}
        )
        self.assertEqual(resp.status, 503)
        data = await resp.json()
        self.assertFalse(data.get("success"))
        self.assertIn("Phone offline", data.get("error", ""))

        cli_ws = await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")
        req = {
            "type": "HTTP_RPC",
            "endpoint": "/api/system/status",
            "requestId": "req_offline_001",
            "reqId": "req_offline_001"
        }
        await cli_ws.send_str(json.dumps(req))
        reply = json.loads(await cli_ws.receive_str())
        self.assertEqual(reply.get("type"), "HTTP_RPC_RESULT")
        self.assertEqual(reply.get("requestId"), "req_offline_001")
        self.assertFalse(reply.get("success"))
        self.assertIn("Phone offline", reply.get("error", ""))
        await cli_ws.close()

    async def test_04_phone_registration_and_ping_pong(self):
        """Phone registers on /p/{PHONE_KEY}/ws and PING gets immediate PONG."""
        phone_ws = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone_ws.send_str(json.dumps({
            "type": "HELLO",
            "timestamp": 1700000000000,
            "sessionId": "phone_sess"
        }))
        await asyncio.sleep(0.05)

        relay: relay_server.PrivateRelay = self.app["relay"]
        self.assertIsNotNone(relay.phone_ws)

        await phone_ws.send_str(json.dumps({
            "type": "PING",
            "pingId": "p_123",
            "sessionId": "phone_sess",
            "timestamp": 1700000001000
        }))
        pong = json.loads(await phone_ws.receive_str())
        self.assertEqual(pong.get("type"), "PONG")
        self.assertEqual(pong.get("pingId"), "p_123")
        self.assertEqual(pong.get("sessionId"), "phone_sess")
        self.assertEqual(pong.get("requestTimestamp"), 1700000001000)

        await phone_ws.close()

    async def test_05_websocket_cli_1_to_1_routing(self):
        """Commands from CLI WebSocket route strictly to phone, and results route back."""
        phone_ws = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone_ws.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        cli_ws = await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")

        await cli_ws.send_str(json.dumps({
            "type": "SHELL_EXEC",
            "command": "whoami",
            "requestId": "cmd_001",
            "reqId": "cmd_001"
        }))

        phone_msg = json.loads(await phone_ws.receive_str())
        self.assertEqual(phone_msg.get("type"), "SHELL_EXEC")
        self.assertEqual(phone_msg.get("command"), "whoami")
        self.assertEqual(phone_msg.get("requestId"), "cmd_001")

        await phone_ws.send_str(json.dumps({
            "type": "SHELL_EXEC_RESULT",
            "requestId": "cmd_001",
            "reqId": "cmd_001",
            "success": True,
            "stdout": "u0_a1878"
        }))

        cli_reply = json.loads(await cli_ws.receive_str())
        self.assertEqual(cli_reply.get("type"), "SHELL_EXEC_RESULT")
        self.assertEqual(cli_reply.get("requestId"), "cmd_001")
        self.assertTrue(cli_reply.get("success"))
        self.assertEqual(cli_reply.get("stdout"), "u0_a1878")

        await cli_ws.close()
        await phone_ws.close()

    async def test_06_http_rest_post_bridge_1_to_1(self):
        """HTTP POST on /c/{CLI_KEY}/api/... bridges to phone and returns HTTP 200."""
        phone_ws = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone_ws.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        async def phone_worker():
            try:
                while True:
                    msg = json.loads(await phone_ws.receive_str())
                    if msg.get("type") == "HTTP_RPC":
                        req_id = msg.get("requestId")
                        endpoint = msg.get("endpoint")
                        if endpoint == "/api/security/status":
                            reply = {
                                "type": "HTTP_RPC_RESULT",
                                "requestId": req_id,
                                "reqId": req_id,
                                "success": True,
                                "status": "SECURE"
                            }
                        elif endpoint == "/api/shell/exec" and msg.get("token") == "bad":
                            reply = {
                                "type": "AUTH_REQUIRED",
                                "requestId": req_id,
                                "reqId": req_id,
                                "error": "UNAUTHORIZED_DEVICE"
                            }
                        else:
                            reply = {
                                "type": "HTTP_RPC_RESULT",
                                "requestId": req_id,
                                "reqId": req_id,
                                "success": True
                            }
                        await phone_ws.send_str(json.dumps(reply))
            except Exception:
                pass

        task = asyncio.create_task(phone_worker())

        try:
            resp = await self.client.post(
                f"/c/{TEST_CLI_KEY}/api/security/status",
                headers={"Authorization": "Bearer good_token"},
                json={"check": True}
            )
            self.assertEqual(resp.status, 200)
            data = await resp.json()
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("status"), "SECURE")

            resp_unauth = await self.client.post(
                f"/c/{TEST_CLI_KEY}/api/shell/exec",
                headers={"Authorization": "Bearer bad"},
                json={"cmd": "reboot"}
            )
            self.assertEqual(resp_unauth.status, 401)
            unauth_data = await resp_unauth.json()
            self.assertEqual(unauth_data.get("error"), "UNAUTHORIZED_DEVICE")

        finally:
            task.cancel()
            await phone_ws.close()

    async def test_07_phone_socket_replacement_on_reconnect(self):
        """Reconnecting phone cleanly closes the older phone socket."""
        phone1 = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone1.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        relay: relay_server.PrivateRelay = self.app["relay"]
        self.assertIsNotNone(relay.phone_ws)

        phone2 = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone2.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        close_frame = await phone1.receive()
        self.assertIn(close_frame.type, (relay_server.WSMsgType.CLOSE, relay_server.WSMsgType.CLOSED))
        self.assertTrue(phone1.closed)
        self.assertIsNotNone(relay.phone_ws)
        self.assertFalse(relay.phone_ws.closed)
        self.assertFalse(phone2.closed)

        await phone2.close()

    async def test_08_cli_connection_limits(self):
        """Max 2 concurrent CLI connections; 3rd is rejected with 429."""
        cli1 = await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")
        cli2 = await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")

        with self.assertRaises(WSServerHandshakeError) as ctx:
            await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")
        self.assertEqual(ctx.exception.status, 429)

        await cli1.close()
        await cli2.close()

    async def test_09_brute_force_probe_jail(self):
        """More than 10 failed probes from an IP triggers a 5-minute ban (404)."""
        attacker_ip = "203.0.113.88"
        headers = {"X-Forwarded-For": attacker_ip}

        for i in range(11):
            res = await self.client.get(f"/p/invalid_probe_{i}/ws", headers=headers)
            self.assertIn(res.status, (401, 404))

        res_banned = await self.client.get("/health", headers=headers)
        self.assertEqual(res_banned.status, 404)

    async def test_10_screen_updates_never_broadcast(self):
        """ACCESSIBILITY_SCREEN_UPDATE is completely dropped and never sent to CLI."""
        phone_ws = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone_ws.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        cli_ws = await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")

        await phone_ws.send_str(json.dumps({
            "type": "ACCESSIBILITY_SCREEN_UPDATE",
            "pkg": "com.android.settings"
        }))

        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(cli_ws.receive_str(), timeout=0.1)

        await cli_ws.close()
        await phone_ws.close()

    async def test_11_directory_traversal_rejection(self):
        """Directory traversal attempts (../ or //) must return 400 Bad Request."""
        phone_ws = await self.client.ws_connect(f"/p/{TEST_PHONE_KEY}/ws")
        await phone_ws.send_str(json.dumps({"type": "HELLO"}))
        await asyncio.sleep(0.05)

        # Path with //
        resp_slash = await self.client.get(f"/c/{TEST_CLI_KEY}/api/security//status")
        self.assertEqual(resp_slash.status, 400)
        data = await resp_slash.json()
        self.assertIn("directory traversal not allowed", data.get("error"))

        # Path with ../
        resp_dotdot = await self.client.get(f"/c/{TEST_CLI_KEY}/api/../../etc/passwd")
        self.assertIn(resp_dotdot.status, (400, 404))

        await phone_ws.close()

    async def test_12_websocket_ping_flood_protection(self):
        """Flooding PING frames (>5/sec) closes the socket with policy violation code 1008."""
        cli_ws = await self.client.ws_connect(f"/c/{TEST_CLI_KEY}/ws")

        # Send 10 rapid PINGs
        for i in range(10):
            await cli_ws.send_str(json.dumps({"type": "PING", "pingId": str(i)}))

        closed = False
        for _ in range(15):
            msg = await cli_ws.receive()
            if msg.type in (relay_server.WSMsgType.CLOSE, relay_server.WSMsgType.CLOSED):
                closed = True
                break
        self.assertTrue(closed)
        self.assertEqual(cli_ws.close_code, 1008)

    async def test_13_ws_auth_and_script_download(self):
        """Verify WS /ws authentication via query/header and GET /c/<CLI_KEY>/send_cmd.py."""
        # 1. WS /ws with ?token=CLI_KEY
        cli_token_ws = await self.client.ws_connect(f"/ws?token={TEST_CLI_KEY}")
        self.assertFalse(cli_token_ws.closed)
        await cli_token_ws.close()

        # 2. WS /ws with Authorization: Bearer CLI_KEY
        cli_bearer_ws = await self.client.ws_connect("/ws", headers={"Authorization": f"Bearer {TEST_CLI_KEY}"})
        self.assertFalse(cli_bearer_ws.closed)
        await cli_bearer_ws.close()

        # 3. GET /c/<CLI_KEY>/send_cmd.py
        resp = await self.client.get(f"/c/{TEST_CLI_KEY}/send_cmd.py")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("Content-Type"), "text/x-python")


def run_tests():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestPrivateRelay)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    run_tests()
