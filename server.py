"""
Aegis Shield API Server
Lightweight, zero-dependency HTTP REST gateway with Stripe monetization rails.
Pure Python standard library (http.server).
"""

import json
import secrets
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from shield_engine import AegisShieldEngine

STORE_DIR = Path(__file__).parent / "data"
TOKENS_FILE = STORE_DIR / "authorized_tokens.json"
STRIPE_PAYMENT_URL = "https://buy.stripe.com/14A8wQ6AF69AeMw5Ve7Zu01"


def init_token_store():
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    if not TOKENS_FILE.exists():
        initial_data = {
            "tokens": {
                "demo-test-token-2026": {
                    "tier": "demo",
                    "created_at": time.time(),
                    "rate_limit_per_min": 60
                }
            }
        }
        with open(TOKENS_FILE, "w", encoding="utf-8") as f:
            json.dump(initial_data, f, indent=2)


def issue_token(customer_email: str, plan_name: str = "Pro Plan") -> str:
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    tokens = {}
    if TOKENS_FILE.exists():
        try:
            with open(TOKENS_FILE, "r", encoding="utf-8") as f:
                tokens = json.load(f).get("tokens", {})
        except Exception:
            tokens = {}
    
    new_token = f"aegis_{secrets.token_urlsafe(24)}"
    tokens[new_token] = {
        "customer": customer_email,
        "plan": plan_name,
        "created_at": time.time(),
        "active": True
    }
    with open(TOKENS_FILE, "w", encoding="utf-8") as f:
        json.dump({"tokens": tokens}, f, indent=2)
    return new_token


class AegisShieldHandler(BaseHTTPRequestHandler):

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/health":
            self._send_json(200, {
                "status": "healthy",
                "service": "Aegis Shield Security Gateway",
                "version": "1.0.0",
                "monetization": "Stripe Live Connected",
                "checkout_url": STRIPE_PAYMENT_URL
            })
            return

        if path == "/v1/checkout":
            self.send_response(302)
            self.send_header("Location", STRIPE_PAYMENT_URL)
            self.end_headers()
            return

        self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""

        try:
            payload = json.loads(raw_body) if raw_body else {}
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return

        if path == "/v1/scan":
            prompt = payload.get("prompt", "")
            if not prompt:
                self._send_json(400, {"error": "'prompt' field is required"})
                return

            # Check optional auth header for metrics
            auth_header = self.headers.get("Authorization", "")
            verdict = AegisShieldEngine.scan(prompt)
            self._send_json(200, {
                "timestamp": time.time(),
                "verdict": verdict
            })
            return

        if path == "/v1/webhook":
            # Stripe Webhook Endpoint
            event_type = payload.get("type", "")
            event_data = payload.get("data", {}).get("object", {})

            if event_type in ["checkout.session.completed", "payment_intent.succeeded"]:
                customer_details = event_data.get("customer_details", {})
                email = customer_details.get("email") or event_data.get("receipt_email") or "customer@stripe.checkout"
                token = issue_token(email, plan_name="Pro Plan")
                print(f"[Stripe Webhook] Payment received! Issued API token: {token} for {email}")
                self._send_json(200, {
                    "status": "success",
                    "event": event_type,
                    "token_provisioned": token
                })
                return

            self._send_json(200, {"status": "event_acknowledged", "event": event_type})
            return

        self._send_json(404, {"error": "Endpoint not found"})


def run_server(host: str = "0.0.0.0", port: int = 8787):
    init_token_store()
    server_address = (host, port)
    httpd = HTTPServer(server_address, AegisShieldHandler)
    print(f"[*] Aegis Shield API listening on http://{host}:{port}")
    print(f"[*] Connected Stripe Checkout: {STRIPE_PAYMENT_URL}")
    httpd.serve_forever()


if __name__ == "__main__":
    run_server()
