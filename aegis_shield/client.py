import urllib.request
import json
from typing import Dict, Any, Optional


class AegisShieldClient:
    """Client for Aegis Shield API cloud gateway."""
    def __init__(self, api_key: str, base_url: str = "http://127.0.0.1:8787"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def scan(self, text: str) -> Dict[str, Any]:
        url = f"{self.base_url}/v1/shield/scan"
        payload = json.dumps({"text": text}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "AegisShield-Python-SDK/1.0"
        }
        req = urllib.request.Request(url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
