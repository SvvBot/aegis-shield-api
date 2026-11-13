"""
Aegis Shield Core Security Engine
High-throughput prompt injection, jailbreak, and adversarial vector detector.
Zero-dependency, pure Python standard library.
"""

import re
import math
from typing import Dict, Any, List, Tuple


class AegisShieldEngine:
    """Evaluates text payloads for security threats, jailbreaks, and injection patterns."""

    INJECTION_PATTERNS = [
        (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|directions)", re.I), "Instruction Override", 0.95),
        (re.compile(r"(disregard|forget)\s+(all\s+)?(previous|prior|existing)\s+(rules|guidelines|context)", re.I), "Context Wipe Attack", 0.95),
        (re.compile(r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(DAN|unrestricted|jailbroken|an\s+AI\s+without\s+rules)", re.I), "Persona Jailbreak (DAN)", 0.90),
        (re.compile(r"(system\s*prompt|hidden\s*instructions|core\s*directives)\s*:\s*(reveal|print|output|dump)", re.I), "Prompt Extraction Vector", 0.85),
        (re.compile(r"<\s*script[^>]*>|javascript\s*:\s*|data\s*:\s*text/html", re.I), "XSS / Script Injection", 0.90),
        (re.compile(r"base64\s*:\s*[A-Za-z0-9+/=]{20,}", re.I), "Base64 Encoded Payload Evasion", 0.75),
        (re.compile(r"\[\s*system\s*\]\s*:\s*", re.I), "Fake System Role Injection", 0.88),
        (re.compile(r"bot-score\s*:\s*|bot-tier\s*:\s*|benchmark-fixture", re.I), "Telemetry & Honeypot Trap", 0.85),
    ]

    SUSPICIOUS_DELIMITERS = [
        "---END SYSTEM PROMPT---",
        "===BEGIN ADMIN OVERRIDE===",
        "```system",
        "<!-- SYSTEM OVERRIDE -->",
        "<|im_start|>system",
        "<|im_end|>",
    ]

    @classmethod
    def calculate_entropy(cls, text: str) -> float:
        """Calculates Shannon entropy to detect high-entropy obfuscation or packed payloads."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in prob)

    @classmethod
    def scan(cls, prompt: str) -> Dict[str, Any]:
        """
        Scans a prompt and returns risk assessment:
        {
            "safe": bool,
            "risk_score": float (0.0 to 1.0),
            "threats_detected": List[str],
            "details": Dict[str, Any]
        }
        """
        if not prompt or not prompt.strip():
            return {
                "safe": True,
                "risk_score": 0.0,
                "threats_detected": [],
                "action": "ALLOW",
                "details": {"entropy": 0.0, "matches": []}
            }

        threats = []
        max_score = 0.0
        matches_detail = []

        # 1. Pattern checks
        for regex, threat_name, severity in cls.INJECTION_PATTERNS:
            found = regex.findall(prompt)
            if found:
                threats.append(threat_name)
                max_score = max(max_score, severity)
                matches_detail.append({
                    "threat": threat_name,
                    "severity": severity,
                    "matches_count": len(found)
                })

        # 2. Structural delimiter hijacking
        for delim in cls.SUSPICIOUS_DELIMITERS:
            if delim.lower() in prompt.lower():
                threats.append(f"Synthetic System Delimiter: {delim}")
                max_score = max(max_score, 0.92)

        # 3. Shannon entropy check for obfuscated payload blocks
        entropy = cls.calculate_entropy(prompt)
        if len(prompt) > 80 and entropy > 4.8 and not any(w in prompt for w in ["the", "and", "is", "of"]):
            threats.append("High-Entropy Obfuscation / Encoded Exploit")
            max_score = max(max_score, 0.80)

        is_safe = max_score < 0.65
        action = "ALLOW" if is_safe else ("QUARANTINE" if max_score < 0.85 else "BLOCK")

        return {
            "safe": is_safe,
            "risk_score": round(max_score, 3),
            "threats_detected": sorted(list(set(threats))),
            "action": action,
            "details": {
                "entropy": round(entropy, 2),
                "length": len(prompt),
                "matches": matches_detail
            }
        }
