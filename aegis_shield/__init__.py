"""
Aegis Shield - Autonomous AI Security & Prompt Injection Defense SDK
Zero-dependency, sub-millisecond detection of prompt injections, jailbreaks, and system prompt leaks.
"""

from aegis_shield.engine import AegisShieldEngine
from aegis_shield.client import AegisShieldClient

__version__ = "1.0.0"
__all__ = ["AegisShieldEngine", "AegisShieldClient", "scan"]


def scan(text: str):
    """Convenience helper for local zero-dependency scan."""
    return AegisShieldEngine.scan(text)
