"""
VALI shared optional LLM client (OpenAI-compatible).
Fully optional — safe offline fallback when disabled or unavailable.
"""

import os
from typing import Optional

import httpx

ENABLE_LLM = os.getenv("ENABLE_LLM", "false").lower() == "true"
API_KEY = os.getenv("OPENAI_API_KEY", "")
BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")


async def llm_complete(system: str, user: str, max_tokens: int = 200) -> Optional[str]:
    """Return LLM text or None if disabled/unavailable."""
    if not ENABLE_LLM or not API_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            r = await client.post(
                f"{BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": MODEL,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.4,
                },
            )
            if r.status_code != 200:
                return None
            data = r.json()
            return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return None


async def ssh_command_response(command: str, cwd: str, username: str) -> Optional[str]:
    """Generate a realistic shell-like response for an unknown command."""
    system = (
        "You are a realistic Linux bash shell on a production server named nexusops-prod-01. "
        "Respond ONLY with the command output a real shell would print. "
        "No explanations. No markdown. If the command would fail, print a realistic error. "
        "Keep responses short."
    )
    user = f"User: {username}\nCWD: {cwd}\nCommand: {command}"
    return await llm_complete(system, user, max_tokens=180)
