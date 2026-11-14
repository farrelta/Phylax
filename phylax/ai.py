"""Configuration and transport for the optional report organizer."""
from __future__ import annotations

import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass


_DOTENV_KEYS = {
    "PHYLAX_AI_PROVIDER", "PHYLAX_AI_MODEL", "PHYLAX_AI_BASE_URL", "PHYLAX_AI_API_KEY",
    "GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "PHYLAX_AI_TIMEOUT_SECONDS",
    "PHYLAX_LOCAL_AI_MODEL",
}


def _load_ai_dotenv() -> None:
    """Read supported AI settings from cwd/.env without evaluating shell syntax.

    Existing process environment values take precedence. This intentionally
    supports simple KEY=value files only; it never executes commands or expands
    variables from the file.
    """
    try:
        with open(".env", encoding="utf-8") as env_file:
            lines = env_file.read().splitlines()
    except OSError:
        return
    for line in lines:
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("export "):
            entry = entry[7:].lstrip()
        key, separator, value = entry.partition("=")
        key = key.strip()
        if not separator or key not in _DOTENV_KEYS or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        os.environ.setdefault(key, value)


@dataclass(frozen=True)
class AIConfig:
    base_url: str
    model: str
    api_key: str
    provider: str = "custom"
    timeout_seconds: int = 90

    @classmethod
    def from_env(cls) -> "AIConfig | None":
        _load_ai_dotenv()
        provider = os.environ.get("PHYLAX_AI_PROVIDER", "custom").strip().casefold()
        presets = {
            "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
            "google": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
            "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
            "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
        }
        if provider in presets:
            base_url, key_name = presets[provider]
            api_key = os.environ.get(key_name, "").strip() or os.environ.get("PHYLAX_AI_API_KEY", "").strip()
        elif provider == "custom":
            base_url = os.environ.get("PHYLAX_AI_BASE_URL", "").strip()
            api_key = os.environ.get("PHYLAX_AI_API_KEY", "").strip()
        else:
            return None
        model = os.environ.get("PHYLAX_AI_MODEL", "").strip()
        try:
            timeout_seconds = int(os.environ.get("PHYLAX_AI_TIMEOUT_SECONDS", "90"))
        except ValueError:
            timeout_seconds = 90
        if not 5 <= timeout_seconds <= 180:
            timeout_seconds = 90
        if provider == "openrouter" and not model:
            model = "openrouter/free"
        if not (base_url and model and api_key):
            return None
        return cls(base_url, model, api_key, provider, timeout_seconds)


def local_config() -> AIConfig | None:
    _load_ai_dotenv()
    model = os.environ.get('PHYLAX_LOCAL_AI_MODEL', '').strip()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./:-]{0,199}', model) or model.casefold().endswith((':cloud', '-cloud')):
        return None
    return AIConfig('http://127.0.0.1:11434/v1', model, '', 'ollama', 90)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _opener(local=False):
    handlers = [urllib.request.ProxyHandler({})] if local else []
    return urllib.request.build_opener(*handlers, _NoRedirect()).open


def _endpoint(base_url: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("AI base URL must be an HTTP(S) origin/path without credentials, query, or fragment")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("AI endpoints must use HTTPS except for loopback development endpoints")
    return base_url.rstrip("/") + "/chat/completions"
