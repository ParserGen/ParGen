from __future__ import annotations
import json
import os
import time
import urllib.request
from http.client import IncompleteRead
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ChunkedEncodingError, RequestException
from urllib3.exceptions import ProtocolError
from urllib3.util import Retry
import httpx
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Protocol
from ..config_manager import load_api_keys
from ..paths import DEFAULT_API_CONFIG

class LLMClient(Protocol):

    def complete(self, prompt: str, **kwargs: Any) -> str:
        ...

@dataclass
class LLMConfig:
    provider: str = 'anthropic'
    model: Optional[str] = None
    temperature: float = 0.2
    max_tokens: int = 8000

def create_llm_client(config: Optional[LLMConfig]=None, ai_client: Optional[Any]=None) -> LLMClient:
    cfg = config or LLMConfig()
    if ai_client:
        return _AIClientWrapper(ai_client, max_tokens=cfg.max_tokens, temperature=cfg.temperature)
    load_api_keys(DEFAULT_API_CONFIG, set_env=True)
    _load_model_config_env()
    return _EnvLLMClient(cfg)

def _normalize_provider(provider: str) -> str:
    p = (provider or '').strip().lower()
    if p in {'anthropic'}:
        return 'anthropic'
    return 'anthropic'

def _is_placeholder_secret(value: str) -> bool:
    raw = (value or '').strip().lower()
    return not raw or raw.startswith('paste-your-') or raw in {'your-api-key', 'changeme', 'replace-me'}

def _pick_env(*names: str) -> str:
    for name in names:
        val = (os.getenv(name) or '').strip()
        if val and (not _is_placeholder_secret(val)):
            return val
    return ''

class _AIClientWrapper:

    def __init__(self, client: Any, max_tokens: int=8000, temperature: float=0.2) -> None:
        self.client = client
        self.max_tokens = max_tokens
        self.temperature = temperature

    def complete(self, prompt: str, **_: Any) -> str:
        resp = self.client.invoke_model([{'role': 'user', 'content': prompt}], max_tokens=self.max_tokens, temperature=self.temperature)
        content = resp.get('content', '')
        if isinstance(content, list):
            content = content[0].get('text', '') if content else ''
        if not content and isinstance(resp, dict):
            choices = resp.get('choices') or []
            if choices:
                message = choices[0].get('message', {})
                content = message.get('content', '')
        return str(content)

class _EnvLLMClient:

    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        provider = _normalize_provider(config.provider or os.getenv('LLM_PROVIDER') or 'anthropic')
        self.provider = 'anthropic'
        self.api_key = _pick_env('CLAUDE_API_KEY', 'ANTHROPIC_API_KEY')
        self.base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com/v1/messages')
        configured = (config.model or '').strip()
        self.model = configured or (os.getenv('ANTHROPIC_MODEL') or os.getenv('CLAUDE_MODEL') or 'model-default').strip()
        if not self.api_key:
            _load_model_config_env()
            self.api_key = _pick_env('CLAUDE_API_KEY', 'ANTHROPIC_API_KEY')
        if not self.api_key:
            raise RuntimeError(f"Missing API key for LLM provider. Set LLM_API_KEY or update {DEFAULT_API_CONFIG}.")
        self.temperature = config.temperature
        self.max_tokens = config.max_tokens

    def complete(self, prompt: str, **_: Any) -> str:
        payload: dict[str, Any] = {'model': self.model, 'max_tokens': self.max_tokens, 'temperature': self.temperature, 'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': prompt}]}]}
        headers = {'Content-Type': 'application/json', 'x-api-key': self.api_key, 'anthropic-version': os.getenv('ANTHROPIC_VERSION', '2023-06-01'), 'Accept-Encoding': 'identity', 'Connection': 'close'}
        last_exc: Exception | None = None
        body: str = ''
        for attempt in range(5):
            try:
                with httpx.Client(http2=False, timeout=600) as client:
                    resp = client.post(self.base_url, json=payload, headers=headers)
                    resp.raise_for_status()
                    body = resp.text
                break
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < 4:
                    time.sleep(1)
                    continue
            except Exception as exc:
                last_exc = exc
                if attempt < 4:
                    time.sleep(1)
                    continue
        if not body:
            session = requests.Session()
            retry_cfg = Retry(total=5, connect=5, read=5, backoff_factor=1, allowed_methods=frozenset({'POST'}), status_forcelist=(502, 503, 504), raise_on_status=False)
            adapter = HTTPAdapter(max_retries=retry_cfg)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            for attempt in range(5):
                try:
                    resp = session.post(self.base_url, json=payload, headers=headers, timeout=600)
                    resp.raise_for_status()
                    body = resp.text
                    break
                except (ChunkedEncodingError, RequestException, ProtocolError) as exc:
                    last_exc = exc
                    if attempt < 4:
                        time.sleep(1)
                        continue
                except Exception as exc:
                    last_exc = exc
                    if attempt < 4:
                        time.sleep(1)
                        continue
        if not body and last_exc:
            raise RuntimeError(f'LLM request failed ({type(last_exc).__name__}): {last_exc}') from last_exc
        parsed = json.loads(body)
        content = parsed.get('content')
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get('type') == 'text':
                    parts.append(str(item.get('text') or ''))
                elif 'text' in item:
                    parts.append(str(item.get('text') or ''))
            return ''.join(parts)
        return str(content or '')

def _load_model_config_env(config_path: Optional[Path]=None) -> None:
    path = config_path or Path(__file__).with_name('model_config.yaml')
    if not path.exists():
        return
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except Exception:
        return
    current = None
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.endswith(':') and (not line.startswith('api:')):
            key = line.rstrip(':').strip()
            current = 'anthropic' if key == 'anthropic' else None
            continue
        if '#' in line:
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
        if current and 'api_key' in line and (':' in line):
            _, val = line.split(':', 1)
            val = val.strip().strip('"').strip("'")
            if not val:
                continue
            env_name = 'ANTHROPIC_API_KEY' if current == 'anthropic' else None
            if env_name and (not os.getenv(env_name)):
                os.environ[env_name] = val
        if current and 'base_url' in line and (':' in line):
            _, val = line.split(':', 1)
            val = val.strip().strip('"').strip("'")
            if not val:
                continue
            env_name = 'ANTHROPIC_BASE_URL' if current == 'anthropic' else None
            if env_name and (not os.getenv(env_name)):
                os.environ[env_name] = val
        if current and 'model' in line and (':' in line) and ('api_key' not in line):
            _, val = line.split(':', 1)
            val = val.strip().strip('"').strip("'")
            if not val:
                continue
            env_name = 'ANTHROPIC_MODEL' if current == 'anthropic' else None
            if env_name and (not os.getenv(env_name)):
                os.environ[env_name] = val
