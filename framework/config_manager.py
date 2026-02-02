from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Dict, Optional
from .paths import DEFAULT_API_CONFIG, EXAMPLE_API_CONFIG

def load_api_keys(config_path: Optional[Path]=None, set_env: bool=True) -> Dict[str, str]:

    def _is_placeholder(value: str) -> bool:
        raw = (value or '').strip().lower()
        if not raw:
            return True
        return raw.startswith('paste-your-') or raw in {'your-api-key', 'changeme', 'replace-me'}
    path = Path(config_path) if config_path else DEFAULT_API_CONFIG
    if not path.exists():
        return {}
    with path.open('r', encoding='utf-8') as handle:
        payload = json.load(handle)
    api_keys = payload.get('api_keys', payload)
    applied: Dict[str, str] = {}
    for env_name, value in api_keys.items():
        if not value or _is_placeholder(str(value)):
            continue
        applied[env_name] = value
        if set_env:
            os.environ.setdefault(env_name, value)
    return applied
__all__ = ['load_api_keys']
