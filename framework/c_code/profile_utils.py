from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple

def _list_of_str(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    out: List[str] = []
    for item in value:
        s = str(item).strip()
        if s:
            out.append(s)
    return out

def profile_forbidden_required(profile: Optional[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    if not isinstance(profile, dict) or not profile:
        return ([], [])
    forbidden = _list_of_str(profile.get('forbidden_substrings'))
    required = _list_of_str(profile.get('required_substrings'))
    return (forbidden, required)

def profile_max_attempts(profile: Optional[Dict[str, Any]], *, default: int=2, key: str='max_codegen_attempts', min_attempts: int=1, max_attempts: int=3) -> int:
    if not isinstance(profile, dict) or not profile:
        return default
    raw = profile.get(key, default)
    try:
        value = int(raw)
    except Exception:
        value = default
    return max(min_attempts, min(max_attempts, value))

def profile_violations(files: Dict[str, str], profile: Optional[Dict[str, Any]]) -> List[str]:
    forbidden, required = profile_forbidden_required(profile)
    if not forbidden and (not required):
        return []
    violations: List[str] = []
    for token in forbidden:
        hits = [name for name, content in files.items() if token in (content or '')]
        if hits:
            violations.append(f'forbidden_substring={token!r} present in files={sorted(hits)}')
    for token in required:
        present = any((token in (content or '') for content in files.values()))
        if not present:
            violations.append(f'required_substring={token!r} missing from all output files')
    return violations
