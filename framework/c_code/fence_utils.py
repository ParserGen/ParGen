from __future__ import annotations
import re
from typing import Dict
_FILE_FENCE_STRICT_RE = re.compile('```file:(.+?)\\n(.*?)\\n```', re.DOTALL)
_FILE_FENCE_LOOSE_RE = re.compile('```file:(.+?)\\n(.*?)```', re.DOTALL)

def split_fenced_files(raw: str) -> Dict[str, str]:
    files: Dict[str, str] = {}
    if not raw:
        return files
    matches = list(_FILE_FENCE_STRICT_RE.finditer(raw))
    if not matches:
        matches = list(_FILE_FENCE_LOOSE_RE.finditer(raw))
    for match in matches:
        name = match.group(1).strip()
        content = match.group(2)
        if content.startswith('\n'):
            content = content[1:]
        files[name] = content.strip()
    return files
