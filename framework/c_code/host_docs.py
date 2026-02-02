from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List

@dataclass
class HostDocChunk:
    source: str
    kind: str
    content: str

def load_host_docs(host_docs_dir: Path) -> List[HostDocChunk]:
    allowed_suffixes = {'.md', '.txt', '.rst', '.c', '.cc', '.cpp', '.h', '.hh', '.hpp', '.py', '.lua', '.spicy', '.evt', '.zeek', '.sig', '.meta', '.cmake', '.in'}
    chunks: List[HostDocChunk] = []
    if not host_docs_dir.exists():
        return chunks
    for path in host_docs_dir.rglob('*'):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in allowed_suffixes:
            continue
        text = path.read_text(encoding='utf-8', errors='ignore')
        kind = 'doc' if suffix in {'.md', '.txt', '.rst'} else 'example_code'
        chunks.append(HostDocChunk(source=str(path), kind=kind, content=text))
    return chunks
