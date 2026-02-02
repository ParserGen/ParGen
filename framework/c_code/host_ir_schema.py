from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import yaml

def _as_text(value: Any) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    try:
        return yaml.safe_dump(value, allow_unicode=True)
    except Exception:
        return str(value)

@dataclass
class ArtifactSpec:
    id: str
    filename_template: str
    language: str
    role: str
    kind: str
    build_src: bool

@dataclass
class SymbolSpec:
    name: str
    visibility: str
    defined_in: str
    used_in: List[str]

@dataclass
class ParseAPIOperation:
    name: str
    kind: str
    signature: str
    description: str

@dataclass
class HostIR:
    host_name: str
    plugin_kind: str
    artifacts: List[ArtifactSpec]
    symbols: List[SymbolSpec]
    parse_api: List[ParseAPIOperation]
    summary: str
    rules: str
    templates: str
    extras: Dict[str, Any]
    raw: Dict[str, Any]

    @classmethod
    def from_raw(cls, host_name: str, raw: Dict[str, Any]) -> 'HostIR':
        raw = raw or {}
        artifacts: List[ArtifactSpec] = []
        for entry in raw.get('artifacts', []) or []:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get('kind') or entry.get('type') or '').strip()
            build_src_val: Optional[bool] = entry.get('build_src')
            build_src = bool(build_src_val) if build_src_val is not None else kind in {'source', 'build_src', 'impl'}
            artifacts.append(ArtifactSpec(id=str(entry.get('id') or entry.get('name') or ''), filename_template=str(entry.get('filename_template') or entry.get('filename') or ''), language=str(entry.get('language') or ''), role=str(entry.get('role') or ''), kind=kind, build_src=build_src))
        symbols: List[SymbolSpec] = []
        for entry in raw.get('symbols', []) or []:
            if not isinstance(entry, dict):
                continue
            used_in_val = entry.get('used_in') or []
            if isinstance(used_in_val, str):
                used_in_list = [used_in_val]
            else:
                used_in_list = [str(v) for v in used_in_val if v is not None]
            symbols.append(SymbolSpec(name=str(entry.get('name') or ''), visibility=str(entry.get('visibility') or entry.get('scope') or 'internal'), defined_in=str(entry.get('defined_in') or entry.get('definition_artifact') or ''), used_in=used_in_list))
        parse_api: List[ParseAPIOperation] = []
        for entry in raw.get('parse_api', []) or []:
            if not isinstance(entry, dict):
                continue
            parse_api.append(ParseAPIOperation(name=str(entry.get('name') or ''), kind=str(entry.get('kind') or ''), signature=_as_text(entry.get('signature')), description=_as_text(entry.get('description'))))
        host_val = str(raw.get('host_name') or host_name or '').strip()
        plugin_kind = str(raw.get('plugin_kind') or raw.get('plugin_type') or '').strip()
        if not host_val:
            raise ValueError('Host-IR missing host_name')
        if not plugin_kind:
            raise ValueError('Host-IR missing plugin_kind')
        if not artifacts:
            raise ValueError('Host-IR has no artifacts')
        return cls(host_name=host_val, plugin_kind=plugin_kind, artifacts=artifacts, symbols=symbols, parse_api=parse_api, summary=_as_text(raw.get('summary')), rules=_as_text(raw.get('rules')), templates=_as_text(raw.get('templates')), extras=raw.get('extras') or {}, raw=raw)
