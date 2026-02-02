from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence
from .parse_ir import Edge, ParseIR
_WS_RE = re.compile('\\\\s+')
_DYNAMIC_TAG_HINT_RE = re.compile('(BS_CONSTRAINT\\s*\\{)|(BS_CONSTRAINT\\s*%[^%])|(BS_CONSTRAINT\\s*\\+)|(BS_CONSTRAINT\\s*\\.format\\s*\\()', flags=re.IGNORECASE)

def _normalize_text(value: object) -> str:
    s = str(value or '').strip()
    if not s:
        return ''
    s = s.replace('\uFF1A', ':').replace('\u2264', '<=').replace('\u2265', '>=').replace('\\u00a0', ' ')
    return _WS_RE.sub(' ', s).strip()

def _hash8(text: str) -> str:
    return hashlib.sha1(text.encode('utf-8')).hexdigest()[:8]

def _maybe_single_enum_value(clause: str) -> Optional[int]:
    normalized = _normalize_text(clause)
    if not normalized:
        return None
    head, sep, tail = normalized.partition(':')
    if sep != ':':
        return None
    if head.strip().lower() != 'enum':
        return None
    tail = tail.strip()
    if not tail or '|' in tail:
        return None
    try:
        return int(tail, 0)
    except Exception:
        return None

def _bit_start_is_parent_zero_offset(*, node_bit_start: object, parent_id: int) -> bool:
    s = str(node_bit_start or '').replace(' ', '')
    if not s:
        return False
    return s.startswith(f'{int(parent_id)}.bit_start') and s.endswith('+0')

def _is_redundant_selector_code_enum(*, parse_ir: ParseIR, node_id: int, clause: str) -> bool:
    value = _maybe_single_enum_value(clause)
    if value is None:
        return False
    node = parse_ir.nodes.get(int(node_id))
    if node is None or node.parent_id is None:
        return False
    parent = parse_ir.nodes.get(int(node.parent_id))
    if parent is None or parent.kind != 'variant':
        return False
    if not _bit_start_is_parent_zero_offset(node_bit_start=node.bit_start, parent_id=int(node.parent_id)):
        return False
    target = f'=={int(value)}'
    for edge in parse_ir.edges:
        if str(getattr(edge, 'rel', '') or '').strip().lower() != 'condition_on':
            continue
        if int(getattr(edge, 'dst', -1)) != int(node.parent_id):
            continue
        src_node = parse_ir.nodes.get(int(getattr(edge, 'src', -1)))
        if src_node is not None and src_node.kind != 'selector':
            continue
        formula = str(getattr(edge, 'formula', '') or '').replace(' ', '')
        if target in formula:
            return True
    return False

def node_constraint_id(*, node_id: int, clause: str) -> Optional[str]:
    normalized = _normalize_text(clause)
    if not normalized:
        return None
    kind = normalized.split(':', 1)[0].strip().lower()
    if kind not in {'enum', 'range', 'complement'}:
        return None
    basis = f'node|{int(node_id)}|{kind}|{normalized}'
    return f'N{int(node_id)}_{kind}_{_hash8(basis)}'

def edge_constraint_id(edge: Edge) -> Optional[str]:
    rel = str(getattr(edge, 'rel', '') or '').strip().lower()
    if rel not in {'length_of', 'condition_on'}:
        return None
    mt = _normalize_text(getattr(edge, 'message_type', '') or '').lower() or 'bidirectional'
    formula = _normalize_text(getattr(edge, 'formula', '') or '')
    basis = f'edge|{int(edge.src)}|{int(edge.dst)}|{rel}|{mt}|{formula}'
    return f'E{int(edge.src)}_{int(edge.dst)}_{rel}_{_hash8(basis)}'

@dataclass(frozen=True)
class ContractItem:
    id: str
    kind: str
    node_id: Optional[int] = None
    node_name: Optional[str] = None
    clause: Optional[str] = None
    src: Optional[int] = None
    src_name: Optional[str] = None
    dst: Optional[int] = None
    dst_name: Optional[str] = None
    rel: Optional[str] = None
    formula: Optional[str] = None
    message_type: Optional[str] = None

def build_contract(parse_ir: ParseIR) -> List[ContractItem]:
    items: List[ContractItem] = []
    for nid in sorted(parse_ir.nodes.keys()):
        node = parse_ir.nodes[nid]
        for raw in node.constraints or []:
            if _is_redundant_selector_code_enum(parse_ir=parse_ir, node_id=int(node.id), clause=str(raw)):
                continue
            cid = node_constraint_id(node_id=int(node.id), clause=str(raw))
            if not cid:
                continue
            items.append(ContractItem(id=cid, kind='node', node_id=int(node.id), node_name=str(node.name), clause=_normalize_text(raw)))
    for edge in parse_ir.edges:
        cid = edge_constraint_id(edge)
        if not cid:
            continue
        src_node = parse_ir.nodes.get(int(edge.src))
        dst_node = parse_ir.nodes.get(int(edge.dst))
        items.append(ContractItem(id=cid, kind='edge', src=int(edge.src), src_name=str(src_node.name) if src_node is not None else None, dst=int(edge.dst), dst_name=str(dst_node.name) if dst_node is not None else None, rel=str(edge.rel), formula=_normalize_text(edge.formula), message_type=_normalize_text(edge.message_type).lower() or 'bidirectional'))
    items.sort(key=lambda x: x.id)
    return items

def tag_for(contract_id: str) -> str:
    return f'BS_CONSTRAINT {str(contract_id).strip()}'

def find_missing_tags(*, files: Dict[str, str], items: Sequence[ContractItem], host_name: Optional[str]=None) -> List[str]:
    if not items:
        return []
    host = str(host_name or '').strip().lower().replace('-', '_')
    if host == 'scapy':

        def _has_scapy_post_dissect_validation(text: str) -> bool:
            if not text or 'post_dissect' not in text:
                return False
            for m in re.finditer('(?m)^(?P<indent>[ \\t]*)def\\s+post_dissect\\s*\\(', text):
                indent = m.group('indent') or ''
                body_start = m.end()
                next_def = re.search(f'(?m)^{re.escape(indent)}def\\s+\\w+\\s*\\(', text[body_start:])
                end = len(text) if next_def is None else body_start + next_def.start()
                block = text[m.start():end]
                if 'BS_CONSTRAINT' in block or '_constraint_violations' in block or 'violations.append' in block:
                    return True
            return False
        if not any((_has_scapy_post_dissect_validation(v or '') for v in files.values())):
            return [it.id for it in items]
    haystack = '\\n'.join([v or '' for v in files.values()])
    has_dynamic_tag_template = bool(_DYNAMIC_TAG_HINT_RE.search(haystack))
    missing: List[str] = []
    for item in items:
        tag = tag_for(item.id)
        if tag not in haystack:
            if has_dynamic_tag_template and str(item.id) in haystack:
                continue
            missing.append(item.id)
    return missing

def format_contract_for_prompt(*, host_name: str, items: Sequence[ContractItem]) -> str:
    host = str(host_name or '').strip().lower().replace('-', '_')
    if not items:
        return '(no constraints in contract)'
    rules = ['Tool constraint contract (STRICT):', '- You MUST implement runtime validation checks for every contract item below.', '- For each check, you MUST emit a deterministic tag EXACTLY: `BS_CONSTRAINT <id>`.', '- Only emit `BS_CONSTRAINT ...` when the constraint is VIOLATED (do not emit tags on success).', '- For Wireshark-C/Wireshark-Lua/Scapy: put the tag inside the emitted diagnostic string.', '- For Zeek+Spicy: if the backend cannot attach messages to parse failures, put the tag in a nearby comment line.', '- On truncation/missing-field situations relevant to a constraint, emit the tag as a violation (do NOT silently skip).', '- For `condition_on` edges: enforce branch selection and presence/absence. If the condition implies a subtree MUST be present but it is missing/truncated, emit the tag. If the condition implies a subtree MUST be absent but extra bytes/fields appear for it, emit the tag.', '- For `length_of` edges: enforce exact byte consumption. If the expected length does not match the bytes available/consumed (truncation or leftover), emit the tag.', '- Do NOT hide violations behind guards like `if len > 0` / `if remaining >= ...`: if you cannot parse due to missing bytes, or a computed length is invalid (including 0 when a range/size requires >0), emit the tag before returning/skipping.']
    host_hint = ''
    if host in {'wireshark_c', 'wireshark-c'}:
        host_hint = 'Host note (wireshark_c): use Expert Info (PI_MALFORMED/PI_ERROR) and include the tag in the message.'
    elif host in {'wireshark_lua', 'wireshark-lua'}:
        host_hint = 'Host note (wireshark_lua): use subtree:add_expert_info(PI_MALFORMED, PI_ERROR, ...) and include the tag (emit it even when the buffer is truncated / a length check fails before parsing any bytes).'
    elif host == 'scapy':
        host_hint = "Host note (scapy): append violations to `pkt._constraint_violations` (list[str]) and include the tag in the string. IMPORTANT: run validation on parsing by implementing `post_dissect()` (and optionally also `post_build()`). Do NOT rely on `post_build()` only (it is not called when dissecting PCAP bytes). Avoid parse-time exceptions: do not write ConditionalField conditions that can throw (e.g., `pkt.auth_type >= 6` when the field may be absent/None). Prefer checking parsed presence via `'<field>' in pkt.fields` and guard comparisons with `is not None`. For truncation/missing bytes, do NOT attempt to read past available data; record the violation tag and stop cleanly."
    elif host in {'zeek_spicy', 'zeek-spicy'}:
        host_hint = 'Host note (zeek_spicy): use &requires / bounds checks; include tags as comments if needed.'
    if host_hint:
        rules.append(host_hint)
    lines: List[str] = []
    for item in items:
        if item.kind == 'node':
            lines.append(f'- id={item.id} kind=node node_id={item.node_id} node_name={item.node_name} clause={item.clause}')
        else:
            lines.append(f'- id={item.id} kind=edge rel={item.rel} src={item.src} dst={item.dst} src_name={item.src_name} dst_name={item.dst_name} message_type={item.message_type} formula={item.formula}')
    return '\\n'.join(rules + ['', 'Contract items:', *lines])

def iter_tags(items: Sequence[ContractItem]) -> Iterable[str]:
    for item in items:
        yield tag_for(item.id)
