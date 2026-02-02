from __future__ import annotations
import os
import re
from collections import Counter
from pathlib import Path
from typing import List, Optional, Sequence
import yaml
from .host_docs import HostDocChunk
from .host_ir_schema import HostIR
from .llm_client import LLMClient
_PLACEHOLDER_PREFIX_RE = re.compile('^\\{[A-Za-z_][A-Za-z0-9_]*\\}.*$')

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception:
        return int(default)

def _env_bool(name: str, default: bool=False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in {'1', 'true', 'yes', 'y', 'on'}

def _keywords_for_host(host_name: str) -> Sequence[str]:
    host = (host_name or '').lower()
    if host in {'scapy'}:
        return ('packet', 'fields_desc', 'bind_layers', 'fieldlenfield', 'strlenfield', 'packetlenfield', 'conditionalfield', 'packetlistfield')
    if host in {'zeek_spicy', 'zeek-spicy'} or host in {'zeek', 'spicy'} or 'spicy' in host:
        return ('spicyz', 'zeek::spicy', 'zeek::spicy::analyzer', 'protocol analyzer', 'packet analyzer', 'file analyzer', 'parse with', 'parse originator', 'parse responder', 'over tcp', 'over udp', 'port', 'event', 'on %done', 'zeek -n zeek::spicy', 'zkg create', 'spicy-protocol-analyzer')
    if host in {'wireshark_lua', 'wireshark-lua'} or 'lua' in host:
        return ('proto:register_heuristic', 'register_heuristic', 'dissectortable.get', 'tcp.port', 'udp.port', 'protofield', 'proto(', 'proto.dissector', 'add(')
    if host in {'wireshark_c', 'wireshark-c'} or 'wireshark' in host:
        return ('proto_register_protocol', 'proto_register_field_array', 'proto_reg_handoff', 'dissector_add_uint', 'tvb_get', 'proto_tree_add_item', 'hf_register_info')
    return ('register', 'dissector', 'proto', 'field', 'table', 'add(')
_STOPWORDS = {'if', 'for', 'while', 'switch', 'case', 'return', 'break', 'continue', 'else', 'elseif', 'then', 'do', 'end', 'in', 'and', 'or', 'not', 'true', 'false', 'nil', 'static', 'const', 'void', 'int', 'char', 'unsigned', 'signed', 'long', 'short', 'float', 'double', 'struct', 'enum', 'typedef', 'function', 'local'}
_RE_CALLLIKE = re.compile('\\b([A-Za-z_][A-Za-z0-9_]*(?:(?:\\.|::|:)[A-Za-z_][A-Za-z0-9_]*)*)\\s*\\(')
_RE_ATTR_ASSIGN = re.compile('\\b([A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+)\\s*=')

def _parse_snippet_keywords_from_env() -> Sequence[str]:
    raw = os.getenv('HOST_IR_SNIPPET_KEYWORDS')
    if raw is None:
        return tuple()
    parts = [p.strip() for p in str(raw).split(',')]
    return tuple([p for p in parts if p])

def _infer_snippet_keywords_from_text(text: str, *, max_keywords: int) -> Sequence[str]:
    if not text or max_keywords <= 0:
        return tuple()
    counts: Counter[str] = Counter()
    for token in _RE_CALLLIKE.findall(text):
        t = (token or '').strip()
        if not t or len(t) < 3:
            continue
        if t.lower() in _STOPWORDS:
            continue
        counts[t] += 1
    for token in _RE_ATTR_ASSIGN.findall(text):
        t = (token or '').strip()
        if not t or len(t) < 3:
            continue
        if t.lower() in _STOPWORDS:
            continue
        counts[t] += 1
    if not counts:
        return tuple()
    qualified = [t for t in counts.keys() if any((sep in t for sep in ('.', '::', ':')))]
    qualified.sort(key=lambda t: (-counts[t], t))
    simple = [t for t in counts.keys() if t not in set(qualified)]
    simple.sort(key=lambda t: (-counts[t], t))
    out: list[str] = []
    seen: set[str] = set()
    for t in qualified + simple:
        if t in seen:
            continue
        out.append(t)
        seen.add(t)
        if len(out) >= max_keywords:
            break
    return tuple(out)

def _select_snippet_keywords(text: str, *, host_name: str) -> Sequence[str]:
    explicit = _parse_snippet_keywords_from_env()
    if explicit:
        return explicit
    inferred = _infer_snippet_keywords_from_text(text, max_keywords=max(10, _env_int('HOST_IR_KEYWORD_LIMIT', 24)))
    if inferred:
        return inferred
    return _keywords_for_host(host_name)

def _extract_keyword_snippets(text: str, *, keywords: Sequence[str], max_snippets: int, snippet_chars: int, max_total_chars: int) -> str:
    if not text or not keywords or max_snippets <= 0 or (snippet_chars <= 0) or (max_total_chars <= 0):
        return ''
    lowered = text.lower()
    hits: list[int] = []
    for kw in keywords:
        key = (kw or '').lower().strip()
        if not key:
            continue
        idx = lowered.find(key)
        if idx >= 0:
            hits.append(idx)
    if not hits:
        return ''
    hits.sort()
    ranges: list[tuple[int, int]] = []
    half = max(1, snippet_chars // 2)
    for idx in hits:
        start = max(0, idx - half)
        end = min(len(text), idx + half)
        nl = text.rfind('\n', 0, start)
        if nl >= 0:
            start = nl + 1
        nl2 = text.find('\n', end)
        if nl2 >= 0:
            end = nl2
        ranges.append((start, end))
    ranges.sort()
    merged: list[list[int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    out: list[str] = []
    used = 0
    for start, end in merged[:max_snippets]:
        snippet = text[start:end].strip()
        if not snippet:
            continue
        if used + len(snippet) + 2 > max_total_chars:
            remaining = max_total_chars - used
            if remaining <= 0:
                break
            snippet = snippet[:remaining].rstrip()
        out.append(snippet)
        used += len(snippet) + 2
        if used >= max_total_chars:
            break
    return '\n\n'.join(out).strip()

def _excerpt_host_doc_text(text: str, *, host_name: str, max_chars: int) -> str:
    if not text:
        return ''
    if max_chars <= 0:
        return ''
    if len(text) <= max_chars:
        return text
    head_chars = max(200, min(_env_int('HOST_IR_DOC_HEAD_CHARS', 1200), max_chars))
    head = text[:head_chars].rstrip()
    remaining = max_chars - len(head)
    if remaining <= 0:
        return head
    snippets = _extract_keyword_snippets(text, keywords=_select_snippet_keywords(text, host_name=host_name), max_snippets=max(1, _env_int('HOST_IR_DOC_MAX_SNIPPETS', 6)), snippet_chars=max(200, _env_int('HOST_IR_DOC_SNIPPET_CHARS', 1400)), max_total_chars=max(0, remaining - 2))
    if not snippets:
        return head
    return (head + '\n\n' + snippets).rstrip()

def _unwrap_markdown_fence(text: str) -> str:
    stripped = text.strip()
    lines = stripped.splitlines()
    if not lines:
        return stripped
    if lines[0].startswith('```'):
        lines = lines[1:]
    if lines and lines[-1].startswith('```'):
        lines = lines[:-1]
    return '\n'.join(lines).strip()

def _split_yaml_comment(line: str) -> tuple[str, str]:
    in_dquote = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == '\\' and in_dquote:
            escaped = True
            continue
        if ch == '"':
            in_dquote = not in_dquote
            continue
        if ch == '#' and (not in_dquote):
            return (line[:idx], line[idx:])
    return (line, '')

def _count_unescaped_double_quotes(text: str) -> int:
    count = 0
    escaped = False
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == '\\':
            escaped = True
            continue
        if ch == '"':
            count += 1
    return count

def _sanitize_unquoted_placeholder_values(yaml_text: str) -> str:
    out_lines: list[str] = []
    for line in yaml_text.splitlines():
        raw_line = line
        comment = ''
        if '#' in line:
            before, after = line.split('#', 1)
            line = before.rstrip()
            comment = '#' + after
        match = re.match('^(\\s*(?:-\\s*)?[^:\\n]+:\\s*)(.+)$', line)
        if not match:
            out_lines.append(raw_line)
            continue
        head, value = (match.group(1), match.group(2).strip())
        if not value:
            out_lines.append(raw_line)
            continue
        if value[0] in ("'", '"'):
            out_lines.append(raw_line)
            continue
        if _PLACEHOLDER_PREFIX_RE.match(value):
            first_brace = value.split('}', 1)[0] + '}'
            if ':' not in first_brace:
                escaped = value.replace('"', '\\"')
                fixed = f'{head}"{escaped}"'
                if comment:
                    fixed = fixed + ' ' + comment
                out_lines.append(fixed)
                continue
        out_lines.append(raw_line)
    return '\n'.join(out_lines).strip()

def _sanitize_unbalanced_double_quotes(yaml_text: str) -> str:
    out_lines: list[str] = []
    for raw_line in yaml_text.splitlines():
        code, comment = _split_yaml_comment(raw_line)
        code_stripped = code.rstrip()
        match = re.match('^(\\s*(?:-\\s*)?[^:\\n]+:\\s*)(\\".*)$', code_stripped)
        if not match:
            out_lines.append(raw_line)
            continue
        head, value = (match.group(1), match.group(2))
        if not value.startswith('"'):
            out_lines.append(raw_line)
            continue
        if _count_unescaped_double_quotes(value) % 2 == 1:
            fixed = f'{code_stripped}"'
            if comment:
                fixed = fixed + ' ' + comment.lstrip()
            out_lines.append(fixed)
            continue
        out_lines.append(raw_line)
    return '\n'.join(out_lines).strip()

class HostIRAgent:

    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.last_raw_host_ir: Optional[str] = None

    def build_host_ir(self, host_name: str, docs: List[HostDocChunk], cache_path: Optional[Path]=None) -> HostIR:
        if cache_path and cache_path.is_file():
            try:
                raw = yaml.safe_load(cache_path.read_text(encoding='utf-8')) or {}
            except Exception:
                raw = {}
            if raw:
                return HostIR.from_raw(host_name, raw)
        prompt = self._build_prompt(host_name, docs)
        yaml_text = self.llm.complete(prompt)
        self.last_raw_host_ir = yaml_text
        yaml_text = _unwrap_markdown_fence(yaml_text)
        try:
            raw = yaml.safe_load(yaml_text) or {}
        except Exception as exc:
            sanitized = yaml_text
            sanitized = _sanitize_unquoted_placeholder_values(sanitized)
            sanitized = _sanitize_unbalanced_double_quotes(sanitized)
            if sanitized != yaml_text:
                try:
                    raw = yaml.safe_load(sanitized) or {}
                except Exception:
                    raise RuntimeError('Failed to parse Host-IR YAML from LLM output') from exc
            else:
                raise RuntimeError('Failed to parse Host-IR YAML from LLM output') from exc
        host_ir = HostIR.from_raw(host_name, raw)
        if cache_path:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding='utf-8')
        return host_ir

    def _build_prompt(self, host_name: str, docs: List[HostDocChunk]) -> str:
        doc_blocks: List[str] = []
        budget = max(0, _env_int('HOST_IR_DOC_CHAR_BUDGET', 18000))
        per_doc_limit = max(500, _env_int('HOST_IR_PER_DOC_CHAR_LIMIT', 6500))
        condense = _env_bool('HOST_IR_CONDENSE_DOCS', False)
        condense_max_chunks = max(0, _env_int('HOST_IR_CONDENSE_MAX_CHUNKS', 4))
        condense_summary_chars = max(600, _env_int('HOST_IR_CONDENSE_SUMMARY_CHARS', 2200))
        used = 0
        condensed_used = 0
        for chunk in docs:
            if budget and used >= budget:
                break
            excerpt = _excerpt_host_doc_text(chunk.content, host_name=host_name, max_chars=per_doc_limit)
            if condense and condensed_used < condense_max_chunks:
                try:
                    keywords = _select_snippet_keywords(chunk.content, host_name=host_name)
                    verbatim = _extract_keyword_snippets(chunk.content, keywords=keywords, max_snippets=max(1, _env_int('HOST_IR_DOC_MAX_SNIPPETS', 6)), snippet_chars=max(200, _env_int('HOST_IR_DOC_SNIPPET_CHARS', 1400)), max_total_chars=min(6000, max(800, per_doc_limit)))
                    summary_prompt = f"You are summarizing host developer documentation for protocol dissector code generation.\nTarget host: {host_name}\nTask: Produce a compact set of rules and templates that help a code generator use the host APIs correctly.\nOutput requirements (plain text, no markdown fences):\n- DO: 6-12 bullet rules (use exact API names/call forms when known).\n- DON'T: 4-10 bullet pitfalls / wrong APIs (if applicable).\n- TEMPLATES: 2-4 short code snippets (registration + dissector skeleton).\n- Keep the whole output under {condense_summary_chars} characters.\n\nVerbatim API snippets (high priority; keep exact as-is):\n{(verbatim or '').strip() or '(none)'}\n\nDoc excerpt to summarize:\n{(excerpt or '').strip() or '(empty)'}\n"
                    summary = (self.llm.complete(summary_prompt) or '').strip()
                    if len(summary) > condense_summary_chars:
                        summary = summary[:condense_summary_chars].rstrip()
                    block_parts: list[str] = [f'# {chunk.kind} | {chunk.source}']
                    if verbatim.strip():
                        block_parts.append('## Verbatim API snippets\n' + verbatim.strip())
                    if summary.strip():
                        block_parts.append('## Summary (LLM)\n' + summary.strip())
                    if not verbatim.strip() and (not summary.strip()):
                        block_parts.append(excerpt.strip())
                    block = '\n\n'.join(block_parts).strip()
                    condensed_used += 1
                except Exception:
                    block = f'# {chunk.kind} | {chunk.source}\n{excerpt}'.strip()
            else:
                block = f'# {chunk.kind} | {chunk.source}\n{excerpt}'.strip()
            if not block:
                continue
            if budget and used + len(block) > budget:
                remain = budget - used
                if remain <= 0:
                    break
                block = block[:remain].rstrip()
            doc_blocks.append(block)
            used += len(block) + 2
        docs_text = '\n\n'.join(doc_blocks)
        schema_hint = '\nReturn a YAML document with keys:\n- host_name\n- plugin_kind            # e.g. protocol_dissector\n- IMPORTANT YAML NOTE (STRICT, MUST FOLLOW):\n  - YAML treats an unquoted value starting with \'{\' as a flow-mapping (e.g., {k: v}).\n    Therefore any placeholder string like {protocol}_handle MUST be quoted.\n  - If any scalar value contains placeholders in curly braces (e.g., {protocol}, {host}, {foo}),\n    wrap the ENTIRE value in DOUBLE QUOTES.\n      BAD (will break yaml.safe_load):\n        - name: {protocol}_handle\n        filename_template: {protocol}.c\n      GOOD:\n        - name: "{protocol}_handle"\n        filename_template: "packet-{protocol}.c"\n  - For long/multiline strings (rules/templates/signature/description), prefer YAML block scalar:\n        rules: |\n          ...\n        templates: |\n          ...\n  - If you start a DOUBLE QUOTE on a line, you MUST close it on the SAME line (balanced quotes).\n- artifacts:             # exhaustive list of build outputs to emit\n    - id                 # stable identifier used by Stage C\n      filename_template  # templated filename, may contain {protocol} (quote if placeholders present)\n      language           # c / c++ / python / build\n      role               # dissector / build_script / header / helper\n      kind               # source | header | build_script | resource\n      build_src: bool    # true if compiled/linked (source translation unit)\n- symbols:               # interface vs internal symbols\n    - name\n      visibility: public | internal\n      defined_in: artifact id\n      used_in: [artifact ids]\n- parse_api:             # host parsing APIs to build trees/fields\n    - name\n      kind: container_op | field_op | selector_op | helper\n      signature: string  # function signature or call form\n      description: string\n- summary                # short description of how to build plugins for this host\n- rules                  # mapping from generic Parse-IR to host constructs/APIs\n- templates              # code templates/snippets\n- extras                 # type mappings, default ports, helper APIs, etc.\n'
        return f'You are a Host-IR learning agent. Read the host developer docs and emit a Host-IR YAML.\nTarget host: {host_name}\nGoal:\n- Summarize how to structure protocol plugins for this host.\n- Describe rules for mapping a generic Parse-IR (nodes/edges describing protocol structure) to host-specific constructs such as field registration, protocol registration, dissector tables, analyzers, packet classes, and related host APIs.\n- Provide example code snippets/templates.\n- Do NOT assume any specific protocol; keep guidance host-generic.\nFollow the schema exactly; output MUST be valid YAML parseable by Python yaml.safe_load; no explanations outside YAML. Before you output, mentally verify there are no unquoted `{{...}}` placeholders.\n{schema_hint}\nReference material:\n{docs_text}\n'
