import copy
import json
import os
import logging
import re
import requests
import time
import numpy as np
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, Set, TYPE_CHECKING
from dataclasses import dataclass, asdict, field
from collections import defaultdict, Counter
from pathlib import Path
from datetime import datetime
import hashlib
import struct
from enum import Enum
from ...config_manager import load_api_keys
from ...paths import DEFAULT_API_CONFIG, STEP2_CACHE_DIR, STEP2_FIX_CACHE_DIR
from ..validation_agent.syntax_validator import validate_protocol_tree
from ..fix_agent.refinement import mcts_fix_tree, apply_patch as fix_apply_patch, run_full_validation
from ..traffic_agent.semantic_validator import run_hybrid_validation
from .core_ir import canonicalize_protocol_tree, add_request_response_variants
if TYPE_CHECKING:
    from ..fix_agent.agent import EnhancedPureAIAgent as FixLLMAgent
_NODE_TYPE_ALIAS = {'protocol': 'protocol', 'header': 'header', 'field': 'field', 'selector': 'selector', 'variant': 'variant', 'payload': 'payload', 'container': 'container', 'body': 'payload', 'segment': 'container', 'composite': 'container'}

def canonicalize_node_type(node_type: Optional[str]) -> str:
    if not node_type:
        return 'field'
    normalized = node_type.strip().lower()
    return _NODE_TYPE_ALIAS.get(normalized, normalized)

def _infer_step2_cache_namespace(sections_file: str, raw_file: str) -> str:
    for cand in (sections_file, raw_file):
        try:
            parts = Path(cand).resolve().parts
        except Exception:
            continue
        for idx, part in enumerate(parts):
            if part != 'data' or idx + 1 >= len(parts):
                continue
            protocol = parts[idx + 1]
            if protocol and protocol not in {'_artifacts', 'logs', 'host_docs'}:
                return protocol
    key = f'{Path(sections_file).resolve()}|{Path(raw_file).resolve()}'
    return hashlib.sha1(key.encode('utf-8')).hexdigest()[:10]

def _summarize_packet_format_field(field_obj: Any) -> Any:
    if not isinstance(field_obj, dict):
        return field_obj
    out: Dict[str, Any] = {}
    for key in ('field_name', 'name', 'byte_position', 'bit_position', 'size', 'data_type', 'description', 'constraints', 'encoding', 'endianness', 'source'):
        if key in field_obj:
            out[key] = field_obj.get(key)
    if 'field_name' not in out and 'name' in out:
        out['field_name'] = out.pop('name')
    return out

def _summarize_packet_format(packet_format: Any, *, max_fields: int=60) -> Any:
    if not isinstance(packet_format, dict):
        return packet_format
    out: Dict[str, Any] = {}
    for key in ('format_name', 'description', 'total_size', 'structure_type'):
        if key in packet_format:
            out[key] = packet_format.get(key)
    fields = packet_format.get('fields')
    if isinstance(fields, list):
        out['fields'] = [_summarize_packet_format_field(f) for f in fields[:max_fields]]
    elif fields is not None:
        out['fields'] = fields
    return out

def _refine_section_digest(section: Dict[str, Any]) -> Dict[str, Any]:
    digest: Dict[str, Any] = {'number': section.get('number', ''), 'title': section.get('title', ''), 'source_file': section.get('source_file', ''), 'content': section.get('content', ''), 'summary': section.get('summary', ''), 'constraints': section.get('constraints', []) or []}
    packet_formats = section.get('packet_formats') or []
    if isinstance(packet_formats, list):
        digest['packet_formats'] = [_summarize_packet_format(pf) for pf in packet_formats[:8]]
    else:
        digest['packet_formats'] = packet_formats
    field_defs = section.get('field_definitions') or []
    if isinstance(field_defs, list):
        digest['field_definitions'] = field_defs[:80]
    else:
        digest['field_definitions'] = field_defs
    return digest
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NumpyEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

class TreeModificationAction(Enum):
    SPLIT_NODE = 'split_node'
    MERGE_NODES = 'merge_nodes'
    RESTRUCTURE_HIERARCHY = 'restructure_hierarchy'
    ADD_CONSTRAINT = 'add_constraint'
    ADJUST_POSITION = 'adjust_position'
    CHANGE_TYPE = 'change_type'
    ADD_DEPENDENCY = 'add_dependency'
    REMOVE_NODE = 'remove_node'
    INSERT_INTERMEDIATE = 'insert_intermediate'

@dataclass
class FieldConstraint:
    constraint_type: str
    constraint_value: Any
    description: str
    is_mandatory: bool = True
    source: str = ''
    confidence: float = 1.0
    validation_count: int = 0
    violation_count: int = 0

    def validate(self, value: Any) -> bool:
        try:
            if self.constraint_type == 'value':
                return value == self.constraint_value
            elif self.constraint_type == 'range':
                if isinstance(self.constraint_value, list) and len(self.constraint_value) == 2:
                    return self.constraint_value[0] <= value <= self.constraint_value[1]
            elif self.constraint_type == 'enum':
                return value in self.constraint_value
            elif self.constraint_type == 'pattern':
                return bool(re.match(self.constraint_value, str(value)))
            elif self.constraint_type == 'length':
                return len(str(value)) == self.constraint_value
        except:
            pass
        return True

@dataclass
class FieldDependency:
    dependency_type: str
    target_field: str
    condition: Optional[str] = None
    formula: Optional[str] = None

@dataclass
class ProtocolNode:
    node_id: str
    name: str
    node_type: str
    description: str
    bit_start: Optional[Union[int, str]] = None
    size_bits: Optional[Union[int, str]] = None
    data_type: Optional[str] = None
    byte_order: str = 'big'
    message_type: str = ''
    constraints: List[Any] = field(default_factory=list)
    dependencies: List[Any] = field(default_factory=list)
    parent_id: Optional[str] = None
    children_ids: List[str] = field(default_factory=list)
    source: str = ''
    confidence_score: float = 1.0
    parse_success_count: int = 0
    parse_failure_count: int = 0
    value_distribution: Dict[str, int] = field(default_factory=dict)

    def calculate_effective_position(self, context: Dict[str, Any]) -> Tuple[int, int]:
        bit_start = self.bit_start
        size_bits = self.size_bits
        if isinstance(bit_start, str):
            try:
                if '.' in bit_start and '+' in bit_start:
                    parts = bit_start.split('+')
                    field_ref = parts[0].strip()
                    offset = int(parts[1].strip())
                    field_name = field_ref.split('.')[0]
                    if field_name in context:
                        ref_end = context[field_name].get('end_bit', 0)
                        bit_start = ref_end + offset
                else:
                    bit_start = int(bit_start)
            except:
                bit_start = 0
        if isinstance(size_bits, str):
            try:
                if 'val(' in size_bits:
                    match = re.search('val\\((\\w+)\\)', size_bits)
                    if match:
                        ref_field = match.group(1)
                        if ref_field in context:
                            ref_value = context[ref_field].get('value', 0)
                            if '*8' in size_bits:
                                size_bits = ref_value * 8
                            else:
                                size_bits = ref_value
                else:
                    size_bits = int(size_bits)
            except:
                size_bits = 8
        return (int(bit_start), int(size_bits))

@dataclass
class ProtocolTree:
    protocol_name: str
    root_node_id: str
    nodes: Dict[str, ProtocolNode]
    edges: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    created_at: str
    _NODE_DROP_FIELDS = {'confidence_score', 'parse_success_count', 'parse_failure_count', 'value_distribution'}

    def get_node(self, node_id: str) -> Optional[ProtocolNode]:
        return self.nodes.get(node_id)

    def get_children(self, node_id: str) -> List[ProtocolNode]:
        node = self.get_node(node_id)
        if not node:
            return []
        return [self.nodes[child_id] for child_id in node.children_ids if child_id in self.nodes]

    def get_all_fields(self) -> List[ProtocolNode]:
        return [node for node in self.nodes.values() if node.node_type == 'field']

    def get_tree_depth(self) -> int:

        def _get_depth(node_id: str, current_depth: int=0) -> int:
            node = self.get_node(node_id)
            if not node or not node.children_ids:
                return current_depth
            return max((_get_depth(child_id, current_depth + 1) for child_id in node.children_ids))
        return _get_depth(self.root_node_id)

    def clone(self) -> 'ProtocolTree':
        return ProtocolTree(protocol_name=self.protocol_name, root_node_id=self.root_node_id, nodes=copy.deepcopy(self.nodes), edges=copy.deepcopy(self.edges), metadata=copy.deepcopy(self.metadata), created_at=self.created_at)

    def to_dict(self) -> Dict[str, Any]:

        def _node_sort_key(node: ProtocolNode) -> Any:
            node_id = getattr(node, 'node_id', '')
            try:
                return int(node_id)
            except Exception:
                return str(node_id)
        serialized_nodes: List[Dict[str, Any]] = []
        for node in sorted(self.nodes.values(), key=_node_sort_key):
            node_dict = asdict(node)
            for drop_field in self._NODE_DROP_FIELDS:
                node_dict.pop(drop_field, None)
            node_dict.setdefault('children_ids', [])
            node_dict.setdefault('constraints', [])
            node_dict.setdefault('dependencies', [])
            serialized_nodes.append(node_dict)
        payload = {'protocol_name': self.protocol_name, 'root_node_id': self.root_node_id, 'nodes': serialized_nodes, 'edges': copy.deepcopy(self.edges)}
        if self.metadata:
            payload['metadata'] = copy.deepcopy(self.metadata)
        return payload
TAG_OPEN = '<attention priority="{priority}">'
TAG_CLOSE = '</attention>'
TAG_PATTERN = re.compile('</?attention(?:\\s+[^>]*)?>', re.IGNORECASE)

def _wrap_with_attention(text: str, priority: str='high', strip_existing: bool=False) -> str:
    if not isinstance(text, str):
        text = '' if text is None else str(text)
    if strip_existing:
        text = TAG_PATTERN.sub('', text)
    if TAG_PATTERN.search(text):
        return text
    return f'{TAG_OPEN.format(priority=priority)}\n{text}\n{TAG_CLOSE}'

def mark_sections_by_batch(sections: List[Dict[str, Any]], batch_start: int, batch_size: int, *, text_key: str='content', out_key: str='content', priority: str='high', strip_existing: bool=False, set_flag_key: str | None='is_focused') -> List[Dict[str, Any]]:
    n = len(sections or [])
    if n == 0 or batch_size <= 0:
        return list(sections or [])
    s = max(0, batch_start)
    e = min(n, batch_start + batch_size)
    out: List[Dict[str, Any]] = []
    for i, sec in enumerate(sections):
        new_sec = dict(sec) if isinstance(sec, dict) else {'content': str(sec)}
        raw = new_sec.get(text_key, '')
        if s <= i < e:
            new_sec[out_key] = _wrap_with_attention(raw, priority=priority, strip_existing=strip_existing)
            if set_flag_key:
                new_sec[set_flag_key] = True
        else:
            new_sec[out_key] = TAG_PATTERN.sub('', raw) if strip_existing else raw
            if set_flag_key:
                new_sec[set_flag_key] = False
        out.append(new_sec)
    return out

class GenerationLLMAgent:

    def __init__(self, api_key: Optional[str]=None, provider: Optional[str]=None, *, model: Optional[str]=None, temperature: Optional[float]=None, max_tokens: Optional[int]=None):
        load_api_keys(DEFAULT_API_CONFIG, set_env=True)
        self.provider = 'anthropic'
        self.temperature = float(temperature) if temperature is not None else 0.1
        self.api_key = (api_key or os.getenv('CLAUDE_API_KEY') or os.getenv('ANTHROPIC_API_KEY') or '').strip()
        self.base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com/v1/messages').strip()
        self.headers = {'x-api-key': self.api_key, 'Content-Type': 'application/json', 'anthropic-version': os.getenv('ANTHROPIC_VERSION', '2023-06-01'), 'anthropic-beta': os.getenv('ANTHROPIC_BETA', 'prompt-caching-2024-07-31')}
        self.default_model = (model or os.getenv('ANTHROPIC_MODEL') or os.getenv('CLAUDE_MODEL') or 'model-default').strip()
        default_budget = 8000
        self.max_tokens = int(max_tokens) if max_tokens is not None else int(default_budget)
        self.connect_timeout = int(os.getenv('AI_CONNECT_TIMEOUT', '10'))
        self.read_timeout = int(os.getenv('AI_READ_TIMEOUT', '180'))
        self.timeout = self.read_timeout
        self.max_retries = int(os.getenv('AI_MAX_RETRIES', '2'))
        self.retry_delay = int(os.getenv('AI_RETRY_DELAY', '3'))
        self.cache_dir = str(STEP2_CACHE_DIR)
        os.makedirs(self.cache_dir, exist_ok=True)

    def _ensure_api_key(self) -> None:
        if self.api_key:
            return
        try:
            load_api_keys(DEFAULT_API_CONFIG, set_env=True)
        except Exception:
            pass
        self.api_key = (os.getenv('CLAUDE_API_KEY') or os.getenv('ANTHROPIC_API_KEY') or '').strip()
        self.headers['x-api-key'] = self.api_key
        if not self.api_key:
            raise RuntimeError('Missing CLAUDE_API_KEY/ANTHROPIC_API_KEY (set env or framework/config/api_config.json).')

    def _filter_protocol_tree_content(self, data: dict) -> dict:
        if not isinstance(data, dict):
            return data
        if 'protocol_tree' in data:
            return data['protocol_tree']
        filtered_data = {'root_node_id': data.get('root_node_id', 'root'), 'nodes': data.get('nodes', []) or [], 'edges': data.get('edges', []) or []}
        logger.info(f"Filtered protocol tree: {len(filtered_data['nodes'])} nodes, {len(filtered_data['edges'])} edges")
        return filtered_data

    def _save_to_cache(self, filename: str, data: Any) -> None:
        cache_path = os.path.join(self.cache_dir, filename)
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            output_data = None
            if isinstance(data, dict) and 'raw_response' in data:
                try:
                    raw_response = data['raw_response']
                    if isinstance(raw_response, str):
                        clean_response = self._clean_raw_response(raw_response)
                        if clean_response:
                            parsed_response = json.loads(clean_response)
                            filtered_response = self._filter_protocol_tree_content(parsed_response)
                            output_data = {'protocol_tree': filtered_response, 'timestamp': data.get('timestamp', datetime.now().isoformat()), 'section_info': data.get('section_info', None)}
                            logger.info(f'Successfully parsed raw_response for {filename}')
                        else:
                            raise ValueError('Empty response after cleaning')
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f'Failed to parse raw_response in {filename}: {e}')
                    output_data = {'raw_response': data['raw_response'], 'timestamp': data.get('timestamp', datetime.now().isoformat()), 'section_info': data.get('section_info', None)}
            elif isinstance(data, dict) and 'protocol_tree' in data:
                output_data = data
            elif isinstance(data, dict) and ('nodes' in data or 'root_node_id' in data):
                filtered_response = self._filter_protocol_tree_content(data)
                output_data = {'protocol_tree': filtered_response, 'timestamp': datetime.now().isoformat(), 'section_info': None}
            else:
                output_data = data
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False, cls=NumpyEncoder)
            logger.info(f'Saved to cache: {cache_path}')
        except Exception as e:
            logger.error(f'Failed to save cache {filename}: {e}')
            raise

    def _merge_similar_nodes(self, tree: Dict) -> Dict:
        if not tree or 'nodes' not in tree:
            return tree
        nodes = tree['nodes']
        node_lookup = {node.get('node_id'): node for node in nodes if node.get('node_id') is not None}
        merged_nodes: List[Dict[str, Any]] = []
        seen_signatures: Dict[Tuple[str, ...], int] = {}
        merge_map: Dict[Any, Any] = {}
        for node in nodes:
            node_id = node.get('node_id')
            signature = self._node_context_signature(node, node_lookup)
            if signature in seen_signatures:
                existing_idx = seen_signatures[signature]
                existing_node = merged_nodes[existing_idx]
                existing_id = existing_node.get('node_id')
                if node_id is not None:
                    merge_map[node_id] = existing_id
                    merge_map[str(node_id)] = existing_id
                existing_constraints = set(existing_node.get('constraints', []))
                new_constraints = set(node.get('constraints', []))
                existing_node['constraints'] = list(existing_constraints | new_constraints)
                if len(node.get('description', '') or '') > len(existing_node.get('description', '') or ''):
                    existing_node['description'] = node.get('description', '')
                logger.debug(f'Merged duplicate node {node_id} into {existing_id}')
            else:
                seen_signatures[signature] = len(merged_nodes)
                merged_nodes.append(node)
                if node_id is not None:
                    node_lookup[node_id] = node
        for node in merged_nodes:
            pid = node.get('parent_id')
            if pid in merge_map:
                node['parent_id'] = merge_map[pid]
            children = node.get('children_ids', [])
            new_children = []
            for child in children:
                if child in merge_map:
                    new_children.append(merge_map[child])
                else:
                    new_children.append(child)

            def _coerce_child_id(raw: Any) -> Any:
                if raw is None:
                    return None
                if isinstance(raw, bool):
                    return raw
                if isinstance(raw, (int, float)) and (not isinstance(raw, bool)):
                    try:
                        return int(raw)
                    except Exception:
                        return raw
                if isinstance(raw, str):
                    s = raw.strip()
                    if s and (s.isdigit() or (s.startswith('-') and s[1:].isdigit())):
                        try:
                            return int(s)
                        except Exception:
                            return raw
                    return raw
                return raw
            deduped: List[Any] = []
            seen: set = set()
            for child in new_children:
                coerced = _coerce_child_id(child)
                if coerced is None:
                    continue
                try:
                    key = coerced
                    if key in seen:
                        continue
                    seen.add(key)
                except TypeError:
                    key = str(coerced)
                    if key in seen:
                        continue
                    seen.add(key)
                deduped.append(coerced)

            def _sort_key(value: Any) -> Tuple[int, Any]:
                if isinstance(value, int) and (not isinstance(value, bool)):
                    return (0, value)
                return (1, str(value))
            node['children_ids'] = sorted(deduped, key=_sort_key)
        new_edges = []
        for edge in tree.get('edges', []):
            src = edge.get('src')
            dst = edge.get('dst')
            if src in merge_map:
                src = merge_map[src]
            elif str(src) in merge_map:
                src = merge_map[str(src)]
            if dst in merge_map:
                dst = merge_map[dst]
            elif str(dst) in merge_map:
                dst = merge_map[str(dst)]
            edge['src'] = src
            edge['dst'] = dst
            new_edges.append(edge)
        tree['nodes'] = merged_nodes
        tree['edges'] = new_edges
        logger.info(f'Node merging: {len(nodes)} -> {len(merged_nodes)} nodes')
        return tree

    def _node_context_signature(self, node: Dict[str, Any], lookup: Dict[Any, Dict[str, Any]]) -> Tuple[str, ...]:
        name = str(node.get('name', '') or '')
        node_type = str(node.get('node_type', '') or '')
        message_type = str(node.get('message_type', '') or '')
        parent_id = node.get('parent_id')
        parent = lookup.get(parent_id) if parent_id is not None else None
        parent_name = str(parent.get('name', '') or '') if parent else ''
        parent_type = str(parent.get('node_type', '') or '') if parent else ''
        parent_message_type = str(parent.get('message_type', '') or '') if parent else ''
        source = str(node.get('source', '') or '')
        return (name, node_type, message_type, parent_name, parent_type, parent_message_type, source)

    def _strip_js_single_line_comments_outside_strings(self, text: str) -> str:
        if not text:
            return text
        out: List[str] = []
        i = 0
        n = len(text)
        in_str = False
        escaped = False
        while i < n:
            ch = text[i]
            if in_str:
                out.append(ch)
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == '"':
                    in_str = False
                i += 1
                continue
            if ch == '"':
                in_str = True
                out.append(ch)
                i += 1
                continue
            if ch == '/' and i + 1 < n and (text[i + 1] == '/'):
                i += 2
                while i < n and text[i] != '\n':
                    i += 1
                continue
            out.append(ch)
            i += 1
        return ''.join(out)

    def _clean_raw_response(self, raw_response: str) -> str:
        if not raw_response:
            return ''
        clean_text = raw_response.strip()
        import re
        # Trim any non-JSON preamble and trailing text (common in LLM responses).
        first_obj = clean_text.find('{')
        first_arr = clean_text.find('[')
        starts = [i for i in (first_obj, first_arr) if i != -1]
        if starts:
            clean_text = clean_text[min(starts):]
        last_obj = clean_text.rfind('}')
        last_arr = clean_text.rfind(']')
        last = max(last_obj, last_arr)
        if last != -1:
            clean_text = clean_text[:last + 1]
        if clean_text.startswith('```json'):
            clean_text = clean_text[7:]
        elif clean_text.startswith('```'):
            clean_text = clean_text[3:]
        if clean_text.endswith('```'):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()
        if clean_text.startswith('"') and clean_text.endswith('"'):
            clean_text = clean_text[1:-1]
        elif clean_text.startswith("'") and clean_text.endswith("'"):
            clean_text = clean_text[1:-1]
        clean_text = re.sub('/\\*.*?\\*/', '', clean_text, flags=re.DOTALL)
        clean_text = self._strip_js_single_line_comments_outside_strings(clean_text)
        clean_text = self._validate_and_fix_json_structure(clean_text)
        clean_text = clean_text.strip()
        try:
            clean_text = re.sub('[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]', '', clean_text)
        except Exception:
            pass
        return clean_text

    def _structured_response_format(self) -> Optional[Dict[str, Any]]:
        return None

    def _patch_response_format(self) -> Optional[Dict[str, Any]]:
        return None

    def _clip_patch_budget(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(patch, dict):
            return patch
        max_new_nodes = 20
        max_edge_adds = 20
        new_nodes = patch.get('new_nodes') or []
        edge_adds = patch.get('edge_adds') or []
        if len(new_nodes) > max_new_nodes:
            patch['new_nodes'] = new_nodes[:max_new_nodes]
        if len(edge_adds) > max_edge_adds:
            patch['edge_adds'] = edge_adds[:max_edge_adds]
        for node in patch.get('new_nodes', []):
            node.setdefault('children_ids', [])
            node.setdefault('byte_order', 'big')
            node.setdefault('message_type', 'bidirectional')
        return patch

    def _is_patch_doc_grounded(self, patch: Dict[str, Any], focused_secs: List[Dict[str, Any]]) -> bool:
        if not isinstance(patch, dict):
            return True
        new_nodes = patch.get('new_nodes') or []
        if not new_nodes:
            return True
        labels: Set[str] = set()
        for sec in focused_secs or []:
            for key in ('number', 'title', 'source_file'):
                val = (sec.get(key) or '').strip()
                if val:
                    labels.add(val.lower())
        for sec in focused_secs or []:
            num = (sec.get('number') or '').strip()
            if num:
                lowered = num.lower()
                labels.add(lowered)
                labels.add(re.sub('\\s+', '', lowered))
        if not labels:
            return True
        for node in new_nodes:
            source_val = (node.get('source') or '').strip().lower()
            if not source_val:
                return False
            if not any((label and label in source_val for label in labels)):
                return False
        return True

    def _validate_and_fix_json_structure(self, text: str) -> str:
        if not text:
            return text
        try:
            import json
            json.loads(text)
            return text
        except json.JSONDecodeError as e:
            logger.warning(f'JSON decode error: {e}, attempting repair...')
            repaired = text
            import re
            repaired = re.sub(',\\s*([}\\]])', '\\1', repaired)
            repaired = re.sub('([{,]\\s*)([a-zA-Z_][a-zA-Z0-9_]*)\\s*:', '\\1"\\2":', repaired)
            repaired_control = self._escape_control_chars_in_json_strings(repaired)
            candidates = []
            if repaired_control != repaired:
                candidates.append((repaired_control, 'after escaping control characters'))
            candidates.append((repaired, 'after structural fixes'))
            for candidate, description in candidates:
                try:
                    json.loads(candidate)
                    logger.info(f'Successfully repaired JSON {description}')
                    return candidate
                except json.JSONDecodeError as repair_error:
                    logger.debug(f'JSON still invalid {description}: {repair_error}')
            logger.warning('Could not repair JSON, returning original text')
            return text

    def _escape_control_chars_in_json_strings(self, text: str) -> str:
        if not text:
            return text
        result: List[str] = []
        in_string = False
        escape = False
        for idx, ch in enumerate(text):
            if in_string:
                if escape:
                    result.append(ch)
                    escape = False
                elif ch == '\\':
                    escape = True
                    result.append(ch)
                elif ch == '"':
                    in_string = False
                    result.append(ch)
                elif ord(ch) < 32:
                    if ch == '\n':
                        result.append('\\n')
                    elif ch == '\r':
                        result.append('\\r')
                    elif ch == '\t':
                        result.append('\\t')
                    else:
                        result.append(f'\\u{ord(ch):04x}')
                else:
                    result.append(ch)
            else:
                result.append(ch)
                if ch == '"':
                    backslash_count = 0
                    j = idx - 1
                    while j >= 0 and text[j] == '\\':
                        backslash_count += 1
                        j -= 1
                    if backslash_count % 2 == 0:
                        in_string = True
                        escape = False
        return ''.join(result)

    def _load_from_cache(self, filename: str) -> Optional[Any]:
        if os.getenv('PARGEN_STEP2_FORCE_REBUILD', '').strip().lower() in {'1', 'true', 'yes', 'on'}:
            return None
        cache_path = os.path.join(self.cache_dir, filename)
        if os.path.exists(cache_path):
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                logger.info(f'Loaded from cache: {cache_path}')
                return data
            except json.JSONDecodeError as e:
                logger.warning(f'Failed to load cache {cache_path}: {e}')
        return None

    def _call_api_with_retry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        for attempt in range(self.max_retries):
            try:
                self._ensure_api_key()
                response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=self.timeout)
                if response.status_code == 200:
                    response_data = response.json()
                    logger.info(f'API response successful, response keys: {response_data.keys()}')
                    return response_data
                else:
                    logger.warning(f'API error: {response.status_code}')
                    logger.warning(f'API error response: {response.text[:1000]}')
                    if attempt < self.max_retries - 1:
                        time.sleep(self.retry_delay * (attempt + 1))
            except Exception as e:
                logger.warning(f'API call failed (attempt {attempt + 1}): {e}')
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                else:
                    raise
        raise Exception('API call failed after all retries')

    def _refine_tree_with_raw_data(self, tree, raw_sections, sections, traffic_file=None):
        if not sections:
            logger.info('No sections provided, skipping refinement')
            return tree
        logger.info(f'Starting CONTROLLED section-by-section refinement with {len(sections)} sections')
        batch_size = 1
        num_sections = len(sections)
        batch_count = (num_sections + batch_size - 1) // batch_size
        logger.info(f'Global+Local Attention: processing ALL {num_sections} sections in {batch_count} batches')
        logger.info(f'Batch size: {batch_size} sections per batch for local context focus')
        batch_cache_files = []
        cumulative_tree = tree.copy() if isinstance(tree, dict) else tree
        cumulative_tree = self._inline_validate_and_fix(cumulative_tree, sections, raw_sections, 'inline_initial_tree.json', 'initial_phase')
        for batch_idx in range(batch_count):
            start_idx = batch_idx * batch_size
            end_idx = min((batch_idx + 1) * batch_size, num_sections)
            cache_filename = f'refine_section_{start_idx}_to_{end_idx}_ai_response.json'
            batch_cache_files.append(cache_filename)
            cached_data = self._load_from_cache(cache_filename)
            sections_with_marks = mark_sections_by_batch(sections, batch_start=start_idx, batch_size=batch_size, text_key='content', out_key='content', strip_existing=True, priority='high', set_flag_key='is_focused')
            batch_sections = sections_with_marks
            if cached_data and 'protocol_tree' in cached_data:
                logger.info(f'[OK] Batch {batch_idx + 1}/{batch_count} loaded from cache: {cache_filename}')
                cumulative_tree = cached_data['protocol_tree']
                is_last_batch = batch_idx == batch_count - 1
                cumulative_tree = self._inline_validate_and_fix(cumulative_tree, sections, raw_sections, cache_filename, f'refine_batch_{batch_idx + 1}', force_full_fix=is_last_batch)
                continue
            elif cached_data and 'raw_response' in cached_data:
                try:
                    raw_response = cached_data['raw_response']
                    cleaned_response = self._clean_raw_response(raw_response)
                    batch_result = json.loads(cleaned_response)
                    tree_obj = batch_result.get('protocol_tree') if isinstance(batch_result, dict) else None
                    if isinstance(tree_obj, dict):
                        cumulative_tree = tree_obj
                    else:
                        logger.warning('Cached raw_response missing protocol_tree; skipping cache reuse.')
                        raise ValueError('Invalid cached response')
                    logger.info(f'[OK] Batch {batch_idx + 1}/{batch_count} parsed from cached raw_response')
                    cumulative_tree = self._inline_validate_and_fix(cumulative_tree, sections, raw_sections, cache_filename, f'refine_batch_{batch_idx + 1}')
                    continue
                except Exception as e:
                    logger.warning(f'Failed to parse cached raw_response for batch {batch_idx + 1}: {e}, regenerating...')
            else:
                logger.warning(f'No valid cache found for batch {batch_idx + 1}, regenerating...')
            batch_sections = sections_with_marks
            tree_snippet_json = json.dumps(self._filter_protocol_tree_content(cumulative_tree), ensure_ascii=False, indent=2, cls=NumpyEncoder)
            focused_secs = [s for i, s in enumerate(sections_with_marks) if start_idx <= i < end_idx]
            marked_summary = [_refine_section_digest(sec) for sec in focused_secs]
            validator_report = validate_protocol_tree(json.dumps({'protocol_tree': cumulative_tree}))
            topk_errors = (getattr(validator_report, 'errors', []) or [])[:5]
            marked_sections_summary_text = json.dumps(marked_summary, ensure_ascii=False, indent=2) if marked_summary else '[]'
            validator_errors_lines = [f'- {str(err)}' for err in topk_errors if err]
            validator_errors_text = '\n'.join(validator_errors_lines) if validator_errors_lines else '- None (validator clean in this snapshot)'
            avoid_block_text = '- None (no rejected strategies recorded for this batch).'
            previous_patch_brief_text = '- None (first attempt for this batch).'
            batch_range_start = start_idx + 1
            batch_range_end = max(batch_range_start, end_idx)
            context_block = f'# CONTEXT\n- Current sub-tree snapshot (IDs are STABLE across this patch):\n{tree_snippet_json}\n\n- Documentation sections (structured digest; includes packet_formats tables; focus only on these ranges for this batch {batch_range_start}-{batch_range_end}):\n{marked_sections_summary_text}\n\n- Known validator issues (BEFORE this patch):\n{validator_errors_text}\n\n- Recently tried & rejected strategies (do NOT repeat):\n{avoid_block_text}\n\n- Previous patch summary (if any):\n{previous_patch_brief_text}\n'
            nodes_in_snapshot = cumulative_tree.get('nodes') or []
            used_ids = [int(node.get('node_id')) for node in nodes_in_snapshot if str(node.get('node_id')).isdigit()]
            max_id = max(used_ids) if used_ids else 100
            reserve_start = max_id + 1
            reserve_end = max_id + 500
            instruction_block = f"""\n# OBJECTIVE - DOC-GROUNDED DIFF (no mode switching)\nYour job is to incorporate **missing** parseable, on-wire structure described by the focused documentation in THIS batch.\nIf the current snapshot already contains the focused batch's structure, return an **empty patch** (`{{}}`) exactly - do NOT expand, rewrite, or "improve" anything.\n\n## FIRST: DECIDE IF ANY CHANGE IS NEEDED (STOP-EARLY)\nBefore proposing any patch:\n1) Check whether every focused `packet_formats[].fields` / `field_definitions` item is already represented by an existing leaf in the snapshot (allow minor naming variants).\n   - IMPORTANT: treat a table row as "represented" only if the matching leaf also has a compatible `bit_start` + `size_bits` (after base-offset alignment). If the name matches but the position/size does not, it is NOT represented - you must fix the misalignment.\n2) If the snapshot is validator-clean AND nothing is missing/misaligned for this batch, return `{{}}` exactly.\n\n## MUST: EXPAND PACKET FORMAT TABLES INTO LEAF FIELDS (ONLY WHEN MISSING)\nThe focused documentation may include structured tables like `packet_formats[].fields` (with `byte_position`, `bit_position`, `size`, `data_type`).\nWhen those are present:\n1) You MUST create **leaf field nodes only for missing table rows** (do NOT duplicate existing fields; at most, add constraints/source/description).\n2) You MUST align `byte_position` semantics (absolute vs relative) before emitting `bit_start`:\n   - Many specs use byte positions **absolute from the protocol message start** (e.g., ADU), while others use offsets **relative to the PDU/variant start**.\n   - Compute a `base_offset_bits` for EACH `packet_format` using ANCHOR alignment:\n       * Find one or more anchor fields in the table that also exist in the current snapshot (by name match, e.g., Function Code / Opcode / Length / Type).\n       * For each anchor, compute `candidate_base = <existing_node.bit_start> - <anchor.byte_position>*8`.\n       * If multiple anchors exist, choose the MOST COMMON `candidate_base` (majority vote).\n   - Then emit `bit_start = base_offset_bits + byte_position*8` (plus `bit_position` if provided).\n   - Fallback only if no anchor exists: use the parent container base (`bit_start = parent.bit_start + byte_position*8`).\n3) Parse sizes:\n   - "1 Byte" -> `size_bits = 8`\n   - "2 Bytes" -> `size_bits = 16`\n   - "N Bytes" -> model as `size_bits = val(<Byte_Count_ID>) * 8` and add a `length_of` edge if needed.\n\n## MUST: DO NOT DROP RESERVED/PADDING TABLE ROWS (LAYOUT PLACEHOLDERS)\n`packet_formats[].fields` rows named "Reserved"/"Padding"/"Spare"/"Unused" (or similar) are real on-wire bits/bytes.\n- Always model them as leaf fields with the documented span; missing them causes coverage gaps and systematic offset drift.\n- Only add hard constraints like `== 0` when the text explicitly mandates it ("MUST be zero"); otherwise keep them unconstrained.\n\n## NOTE: `reserved_values` ARE NOT HARD CONSTRAINTS\n`field_definitions[].constraints.reserved_values` (e.g., "9-31 reserved/unassigned") is descriptive.\n- Do NOT translate it into a `range:` constraint and do NOT AND it with `enum` into a contradiction.\n- The allowed numeric domain should remain the full bit-width or documented min/max (e.g., 5-bit -> 0..31). Put reserved ranges in description only unless explicitly forbidden.\n4) Direction: leaf nodes under a request-only variant MUST use `message_type = "request"`, likewise for response.\n5) No overlaps: if you keep a generic fallback payload variant (e.g., Request_Payload), its `condition_on` must be the **complement** of the modeled function codes to avoid overlap with specific variants.\n6) Every new leaf node MUST include `"source"` that matches THIS batch (e.g., section number/title/file).\n7) SELECTOR RULE (GENERAL, NOT JUST "Function Code"):\n   - Do NOT duplicate an existing selector field inside each variant (e.g., avoid per-variant leaves like `Function_Code_0F_Response` when a shared `Function_Code` selector already exists).\n   - Treat any small fixed-width control field with enum/range constraints as a selector candidate (e.g., Function Code, OpCode, Message Type, Command ID, Type, Sub-Function Code).\n   - If a matching selector already exists in the current snapshot, you MUST reuse it:\n       * encode the constant in the `condition_on` edge (e.g., `val(<selector_id>) == 15`),\n       * and the variant's `bit_start`/children MUST start AFTER the selector field (do not re-parse the selector again).\n   - If the spec defines a SECONDARY selector (e.g., Sub-Function Code / Subcommand / MEI Type):\n       * you MAY create an additional selector node, but place it INSIDE the correct parent variant (usually after the primary selector),\n       * then create nested sub-variants under that parent variant controlled by the secondary selector (one selector per sibling variant-group).\n\n## CRITICAL: CONTEXT LINKING STRATEGY\nThe "Current sub-tree snapshot" contains **Selectors** (Function Codes, Opcodes) defined in previous batches.\nWhen the focused documentation in THIS batch describes a specific **Variant** (e.g., "Response for Function Code 0x01"):\n1. **SEARCH** the `Current sub-tree snapshot` for the existing Selector node ID (e.g., the "Function Code" field).\n2. **CREATE** a `condition_on` edge where:\n   - `src`: The ID of the EXISTING Selector node (from the snapshot).\n   - `dst`: The ID of your NEW Variant node (being created now).\n   - `formula`: The value constraint (e.g., `val(src_id) == 1`).\n   - `message_type`: "request" or "response" as appropriate.\n**DO NOT** create a new duplicate Selector node. You MUST link to the existing one.\n\nEach new node MUST include a "source" pointing to the exact section (e.g., `file:number` or section title).\nIf the focused sections contain **no new parseable structure**, return either a **small corrective patch** (e.g., add `length_of`, fix illegal expressions) or **empty patch (`{{}}`)**.\n\n# HARD LIMITS (do not exceed)\n- new_nodes <= 20\n- edge_adds <= 20\n- Any NEW node_id MUST be within [{reserve_start}, {reserve_end}].\n\n# INVARIANTS (strict)\n1) Single root; do NOT create a second root.\n2) Positioning: `bit_start = parent.bit_start + offset_within_parent`; no forward/cross-container/self references.\n3) Sizing: numeric-only arithmetic; variable-size fields pair with a **`length_of`** edge (avoid boolean in `size_bits`).\n4) Selector/Variant: `condition_on` edges from a selector MUST target `node_type="variant"` nodes only (do NOT attach per-field `condition_on` leaves). Variants exclude shared headers/selectors; each variant MUST have exactly one `condition_on` driven by its selector.\n5) Every edge MUST include `message_type` and numeric `src`/`dst`.\n6) Patch only: NEVER return a full `protocol_tree`.\n7) Boolean OR must be explicit: use `or` and repeat the full comparison each time (e.g., `val(7)==1 or val(7)==2 or val(7)==4 or val(7)==15`). Do NOT use `||` or shorthand like `val(7)==1 || 2`.\n8) Keep formula syntax aligned with validator/interpreter/Z3 (STRICT): allowed identifiers val(<ID>), <ID>.size_bits, <ID>.bit_start; operators + - * / ( ) and/or/not with == != >= > <= < only (NO &&, ||, &, |); no chained comparisons-write `val(x) >= 1 and val(x) <= 4`; size_bits is arithmetic-only; condition_on is selector-only (no message_type inside); OR must be fully expanded (GOOD: `val(7)==1 or val(7)==2 or val(7)==4 or val(7)==15`; BAD: `val(7)==1 || 2 || 4 || 15`).\n9) No self-loop edges: never create edges where src == dst (length_of/condition_on or any other rel).\n10) Each variant must have exactly ONE condition_on from a single selector; do not attach multiple selectors or duplicate formulas to the same variant. Formulas across variants must be mutually exclusive. If you cannot give one clean condition_on, return {{}} instead of emitting multiple edges.\n\n# OUTPUT - STRICT JSON PATCH (NOT a full tree)\n{{ "patch_metadata": {{"intent":"expand","scope":"atomic"}},\n   "new_nodes":[...], "node_updates":[...], "edge_adds":[...],\n   "edge_updates":[...], "edge_removes":[...], "nodes_to_remove":[...], "validation_notes":[...] }}\n"""
            direction_rules = '\n# DIRECTIONALITY RULES (STRICT, REFINE-ONLY)\n\n## A. Variants & edges must carry direction\n- Every *variant* node must set `message_type` to **"request"** or **"response"**. Shared selectors/headers/length fields can remain "bidirectional".\n- Never embed direction checks inside `condition_on` formulas. Formulas may reference selector values only (e.g., `val(SEL_ID) == 2`, `val(SEL_ID) in {1,2}`).\n\n## B. Condition edges must inherit direction from dst\n- For every `condition_on` edge, set `message_type` to exactly match the destination variant\'s `message_type`.\n  - If `dst.message_type == "request"`, the edge must also be `"request"`.\n  - If `dst.message_type == "response"`, the edge must be `"response"`.\n  - Only when `dst` itself is `"bidirectional"` may the edge be `"bidirectional"`.\n- Do **not** use a single `"bidirectional"` `condition_on` to cover both request and response variants. Split them into two directional edges.\n\n## C. Dedup & mutual exclusivity\n- Do not emit duplicate edges with the same `src` and `formula` pointing to different variants. Distinguish them via direction or adjust the selector predicates.\n- Variant formulas must be disjoint and collectively cover the selector domain; overlapping predicates are rejected.\n\n## D. Examples\nGOOD:\n  {"src": 6, "dst": 8,  "rel": "condition_on", "formula": "val(6) == 2", "message_type": "request"}\n  {"src": 6, "dst": 11, "rel": "condition_on", "formula": "val(6) == 2", "message_type": "response"}\n\nBAD:\n  {"src": 6, "dst": 8, "rel": "condition_on", "formula": "val(6)==2 and message_type==\'request\'", "message_type": "bidirectional"}\n  {"src": 6, "dst": 9, "rel": "condition_on", "formula": "val(6) == 2", "message_type": "bidirectional"}  # if dst is request-only, edge must be request\n'
            instruction_block = instruction_block + '\n' + direction_rules
            prompt = context_block + '\n' + instruction_block
            payload = {'model': self.default_model, 'system': 'You are a protocol tree patching assistant. You MUST return an incremental JSON patch only - no markdown, no comments. If no safe improvement can be made, return {} exactly.', 'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': prompt}]}], 'max_tokens': int(self.max_tokens), 'temperature': 0.1}
            max_json_retries = 3
            json_retry_count = 0
            tree_parsed = False
            while json_retry_count < max_json_retries and (not tree_parsed):
                result = self._call_api_with_retry(payload)
                if 'content' in result and isinstance(result['content'], list):
                    raw_response = result['content'][0]['text']
                elif 'choices' in result:
                    raw_response = result['choices'][0]['message']['content']
                else:
                    raise ValueError(f'Unexpected API response format: {result.keys()}')
                self._save_to_cache(f'refine_section_{start_idx}_to_{end_idx}_ai_response.json', {'prompt': prompt, 'raw_response': raw_response, 'timestamp': datetime.now().isoformat(), 'section_info': f'Section {start_idx} to {end_idx}', 'json_retry_count': json_retry_count})
                if not raw_response or not raw_response.strip():
                    raise json.JSONDecodeError('Empty response', '', 0)
                logger.info(f'Raw response length: {len(raw_response)}, first 100 chars: {raw_response[:100]}')
                clean_response = self._clean_raw_response(raw_response)
                if not clean_response.strip():
                    exc = json.JSONDecodeError('Empty response', raw_response, 0)
                    logger.warning('JSON decode failed on batch %d attempt %d: %s', batch_idx + 1, json_retry_count + 1, exc)
                    json_retry_count += 1
                    if json_retry_count >= max_json_retries:
                        raise exc
                    logger.warning('Retrying batch %d (attempt %d)', batch_idx + 1, json_retry_count + 1)
                    continue
                try:
                    response_payload = json.loads(clean_response)
                except json.JSONDecodeError as exc:
                    logger.warning('JSON decode failed on batch %d attempt %d: %s', batch_idx + 1, json_retry_count + 1, exc)
                    json_retry_count += 1
                    if json_retry_count >= max_json_retries:
                        raise
                    logger.warning('Retrying batch %d (attempt %d)', batch_idx + 1, json_retry_count + 1)
                    continue
                patch_payload = None
                refined_tree = None
                if not isinstance(response_payload, dict):
                    raise ValueError('LLM response must be a JSON object containing either protocol_tree or patch data')
                has_tree = 'protocol_tree' in response_payload and isinstance(response_payload['protocol_tree'], dict)
                has_patch = 'patch' in response_payload and isinstance(response_payload['patch'], dict)
                if has_tree and (not has_patch):
                    logger.warning('Refine batch %s returned a complete protocol_tree despite patch-only instructions; retrying.', batch_idx + 1)
                    json_retry_count += 1
                    if json_retry_count >= max_json_retries:
                        raise ValueError('Refine LLM kept returning full protocol_tree instead of patch.')
                    logger.warning('Retrying batch %d (attempt %d) after full-tree response', batch_idx + 1, json_retry_count + 1)
                    continue
                if has_patch:
                    patch_payload = response_payload['patch']
                elif not has_tree:
                    patch_payload = response_payload
                else:
                    refined_tree = response_payload['protocol_tree']
                if patch_payload is None:
                    raise ValueError('Refine response missing patch payload after validation.')
                patch_payload = self._clip_patch_budget(patch_payload)
                focused_batch_sections = focused_secs
                if not self._is_patch_doc_grounded(patch_payload, focused_batch_sections):
                    if payload.get('messages'):
                        payload['messages'][-1]['content'] = prompt + "\n\n# NOTE\nYour previous patch added nodes without valid 'source' pointing to the focused sections. Retry: for EACH new node, set a 'source' that matches the section number/title/file of THIS batch."
                    json_retry_count += 1
                    if json_retry_count < max_json_retries:
                        continue
                    logger.warning('Rejecting ungrounded expansion (no valid sources). Skipping this batch.')
                    refined_tree = cumulative_tree
                else:
                    logger.info('Applying refine patch response (keys=%s)', list(patch_payload.keys()))
                    refined_tree = fix_apply_patch(cumulative_tree, patch_payload)
                node_count = len(refined_tree.get('nodes', []))
                try:
                    merge_threshold = int(os.getenv('STEP2_NODE_MERGE_THRESHOLD', '0').strip())
                except Exception:
                    merge_threshold = 0
                merge_threshold = max(0, merge_threshold)
                if merge_threshold and node_count > merge_threshold:
                    logger.warning('Refined tree has %d nodes (>%d), applying node merging strategy', node_count, merge_threshold)
                    refined_tree = self._merge_similar_nodes(refined_tree)
                    node_count = len(refined_tree.get('nodes', []))
                    logger.info('After merging: %d nodes', node_count)
                cumulative_tree = refined_tree
                is_last_batch = batch_idx == batch_count - 1
                cumulative_tree = self._inline_validate_and_fix(cumulative_tree, sections, raw_sections, cache_filename, f'refine_batch_{batch_idx + 1}', force_full_fix=is_last_batch, traffic_file=traffic_file)
                try:
                    self._save_to_cache(cache_filename, {'protocol_tree': cumulative_tree, 'timestamp': datetime.now().isoformat(), 'stage_label': f'refine_batch_{batch_idx + 1}', 'source': 'refine_patch'})
                except Exception as save_exc:
                    logger.warning('Failed to persist refined tree for batch %s: %s', batch_idx + 1, save_exc)
                tree_parsed = True
                logger.info(f'[OK] Batch {batch_idx + 1}/{batch_count} AI response parsed successfully (attempt {json_retry_count + 1}), {node_count} nodes')
                logger.info(f"[OK] Cumulative tree now has {len(cumulative_tree.get('nodes', []))} total nodes")
        final_merged_tree = cumulative_tree
        enable_variants = os.getenv('GEN_ENABLE_MESSAGE_VARIANTS', '0') == '1'
        if enable_variants:
            final_merged_tree = add_request_response_variants(final_merged_tree)
        final_merged_tree = canonicalize_protocol_tree(final_merged_tree)
        final_output = {'protocol_tree': final_merged_tree, 'timestamp': datetime.now().isoformat(), 'merge_info': {'total_batches': len(batch_cache_files), 'total_sections': num_sections, 'batch_files': batch_cache_files, 'cumulative_learning': True}}
        final_cache_path = os.path.join(self.cache_dir, 'final_complete_protocol_tree.json')
        with open(final_cache_path, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False, cls=NumpyEncoder)
        logger.info(f'FINAL COMPLETE PROTOCOL TREE SAVED: {final_cache_path}')
        logger.info(f"Total nodes: {len(final_merged_tree['nodes'])}")
        logger.info(f"Total edges: {len(final_merged_tree['edges'])}")
        logger.info('=' * 60)
        protocol_tree = self._parse_tree_response(final_merged_tree)
        return protocol_tree

    def _inline_validate_and_fix(self, tree: Dict[str, Any], sections: Sequence[Dict[str, Any]], raw_sections: Optional[Sequence[Dict[str, Any]]], cache_filename: str, stage_label: str, force_full_fix: bool=False, traffic_file: Optional[str]=None) -> Dict[str, Any]:
        payload = {'protocol_tree': tree}
        report = validate_protocol_tree(json.dumps(payload))
        issue_count = len(getattr(report, 'issues', {}) or {})
        error_count = len(report.errors)
        logger.info('Inline validation (%s): %s errors, %s total issues', stage_label, error_count, issue_count)
        snapshot_dir = Path(STEP2_FIX_CACHE_DIR) / 'inline_snapshots'
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = snapshot_dir / f'{stage_label}.json'
        snapshot_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        if report.ok:
            return tree
        logger.warning('Inline validation failed for batch %s: hard_errors=%s total_issues=%s (sum=%s); invoking standard fix agent (syntax validator).', stage_label, error_count, issue_count, error_count + issue_count)
        fix_batch_size = max(1, int(os.getenv('INLINE_FIX_BATCH_SIZE', '5')))
        max_calls = max(1, int(os.getenv('INLINE_FIX_MAX_CALLS', '20')))
        inline_fix_root = Path(STEP2_FIX_CACHE_DIR) / 'inline_runs'
        inline_fix_dir = inline_fix_root / stage_label.replace('/', '_')
        inline_fix_dir.mkdir(parents=True, exist_ok=True)
        node_snapshot_dir = inline_fix_dir / 'node_snapshots'
        node_snapshot_dir.mkdir(parents=True, exist_ok=True)
        from ..fix_agent.agent import EnhancedPureAIAgent as FixLLMAgent
        fix_agent = FixLLMAgent(api_key=self.api_key, provider=self.provider)
        fix_agent.base_url = self.base_url
        fix_agent.headers = dict(self.headers)
        fix_agent.cache_dir = str(inline_fix_dir)
        fixed_tree = mcts_fix_tree(fix_agent, tree, sections=sections, raw_sections=raw_sections or sections, batch_size=fix_batch_size, max_llm_calls=max_calls, node_snapshot_dir=str(node_snapshot_dir), validator_fn=run_full_validation, prompt_mode='fix')
        fixed_payload = {'protocol_tree': fixed_tree}
        fixed_report = run_full_validation(fixed_payload)
        if fixed_report.ok:
            logger.info('Inline fix resolved validator issues for %s', stage_label)
        else:
            logger.warning('Inline fix still has %s errors for batch %s - continuing with best-effort tree.', len(fixed_report.errors) + len(getattr(fixed_report, 'issues', {}) or {}), stage_label)
        inline_cache_payload = {'protocol_tree': fixed_tree, 'timestamp': datetime.now().isoformat(), 'source': 'inline_fix', 'stage_label': stage_label, 'validation_ok': fixed_report.ok, 'errors': fixed_report.errors, 'issues': list(getattr(fixed_report, 'issues', {}).keys())}
        self._save_to_cache(cache_filename, inline_cache_payload)
        snapshot_path.write_text(json.dumps({'protocol_tree': fixed_tree}, ensure_ascii=False, indent=2), encoding='utf-8')
        return fixed_tree

    @staticmethod
    def _merge_full_tree(base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(base, dict):
            return copy.deepcopy(new)
        if not isinstance(new, dict):
            return copy.deepcopy(base)
        merged = copy.deepcopy(base)
        merged['root_node_id'] = new.get('root_node_id', merged.get('root_node_id'))
        base_nodes = {n.get('node_id'): n for n in merged.get('nodes', []) if isinstance(n, dict)}
        new_nodes = {n.get('node_id'): n for n in new.get('nodes', []) if isinstance(n, dict)}
        base_nodes.update(new_nodes)
        merged['nodes'] = list(base_nodes.values())
        if isinstance(new.get('edges'), list) and new.get('edges'):
            merged['edges'] = copy.deepcopy(new['edges'])
        return merged

    def _adjust_modbus_length_binding(self, tree: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(tree, dict):
            return tree
        nodes = {n.get('node_id'): n for n in tree.get('nodes', []) if isinstance(n, dict)}

        def _coerce(nid: Any) -> Any:
            try:
                return int(nid)
            except Exception:
                return nid
        for edge in tree.get('edges', []):
            if edge.get('rel') != 'length_of':
                continue
            src = edge.get('src')
            dst = edge.get('dst')
            src_node = nodes.get(src) or nodes.get(str(src))
            dst_node = nodes.get(dst) or nodes.get(str(dst))
            if not src_node or not dst_node:
                continue
            src_name = (src_node.get('name') or '').lower()
            dst_name = (dst_node.get('name') or '').lower()
            if not any((tok in src_name for tok in ('length', 'len', 'byte_count', 'bytecount'))):
                continue
            if not any((tok in dst_name for tok in ('pdu', 'payload'))):
                continue
            formula = edge.get('formula') or ''
            if '-' in str(formula):
                continue
            m = re.fullmatch('\\s*val\\(([\\w-]+)\\)\\s*\\*\\s*8\\s*', str(formula))
            if not m:
                continue
            src_in_formula = _coerce(m.group(1))
            if _coerce(src) != src_in_formula:
                continue
            new_formula = f'(val({src_in_formula}) - 1) * 8'
            edge['formula'] = new_formula
            tgt_size = dst_node.get('size_bits')
            if isinstance(tgt_size, str) and 'val' in tgt_size and (str(src_in_formula) in tgt_size) and ('*' in tgt_size) and ('-' not in tgt_size):
                dst_node['size_bits'] = new_formula
            logger.info('Adjusted length_of formula %s->%s to account for Unit Identifier: %s', src, dst, new_formula)
        return tree

    def build_initial_tree(self, sections: List[Dict]) -> Optional[ProtocolTree]:
        force_rebuild = os.getenv('PARGEN_STEP2_FORCE_REBUILD', '').strip().lower() in {'1', 'true', 'yes', 'on'}
        if not force_rebuild:
            cached_initial = self._load_from_cache('initial_tree_ai_response.json')
            if cached_initial:
                if 'protocol_tree' in cached_initial:
                    logger.info('Using cached initial tree from initial_tree_ai_response.json')
                    return self._adjust_modbus_length_binding(cached_initial['protocol_tree'])
                if 'raw_response' in cached_initial:
                    try:
                        cleaned = self._clean_raw_response(cached_initial['raw_response'])
                        return self._adjust_modbus_length_binding(json.loads(cleaned))
                    except Exception as exc:
                        logger.warning(f'Failed to parse cached raw_response for initial tree: {exc}')
        if not force_rebuild:
            cache_root = Path(self.cache_dir)
            fallback_candidates = [cache_root / 'final_complete_protocol_tree.json', cache_root / 'format_tree.json']
            if os.getenv('PARGEN_ALLOW_GLOBAL_STEP2_CACHE_FALLBACK', '0') == '1':
                fallback_candidates.extend([STEP2_CACHE_DIR / 'final_complete_protocol_tree.json', STEP2_CACHE_DIR / 'format_tree.json'])
            for fb in fallback_candidates:
                try:
                    if fb.exists():
                        with fb.open('r', encoding='utf-8') as f:
                            logger.info(f'Using fallback initial tree from {fb}')
                            tree = json.load(f)
                            tree = self._adjust_modbus_length_binding(tree)
                            return tree
                except Exception as exc:
                    logger.warning(f'Failed to load fallback initial tree from {fb}: {exc}')
        enhanced_sections = []
        for section in sections[:]:
            if not isinstance(section, dict):
                enhanced_section: Dict[str, Any] = {'content': str(section)}
            else:
                enhanced_section = copy.deepcopy(section)
            if 'content' not in enhanced_section and 'summary' in enhanced_section:
                enhanced_section['content'] = enhanced_section.get('summary', '')
            enhanced_section.setdefault('number', '')
            enhanced_section.setdefault('title', '')
            enhanced_section.setdefault('source_file', 'unknown')
            enhanced_section['full_source'] = f"{enhanced_section.get('source_file', 'unknown')}:{enhanced_section.get('number', '')}"
            enhanced_sections.append(enhanced_section)
        """
        prompt = '\n\n## CRITICAL NON-NEGOTIABLE GUIDELINES\n\n- **Selector coverage must be exhaustive**: enumerate every documented value or range for each control field before creating variants. Keep selector constraints (enum/range) identical to the union of your `condition_on` predicates so no value is left without a variant.\n- **Mutually-exclusive layouts must be modeled as variants**: when a control field selects between multiple on-wire layouts that begin at the same offset (different format tables / alternatives), model the control field as `node_type="selector"` and create `node_type="variant"` containers for each alternative, routed via `condition_on`. IMPORTANT: do **NOT** set `parent_id=selector` for those variants unless the entire variant is physically contained within the selector\'s own bit range (rare, e.g., sub-bitfields). In most protocols the selector is a fixed-size field (e.g., 8 bits) and variants describe the *following* bytes, so variants should be siblings under the same parent container and start at `selector.bit_start + selector.size_bits`. Fields across different variants are allowed to share the same `bit_start` (overlap is expected); do NOT shift offsets to avoid overlap.\n- **Selector routing must target variants (not fields)**: for a `node_type="selector"`, every outgoing `condition_on` edge MUST point to a `node_type="variant"` node (never directly to `field` leaves). If multiple leaf fields share the same selector predicate, group them under ONE variant container and attach a single `condition_on` edge to that variant.\n- **condition_on formulas must reference ONLY the controlling selector**: for an edge `src -> dst` with `rel="condition_on"`, the formula may reference ONLY `val(src)` (plus constants and boolean ops). Do NOT reference `val(other_id)`; if multiple control fields are involved, introduce a nested selector/variant structure instead of mixing them in one formula.\n- **condition_on formulas must be valid booleans**: NEVER concatenate clauses (e.g., `A (B)` or `A B`). If you need multiple cases, use explicit `or`/`and` with parentheses.\n- **Model nested selectors (don't flatten)**: if a present/flag-gated section begins with a "Type/Kind/Opcode" field (enumerated values), model it as a nested `node_type="selector"` inside the "section present" variant, then route to auth/option variants from that selector. Do NOT create per-variant shadow selector fields like `Type_MD5`, `Type_SHA1` and then gate variants on those.\n- **Reserved/Padding rows are on-wire**: fields named `Reserved`, `Padding`, `Spare`, `Unused` (or similar) in format tables occupy real bits/bytes. Include them as real leaf fields with the documented span so later offsets stay aligned. Only add hard constraints like `== 0` when the spec explicitly mandates it ("MUST be zero").\n- **`reserved_values` are descriptive, not restrictive**: documentation `reserved_values` / "reserved/unassigned" ranges do NOT mean "value must be in that range". Do NOT translate them into `range:` constraints. Keep the allowed numeric domain as the full bit-width or documented min/max; treat reserved ranges as "unknown semantics" (record in description) unless the spec explicitly forbids them.\n- **Bytes/payload length constraints use `size_bits`, not `value`**: for nodes with `data_type="bytes"` or `node_type="payload"`, NEVER write `range: ... <= value <= ...` to express byte length. Either omit the range and rely on `size_bits`/`length_of`, or constrain length via `range: ... <= size_bits <= ...` (in bits).\n- **Represent exception patterns explicitly**: when the specification describes bit-derived or offset-based exceptions (e.g., high bit indicates error, value + constant), create separate variants with matching predicates.\n- **Length bindings must respect the spec**: if a length field includes shared headers or auxiliary bytes, subtract them before binding to downstream payloads. Use `length_of` edges instead of embedding arithmetic in `size_bits`.\n- **Length expressions are in bits**: treat all size formulas as bit-based. If a count field is in bytes, convert with `val(byte_field) * 8`; if it is already a bit count, use `val(field)` directly. Do not use reverse/rounding formulas.\n- **length_of direction and typing**: `length_of` edges go from the length/count field to the payload, and src/dst `message_type` must match. Put validation/range checks on the length field's `constraints`; do not use reverse inference inside `length_of`.\n- **Parent sizing rule**: a parent container's size_bits should equal the sum of children or be driven by a length_of binding. Do not hide variable children with max(variant.size_bits) or fixed constants; every variable child must have a length_of binding.\n- **Avoid duplicate payloads**: do not keep two equivalent payload representations at the same level (e.g., *_Bytes alongside *_Response). Keep a single set of nodes with a clear length chain.\n- **HARD OUTPUT CONSTRAINTS**:\n  1. node_type MUST be one of: "protocol", "header", "payload", "field", "selector", "variant", "container", "message", "tlv_seq". If unsure, use "field".\n  2. message_type MUST be one of: "bidirectional", "request", "response". If unsure, use "bidirectional".\n  3. size_bits MUST be either an integer (e.g., 8) or an SMT-safe expression using ONLY:\n     - `val(<id>)` for field values\n     - `<id>.bit_start` / `<id>.size_bits` for already-parsed node attributes\n     - basic arithmetic `+ - * / %` and parentheses.\n     Examples: `val(124)*8`, `0.size_bits - 100.bit_start`, `(10.bit_start + 10.size_bits) - 20.bit_start`.\n     If unknown, set size_bits to "variable".\n  4. bit_start MUST be non-negative. For siblings that can co-exist in one frame, keep bit_start non-decreasing and avoid overlap. For nodes gated by mutually-exclusive `condition_on` (selector routing), overlapping wire ranges are acceptable (prefer modeling them under variant containers).\n  5. Do NOT invent extra node_type values or arbitrary fields; output the minimal schema-compliant JSON.\n- **Variants contain only selector-specific bodies**: do not copy shared headers/selectors into variants; start variant `bit_start` immediately after the shared fields to avoid overlap.\n- **SMT-safe expressions are mandatory**: follow the numeric-expression and constraint rules below so every formula is Z3 compatible.\n- **Exactly one protocol root**: create a single root node (e.g., `MODBUS_Message`) with `parent_id = null`. Every other node must attach beneath that root; never introduce multiple parentless nodes.\n- **Selector hierarchy must be unique**: for any selector (opcode, function code, message type, etc.), attach all of its variants beneath a single selector chain. The same variant body must never be referenced by multiple selectors or by both the root and a selector simultaneously.\n- **Do not delete documented nodes**: re-parent or restructure them instead of removing them from the tree.\n- **Initial-tree minimalism**: if some details are unknown, leave them as `size_bits="variable"` / empty `constraints` rather than inventing undocumented fields or constraints.\n\n## STRUCTURAL ANTI-PATTERNS (AVOID THESE)\n\n1. **Fixed-Header Overflow**: Do NOT place variable or selector fields inside a `header` node if they cause the total size to exceed the header\'s documented fixed length.\n   - *Anti-Pattern*: Packing a 1-byte Selector into a 7-byte Header that is already full.\n   - *Solution*: Move the Selector to be a sibling following the Header.\n\n2. **Ambiguous Variants**: When a single Selector value (e.g., 0x01) is valid for BOTH Request and Response messages:\n   - You MUST explicitly distinguish them using `message_type`.\n   - Set `message_type="request"` for the Request variant and its `condition_on` edge.\n   - Set `message_type="response"` for the Response variant and its `condition_on` edge.\n   - *Reasoning*: Without this distinction, the validator will reject them as "duplicate conditions".\n\n## UNIVERSAL NODE TYPES (Protocol-Agnostic)\n\n```yaml\nprotocol:     # Root container for entire protocol message\nheader:       # Fixed-structure container with sub-fields  \nfield:        # Concrete data field (leaf node)\nselector:     # Control field that determines message variants\nvariant:      # Alternative message structure based on selector\npayload:      # Variable-content data section\ncontainer:    # Generic grouping of related fields\n```\n\n## POSITIONING STRATEGY (Universal)\n\nCRITICAL: Always Use Numeric Node IDs in Expressions\n\n### PROHIBITED Positioning Patterns:\n**Self-references**: `node.bit_start + node.size_bits` (e.g., "22.bit_start + 22.size_bits")\n**Parent container references**: Child referencing its direct parent container (e.g., Node 41 with parent_id=40 using "40.bit_start + 0")\n**Forward references**: Referencing nodes that don\'t exist or come later in sequence\n**Cross-container references** without proper hierarchy\n**Circular dependencies** between nodes\n\n**Key Principle**: bit_start = parent.bit_start + offset_within_parent\n\n## SMT-COMPATIBLE EXPRESSION RULES (STRICT)\n\n- `bit_start` / `size_bits` expressions must remain numeric. Use only literals, additions, or `val(NODE_ID) * constant` forms.\n- NEVER embed boolean expressions inside arithmetic (no `(val(X) == 2)` inside `size_bits`).\n- Conditions must remain boolean expressions (comparisons + `And`/`Or`/`Not`).\n- Reference other nodes via `val(NODE_ID)` or `NODE_ID.bit_start/size_bits`; do not introduce field names. `condition_on` formulas MUST be expressed with `val(<selector_id>)` and may reference only the selector that drives the variants.\n- For length prefixes, express the relationship via `length_of` edges rather than inline conditional arithmetic.\n\n## MESSAGE TYPE CLASSIFICATION (Mandatory)\n\nEvery node MUST have exactly one message_type:\n\n- **"bidirectional"**: Used in both directions (headers, control fields)\n- **"request"**: Client-to-server/caller-to-callee structures  \n- **"response"**: Server-to-client/callee-to-caller structures\n\n## CONTROL FIELD DETECTION & VARIANT CREATION\nWhen you find a field that determines message structure:\n\n1. **Identify the selector field** (command, type, opcode, operation, etc.).\n2. **Enumerate every documented value or range** and determine which directions (request/response/exception) exist for each.\n3. **Do not duplicate selector fields** inside variants-variants only contain the selector-specific payload.\n4. **Add condition_on edges** that mirror the selector constraints exactly, including any bitwise predicates required for exceptions.\n5. **Verify coverage**: the union of all condition predicates must equal the selector\'s declared domain.\n6. **Combine multiple selector values in a SINGLE condition_on formula** using `or` (e.g., `val(ID) == 1 or val(ID) == 2`). Do NOT emit multiple condition_on edges for the same variant from the same selector.\n7. **Direction-specific opcodes are still modeled under the same selector**: if request/response/exception messages occupy different selector values, create separate variants branching from the same selector (do not mirror the entire payload under a second selector elsewhere).\n```\n\n### ANTI-PATTERN - Avoid This:\n```json\n{\n  "node_id": "variant1_id",\n  "name": "Command_A_Variant",\n  "bit_start": "same_as_selector",  // POSITION CONFLICT!\n  "children_ids": ["duplicate_selector", "field1", "field2"]\n},\n{\n  "node_id": "duplicate_selector", \n  "name": "Command_A_Control_Field",  // DUPLICATE SELECTOR!\n  "bit_start": "same_as_original_selector"\n}\n```\n\n**Universal Rules for Variant Creation:**\n- **One selector per protocol layer** - never duplicate control fields\n- **Variants contain only command-specific data** - no repeated headers/selectors\n- **Sequential positioning** - variants start after shared fields\n- **Conditional edges** - link selector values to appropriate data variants and cover the entire selector domain\n \n**Initial tree scope (skeleton-first):** Build a stable universal skeleton. CRITICAL: If you identify fields that act as **Selectors** (e.g., opcodes, message types, auth type, flags that enable/disable blocks), you MUST:\n1) set the field `node_type` to `"selector"`, and\n2) create **placeholder** `node_type="variant"` children for every documented value/range (including a reserved/catch-all range if present),\n3) connect selector -> variant via `condition_on` edges (**Selector routing must target variants**, not leaf fields).\nIt is OK for variant bodies to be minimal/empty at this stage; the refinement stage can add detailed fields later.\n\n## CONSTRAINT EXTRACTION (SMT-Compatible Only)\n\nExtract constraints as PURE mathematical expressions:\n- "must be 0" -> `"enum: 0"`\n- "values 1-255" -> `"range: 1 <= value <= 255"`\n- "one of A, B, C" -> `"enum: A|B|C"`\n- "length field maximum 64 (bytes)" -> `"range: 0 <= value <= 64"`\n- "payload maximum 64 bytes" -> `"range: 0 <= size_bits <= 512"`  *(or omit and rely on `length_of`)*\n- "aligned to 2 bytes" -> `"formula: value % 2 == 0"`\n- "multiple of 8" -> `"formula: value % 8 == 0"`\n- "depends on field X" -> `"formula: value = val(X_NODE_ID)"`\n- **Formula assignment**: Every `formula:` constraint must be written as `formula: value = <expression>`, for example `formula: value = min(val(37), 252 * 8)`.\n\n**CRITICAL: SMT Solver Compatibility**\nAll constraints will be processed by an SMT solver for traffic generation.\nFORBIDDEN constraint formats (natural language):\n- "encoding: hexadecimal"\n- "alignment: 2-byte boundary"\n- "padding: zero bits"\n- "endianness: big"\n\nREQUIRED constraint formats (pure math only):\n- Use "range: min <= value <= max" for ranges\n- Use "enum: val1|val2|val3" for specific values\n- Use "formula: mathematical_expression" for complex conditions\n- Always use val(NODE_ID) to reference other nodes, NEVER field names\n\nCRITICAL: NO natural language in constraints - only mathematical expressions!\n\n## EDGE MESSAGE TYPE RULES\n\nEvery edge MUST have a message_type attribute:\n- **"bidirectional"**: Edge applies to both request and response messages\n- **"request"**: Edge only applies in request messages\n- **"response"**: Edge only applies in response messages\n\nFor condition_on edges:\n- If the condition determines a request variant -> message_type = "request"\n- If the condition determines a response variant -> message_type = "response"\n- If the condition applies to both -> message_type = "bidirectional"\n\nFor length_of, offset_of, crc_of edges:\n- Usually message_type = "bidirectional" unless specific to one direction\n- `src` / `dst` MUST be existing numeric node IDs (write them as numbers, not quoted strings).\n\n## OUTPUT SCHEMA (Strict JSON)\n\n## TLV-SEQUENCE MODELLING (protocol-agnostic)\n\nIf the protocol contains a repeated TLV list (Tag/Code + optional Length + Value/Data repeated until end-of-list),\nmodel it using a dedicated sequence node:\n- Use a node with `node_type: "tlv_seq"` to represent the repeated list.\n- The `tlv_seq` node\'s children define the *item template* to be parsed repeatedly from the current cursor.\n- Stop conditions should be expressed via `stop_condition` on the tlv_seq node (e.g., `val(CODE_ID) == END_CODE`)\n  and/or by bounding the tlv_seq via its declared `size_bits` (end-of-container).\n- Within the item template, use a `selector` + `variant` with `condition_on` edges to model special codes such as\n  PAD/END vs normal TLVs. IMPORTANT: `parent_id`/`children_ids` represent *physical containment* in this IR, so\n  variants MUST NOT be children of the `selector` node unless they are sub-bitfields within the selector byte.\n  Instead, introduce an item container (e.g., `TLV_Item`) under `tlv_seq`, put the tag selector under it, and\n  attach all variants as siblings under that item container.\n- IMPORTANT: If the TLV tag is modeled as a `selector` (consuming the tag byte), then variants that start at\n  `selector.bit_start + selector.size_bits` MUST NOT include a redundant `Code_*`/`Tag_*` field at offset 0.\n  Either (A) omit the code field and begin the body with Length/Value, or (B) if you insist on a code field,\n  set the variant\'s `bit_start` to `selector.bit_start` (not after it). Mixing both shifts the TLV body by 1 byte.\n\n### CLASSIC TLV-SEQ PATTERN (copy & adapt; IDs/values are examples)\n\nThis example shows the intended modelling shape that avoids common failure modes:\n  - missing stop_condition -> tlv_seq scans into padding/next layer\n  - treating byte length as bit length -> leftover_bits != 0, gap_bits=8, OOB reads\n  - modelling END as both a TLV variant and an extra trailing field -> double-consumption\n\n\t```json\n\t{\n\t  "root_node_id": 0,\n\t  "nodes": [\n    {"node_id": 0, "name": "PDU", "node_type": "protocol", "message_type": "bidirectional",\n     "bit_start": 0, "size_bits": "variable", "data_type": "binary", "byte_order": "big",\n     "parent_id": null, "children_ids": [100], "constraints": [], "source": "doc", "dependencies": []},\n\n    {"node_id": 100, "name": "Options_Area", "node_type": "container", "message_type": "bidirectional",\n     "bit_start": "0.bit_start + 0", "size_bits": "0.size_bits - 100.bit_start", "data_type": "binary",\n     "byte_order": "big", "parent_id": 0, "children_ids": [110, 190], "constraints": [], "source": "doc", "dependencies": []},\n\n\t    {"node_id": 110, "name": "Options", "node_type": "tlv_seq", "message_type": "bidirectional",\n\t     "bit_start": "100.bit_start + 0", "size_bits": "variable",\n\t     "stop_condition": "val(120) == 255",\n\t     "parent_id": 100, "children_ids": [115], "constraints": [], "source": "doc", "dependencies": []},\n\n\t    {"node_id": 115, "name": "TLV_Item", "node_type": "container", "message_type": "bidirectional",\n\t     "bit_start": "110.bit_start + 0", "size_bits": "variable", "data_type": "binary",\n\t     "byte_order": "big", "parent_id": 110, "children_ids": [120, 121, 122, 123], "constraints": [], "source": "doc", "dependencies": []},\n\n\t    {"node_id": 120, "name": "TLV_Tag", "node_type": "selector", "message_type": "bidirectional",\n\t     "bit_start": "115.bit_start + 0", "size_bits": 8, "data_type": "uint8",\n\t     "byte_order": "big", "parent_id": 115, "children_ids": [], "constraints": [], "source": "doc", "dependencies": []},\n\n\t    {"node_id": 121, "name": "Pad_Option", "node_type": "variant", "message_type": "bidirectional",\n\t     "bit_start": "120.bit_start + 120.size_bits", "size_bits": 0, "data_type": "binary", "byte_order": "big",\n\t     "parent_id": 115, "children_ids": [], "constraints": [], "source": "doc", "dependencies": []},\n\n\t    {"node_id": 122, "name": "End_Option", "node_type": "variant", "message_type": "bidirectional",\n\t     "bit_start": "120.bit_start + 120.size_bits", "size_bits": 0, "data_type": "binary", "byte_order": "big",\n\t     "parent_id": 115, "children_ids": [], "constraints": [], "source": "doc", "dependencies": []},\n\n\t    {"node_id": 123, "name": "Normal_TLV", "node_type": "variant", "message_type": "bidirectional",\n\t     "bit_start": "120.bit_start + 120.size_bits", "size_bits": "variable", "data_type": "binary", "byte_order": "big",\n\t     "parent_id": 115, "children_ids": [124, 125], "constraints": [], "source": "doc", "dependencies": []},\n\n    {"node_id": 124, "name": "TLV_Length_Bytes", "node_type": "field", "message_type": "bidirectional",\n     "bit_start": "123.bit_start + 0", "size_bits": 8, "data_type": "uint8", "byte_order": "big",\n     "parent_id": 123, "children_ids": [], "constraints": [], "source": "doc", "dependencies": []},\n\n    {"node_id": 125, "name": "TLV_Value", "node_type": "payload", "message_type": "bidirectional",\n     "bit_start": "124.bit_start + 124.size_bits", "size_bits": "variable", "data_type": "bytes", "byte_order": "big",\n     "parent_id": 123, "children_ids": [], "constraints": [], "source": "doc", "dependencies": []},\n\n    {"node_id": 190, "name": "Padding", "node_type": "payload", "message_type": "bidirectional",\n     "bit_start": "110.bit_start + 110.size_bits", "size_bits": "0.size_bits - 190.bit_start", "data_type": "bytes",\n     "byte_order": "big", "parent_id": 100, "children_ids": [], "constraints": [], "source": "doc", "dependencies": []}\n  ],\n  "edges": [\n    {"src": 120, "dst": 121, "rel": "condition_on", "formula": "val(120) == 0", "message_type": "bidirectional"},\n    {"src": 120, "dst": 122, "rel": "condition_on", "formula": "val(120) == 255", "message_type": "bidirectional"},\n    {"src": 120, "dst": 123, "rel": "condition_on", "formula": "(val(120) != 0) and (val(120) != 255)", "message_type": "bidirectional"},\n    {"src": 124, "dst": 125, "rel": "length_of", "formula": "val(124)*8", "message_type": "bidirectional"}\n  ]\n}\n```\n\nNotes:\n- If the options/TLV area is bounded by a length field (not "to end of message"), do NOT use `0.size_bits - ...`;\n  bind the container or tlv_seq via `length_of` from that length field instead.\n- `Padding` is optional: only include when the spec allows trailing pad bytes after end-of-list.\n\n{\n  "protocol_tree": {\n    "root_node_id": 0,\n    "nodes": [\n      {\n        "node_id": 0,\n        "name": "Protocol_Root",\n        "node_type": "protocol|header|field|selector|variant|payload|container|tlv_seq",\n        "message_type": "bidirectional|request|response",\n        "bit_start": "positioning_expression (e.g., 0 or \'PARENT.bit_start + 8\')",\n        "size_bits": "size_expression_or_integer",\n        "data_type": "binary|uint8|uint16|uint32|uint64|string|bytes",\n        "byte_order": "big|little",\n        "parent_id": "parent_node_id_or_null",\n        "children_ids": ["array_of_child_node_ids"],\n        "constraints": ["constraint_strings"],\n        "source": "documentation_reference",\n        "dependencies": []\n      }\n    ],\n    "edges": [\n      {\n        "src": source_node_id,\n        "dst": destination_node_id,\n        "rel": "length_of|condition_on|offset_of|repeat_count|crc_of",\n        "formula": "relationship_expression",\n        "message_type": "bidirectional|request|response"\n      }\n    ]\n  }\n}\n\n\n## EXAMPLE OUTPUT (Valid JSON; selector -> variants skeleton)\n\n{\n  "protocol_tree": {\n    "root_node_id": 0,\n    "nodes": [\n      {\n        "node_id": 0,\n        "name": "PDU",\n        "node_type": "protocol",\n        "message_type": "bidirectional",\n        "bit_start": 0,\n        "size_bits": "variable",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": null,\n        "children_ids": [1, 2],\n        "constraints": [],\n        "source": "doc",\n        "dependencies": []\n      },\n      {\n        "node_id": 1,\n        "name": "Header",\n        "node_type": "header",\n        "message_type": "bidirectional",\n        "bit_start": "0.bit_start + 0",\n        "size_bits": 16,\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": 0,\n        "children_ids": [10],\n        "constraints": [],\n        "source": "doc",\n        "dependencies": []\n      },\n      {\n        "node_id": 10,\n        "name": "Type",\n        "node_type": "selector",\n        "message_type": "bidirectional",\n        "bit_start": "1.bit_start + 0",\n        "size_bits": 8,\n        "data_type": "uint8",\n        "byte_order": "big",\n        "parent_id": 1,\n        "children_ids": [],\n        "constraints": ["enum: 1|2|3"],\n        "source": "doc",\n        "dependencies": []\n      },\n      {\n        "node_id": 2,\n        "name": "Type_Variants",\n        "node_type": "container",\n        "message_type": "bidirectional",\n        "bit_start": "1.bit_start + 16",\n        "size_bits": "variable",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": 0,\n        "children_ids": [20, 21],\n        "constraints": [],\n        "source": "doc",\n        "dependencies": []\n      },\n      {\n        "node_id": 20,\n        "name": "Type_1_Body",\n        "node_type": "variant",\n        "message_type": "bidirectional",\n        "bit_start": "2.bit_start + 0",\n        "size_bits": "variable",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": 2,\n        "children_ids": [],\n        "constraints": [],\n        "source": "doc",\n        "dependencies": []\n      },\n      {\n        "node_id": 21,\n        "name": "Type_2_or_3_Body",\n        "node_type": "variant",\n        "message_type": "bidirectional",\n        "bit_start": "2.bit_start + 0",\n        "size_bits": "variable",\n        "data_type": "binary",\n        "byte_order": "big",\n        "parent_id": 2,\n        "children_ids": [],\n        "constraints": [],\n        "source": "doc",\n        "dependencies": []\n      }\n    ],\n    "edges": [\n      {\n        "src": 10,\n        "dst": 20,\n        "rel": "condition_on",\n        "formula": "val(10) == 1",\n        "message_type": "bidirectional"\n      },\n      {\n        "src": 10,\n        "dst": 21,\n        "rel": "condition_on",\n        "formula": "val(10) == 2 or val(10) == 3",\n        "message_type": "bidirectional"\n      }\n    ]\n  }\n}\n\n## CRITICAL SUCCESS FACTORS\n\n1. **Protocol Agnostic**: No hardcoded assumptions about specific protocols\n2. **Structure First**: Focus on binary layout over semantic meaning\n3. **Concrete Only**: Extract only fields with clear bit positions/sizes\n4. **Relationship Driven**: Use edges to express field interdependencies\n5. **Variant Aware**: Detect and model conditional message structures\n6. **Position Safe**: Avoid circular dependencies and cross-container references\n7. **Hierarchy Complete**: Whenever you add a node, append its ID to the parent `children_ids` so the tree stays connected.\n8. **Format Consistency**: Ensure the protocol tree format stays consistent and aligned with the protocol semantics, constraints, and specifications described.\n\n## QUALITY CHECKLIST\n\nBefore returning your result, verify:\n- [ ] Every node has unique numeric node_id\n- [ ] Every node has required message_type field\n- [ ] No self-referential positioning expressions\n- [ ] All selector fields have corresponding variant nodes\n- [ ] Container hierarchy makes logical sense\n- [ ] Size and position expressions are well-formed\n\nBuild a **minimal but correct** structure. Better to have a simple, accurate skeleton than a complex, incorrect tree.\n\n## DOCUMENTATION TO ANALYZE:\n' + json.dumps(enhanced_sections, indent=2) + '\n\nPlease analyze the above documentation and extract a protocol tree structure following the guidelines above.\nOutput ONLY the JSON object, no other text.'
        """
        prompt_lines = [
            '## CRITICAL NON-NEGOTIABLE GUIDELINES',
            '',
            '- **Selector coverage must be exhaustive**: enumerate every documented value or range for each control field before creating variants. Keep selector constraints (enum/range) identical to the union of your `condition_on` predicates so no value is left without a variant.',
            '- **Mutually-exclusive layouts must be modeled as variants**: when a control field selects between multiple on-wire layouts that begin at the same offset, model the control field as `node_type="selector"` and create `node_type="variant"` containers for each alternative, routed via `condition_on`.',
            '- **Selector routing must target variants (not fields)**: for a `node_type="selector"`, every outgoing `condition_on` edge MUST point to a `node_type="variant"` node (never directly to `field` leaves).',
            '- **condition_on formulas must reference ONLY the controlling selector**: for an edge `src -> dst` with `rel="condition_on"`, the formula may reference ONLY `val(src)` (plus constants and boolean ops).',
            '- **condition_on formulas must be valid booleans**: NEVER concatenate clauses; use explicit `or`/`and` with parentheses.',
            '- **Model nested selectors (do not flatten)**: if a present/flag-gated section begins with a Type/Kind/Opcode field, model it as a nested `node_type="selector"` inside the present variant, then route to auth/option variants from that selector.',
            '- **Reserved/Padding rows are on-wire**: rows named `Reserved`/`Padding`/`Spare`/`Unused` occupy real bits/bytes. Include them as real leaf fields at the documented span so later offsets stay aligned.',
            '- **`reserved_values` are descriptive, not restrictive**: do NOT translate documented reserved/unassigned ranges into `range:` constraints unless the spec explicitly forbids them.',
            '- **Bytes/payload length constraints use `size_bits`, not `value`**: for `data_type="bytes"` or `node_type="payload"`, do not express byte length via `value`; rely on `size_bits`/`length_of`.',
            '- **Length bindings must respect the spec**: prefer `length_of` edges over embedding arithmetic in `size_bits`.',
            '- **Length expressions are in bits**: if a count field is in bytes, convert with `val(field) * 8`.',
            '- **length_of direction and typing**: `length_of` edges go from the length/count field to the payload, and src/dst `message_type` must match.',
            '- **Parent sizing rule**: a parent container `size_bits` should equal the sum of children or be driven by a `length_of` binding.',
            '',
            '## HARD OUTPUT CONSTRAINTS',
            '',
            '- Output MUST be valid JSON only (no markdown, no comments, no extra text).',
            '- Top-level must be `{ "protocol_tree": ... }`.',
            '- `protocol_tree` must include: `root_node_id`, `nodes`, `edges`.',
            '- All `node_id` values must be unique integers.',
            '- Every node must include: `node_id`, `name`, `node_type`, `message_type`, `bit_start`, `size_bits`, `data_type`, `byte_order`, `parent_id`, `children_ids`, `constraints`, `source`, `dependencies`.',
            '- Every edge must include: `src`, `dst`, `rel`, `formula`, `message_type`.',
            '- Ensure every child node_id appears in its parent `children_ids`.',
            '',
            '## DOCUMENTATION TO ANALYZE:',
            json.dumps(enhanced_sections, indent=2),
            '',
            'Please analyze the above documentation and extract a protocol tree structure following the guidelines above.',
            'Output ONLY the JSON object, no other text.',
        ]
        prompt = '\n'.join(prompt_lines)
        payload = {'model': self.default_model, 'system': 'You are building a protocol format tree. Be specific and comprehensive. CRITICAL: You must respond with valid JSON only. No markdown, no comments, no extra text.', 'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': prompt + '\n\nIMPORTANT: Respond with ONLY the JSON object, no markdown formatting, no comments.'}]}], 'max_tokens': int(self.max_tokens), 'temperature': self.temperature}
        try:
            result = self._call_api_with_retry(payload)
            raw_response_parts: list[str] = []
            if 'content' in result and isinstance(result['content'], list):
                for item in result['content']:
                    if isinstance(item, dict) and 'text' in item:
                        raw_response_parts.append(str(item.get('text') or ''))
            raw_response = ''.join(raw_response_parts).strip()
            if not raw_response:
                raise ValueError(f'Unexpected API response format: {result.keys()}')
            cache_data = {'prompt': prompt, 'raw_response': raw_response, 'timestamp': datetime.now().isoformat()}
            self._save_to_cache('initial_tree_ai_response.json', cache_data)
            cached_result = self._load_from_cache('initial_tree_ai_response.json')
            if cached_result and 'protocol_tree' in cached_result:
                tree_data = cached_result['protocol_tree']
                logger.info('Initial tree loaded from processed cache')
                tree_data = self._adjust_modbus_length_binding(tree_data)
                return tree_data
            else:
                raw_text = raw_response.strip()
                if raw_text.startswith('```json'):
                    raw_text = raw_text[7:-3] if raw_text.endswith('```') else raw_text[7:]
                tree_data = json.loads(raw_text)
                logger.info('[OK] Initial tree parsed directly from API response')
                tree_data = self._adjust_modbus_length_binding(tree_data)
                return tree_data
        except Exception as e:
            logger.error(f'Initial tree building failed: {e}')
            try:
                cached_result = self._load_from_cache('initial_tree_ai_response.json')
                if cached_result and 'protocol_tree' in cached_result:
                    logger.info('[OK] Recovered initial tree from cache')
                    return cached_result['protocol_tree']
            except:
                pass
        return None

    def _parse_tree_response(self, tree_data: Dict[str, Any]) -> Optional[ProtocolTree]:
        try:
            nodes = {}
            for node_data in tree_data.get('nodes', []):
                children = node_data.get('children_ids', []) or []
                normalized_children = [str(child) for child in children]
                parent_id = node_data.get('parent_id')
                if parent_id is not None:
                    parent_id = str(parent_id)
                node_type = canonicalize_node_type(node_data.get('node_type'))
                node = ProtocolNode(node_id=str(node_data.get('node_id')), name=node_data.get('name', 'Unknown'), node_type=node_type, description=node_data.get('description', ''), bit_start=node_data.get('bit_start'), size_bits=node_data.get('size_bits'), data_type=node_data.get('data_type'), byte_order=node_data.get('byte_order', 'big'), message_type=node_data.get('message_type', '') or '', constraints=node_data.get('constraints', []) or [], dependencies=node_data.get('dependencies', []) or [], parent_id=parent_id, children_ids=normalized_children, confidence_score=node_data.get('confidence_score', 0.7))
                nodes[node.node_id] = node
            tree = ProtocolTree(protocol_name=tree_data.get('protocol_name', 'Unknown Protocol'), root_node_id=tree_data.get('root_node_id', 'root'), nodes=nodes, edges=list(tree_data.get('edges', [])), metadata={'initial_nodes': len(nodes)}, created_at=datetime.now().isoformat())
            return tree
        except Exception as e:
            logger.error(f'Tree parsing failed: {e}')
            return None

class UniversalProtocolAnalyzer:

    def __init__(self, *, initial_provider: Optional[str]=None, initial_model: Optional[str]=None, initial_temperature: Optional[float]=None, initial_max_tokens: Optional[int]=None, refine_provider: Optional[str]=None, refine_model: Optional[str]=None, refine_temperature: Optional[float]=None, refine_max_tokens: Optional[int]=None):
        self.ai_agent = GenerationLLMAgent(model=initial_model, temperature=initial_temperature, max_tokens=initial_max_tokens)
        self.refine_agent = GenerationLLMAgent(model=refine_model, temperature=refine_temperature, max_tokens=refine_max_tokens)

    def analyze_protocol(self, sections_file: str, raw_file: str, traffic_file: Optional[str]=None):
        namespace = os.getenv('PARGEN_STEP2_CACHE_NAMESPACE') or _infer_step2_cache_namespace(sections_file, raw_file)
        if namespace:
            cache_dir = str(Path(STEP2_CACHE_DIR) / namespace)
            self.ai_agent.cache_dir = cache_dir
            self.refine_agent.cache_dir = cache_dir
            os.makedirs(cache_dir, exist_ok=True)
            logger.info('Step2 cache namespace: %s (%s) initial_provider=%s refine_provider=%s', namespace, cache_dir, getattr(self.ai_agent, 'provider', '?'), getattr(self.refine_agent, 'provider', '?'))
        with open(sections_file, 'r', encoding='utf-8') as f:
            sections_data = json.load(f)
            if isinstance(sections_data, list):
                sections = sections_data
            else:
                sections = sections_data.get('sections', [])
        with open(raw_file, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
            if isinstance(raw_data, list):
                raw_sections = raw_data
            else:
                raw_sections = raw_data.get('sections', [])
        logger.info('Phase 1: Building initial protocol tree...')
        initial_tree_data = self.ai_agent.build_initial_tree(sections)
        initial_tree_data = self.ai_agent._adjust_modbus_length_binding(initial_tree_data)
        if not initial_tree_data:
            raise ValueError('Failed to build initial tree')
        logger.info('Phase 2: Refine protocol tree...')
        final_tree = self.refine_agent._refine_tree_with_raw_data(initial_tree_data, raw_sections, sections, traffic_file=traffic_file)
        return final_tree

    def _display_node(self, tree: ProtocolTree, node_id: str, depth: int, max_depth: int=4):
        if depth > max_depth:
            return
        node = tree.get_node(node_id)
        if not node:
            return
        indent = '  ' * depth
        icon = {'protocol': '', 'header': '', 'payload': '', 'field': '', 'composite': ''}.get(node.node_type, '')
        info = f'{icon} {node.name}'
        if node.node_type == 'field':
            info += f' [{node.size_bits} bits'
            if isinstance(node.bit_start, int):
                info += f' @{node.bit_start}'
            info += f", {node.data_type or 'unknown'}]"
        if node.parse_success_count > 0 or node.parse_failure_count > 0:
            total = node.parse_success_count + node.parse_failure_count
            success_rate = node.parse_success_count / total * 100
        for child_id in node.children_ids:
            self._display_node(tree, child_id, depth + 1, max_depth)
