import argparse
import os
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Sequence, Dict, Any, List, Tuple, Optional, Set
from copy import deepcopy
from collections import defaultdict, Counter
from framework.logging_utils import setup_logging
from .agent import EnhancedPureAIAgent
from .refinement import mcts_fix_tree, run_full_validation
from ...paths import STEP2_CACHE_DIR, STEP2_FIX_CACHE_DIR
from ..traffic_agent.semantic_validator import run_hybrid_validation
from ..validation_agent.syntax_validator import is_hard_error, Severity

def _coerce_int(value):
    try:
        return int(value)
    except Exception:
        return None

def _strip_outer_parens(text: str) -> str:
    if not text:
        return text
    stripped = text.strip()
    while stripped.startswith('(') and stripped.endswith(')'):
        inner = stripped[1:-1].strip()
        if not inner:
            break
        stripped = inner
    return stripped

def _rewrite_assignment_formula(text: str, src_id: int) -> Tuple[bool, str]:
    assignment_pattern = re.compile(f'^\\s*val\\(\\s*{src_id}\\s*\\)\\s*=\\s*(.+)$', re.IGNORECASE)
    match = assignment_pattern.match(text)
    if not match:
        return (False, text)
    rhs = _strip_outer_parens(match.group(1))
    pattern_a = re.compile('^\\s*(?P<const>-?\\d+)\\s*\\+\\s*\\(\\s*(?P<dst>\\d+)\\.size_bits\\s*/\\s*(?P<div>\\d+)\\s*\\)\\s*$', re.IGNORECASE)
    m_a = pattern_a.match(rhs)
    if m_a:
        const = int(m_a.group('const'))
        divisor = int(m_a.group('div'))
        return (True, f'(val({src_id}) - {const}) * {divisor}')
    pattern_b = re.compile('^\\s*\\(\\s*(?P<dst>\\d+)\\.size_bits\\s*/\\s*(?P<div>\\d+)\\s*\\)\\s*\\+\\s*(?P<const>-?\\d+)\\s*$', re.IGNORECASE)
    m_b = pattern_b.match(rhs)
    if m_b:
        const = int(m_b.group('const'))
        divisor = int(m_b.group('div'))
        return (True, f'(val({src_id}) - {const}) * {divisor}')
    pattern_c = re.compile('^\\s*\\(?\\s*(?P<dst>\\d+)\\.size_bits\\s*/\\s*(?P<div>\\d+)\\s*\\)?\\s*$', re.IGNORECASE)
    m_c = pattern_c.match(rhs)
    if m_c:
        divisor = int(m_c.group('div'))
        return (True, f'val({src_id}) * {divisor}')
    return (True, f'val({src_id})')

def _normalize_length_formula(formula: str, src_id: int) -> str:
    if not formula:
        return f'(val({src_id})) * 8'
    text = _strip_outer_parens(str(formula).strip())
    handled_assignment, rewritten = _rewrite_assignment_formula(text, src_id)
    if handled_assignment:
        text = rewritten
    if re.search('val\\(\\s*(?!%d)\\d+\\s*\\)' % src_id, text, re.IGNORECASE):
        text = f'val({src_id})'
    if '.size_bits' in text or '=' in text:
        text = f'val({src_id})'
    text = _align_formula_with_src(text, src_id)
    if not re.search('val\\(\\s*\\d+\\s*\\)', text):
        text = f'val({src_id})'
    if '*' not in text:
        base = _strip_outer_parens(text)
        if re.search('[+\\-*/\\s]', base):
            return f'({base}) * 8'
        return f'{base} * 8'
    return text
_VAL_REF_PATTERN = re.compile('val\\(\\s*(\\d+)\\s*\\)', re.IGNORECASE)
_VAL_EQ_PATTERN = re.compile('^val\\(\\s*(\\d+)\\s*\\)\\s*==\\s*(.+)$', re.IGNORECASE)

def _align_formula_with_src(formula: str, src_id: int) -> str:
    if not formula or src_id is None:
        return formula

    def _replace(match: re.Match) -> str:
        try:
            ref_id = int(match.group(1))
        except Exception:
            return match.group(0)
        if ref_id == src_id:
            return match.group(0)
        return f'val({src_id})'
    return _VAL_REF_PATTERN.sub(_replace, formula)

def _build_node_map(nodes: List[Dict[str, Any]]) -> Dict[int, Dict[str, Any]]:
    mapping: Dict[int, Dict[str, Any]] = {}
    for node in nodes or []:
        nid = _coerce_int(node.get('node_id'))
        if nid is None:
            continue
        mapping[nid] = node
    return mapping

def _truthy(flag: Any) -> bool:
    if isinstance(flag, bool):
        return flag
    if isinstance(flag, (int, float)):
        return bool(flag)
    if isinstance(flag, str):
        return flag.strip().lower() in {'1', 'true', 'yes', 'on'}
    return False

def _is_optional_variant(node: Dict[str, Any]) -> bool:
    annotations = node.get('annotations') or node.get('metadata')
    if isinstance(annotations, dict):
        if _truthy(annotations.get('optional_variant')) or _truthy(annotations.get('allow_variant_removal')):
            return True
    if _truthy(node.get('optional_variant')) or _truthy(node.get('allow_variant_removal')):
        return True
    return False

def _size_repr(value: Any) -> str:
    if isinstance(value, (int, float)):
        try:
            return str(int(value))
        except Exception:
            return str(value)
    return (value or '').strip() if isinstance(value, str) else ''

def _bit_start_repr(value: Any) -> str:
    if isinstance(value, (int, float)):
        try:
            return str(int(value))
        except Exception:
            return str(value)
    return (value or '').strip() if isinstance(value, str) else ''

def _node_signature_basic(node: Dict[str, Any]) -> Tuple[Any, ...]:
    name = (node.get('name', '') or '').strip()
    node_type = str(node.get('node_type', '') or '').lower()
    message_type = str(node.get('message_type', '') or '').lower()
    data_type = str(node.get('data_type', '') or '').lower()
    size_bits = _size_repr(node.get('size_bits'))
    bit_start = _bit_start_repr(node.get('bit_start'))
    return (name, node_type, message_type, data_type, size_bits, bit_start)

def _create_node_resolver(original_tree: Dict[str, Any], final_tree: Dict[str, Any]):
    orig_nodes = [n for n in original_tree.get('nodes', []) if isinstance(n, dict)]
    final_nodes = [n for n in final_tree.get('nodes', []) if isinstance(n, dict)]
    orig_nodes_map = _build_node_map(orig_nodes)
    final_nodes_map = _build_node_map(final_nodes)
    final_signature_index: Dict[Tuple[Any, ...], List[int]] = defaultdict(list)
    name_type_index: Dict[Tuple[str, str, str], List[int]] = defaultdict(list)
    name_index: Dict[str, List[int]] = defaultdict(list)
    for nid, node in final_nodes_map.items():
        sig = _node_signature_basic(node)
        final_signature_index[sig].append(nid)
        name = (node.get('name', '') or '').strip()
        node_type = str(node.get('node_type', '') or '').lower()
        msg_type = str(node.get('message_type', '') or '').lower()
        name_type_index[name, node_type, msg_type].append(nid)
        name_index[name].append(nid)

    def _map_node_id(old_id: Optional[int]) -> Optional[int]:
        if old_id is None:
            return None
        if old_id in final_nodes_map:
            return old_id
        orig_node = orig_nodes_map.get(old_id)
        if not orig_node:
            return None
        sig = _node_signature_basic(orig_node)
        candidates = list(final_signature_index.get(sig, []))
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            target_size = _size_repr(orig_node.get('size_bits'))
            filtered = [cid for cid in candidates if _size_repr(final_nodes_map[cid].get('size_bits')) == target_size]
            if len(filtered) == 1:
                return filtered[0]
            candidates = filtered
        if len(candidates) != 1:
            name = (orig_node.get('name', '') or '').strip()
            node_type = str(orig_node.get('node_type', '') or '').lower()
            msg_type = str(orig_node.get('message_type', '') or '').lower()
            candidates = list(name_type_index.get((name, node_type, msg_type), []))
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                target_size = _size_repr(orig_node.get('size_bits'))
                filtered = [cid for cid in candidates if _size_repr(final_nodes_map[cid].get('size_bits')) == target_size]
                if len(filtered) == 1:
                    return filtered[0]
                candidates = filtered
        if len(candidates) != 1:
            name = (orig_node.get('name', '') or '').strip()
            candidates = list(name_index.get(name, []))
            if len(candidates) == 1:
                return candidates[0]
            if len(candidates) > 1:
                target_size = _size_repr(orig_node.get('size_bits'))
                filtered = [cid for cid in candidates if _size_repr(final_nodes_map[cid].get('size_bits')) == target_size]
                if len(filtered) == 1:
                    return filtered[0]
        return candidates[0] if len(candidates) == 1 else None
    return (_map_node_id, orig_nodes_map, final_nodes_map)

def _collect_variant_signatures(tree: Dict[str, Any]) -> Counter:
    nodes_map = _build_node_map(tree.get('nodes', []))
    counter: Counter = Counter()
    for nid, node in nodes_map.items():
        if str(node.get('node_type', '')).lower() != 'variant':
            continue
        if _is_optional_variant(node):
            continue
        parent = nodes_map.get(_coerce_int(node.get('parent_id')))
        parent_name = (parent.get('name', '') or '').strip() if parent else ''
        parent_type = str(parent.get('node_type', '') or '').lower() if parent else ''
        signature = ((node.get('name', '') or '').strip(), str(node.get('message_type', '') or '').lower(), parent_name, parent_type)
        counter[signature] += 1
    return counter

def _collect_selector_condition_map(tree: Dict[str, Any]) -> Dict[Tuple[Any, ...], set]:
    nodes_map = _build_node_map(tree.get('nodes', []))
    selector_map: Dict[Tuple[Any, ...], set] = defaultdict(set)
    for edge in tree.get('edges', []) or []:
        if str(edge.get('rel', '')).lower() != 'condition_on':
            continue
        src_id = _coerce_int(edge.get('src'))
        if src_id is None:
            continue
        node = nodes_map.get(src_id)
        if not node:
            continue
        if _is_optional_variant(node):
            continue
        parent = nodes_map.get(_coerce_int(node.get('parent_id')))
        parent_name = (parent.get('name', '') or '').strip() if parent else ''
        parent_type = str(parent.get('node_type', '') or '').lower() if parent else ''
        signature = ((node.get('name', '') or '').strip(), str(node.get('message_type', '') or '').lower(), parent_name, parent_type)
        formula_norm = _normalize_condition_formula_text(str(edge.get('formula') or ''))
        if formula_norm:
            selector_map[signature].add(formula_norm)
    return selector_map

def _validate_structural_invariants(original_tree: Dict[str, Any], final_tree: Dict[str, Any]) -> None:
    orig_variants = _collect_variant_signatures(original_tree)
    final_variants = _collect_variant_signatures(final_tree)
    missing_variants = orig_variants - final_variants
    extra_variants = final_variants - orig_variants
    if missing_variants:
        raise RuntimeError(f'Missing variant definitions after fix: {dict(missing_variants)}')
    if extra_variants:
        raise RuntimeError(f'Unexpected new variants introduced: {dict(extra_variants)}')
    orig_selector_map = _collect_selector_condition_map(original_tree)
    final_selector_map = _collect_selector_condition_map(final_tree)
    missing_selectors = set(orig_selector_map) - set(final_selector_map)
    if missing_selectors:
        raise RuntimeError(f'Missing selector conditions after fix: {missing_selectors}')
    for signature, formulas in orig_selector_map.items():
        candidate_formulas = final_selector_map.get(signature, set())
        missing_formulas = formulas - candidate_formulas
        if missing_formulas:
            raise RuntimeError(f'Selector {signature} lost condition(s): {missing_formulas}')

def _split_top_level_args(expr: str) -> List[str]:
    args: List[str] = []
    depth = 0
    current: List[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            if depth > 0:
                depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            arg = ''.join(current).strip()
            if arg:
                args.append(arg)
            current = []
        else:
            current.append(ch)
        i += 1
    tail = ''.join(current).strip()
    if tail:
        args.append(tail)
    return args

def _rewrite_logic_function_calls(expr: str) -> str:
    if not expr:
        return expr
    pattern = re.compile('\\b(OR|AND)\\s*\\(', re.IGNORECASE)
    result = expr
    while True:
        match = pattern.search(result)
        if not match:
            break
        func_name = match.group(1).lower()
        joiner = ' or ' if func_name == 'or' else ' and '
        start = match.start()
        args_start = match.end()
        depth = 1
        idx = args_start
        while idx < len(result) and depth > 0:
            ch = result[idx]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    break
            idx += 1
        if depth != 0:
            break
        args_end = idx
        args_blob = result[args_start:args_end]
        args = _split_top_level_args(args_blob)
        normalized = [a.strip() for a in args if a.strip()]
        if not normalized:
            replacement = ''
        elif len(normalized) == 1:
            replacement = f'({normalized[0]})'
        else:
            replacement = '(' + joiner.join(normalized) + ')'
        result = result[:start] + replacement + result[args_end + 1:]
    return result

def _normalize_condition_formula_text(formula: str) -> str:
    if not isinstance(formula, str):
        return formula
    text = formula.strip()
    if not text:
        return text
    text = text.replace('&&', ' and ').replace('||', ' or ')
    text = _rewrite_logic_function_calls(text)
    text = re.sub('\\bAND\\b', ' and ', text, flags=re.IGNORECASE)
    text = re.sub('\\bOR\\b', ' or ', text, flags=re.IGNORECASE)
    text = re.sub('(?<![<>=!])=(?!=)', '==', text)
    text = re.sub('\\s+', ' ', text).strip()
    return text

def _split_top_level_disjunctions(expr: str) -> List[str]:
    clauses: List[str] = []
    if not expr:
        return clauses
    depth = 0
    start = 0
    i = 0
    length = len(expr)
    while i < length:
        ch = expr[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            if depth > 0:
                depth -= 1
        elif depth == 0 and expr[i:i + 4].lower() == ' or ':
            clause = expr[start:i].strip()
            if clause:
                clauses.append(clause)
            start = i + 4
            i += 3
        i += 1
    tail = expr[start:].strip()
    if tail:
        clauses.append(tail)
    return clauses

def _extract_simple_disjunction_clauses(formula: str, src_id: Optional[int]) -> Optional[List[str]]:
    normalized = _normalize_condition_formula_text(str(formula or ''))
    if not normalized:
        return None
    stripped = _strip_outer_parens(normalized)
    if ' or ' not in stripped.lower():
        return None
    clauses = _split_top_level_disjunctions(stripped)
    if len(clauses) <= 1:
        return None
    simple_clauses: List[str] = []
    for clause in clauses:
        clause_text = _strip_outer_parens(_normalize_condition_formula_text(clause))
        clause_lower = clause_text.lower()
        if ' or ' in clause_lower or ' and ' in clause_lower or '||' in clause_text or ('&&' in clause_text):
            return None
        match = _VAL_EQ_PATTERN.match(clause_text)
        if not match:
            return None
        try:
            clause_src = int(match.group(1))
        except Exception:
            return None
        if src_id is not None and clause_src != src_id:
            return None
        simple_clauses.append(clause_text)
    unique_clauses = []
    seen: Set[str] = set()
    for clause in simple_clauses:
        trimmed = clause.strip()
        if trimmed in seen:
            continue
        seen.add(trimmed)
        unique_clauses.append(trimmed)
    if len(unique_clauses) <= 1:
        return None
    return unique_clauses

def _expand_condition_on_disjunctions(tree: Dict[str, Any]) -> None:
    if not isinstance(tree, dict):
        return
    edges = tree.get('edges')
    if not isinstance(edges, list):
        return
    new_edges: List[Dict[str, Any]] = []
    seen_keys: Set[Tuple[Any, Any, Any, Any, Any]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        rel = str(edge.get('rel') or '').lower()
        if rel != 'condition_on':
            key = (edge.get('src'), edge.get('dst'), edge.get('rel'), edge.get('formula'), edge.get('message_type'))
            if key not in seen_keys:
                new_edges.append(edge)
                seen_keys.add(key)
            continue
        src_id = _coerce_int(edge.get('src'))
        formula = edge.get('formula')
        clauses = _extract_simple_disjunction_clauses(formula, src_id)
        if not clauses:
            normalized = _normalize_condition_formula_text(str(formula or ''))
            if normalized != formula:
                edge = dict(edge)
                edge['formula'] = normalized
            key = (edge.get('src'), edge.get('dst'), edge.get('rel'), edge.get('formula'), edge.get('message_type'))
            if key not in seen_keys:
                new_edges.append(edge)
                seen_keys.add(key)
            continue
        for clause in clauses:
            new_edge = dict(edge)
            new_edge['formula'] = clause
            key = (new_edge.get('src'), new_edge.get('dst'), new_edge.get('rel'), new_edge.get('formula'), new_edge.get('message_type'))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            new_edges.append(new_edge)
    tree['edges'] = new_edges

def _normalize_condition_formulas(tree: Dict[str, Any]) -> None:
    if not isinstance(tree, dict):
        return
    edges = tree.get('edges', [])
    if not isinstance(edges, list):
        return
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get('rel')).lower() != 'condition_on':
            continue
        formula = edge.get('formula')
        if formula is None:
            continue
        normalized = _normalize_condition_formula_text(str(formula))
        if normalized:
            edge['formula'] = normalized

def _restore_length_formulas(original_tree: Dict[str, Any], final_tree: Dict[str, Any]) -> None:
    if not isinstance(original_tree, dict) or not isinstance(final_tree, dict):
        return
    orig_edges = original_tree.get('edges', []) or []
    final_edges = final_tree.get('edges')
    if not isinstance(final_edges, list):
        final_edges = []
        final_tree['edges'] = final_edges
    map_node_id, _, final_nodes_map = _create_node_resolver(original_tree, final_tree)
    final_edge_index: Dict[tuple, Dict[str, Any]] = {}
    for edge in final_edges:
        if not isinstance(edge, dict):
            continue
        if str(edge.get('rel')) != 'length_of':
            continue
        key = (_coerce_int(edge.get('src')), _coerce_int(edge.get('dst')))
        if None in key:
            continue
        final_edge_index[key] = edge
    for edge in orig_edges:
        if str(edge.get('rel')) != 'length_of':
            continue
        src = map_node_id(_coerce_int(edge.get('src')))
        dst = map_node_id(_coerce_int(edge.get('dst')))
        if src is None or dst is None:
            continue
        if dst not in final_nodes_map:
            continue
        orig_formula = str(edge.get('formula') or '').strip()
        if not orig_formula:
            continue
        normalized_formula = orig_formula
        key = (src, dst)
        target_edge = final_edge_index.get(key)
        if target_edge is None:
            target_edge = {'src': src, 'dst': dst, 'rel': 'length_of', 'formula': normalized_formula}
            message_type = edge.get('message_type')
            if message_type:
                target_edge['message_type'] = message_type
            final_edges.append(target_edge)
            final_edge_index[key] = target_edge
        else:
            target_edge['src'] = src
            target_edge['dst'] = dst
            target_edge['formula'] = normalized_formula
            if edge.get('message_type') and (not target_edge.get('message_type')):
                target_edge['message_type'] = edge.get('message_type')
        node = final_nodes_map.get(dst)
        if node is not None:
            current_size = node.get('size_bits')
            should_overwrite = False
            if isinstance(current_size, str):
                stripped = current_size.strip().lower()
                should_overwrite = not stripped or stripped == 'variable' or 'val(' in stripped or ('dynamic' in stripped)
            elif current_size is None:
                should_overwrite = True
            if should_overwrite:
                node['size_bits'] = normalized_formula

def _rewrite_problematic_size_bits(final_tree: Dict[str, Any]) -> None:
    if not isinstance(final_tree, dict):
        return
    nodes: List[Dict[str, Any]] = [n for n in final_tree.get('nodes', []) if isinstance(n, dict)]
    edges: List[Dict[str, Any]] = [e for e in final_tree.get('edges', []) if isinstance(e, dict)]
    length_edges_by_dst: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if str(edge.get('rel')) != 'length_of':
            continue
        dst = _coerce_int(edge.get('dst'))
        if dst is None:
            continue
        length_edges_by_dst[dst].append(edge)
    for node in nodes:
        node_id = _coerce_int(node.get('node_id'))
        if node_id is None:
            continue
        size_expr = node.get('size_bits')
        if isinstance(size_expr, str):
            stripped = size_expr.strip()
        else:
            stripped = ''
        if not stripped:
            continue
        if 'val(' not in stripped and '.size_bits' not in stripped and ('=' not in stripped):
            continue
        node_type = str(node.get('node_type', '')).lower()
        dst_edges = length_edges_by_dst.get(node_id, [])
        if dst_edges:
            edge = dst_edges[0]
            src = _coerce_int(edge.get('src'))
            if src is not None:
                formula = str(edge.get('formula') or '').strip() or f'val({src})'
                node['size_bits'] = formula
                continue
        if node_type in {'container', 'variant', 'selector'}:
            node['size_bits'] = 'variable'
        else:
            node['size_bits'] = 'variable'

def _infer_container_sizes(final_tree: Dict[str, Any]) -> None:
    if not isinstance(final_tree, dict):
        return
    nodes: List[Dict[str, Any]] = [n for n in final_tree.get('nodes', []) if isinstance(n, dict)]
    nodes_by_id = {_coerce_int(n.get('node_id')): n for n in nodes}
    for node in nodes:
        node_id = _coerce_int(node.get('node_id'))
        if node_id is None:
            continue
        node_type = str(node.get('node_type', '')).lower()
        if node_type not in {'container', 'header', 'variant'}:
            continue
        size_bits = node.get('size_bits')
        if isinstance(size_bits, int):
            continue
        if isinstance(size_bits, str) and size_bits.strip().lower() not in {'', 'none', 'variable'}:
            continue
        children_ids = node.get('children_ids') or []
        if not children_ids:
            continue
        child_sizes: List[int] = []
        all_static = True
        for child_id in children_ids:
            child_node = nodes_by_id.get(child_id)
            if not child_node:
                all_static = False
                break
            child_size = child_node.get('size_bits')
            if not isinstance(child_size, int):
                all_static = False
                break
            child_sizes.append(child_size)
        if not all_static or not child_sizes:
            continue
        inferred = sum(child_sizes)
        if inferred <= 0:
            continue
        node['size_bits'] = inferred
        changed = True

def _normalize_value_constraints(final_tree: Dict[str, Any]) -> None:
    if not isinstance(final_tree, dict):
        return
    nodes: List[Dict[str, Any]] = [n for n in final_tree.get('nodes', []) if isinstance(n, dict)]
    for node in nodes:
        constraints = node.get('constraints')
        if not isinstance(constraints, list):
            continue
        normalized: List[Any] = []
        changed = False
        for item in constraints:
            if isinstance(item, str) and item.strip().lower().startswith('range:'):
                body = item.split(':', 1)[1].strip()
                if re.search('value\\s*[%*/+-]', body):
                    normalized.append(f'formula: {body}')
                    changed = True
                    continue
            normalized.append(item)
        if changed:
            node['constraints'] = normalized
logger = logging.getLogger(__name__)

def ensure_logging(log_filename: str) -> None:
    setup_logging(console_level=logging.ERROR, file_path=log_filename, file_level=logging.INFO, replace_existing=False)

def load_json(path: str):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)

def _coerce_sections(payload: Any) -> Sequence[Dict[str, Any]]:
    if isinstance(payload, dict) and 'sections' in payload:
        payload = payload['sections']
    if isinstance(payload, list):
        return payload
    raise ValueError("Sections file must be a list or contain a 'sections' array")

def _env_flag_true(name: str, default: bool=False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {'1', 'true', 'yes', 'on'}

def _issue_stats(report) -> tuple[int, int]:
    issues_raw = getattr(report, 'issues', {}) or {}
    issues = {iid: iss for iid, iss in issues_raw.items() if getattr(iss, 'severity', None) == Severity.ERROR}
    hard = sum((1 for issue in issues.values() if is_hard_error(issue)))
    return (hard, len(issues))

def run_step2_fix(cache_path: Optional[Path]=None, sections_path: Optional[Path]=None, output_dir: Optional[Path]=None, log_dir: Optional[Path]=None, *, traffic_path: Optional[Path]=None, max_packets: int=0, target_message_type: Optional[str]=None, use_hybrid_validator: bool=False, max_llm_calls: Optional[int]=None) -> Path:
    base_dir = Path(__file__).resolve().parent
    cache_path = Path(cache_path) if cache_path else STEP2_CACHE_DIR / 'final_complete_protocol_tree.json'
    sections_path = Path(sections_path) if sections_path else base_dir / 'modbus_document_sections_subset.json'
    output_dir = Path(output_dir) if output_dir else base_dir / 'results'
    log_dir = Path(log_dir) if log_dir else base_dir / 'logs'
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_filename = log_dir / f'log_{int(time.time())}.txt'
    os.environ.setdefault('STEP2_MCTS_LOG_UCT', '1')
    os.environ.setdefault('STEP2_MCTS_LOG_FILE', str(log_filename))
    os.environ.setdefault('STEP2_ENABLE_MCTS_LOG', '1')
    ensure_logging(str(log_filename))
    try:
        with open(cache_path, 'r', encoding='utf-8') as handle:
            tree_data = json.load(handle)
        tree = tree_data.get('protocol_tree', tree_data)
        logger.info('Loaded protocol tree from cache: %s', cache_path)
    except Exception as exc:
        logger.error('Failed to load protocol tree %s: %s', cache_path, exc)
        raise
    try:
        sections_data = load_json(str(sections_path))
        sections: Sequence[Dict[str, Any]] = _coerce_sections(sections_data)
        logger.info('Loaded %d sections from: %s', len(sections), sections_path)
    except Exception as exc:
        logger.error('Failed to load sections %s: %s', sections_path, exc)
        raise
    try:
        agent = EnhancedPureAIAgent(cache_dir=STEP2_FIX_CACHE_DIR)
        logger.info('Initialized AI agent')
    except Exception as exc:
        logger.error('Failed to initialize AI agent: %s', exc)
        raise
    original_tree_snapshot = deepcopy(tree)
    preprocessed_tree = deepcopy(tree)
    strict_validator_loop = os.getenv('STEP2_STRICT_VALIDATOR_LOOP', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
    if strict_validator_loop:
        logger.info('STEP2_STRICT_VALIDATOR_LOOP enabled: skipping pre-MCTS heuristic normalizations; traffic fixing will be driven only by validator results')
    else:
        try:
            _restore_length_formulas(original_tree_snapshot, preprocessed_tree)
        except Exception as exc:
            logger.warning('Pre-MCTS length formula normalization failed: %s', exc)
        try:
            logger.info('Skipping _expand_condition_on_disjunctions to preserve complex formulas.')
        except Exception as exc:
            logger.warning('Pre-MCTS condition split failed: %s', exc)
        try:
            _normalize_condition_formulas(preprocessed_tree)
        except Exception as exc:
            logger.warning('Pre-MCTS condition formula normalization failed: %s', exc)
        try:
            _infer_container_sizes(preprocessed_tree)
        except Exception as exc:
            logger.warning('Pre-MCTS container size inference failed: %s', exc)
        try:
            _rewrite_problematic_size_bits(preprocessed_tree)
        except Exception as exc:
            logger.warning('Pre-MCTS size_bits sanitation failed: %s', exc)
        try:
            _normalize_value_constraints(preprocessed_tree)
        except Exception as exc:
            logger.warning('Pre-MCTS constraint normalization failed: %s', exc)
    initial_report = run_full_validation(preprocessed_tree)
    initial_hard_errors, initial_total_issues = _issue_stats(initial_report)
    try:
        if strict_validator_loop:
            logger.info('Starting strict validator-driven fix loop')
        else:
            logger.info('Starting MCTS fix process')
        try:
            env_batch = int(os.getenv('STEP2_MCTS_BATCH_SIZE', str(len(sections))))
            batch_size_override = max(1, env_batch)
        except Exception:
            batch_size_override = len(sections)
        if max_llm_calls is None:
            raw_max_calls = os.getenv('STEP2_MCTS_MAX_CALLS', '').strip()
            if not raw_max_calls:
                raw_max_calls = os.getenv('STEP2_MCTS_MAX_LLM_CALLS', '20').strip()
            try:
                max_llm_calls = int(raw_max_calls)
            except Exception:
                max_llm_calls = 20
        max_llm_calls = max(0, int(max_llm_calls))
        node_snapshot_dir = STEP2_FIX_CACHE_DIR / 'mcts_node_snapshots'
        node_snapshot_dir.mkdir(parents=True, exist_ok=True)
        validator_fn = run_full_validation
        prompt_mode = 'fix'
        hybrid_path: Optional[Path] = None
        if use_hybrid_validator and traffic_path is not None:
            hybrid_path = Path(traffic_path)
            if not hybrid_path.exists():
                logger.warning('Hybrid validator enabled but traffic file missing: %s; falling back to syntax-only', hybrid_path)
                hybrid_path = None
        if use_hybrid_validator and hybrid_path is not None:
            prompt_mode = 'traffic_fix'

            def _hybrid_validator(tree_payload: Dict[str, Any]):
                return run_hybrid_validation(tree_payload, traffic_path=hybrid_path, max_packets=max_packets, target_message_type=target_message_type)
            validator_fn = _hybrid_validator
        final_tree = mcts_fix_tree(agent, preprocessed_tree, sections=sections, raw_sections=sections, batch_size=batch_size_override, max_llm_calls=max_llm_calls, node_snapshot_dir=str(node_snapshot_dir), validator_fn=validator_fn, prompt_mode=prompt_mode)
        if strict_validator_loop:
            logger.info('Strict validator-driven fix loop completed successfully')
        else:
            logger.info('MCTS fix process completed successfully')
        final_report = run_full_validation({'protocol_tree': final_tree})
        final_hard_errors, final_total_issues = _issue_stats(final_report)
        output_path = output_dir / f'fixed_protocol_tree_{int(time.time())}.json'
        with open(output_path, 'w', encoding='utf-8') as handle:
            json.dump({'protocol_tree': final_tree, 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'), 'fix_info': {'original_nodes': len(tree.get('nodes', [])), 'fixed_nodes': len(final_tree.get('nodes', [])) if isinstance(final_tree, dict) else 0}}, handle, indent=2, ensure_ascii=False)
        logger.info('Fixed tree saved to: %s', output_path)
        summary = {'protocol_name': cache_path.stem, 'initial_hard_errors': initial_hard_errors, 'initial_total_issues': initial_total_issues, 'after_fix_hard_errors': final_hard_errors, 'after_fix_total_issues': final_total_issues, 'mcts_simulations': None, 'best_issue_count': final_total_issues, 'timestamp': datetime.utcnow().isoformat()}
        summary_path = output_dir / 'summary.json'
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
        logger.info('Step2 summary saved to: %s', summary_path)
        return output_path
    except Exception as exc:
        logger.error('MCTS fix process failed: %s', exc)
        raise

def _parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Run the Step2 fix pipeline')
    parser.add_argument('--tree', type=Path, default=None, help='Path to final_complete_protocol_tree.json')
    parser.add_argument('--sections', type=Path, default=None, help='Path to sections JSON')
    parser.add_argument('--output-dir', type=Path, default=None, help='Directory to write fixed trees')
    parser.add_argument('--log-dir', type=Path, default=None, help='Directory to store log files')
    parser.add_argument('--traffic', type=Path, default=None, help='Optional traffic hex dump for hybrid validation')
    parser.add_argument('--max-llm-calls', type=int, default=None, help='Max LLM calls for Step2 fix (default: $STEP2_MCTS_MAX_CALLS or 20).')
    parser.add_argument('--max-packets', type=int, default=0, help='Limit traffic samples used in hybrid validation (0 = no limit)')
    parser.add_argument('--target-message-type', type=str, default=None, help='Optional message_type filter for hybrid validation (request/response)')
    parser.add_argument('--use-hybrid-validator', action='store_true', default=False, help='Use hybrid (syntax + traffic) validation inside the fixer')
    return parser.parse_args()
if __name__ == '__main__':
    cli_args = _parse_cli_args()
    run_step2_fix(cache_path=cli_args.tree, sections_path=cli_args.sections, output_dir=cli_args.output_dir, log_dir=cli_args.log_dir, traffic_path=cli_args.traffic, max_llm_calls=cli_args.max_llm_calls, max_packets=cli_args.max_packets, target_message_type=cli_args.target_message_type, use_hybrid_validator=cli_args.use_hybrid_validator)
