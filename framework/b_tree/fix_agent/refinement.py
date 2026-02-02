from __future__ import annotations
import copy
import hashlib
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING
from .message import build_patch_refinement_message, summarize_sections_for_patch
from .mcts import MCTSConfig, SearchOutcome, ValidationSummary, log_mcts_event, search_for_batch
from ..tree_utils import normalize_protocol_tree
from ..generation_agent.core_ir import canonicalize_protocol_tree
from ..validation_agent.syntax_validator import validate_protocol_tree, ValidationReport, Issue, IssueType, Severity
from ...paths import STEP2_FIX_CACHE_DIR
if TYPE_CHECKING:
    from .agent import EnhancedPureAIAgent
    from .mcts import PatchEvaluation, TreeState
logger = logging.getLogger(__name__)

def _extract_cached_patch_entries(cached_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not isinstance(cached_data, dict):
        return entries
    cached_patches = cached_data.get('patches')
    if isinstance(cached_patches, list):
        for item in cached_patches:
            if isinstance(item, dict):
                if isinstance(item.get('patch'), dict):
                    entries.append(item)
                elif all((isinstance(value, dict) for value in item.values())):
                    for value in item.values():
                        if isinstance(value, dict):
                            entries.append({'patch': value})
                elif 'patch' not in item:
                    entries.append({'patch': item})
    elif isinstance(cached_data.get('patch'), dict):
        entries.append({'patch': cached_data['patch'], 'source': cached_data.get('source', 'cache'), 'summary': cached_data.get('patch_summary')})
    return entries

def _hash_patch(patch: Dict[str, Any]) -> str:
    serialized = json.dumps(patch, ensure_ascii=True, sort_keys=True)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

def _persist_batch_tree(batch_index: int, tree: Dict[str, Any]) -> None:
    payload = {'timestamp': datetime.now().isoformat(), 'batch_index': batch_index, 'protocol_tree': tree}
    filename = f'intermediate_tree_batch_{batch_index:03d}.json'
    path = STEP2_FIX_CACHE_DIR / filename
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    except OSError as exc:
        logger.warning('Failed to persist intermediate tree for batch %s: %s', batch_index + 1, exc)

def _validator_disabled() -> bool:
    return os.getenv('STEP2_DISABLE_VALIDATOR', '0') == '1'

def _strict_validator_loop_enabled() -> bool:
    val = os.getenv('STEP2_STRICT_VALIDATOR_LOOP', '0')
    return val.strip().lower() in {'1', 'true', 'yes', 'on'}

def _filter_error_issues(issues: Dict[str, Issue]) -> Dict[str, Issue]:
    if not issues:
        return {}
    return {issue_id: issue for issue_id, issue in issues.items() if getattr(issue, 'severity', None) == Severity.ERROR}

def _is_noop_patch(patch: Optional[Dict[str, Any]]) -> bool:
    if not patch:
        return True
    metadata = patch.get('patch_metadata')
    if isinstance(metadata, dict):
        intent = metadata.get('intent') or metadata.get('action')
        if isinstance(intent, str) and intent.strip().lower() in {'noop', 'no-op', 'skip'}:
            return True
    meaningful_keys = ('new_nodes', 'node_updates', 'new_edges', 'edge_updates', 'edge_removes', 'nodes_to_remove')
    for key in meaningful_keys:
        value = patch.get(key)
        if isinstance(value, list) and value:
            return False
    if patch.get('protocol_tree'):
        return False
    return True

def _merge_sections_with_raw(sections: Sequence[Dict[str, Any]], raw_sections: Optional[Sequence[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    for index, section in enumerate(sections):
        base = copy.deepcopy(section)
        if raw_sections and index < len(raw_sections):
            raw_entry = raw_sections[index]
            if isinstance(raw_entry, dict):
                if 'content' in raw_entry and 'raw_content' not in base:
                    base['raw_content'] = raw_entry.get('content')
                if 'summary' in raw_entry and 'raw_summary' not in base:
                    base['raw_summary'] = raw_entry.get('summary')
                if 'packet_formats' in raw_entry and 'raw_packet_formats' not in base:
                    base['raw_packet_formats'] = raw_entry.get('packet_formats')
        merged.append(base)
    return merged

class BatchPatchSupplier:

    def __init__(self, agent: 'EnhancedPureAIAgent', sections: Sequence[Dict[str, Any]], batch_index: int, batch_start: int, batch_size: int, *, initial_feedback: Optional[str], cached_entries: Optional[Sequence[Dict[str, Any]]], max_calls: int, cache_filename: str, prompt_mode: str='fix', fix_history: Optional[List[Dict[str, Any]]]=None, size_bits_candidates: Optional[Dict[int, List[Any]]]=None, payload_fill_candidates: Optional[Dict[int, List[Any]]]=None) -> None:
        self.agent = agent
        self.sections = sections
        self.batch_index = batch_index
        self.batch_start = batch_start
        self.batch_size = batch_size
        self.batch_end = batch_start + batch_size
        self.feedback: Optional[str] = initial_feedback
        self.previous_patch_summary: Optional[str] = None
        self.cached_archive: List[Dict[str, Any]] = [copy.deepcopy(entry) for entry in cached_entries or []]
        self.remaining_cached: List[Dict[str, Any]] = []
        self.max_calls = max_calls
        self.cache_filename = cache_filename
        self.calls_made = 0
        self._total_emitted = 0
        self._llm_first_toggle = False
        self.generated_log: List[Dict[str, Any]] = []
        self.action_info: Dict[str, Dict[str, Any]] = {}
        self.evaluation_records: List[Dict[str, Any]] = []
        self.patch_dir: Path = STEP2_FIX_CACHE_DIR / 'patches' / f'batch_{batch_index:02d}'
        self.patch_dir.mkdir(parents=True, exist_ok=True)
        self.patch_files: Dict[str, Path] = {}
        self._atomic_queue: List[Dict[str, Any]] = []
        self.prompt_mode = (prompt_mode or 'fix').strip().lower()
        self._traffic_debug_logged = False
        self.fix_history: List[Dict[str, Any]] = fix_history if fix_history is not None else []
        self._size_bits_candidates = size_bits_candidates or {}
        self._payload_fill_candidates = payload_fill_candidates or {}
        self._served_algorithmic: Set[Tuple[int, str]] = set()
        self._served_payload_fill: Set[Tuple[Any, Any, Any]] = set()
        self._served_repair_hints: Set[Tuple[Any, ...]] = set()
        self._next_new_node_id_base: Optional[int] = None

    def __call__(self, state: 'TreeState', count: int, avoid_summaries: Optional[List[str]]=None) -> Sequence[Dict[str, Any]]:
        patches: List[Dict[str, Any]] = []
        seen_hashes: Set[str] = set()
        if self.prompt_mode != 'traffic_fix':
            while len(patches) < count and self.calls_made < self.max_calls:
                patch = self._produce_patch(state, avoid_summaries)
                if patch is None:
                    continue
                try:
                    h = _hash_patch(patch)
                except Exception:
                    h = None
                if h and h in seen_hashes:
                    logger.info('Batch %s suppressed duplicate patch in same iteration: %s', self.batch_index + 1, h[:8])
                    continue
                if h:
                    seen_hashes.add(h)
                patches.append(patch)
            return patches
        llm_only = os.getenv('STEP2_TRAFFIC_LLM_ONLY', '1').strip().lower() in {'1', 'true', 'yes', 'on'}
        sources = ['llm'] if llm_only else ['algo', 'llm']
        if not self._traffic_debug_logged:
            self._traffic_debug_logged = True
            try:
                from collections import Counter
                hints = tuple(getattr(getattr(state, 'validation', None), 'traffic_repair_hints', ()) or ())
                failures = tuple(getattr(getattr(state, 'validation', None), 'traffic_failures', ()) or ())
                kind_counts = Counter((str(h.get('kind', '')) for h in hints if isinstance(h, dict)))
            except Exception:
                pass
        max_attempts = max(10, int(count) * 6)
        attempts = 0
        while len(patches) < count and attempts < max_attempts:
            attempts += 1
            patch = self._request_patch(sources, state, avoid_summaries)
            if patch is None:
                break
            try:
                h = _hash_patch(patch)
            except Exception:
                h = None
            if h and h in seen_hashes:
                logger.info('Batch %s suppressed duplicate patch in same iteration: %s', self.batch_index + 1, h[:8])
                continue
            if h:
                seen_hashes.add(h)
            patches.append(patch)
        return patches

    def _next_attempt_number(self) -> int:
        return self._total_emitted + 1

    def _bump_counters(self, *, llm_used: bool) -> None:
        self._total_emitted += 1
        if llm_used:
            self.calls_made += 1

    def _has_algorithmic_candidates(self) -> bool:
        if self.prompt_mode != 'traffic_fix':
            return False
        if self._payload_fill_candidates:
            for raw_nid, cands in self._payload_fill_candidates.items():
                for cand in cands or []:
                    key = (getattr(cand, 'dst_id', None) or getattr(cand, 'target_node_id', raw_nid), getattr(cand, 'bit_start_expr', None), getattr(cand, 'size_bits_expr', None))
                    if key not in self._served_payload_fill:
                        return True
        if not self._size_bits_candidates:
            return False

        def _coerce_node_id(raw: Any) -> Optional[int]:
            try:
                return int(raw)
            except Exception:
                return None
        for raw_nid, cands in self._size_bits_candidates.items():
            nid = _coerce_node_id(raw_nid)
            if nid is None:
                continue
            for cand in cands or []:
                key = (nid, getattr(cand, 'expression', None))
                if key not in self._served_algorithmic:
                    return True
        return False

    def _request_patch(self, sources: List[str], state: 'TreeState', avoid_summaries: Optional[List[str]]) -> Optional[Dict[str, Any]]:
        if self._atomic_queue:
            return self._atomic_queue.pop(0)
        for source in sources:
            patch: Optional[Dict[str, Any]] = None
            if source == 'algo':
                patch = self._next_algorithmic_patch(state)
            elif source == 'llm':
                if self.calls_made < self.max_calls:
                    patch = self._generate_patch_via_llm(state, avoid_summaries)
            elif source == 'cache':
                patch = self._consume_cached_patch()
            if patch is not None:
                return patch
        return None

    def _compute_next_node_id(self, state: 'TreeState') -> int:
        if self._next_new_node_id_base is None:
            max_id = 0
            try:
                for node in state.tree.get('nodes', []) or []:
                    try:
                        nid = int(node.get('node_id'))
                        if nid > max_id:
                            max_id = nid
                    except Exception:
                        continue
            except Exception:
                max_id = 0
            self._next_new_node_id_base = max_id + 1
        next_id = self._next_new_node_id_base
        self._next_new_node_id_base += 1
        return next_id

    def _produce_patch(self, state: 'TreeState', avoid_summaries: Optional[List[str]]=None) -> Optional[Dict[str, Any]]:
        if self._atomic_queue:
            return self._atomic_queue.pop(0)
        if self.calls_made >= self.max_calls:
            return None
        algo_patch = self._next_algorithmic_patch(state)
        if algo_patch is not None:
            return algo_patch
        return self._generate_patch_via_llm(state, avoid_summaries)

    def _consume_cached_patch(self) -> Optional[Dict[str, Any]]:
        entry = self.remaining_cached.pop(0)
        patch = copy.deepcopy(entry.get('patch', {}))
        if not isinstance(patch, dict):
            logger.warning('Cached patch for batch %s is not a dict, skipping', self.batch_index + 1)
            self._bump_counters(llm_used=True)
            return None
        self._ensure_patch_defaults(patch)
        attempt_number = self._next_attempt_number()
        summary = entry.get('summary') or _summarize_patch_for_prompt(patch)
        patch_hash = _hash_patch(patch)
        source = entry.get('source', 'cache')
        self._record_patch(patch, patch_hash, summary, source, attempt_number, entry.get('messages'))
        self.action_info[patch_hash] = {'summary': summary, 'source': source, 'attempt': attempt_number}
        self.previous_patch_summary = summary
        self._bump_counters(llm_used=True)
        logger.info('Batch %s using cached patch (attempt %s): hash=%s', self.batch_index + 1, attempt_number, patch_hash[:8])
        return patch

    def _next_algorithmic_patch(self, state: 'TreeState') -> Optional[Dict[str, Any]]:
        if self.prompt_mode != 'traffic_fix':
            return None
        hint_patch = self._next_repair_hint_patch(state)
        if hint_patch is not None:
            return hint_patch
        fill_patch = self._next_payload_fill_patch(state)
        if fill_patch is not None:
            return fill_patch
        if not self._size_bits_candidates:
            return None

        def _coerce_node_id(raw: Any) -> Optional[int]:
            try:
                return int(raw)
            except Exception:
                return None
        for issue in (state.pending_issues or {}).values():
            target = getattr(issue, 'target', None)
            if not target or getattr(target, 'kind', None) != 'node':
                continue
            nid = _coerce_node_id(getattr(target, 'identifier', None))
            if nid is None:
                continue
            candidates = self._size_bits_candidates.get(nid) or self._size_bits_candidates.get(str(nid)) or []
            for cand in candidates:
                key = (nid, getattr(cand, 'expression', None))
                if key in self._served_algorithmic:
                    continue
                summary = f'Set node {nid} size_bits={cand.expression} (traffic-derived)'
                patch: Dict[str, Any] = {'patch_metadata': {'description': summary, 'intent': 'traffic_length_fit', 'source': 'traffic_inference'}, 'node_updates': [{'node_id': nid, 'property': 'size_bits', 'value': cand.expression}], 'new_edges': [], 'edge_updates': [], 'edge_removes': [], 'new_nodes': [], 'nodes_to_remove': []}
                if getattr(cand, 'controlling_field_id', None) is not None:
                    patch['new_edges'].append({'src': cand.controlling_field_id, 'dst': nid, 'rel': 'length_of', 'formula': cand.expression})
                self._ensure_patch_defaults(patch)
                attempt_number = self._next_attempt_number()
                patch_hash = _hash_patch(patch)
                self._record_patch(patch, patch_hash, summary, 'traffic_inference', attempt_number, None)
                self.action_info[patch_hash] = {'summary': summary, 'source': 'traffic_inference', 'attempt': attempt_number}
                self.previous_patch_summary = summary
                self._bump_counters(llm_used=False)
                self._served_algorithmic.add(key)
                return patch
        for raw_nid, candidates in self._size_bits_candidates.items():
            nid = _coerce_node_id(raw_nid)
            if nid is None:
                continue
            for cand in candidates:
                key = (nid, getattr(cand, 'expression', None))
                if key in self._served_algorithmic:
                    continue
                summary = f'Set node {nid} size_bits={cand.expression} (traffic-derived)'
                patch: Dict[str, Any] = {'patch_metadata': {'description': summary, 'intent': 'traffic_length_fit', 'source': 'traffic_inference'}, 'node_updates': [{'node_id': nid, 'property': 'size_bits', 'value': cand.expression}], 'new_edges': [], 'edge_updates': [], 'edge_removes': [], 'new_nodes': [], 'nodes_to_remove': []}
                if getattr(cand, 'controlling_field_id', None) is not None:
                    patch['new_edges'].append({'src': cand.controlling_field_id, 'dst': nid, 'rel': 'length_of', 'formula': cand.expression})
                self._ensure_patch_defaults(patch)
                attempt_number = self._next_attempt_number()
                patch_hash = _hash_patch(patch)
                self._record_patch(patch, patch_hash, summary, 'traffic_inference', attempt_number, None)
                self.action_info[patch_hash] = {'summary': summary, 'source': 'traffic_inference', 'attempt': attempt_number}
                self.previous_patch_summary = summary
                self._bump_counters(llm_used=False)
                self._served_algorithmic.add(key)
                return patch
        return None

    def _next_repair_hint_patch(self, state: 'TreeState') -> Optional[Dict[str, Any]]:
        if self.prompt_mode != 'traffic_fix':
            return None
        hints = list(getattr(getattr(state, 'validation', None), 'traffic_repair_hints', None) or [])
        if not hints:
            return None
        tree = state.tree
        nodes = tree.get('nodes', []) if isinstance(tree, dict) else []
        edges = tree.get('edges', []) if isinstance(tree, dict) else []
        if not isinstance(nodes, list):
            nodes = []
        if not isinstance(edges, list):
            edges = []
        nodes_by_id: Dict[int, Dict[str, Any]] = {}
        for node in nodes:
            if not isinstance(node, dict):
                continue
            try:
                nid = int(node.get('node_id'))
            except Exception:
                continue
            nodes_by_id[nid] = node

        def _coerce_int(value: Any) -> Optional[int]:
            try:
                return int(value)
            except Exception:
                return None
        shift_hint_by_variant: Dict[int, int] = {}
        for raw_hint in hints:
            if not isinstance(raw_hint, dict):
                continue
            if str(raw_hint.get('kind', '') or '').strip() != 'shift_variant_subtree':
                continue
            vid_hint = _coerce_int(raw_hint.get('variant_id'))
            shift_bits_hint = _coerce_int(raw_hint.get('shift_bits'))
            if vid_hint is None or shift_bits_hint is None or shift_bits_hint == 0:
                continue
            shift_hint_by_variant.setdefault(int(vid_hint), int(shift_bits_hint))

        def _edge_exists(src_id: int, dst_id: int, rel: str) -> Optional[Dict[str, Any]]:
            for edge in edges or []:
                if not isinstance(edge, dict):
                    continue
                if str(edge.get('rel') or '') != rel:
                    continue
                if _coerce_int(edge.get('src')) != src_id:
                    continue
                if _coerce_int(edge.get('dst')) != dst_id:
                    continue
                return edge
            return None

        def _descendants(root_id: int) -> List[int]:
            out: List[int] = []
            stack: List[int] = [root_id]
            seen: Set[int] = {root_id}
            while stack:
                cur = stack.pop()
                node = nodes_by_id.get(cur)
                if not node:
                    continue
                for cid in node.get('children_ids') or []:
                    child_id = _coerce_int(cid)
                    if child_id is None or child_id in seen:
                        continue
                    seen.add(child_id)
                    out.append(child_id)
                    stack.append(child_id)
            return out
        for hint in hints:
            if not isinstance(hint, dict):
                continue
            kind = str(hint.get('kind', '') or '').strip()
            if kind == 'add_length_of':
                src_id = _coerce_int(hint.get('src_id'))
                dst_id = _coerce_int(hint.get('dst_id'))
                formula = hint.get('formula')
                if src_id is None or dst_id is None or (not formula):
                    continue
                key = ('add_length_of', src_id, dst_id, str(formula))
                if key in self._served_repair_hints:
                    continue
                existing = _edge_exists(src_id, dst_id, 'length_of')
                if existing is not None:
                    self._served_repair_hints.add(key)
                    continue
                src_node = nodes_by_id.get(src_id) or {}
                dst_node = nodes_by_id.get(dst_id) or {}
                msg_type = dst_node.get('message_type') or src_node.get('message_type') or 'bidirectional'
                summary = f'Add length_of edge {src_id}->{dst_id} formula={formula} (traffic hint)'
                patch: Dict[str, Any] = {'patch_metadata': {'description': summary, 'intent': 'traffic_repair_hint', 'source': 'traffic_repair_hint'}, 'new_edges': [{'src': src_id, 'dst': dst_id, 'rel': 'length_of', 'formula': str(formula), 'message_type': msg_type}], 'node_updates': [], 'edge_updates': [], 'edge_removes': [], 'new_nodes': [], 'nodes_to_remove': []}
                self._ensure_patch_defaults(patch)
                attempt_number = self._next_attempt_number()
                patch_hash = _hash_patch(patch)
                self._record_patch(patch, patch_hash, summary, 'traffic_repair_hint', attempt_number, None)
                self.action_info[patch_hash] = {'summary': summary, 'source': 'traffic_repair_hint', 'attempt': attempt_number}
                self.previous_patch_summary = summary
                self._served_repair_hints.add(key)
                self._bump_counters(llm_used=False)
                return patch
            if kind == 'set_variant_size_bits':
                vid = _coerce_int(hint.get('variant_id'))
                suggested = hint.get('suggested_size_bits')
                if vid is None or not suggested:
                    continue
                key = ('set_variant_size_bits', vid, str(suggested))
                if key in self._served_repair_hints:
                    continue
                cur_node = nodes_by_id.get(vid) or {}
                if str(cur_node.get('size_bits') or '') == str(suggested):
                    self._served_repair_hints.add(key)
                    continue
                node_updates: List[Dict[str, Any]] = [{'node_id': vid, 'property': 'size_bits', 'value': str(suggested)}]
                shift_bits = shift_hint_by_variant.get(int(vid))
                key_shift: Optional[Tuple[Any, ...]] = None
                if shift_bits is not None:
                    key_shift = ('shift_variant_subtree', int(vid), int(shift_bits))
                    if key_shift in self._served_repair_hints:
                        key_shift = None
                if key_shift is not None:
                    for nid in _descendants(int(vid)):
                        node = nodes_by_id.get(nid) or {}
                        raw = node.get('bit_start')
                        if raw is None:
                            continue
                        if isinstance(raw, (int, float)) and (not isinstance(raw, bool)):
                            new_val = int(raw) + int(shift_bits)
                        elif isinstance(raw, str):
                            try:
                                new_val = int(raw.strip(), 0) + int(shift_bits)
                            except Exception:
                                continue
                        else:
                            continue
                        node_updates.append({'node_id': nid, 'property': 'bit_start', 'value': new_val})
                if key_shift is not None and len(node_updates) <= 1:
                    key_shift = None
                    node_updates = [{'node_id': vid, 'property': 'size_bits', 'value': str(suggested)}]
                if key_shift is not None:
                    summary = f'Shift variant {vid} descendants by {shift_bits} bits and set size_bits={suggested} (traffic hint)'
                else:
                    summary = f'Set variant {vid} size_bits={suggested} (traffic hint)'
                patch = {'patch_metadata': {'description': summary, 'intent': 'traffic_repair_hint', 'source': 'traffic_repair_hint'}, 'node_updates': node_updates, 'new_edges': [], 'edge_updates': [], 'edge_removes': [], 'new_nodes': [], 'nodes_to_remove': []}
                self._ensure_patch_defaults(patch)
                attempt_number = self._next_attempt_number()
                patch_hash = _hash_patch(patch)
                self._record_patch(patch, patch_hash, summary, 'traffic_repair_hint', attempt_number, None)
                self.action_info[patch_hash] = {'summary': summary, 'source': 'traffic_repair_hint', 'attempt': attempt_number}
                self.previous_patch_summary = summary
                self._served_repair_hints.add(key)
                if key_shift is not None:
                    self._served_repair_hints.add(key_shift)
                self._bump_counters(llm_used=False)
                return patch
            if kind == 'shift_variant_subtree':
                vid = _coerce_int(hint.get('variant_id'))
                shift_bits = _coerce_int(hint.get('shift_bits'))
                if vid is None or shift_bits is None or shift_bits == 0:
                    continue
                key = ('shift_variant_subtree', vid, shift_bits)
                if key in self._served_repair_hints:
                    continue
                updates: List[Dict[str, Any]] = []
                for nid in _descendants(vid):
                    node = nodes_by_id.get(nid) or {}
                    raw = node.get('bit_start')
                    if raw is None:
                        continue
                    if isinstance(raw, (int, float)) and (not isinstance(raw, bool)):
                        new_val = int(raw) + int(shift_bits)
                    elif isinstance(raw, str):
                        try:
                            new_val = int(raw.strip(), 0) + int(shift_bits)
                        except Exception:
                            continue
                    else:
                        continue
                    updates.append({'node_id': nid, 'property': 'bit_start', 'value': new_val})
                if not updates:
                    self._served_repair_hints.add(key)
                    continue
                summary = f'Shift variant {vid} descendants by {shift_bits} bits (traffic hint)'
                patch = {'patch_metadata': {'description': summary, 'intent': 'traffic_repair_hint', 'source': 'traffic_repair_hint'}, 'node_updates': updates, 'new_edges': [], 'edge_updates': [], 'edge_removes': [], 'new_nodes': [], 'nodes_to_remove': []}
                self._ensure_patch_defaults(patch)
                attempt_number = self._next_attempt_number()
                patch_hash = _hash_patch(patch)
                self._record_patch(patch, patch_hash, summary, 'traffic_repair_hint', attempt_number, None)
                self.action_info[patch_hash] = {'summary': summary, 'source': 'traffic_repair_hint', 'attempt': attempt_number}
                self.previous_patch_summary = summary
                self._served_repair_hints.add(key)
                self._bump_counters(llm_used=False)
                return patch
        return None

    def _next_payload_fill_patch(self, state: 'TreeState') -> Optional[Dict[str, Any]]:
        if not self._payload_fill_candidates or self.prompt_mode != 'traffic_fix':
            return None
        for dst, candidates in self._payload_fill_candidates.items():
            for cand in candidates or []:
                key = (getattr(cand, 'dst_id', None) or getattr(cand, 'target_node_id', dst), getattr(cand, 'parent_id', None), getattr(cand, 'bit_start_expr', None), getattr(cand, 'size_bits_expr', None))
                if key in self._served_payload_fill:
                    continue
                try:
                    dst_id = int(getattr(cand, 'dst_id', None) or getattr(cand, 'target_node_id', dst) or dst)
                except Exception:
                    dst_id = dst
                try:
                    parent_id = int(getattr(cand, 'parent_id', None) or dst_id)
                except Exception:
                    parent_id = getattr(cand, 'parent_id', None) or dst_id
                new_node_id = self._compute_next_node_id(state)
                bit_start_expr = getattr(cand, 'bit_start_expr', None) or ''
                size_bits_expr = getattr(cand, 'size_bits_expr', None) or str(getattr(cand, 'gap_bits', '') or '')
                summary = f'Add opaque payload under node {parent_id} (container {dst_id}) to fill coverage gap'
                patch: Dict[str, Any] = {'patch_metadata': {'description': summary, 'intent': 'traffic_payload_fill', 'source': 'traffic_payload_fill'}, 'new_nodes': [{'node_id': new_node_id, 'name': 'opaque_payload', 'node_type': 'field', 'data_type': 'bytes', 'bit_start': bit_start_expr, 'size_bits': size_bits_expr, 'parent_id': parent_id}], 'node_updates': [], 'new_edges': [], 'edge_updates': [], 'edge_removes': [], 'nodes_to_remove': []}
                self._ensure_patch_defaults(patch)
                attempt_number = self._next_attempt_number()
                patch_hash = _hash_patch(patch)
                self._record_patch(patch, patch_hash, summary, 'traffic_payload_fill', attempt_number, None)
                self.action_info[patch_hash] = {'summary': summary, 'source': 'traffic_payload_fill', 'attempt': attempt_number}
                self.previous_patch_summary = summary
                self._served_payload_fill.add(key)
                self._bump_counters(llm_used=False)
                return patch
        return None

    def _generate_patch_via_llm(self, state: 'TreeState', avoid_summaries: Optional[List[str]]=None) -> Optional[Dict[str, Any]]:
        attempt_number = self._next_attempt_number()
        marked_sections = summarize_sections_for_patch(self.sections, self.batch_start, self.batch_size, focus_only=True)
        feedback_hint = self._merge_feedback_with_failures(self.feedback, state)
        previous_attempt_context = self._build_previous_attempt_context(state)
        messages = build_patch_refinement_message(state.tree, marked_sections, self.batch_start, self.batch_size, feedback_hint, self.previous_patch_summary, previous_attempt_context, mode=self.prompt_mode, avoid_summaries=avoid_summaries, experience=self.fix_history)
        logger.info('Batch %s requesting patch via %s (attempt %s/%s)', self.batch_index + 1, self.agent.provider, attempt_number, self.max_calls)
        try:
            base_temp = 0.4
            temp_increment = 0.05
            dynamic_temp = min(0.7, base_temp + self.calls_made * temp_increment)
            temperature_fix = dynamic_temp
            temperature_expand = float(os.getenv('STEP2_EXPAND_TEMPERATURE', '0.5'))
            temperature = temperature_fix if self.prompt_mode == 'fix' else temperature_expand
            payload = {'model': self.agent.default_model, 'system': messages[0]['content'], 'messages': [{'role': 'user', 'content': messages[1]['content']}], 'max_tokens': 64000, 'temperature': temperature}
            fallback_model = os.getenv('STEP2_PATCH_FALLBACK_MODEL')
            empty_retry_limit = max(1, int(os.getenv('STEP2_EMPTY_RESPONSE_RETRIES', '2')))
            quick_timeout = int(os.getenv('STEP2_EMPTY_RESPONSE_TIMEOUT', '45'))
            original_timeout = self.agent.read_timeout
            active_payload = dict(payload)
            clean_response: Optional[str] = None
            raw_response: Optional[str] = None
            try:
                for quick_attempt in range(empty_retry_limit):
                    if quick_attempt > 0 and quick_timeout > 0:
                        self.agent.read_timeout = min(original_timeout, quick_timeout)
                    result = self.agent._call_api_with_retry(active_payload)
                    if 'content' in result and isinstance(result['content'], list):
                        first_item = result['content'][0]
                        if isinstance(first_item, dict):
                            raw_response = first_item.get('text', '') or first_item.get('content', '')
                        else:
                            raw_response = str(first_item)
                    else:
                        raise ValueError(f'Unexpected API response format: {list(result.keys())}')
                    clean_response = self.agent._clean_raw_response(raw_response or '')
                    if clean_response:
                        break
                    if quick_attempt == empty_retry_limit - 1:
                        raise ValueError('LLM returned empty patch response')
                    logger.warning('Empty response for batch %s attempt %s; retrying immediately (quick retry %s/%s)', self.batch_index + 1, attempt_number, quick_attempt + 1, empty_retry_limit - 1)
                    if fallback_model and active_payload.get('model') != fallback_model:
                        active_payload = dict(active_payload)
                        active_payload['model'] = fallback_model
                        logger.info('Switching to fallback model %s for batch %s due to empty response', fallback_model, self.batch_index + 1)
                else:
                    raise ValueError('LLM failed to provide patch response')
            finally:
                self.agent.read_timeout = original_timeout
            if not clean_response:
                raise ValueError('Received empty patch response after retries')
            patch = json.loads(clean_response)
            if not isinstance(patch, dict):
                raise ValueError('LLM response did not decode to an object')
            self._ensure_patch_defaults(patch)
            meta = patch.get('patch_metadata')
            if not isinstance(meta, dict):
                meta = {}
                patch['patch_metadata'] = meta
            meta['source'] = 'llm'
            patch = _strip_payload_fill_child_link_updates(state.tree, patch)
            self._maybe_enqueue_atomic_splits(patch)
            summary = _summarize_patch_for_prompt(patch)
            patch_hash = _hash_patch(patch)
            truncated_messages = [{'role': msg.get('role', ''), 'content': msg.get('content', '')[:500]} for msg in messages]
            self._record_patch(patch, patch_hash, summary, 'llm', attempt_number, truncated_messages)
            self.action_info[patch_hash] = {'summary': summary, 'source': 'llm', 'attempt': attempt_number}
            self.previous_patch_summary = summary
            self._bump_counters(llm_used=True)
            return patch
        except json.JSONDecodeError as exc:
            logger.error('Failed to parse patch JSON on batch %s attempt %s: %s', self.batch_index + 1, attempt_number, exc)
        except Exception as exc:
            logger.error('Patch request failed on batch %s attempt %s: %s', self.batch_index + 1, attempt_number, exc)
        self._bump_counters(llm_used=True)
        return None

    def _count_patch_changes(self, patch: Dict[str, Any]) -> int:
        total = 0
        for key in ('new_nodes', 'node_updates', 'new_edges', 'edge_updates', 'edge_removes', 'nodes_to_remove'):
            items = patch.get(key)
            if isinstance(items, list):
                total += len(items)
        return total

    def _maybe_enqueue_atomic_splits(self, patch: Dict[str, Any]) -> None:
        try:
            from os import getenv
            enabled = getenv('STEP2_PATCH_ATOMIC_SPLIT', '0').lower() in {'1', 'true'}
            if not enabled:
                return
            limit = int(getenv('STEP2_PATCH_MAX_CHANGES', '1'))
            if limit < 1:
                limit = 1
        except Exception:
            return
        total = self._count_patch_changes(patch)
        if total <= limit:
            return
        meta_keys = {'patch_metadata'}
        shared: Dict[str, Any] = {k: copy.deepcopy(v) for k, v in patch.items() if k in meta_keys}
        units: List[Tuple[str, Any]] = []
        for key in ('edge_removes', 'nodes_to_remove', 'edge_updates', 'new_edges', 'node_updates', 'new_nodes'):
            items = patch.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                units.append((key, copy.deepcopy(item)))
        bucket: List[Tuple[str, Any]] = []
        atomic_patches: List[Dict[str, Any]] = []
        for entry in units:
            bucket.append(entry)
            if len(bucket) >= limit:
                atomic_patches.append(self._build_atomic_patch(shared, bucket))
                bucket = []
        if bucket:
            atomic_patches.append(self._build_atomic_patch(shared, bucket))
        self._atomic_queue.extend(atomic_patches)

    def _build_atomic_patch(self, shared: Dict[str, Any], entries: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        atomic: Dict[str, Any] = {k: copy.deepcopy(v) for k, v in shared.items()}
        for key in ('new_nodes', 'node_updates', 'new_edges', 'edge_updates', 'edge_removes', 'nodes_to_remove'):
            atomic[key] = []
        for key, item in entries:
            atomic[key].append(copy.deepcopy(item))
        return atomic

    def _derive_followup_tasks(self, state: 'TreeState') -> List[str]:
        tasks: List[str] = []
        task_set: set[str] = set()

        def add_task(text: str) -> None:
            cleaned = text.strip()
            if cleaned and cleaned not in task_set:
                task_set.add(cleaned)
                tasks.append(cleaned)
        last_action = getattr(state, 'last_action', None)
        patch = last_action.patch if last_action is not None else None
        if not isinstance(patch, dict):
            return tasks
        tree = state.tree
        nodes_index = {node.get('node_id'): node for node in tree.get('nodes', []) if isinstance(node, dict)}

        def node_label(node_dict: Dict[str, Any]) -> str:
            node_id = node_dict.get('node_id')
            name = node_dict.get('name', f'node_{node_id}')
            return f'{name}(ID:{node_id})'
        new_nodes = patch.get('new_nodes', []) or []
        for entry in new_nodes:
            if not isinstance(entry, dict):
                continue
            label = node_label(entry)
            parent_id = entry.get('parent_id')
            parent = nodes_index.get(parent_id)
            parent_label = node_label(parent) if parent else f'node_{parent_id}'
            node_type = (entry.get('node_type') or '').lower()
            if node_type == 'selector':
                add_task(f'Define condition_on edges for selector {label} and ensure each branch is represented by variants.')
            else:
                add_task(f'Review newly added {label} under {parent_label}: add required condition_on/length_of edges and adjust sibling bit_start expressions so ranges do not overlap.')
        for update in patch.get('node_updates', []) or []:
            if not isinstance(update, dict):
                continue
            changes = update.get('changes') or {}
            if 'children_ids' in changes:
                parent_id = update.get('node_id')
                parent = nodes_index.get(parent_id)
                parent_label = node_label(parent) if parent else f'node_{parent_id}'
                add_task(f'Parent {parent_label} had children_ids rewritten; ensure every listed child has the correct structural edges and ordering.')
        nodes = tree.get('nodes', []) or []
        edges = tree.get('edges', []) or []
        condition_edges: Dict[str, List[Dict[str, Any]]] = {}
        length_edge_rels = {'length_of', 'repeat_count', 'offset_of'}
        length_edges: Dict[str, List[Dict[str, Any]]] = {}
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            src = edge.get('src')
            rel = edge.get('rel')
            if src is None:
                continue
            key = str(src)
            if rel == 'condition_on':
                condition_edges.setdefault(key, []).append(edge)
            if rel in length_edge_rels:
                length_edges.setdefault(key, []).append(edge)

        def parse_enum_values(node: Dict[str, Any]) -> List[str]:
            enums: List[str] = []
            for constraint in node.get('constraints', []) or []:
                if not isinstance(constraint, str):
                    continue
                lowered = constraint.lower()
                if lowered.startswith('enum:'):
                    payload = constraint.split(':', 1)[1]
                    enums = [item.strip() for item in payload.split('|') if item.strip()]
                    break
            return enums
        for node in nodes:
            if not isinstance(node, dict):
                continue
            node_id = node.get('node_id')
            label = node_label(node)
            node_type = (node.get('node_type') or '').lower()
            if node_type == 'selector':
                cond = condition_edges.get(str(node_id)) or []
                if not cond:
                    add_task(f'Selector {label} lacks condition_on edges; add variants and boolean condition_on mappings covering its value constraints.')
                enums = parse_enum_values(node)
                if enums:
                    formatted = ', '.join(enums[:6]) + ('...' if len(enums) > 6 else '')
                    add_task(f'Ensure selector {label} has variants/condition_on edges for enumerated values ({formatted}).')

            def looks_like_length(n: Dict[str, Any]) -> bool:
                name = (n.get('name') or '').lower()
                keywords = ('length', 'count', 'size', 'number', 'total', 'cnt')
                return any((keyword in name for keyword in keywords))
            if looks_like_length(node):
                token = f'val({node_id})'
                referenced = False
                for other in nodes:
                    if not isinstance(other, dict):
                        continue
                    for key in ('size_bits', 'bit_start'):
                        expr = other.get(key)
                        if isinstance(expr, str) and token in expr:
                            referenced = True
                            break
                    if referenced:
                        break
                    for constraint in other.get('constraints') or []:
                        if isinstance(constraint, str) and token in constraint:
                            referenced = True
                            break
                if not referenced:
                    for edge in edges:
                        if not isinstance(edge, dict):
                            continue
                        formula = edge.get('formula')
                        if isinstance(formula, str) and token in formula:
                            referenced = True
                            break
                if length_edges.get(str(node_id)) or referenced:
                    add_task(f'Connect length/count field {label} to dependent payloads using length_of/repeat_count/offset_of edges.')
            if node_type not in {'selector', 'variant'}:
                enums = parse_enum_values(node)
                if enums:
                    add_task(f"Field {label} defines enumerated values ({', '.join(enums[:6])}{('...' if len(enums) > 6 else '')}); consider modelling dedicated variants or gating edges for these cases.")

        def resolve_label(node_id: Optional[int], text: str='') -> str:
            if node_id is not None:
                node = nodes_index.get(node_id)
                if node:
                    return node_label(node)
            match = re.search('([A-Za-z0-9_]+\\(ID:\\d+\\))', text)
            if match:
                return match.group(1)
            return 'the affected node'

        def apply_issue_templates(text: str, *, node_id: Optional[int]=None) -> None:
            if not text:
                return
            lowered = text.lower()
            label = resolve_label(node_id, text)
            if 'multiple root nodes' in lowered:
                add_task('Ensure the protocol has exactly one root node; reparent or remove extra roots and update children_ids accordingly.')
            if 'no root node found' in lowered:
                add_task('Designate a single root node and attach any previously rootless nodes beneath it, keeping parent_id/children_ids consistent.')
            if 'parent node' in lowered and 'does not exist' in lowered:
                add_task(f'Attach {label} to a valid parent and update both parent_id and children_ids so the relationship is consistent.')
            if 'child' in lowered and 'does not exist' in lowered:
                add_task(f'Either create the missing child referenced by {label} or remove it from children_ids to keep the tree consistent.')
            if "not listed in parent's children_ids" in lowered:
                add_task(f"Update {label}'s parent children_ids to include it, or adjust parent_id so the hierarchy stays consistent.")
            if 'missing required field' in lowered:
                add_task(f'Populate the required fields (name/node_type/message_type/bit_start/size_bits) for {label} so it is fully defined.')
            if 'size_bits references' in lowered or 'bit_start references' in lowered:
                add_task(f'Rewrite the expressions on {label} so they only reference existing sibling nodes or literal values.')
            if 'children may exceed parent size' in lowered:
                add_task(f'Recalculate bit_start and size_bits for each child under {label}, adjusting the parent size_bits so the layout fits without overflow.')
            if 'invalid overlap with sibling' in lowered:
                add_task(f"Adjust {label}'s bit_start/size_bits or split variants so it no longer overlaps with the sibling mentioned in the validator warning.")
            if 'expression references sibling' in lowered:
                add_task(f"Duplicate shared data into {label}'s branch or change its expressions so they reference nodes within the same selector path instead of sibling branches.")
            if 'non-exclusive conditions' in lowered:
                add_task(f'Provide mutually exclusive condition_on formulas so {label} only activates when its selector value matches the intended branch.')
            if 'variable-length field lacks explicit length binding' in lowered:
                add_task(f'Add explicit length_of edges (and matching formulas) so {label} ties clearly to the associated length/count field.')
            if 'formula constraint cannot be satisfied' in lowered:
                add_task(f'Rewrite the constraint on {label} so it matches the documented range and can be satisfied alongside existing selector/domain limits.')
            if 'unable to interpret formula constraint' in lowered or 'malformed formula constraint' in lowered:
                add_task(f'Restate the constraint on {label} using supported arithmetic or If(...) syntax so the validator can evaluate it.')
            if 'formula constraint references' in lowered and 'should only depend on "value"' in lowered:
                add_task(f"Rewrite or remove the constraint on {label} so it only references 'value'. Use length_of edges or size_bits formulas to relate to other fields.")
            if 'formula may underflow' in lowered or 'formula may overflow' in lowered:
                add_task(f'Clamp or reformulate the constraint on {label} so its value stays within the data type bounds reported by the validator.')
            if 'multiple variants share identical condition' in lowered:
                add_task(f'Give each variant under the relevant selector unique condition_on formulas so the branches cannot trigger simultaneously.')
            if 'lacks activation conditions' in lowered:
                add_task(f'Add condition_on edges for the selector controlling {label}, covering every documented request/response variant value.')
            if 'edge source' in lowered and 'does not exist' in lowered:
                add_task('Remove or fix edges whose source node is missing so every graph edge connects valid nodes.')
            if 'edge destination' in lowered and 'does not exist' in lowered:
                add_task('Repair or delete edges that target missing nodes to keep the edge graph consistent.')
            if 'node is not reachable from any root' in lowered:
                add_task(f'Either attach {label} to a reachable parent or remove it if the documentation no longer references it.')
            if 'part of circular dependency' in lowered:
                add_task(f'Break the circular dependency involving {label} by rewriting expressions so they no longer reference each other recursively.')
            if 'variant condition for' in lowered and 'cannot be satisfied' in lowered:
                add_task(f"Adjust condition_on logic so the activation constraint for {label} is satisfiable within the selector's documented range.")
        for issue in (state.pending_issues or {}).values():
            if not isinstance(issue, Issue):
                continue
            target_id: Optional[int] = None
            if issue.target and issue.target.kind == 'node':
                try:
                    target_id = int(issue.target.identifier) if issue.target.identifier is not None else None
                except (TypeError, ValueError):
                    target_id = None
            apply_issue_templates(issue.description, node_id=target_id)
        for raw_error in state.validation.errors:
            apply_issue_templates(raw_error)
        for extra in state.validation.extras:
            apply_issue_templates(extra)
        return tasks

    def _build_previous_attempt_context(self, state: 'TreeState') -> Optional[Dict[str, Any]]:
        context: Dict[str, Any] = {}
        if state.last_action is not None:
            context['raw_patch'] = copy.deepcopy(state.last_action.patch)
            context['last_patch_hash'] = state.last_action.hash
            if state.history:
                last_record = state.history[-1]
                context['last_reward'] = last_record.reward
                if last_record.introduced:
                    context['issues_introduced'] = self._summarize_issues(last_record.introduced)
                if last_record.resolved:
                    context['issues_resolved'] = self._summarize_issues(last_record.resolved)
        if state.validation.errors:
            context['validator_errors'] = list(state.validation.errors)
        if state.validation.extras:
            context['validator_extras'] = list(state.validation.extras)
        if state.pending_issues:
            context['pending_issues'] = self._summarize_issues(state.pending_issues)
        if not _strict_validator_loop_enabled():
            followup_tasks = self._derive_followup_tasks(state)
            if followup_tasks:
                context['followup_tasks'] = followup_tasks
        if state.history:
            recent: List[Dict[str, Any]] = []
            for record in reversed(state.history[-3:]):
                recent.append({'hash': record.action.hash, 'summary': record.action.summary, 'reward': record.reward, 'introduced': self._summarize_issues(record.introduced) if record.introduced else [], 'resolved': self._summarize_issues(record.resolved) if record.resolved else [], 'timestamp': record.created_at})
            context['recent_records'] = list(recent)
        if not context:
            return None
        return context

    def _record_patch(self, patch: Dict[str, Any], patch_hash: str, summary: Optional[str], source: str, attempt_number: int, messages: Optional[Sequence[Dict[str, Any]]]) -> None:
        sequence_index = len(self.generated_log) + 1
        locations = self._summarize_patch_locations(patch)
        record: Dict[str, Any] = {'patch_snapshot': copy.deepcopy(patch), 'patch_hash': patch_hash, 'summary': summary, 'source': source, 'attempt': attempt_number, 'timestamp': datetime.now().isoformat(), 'sequence_index': sequence_index, 'batch_index': self.batch_index, 'locations': locations}
        if messages:
            record['messages'] = list(messages)
        self.generated_log.append(record)
        self.patch_files[patch_hash] = self._write_patch_record(record)

    def on_candidate_evaluated(self, evaluation: 'PatchEvaluation') -> None:
        info = self.action_info.get(evaluation.action.hash, {})
        entry = {'batch': self.batch_index, 'source': info.get('source', 'llm'), 'attempt': info.get('attempt'), 'reward': evaluation.reward, 'errors': list(evaluation.validation_after.errors), 'extras': list(evaluation.validation_after.extras), 'patch_summary': info.get('summary'), 'issues_after': self._summarize_issues(evaluation.validation_after.issues) if evaluation.validation_after.issues else [], 'introduced': self._summarize_issues(evaluation.delta.introduced) if evaluation.delta.introduced else [], 'resolved': self._summarize_issues(evaluation.delta.resolved) if evaluation.delta.resolved else []}
        self.evaluation_records.append(entry)
        for record in self.generated_log:
            if record.get('patch_hash') == evaluation.action.hash:
                record['errors'] = list(evaluation.validation_after.errors)
                record['extras'] = list(evaluation.validation_after.extras)
                record['reward'] = evaluation.reward
                if evaluation.delta.introduced:
                    record['issues_introduced'] = self._summarize_issues(evaluation.delta.introduced)
                if evaluation.delta.resolved:
                    record['issues_resolved'] = self._summarize_issues(evaluation.delta.resolved)
                path = self.patch_files.get(evaluation.action.hash)
                if path is None:
                    path = self._write_patch_record(record)
                    self.patch_files[evaluation.action.hash] = path
                else:
                    self._write_patch_record(record, path)
                break
        self.feedback = _build_patch_feedback(list(evaluation.validation_after.errors), list(evaluation.validation_after.extras), evaluation.tree_after)
        if info.get('summary'):
            self.previous_patch_summary = info['summary']

    def persist_cache(self) -> None:
        if not self.generated_log:
            return
        payload = {'analysis_only': True, 'notice': 'Cached records are stored for offline review only. The refinement loop ignores these entries during future runs.', 'patches': self.generated_log, 'timestamp': datetime.now().isoformat(), 'batch_info': f'Sections {self.batch_start} to {self.batch_end - 1}'}
        self.agent._save_to_cache(self.cache_filename, payload)

    def get_action_info(self, action_hash: Optional[str]) -> Optional[Dict[str, Any]]:
        if not action_hash:
            return None
        return self.action_info.get(action_hash)

    def _write_patch_record(self, record: Dict[str, Any], destination: Optional[Path]=None) -> Path:
        patch_hash = record.get('patch_hash') or 'unknown'
        if destination is None:
            attempt = record.get('attempt') or 0
            filename = f'{attempt:03d}_{patch_hash[:8]}.json'
            destination = self.patch_dir / filename
        snapshot = copy.deepcopy(record)
        with destination.open('w', encoding='utf-8') as handle:
            json.dump(snapshot, handle, ensure_ascii=False, indent=2)
        return destination

    @staticmethod
    def _ensure_patch_defaults(patch: Dict[str, Any]) -> None:
        for key in ['new_nodes', 'node_updates', 'new_edges', 'edge_updates', 'edge_removes', 'nodes_to_remove']:
            if key not in patch or not isinstance(patch[key], list):
                patch[key] = []

    @staticmethod
    def _summarize_patch_locations(patch: Dict[str, Any]) -> Dict[str, Any]:
        summary: Dict[str, Any] = {}

        def _node_info(entry: Dict[str, Any]) -> Dict[str, Any]:
            info: Dict[str, Any] = {}
            node_id = entry.get('node_id')
            if node_id is not None:
                info['node_id'] = node_id
            name = entry.get('name')
            if name:
                info['name'] = name
            parent_id = entry.get('parent_id')
            if parent_id is not None:
                info['parent_id'] = parent_id
            return info
        new_nodes: List[Dict[str, Any]] = []
        for entry in patch.get('new_nodes', []) or []:
            if isinstance(entry, dict):
                new_nodes.append(_node_info(entry))
        if new_nodes:
            summary['new_nodes'] = new_nodes
        updated_nodes: List[Dict[str, Any]] = []
        for entry in patch.get('node_updates', []) or []:
            if not isinstance(entry, dict):
                continue
            info = _node_info(entry)
            if not info and entry.get('node_id') is not None:
                info['node_id'] = entry.get('node_id')
            if entry.get('updates'):
                info['fields'] = sorted(entry['updates'].keys())
            else:
                fields = [key for key in entry.keys() if key not in {'node_id', 'name', 'parent_id'}]
                if fields:
                    info['fields'] = sorted(fields)
            if info:
                updated_nodes.append(info)
        if updated_nodes:
            summary['updated_nodes'] = updated_nodes
        new_edges: List[Dict[str, Any]] = []
        for entry in patch.get('new_edges', []) or []:
            if not isinstance(entry, dict):
                continue
            info = {key: entry.get(key) for key in ('src', 'dst', 'rel') if entry.get(key) is not None}
            if entry.get('formula'):
                info['formula'] = entry['formula']
            if info:
                new_edges.append(info)
        if new_edges:
            summary['new_edges'] = new_edges
        edge_updates: List[Dict[str, Any]] = []
        for entry in patch.get('edge_updates', []) or []:
            if not isinstance(entry, dict):
                continue
            info = {key: entry.get(key) for key in ('src', 'dst', 'rel') if entry.get(key) is not None}
            if entry.get('updates') and isinstance(entry['updates'], dict):
                info['fields'] = sorted(entry['updates'].keys())
            if info:
                edge_updates.append(info)
        if edge_updates:
            summary['edge_updates'] = edge_updates
        edge_removes: List[Dict[str, Any]] = []
        for entry in patch.get('edge_removes', []) or []:
            if not isinstance(entry, dict):
                continue
            info = {key: entry.get(key) for key in ('src', 'dst', 'rel') if entry.get(key) is not None}
            if info:
                edge_removes.append(info)
        if edge_removes:
            summary['edge_removes'] = edge_removes
        removed_nodes: List[int] = []
        for entry in patch.get('nodes_to_remove', []) or []:
            if isinstance(entry, dict):
                node_id = entry.get('node_id')
            else:
                node_id = entry
            if isinstance(node_id, int):
                removed_nodes.append(node_id)
        if removed_nodes:
            summary['nodes_to_remove'] = sorted(set(removed_nodes))
        touched = set()
        for group in (summary.get('new_nodes', []), summary.get('updated_nodes', [])):
            if not group:
                continue
            for item in group:
                node_id = item.get('node_id')
                if isinstance(node_id, int):
                    touched.add(node_id)
        for node_id in summary.get('nodes_to_remove', []) or []:
            touched.add(node_id)
        if touched:
            summary['touched_node_ids'] = sorted(touched)
        return summary

    @staticmethod
    def _summarize_issues(issues: Dict[str, Issue]) -> List[Dict[str, Any]]:
        summary: List[Dict[str, Any]] = []
        for issue_id, issue in sorted(issues.items()):
            target = issue.target.identifier if issue.target else None
            summary.append({'id': issue_id, 'type': issue.type.value, 'severity': issue.severity.value, 'description': issue.description, 'target': target})
        return summary

    def _merge_feedback_with_failures(self, base_feedback: Optional[str], state: Any) -> Optional[str]:
        validation = getattr(state, 'validation', None)
        if validation is None:
            return base_feedback
        failures = getattr(validation, 'traffic_failures', ()) or ()
        if not failures:
            return base_feedback
        summary = getattr(validation, 'traffic_global_summary', None)
        total_samples = getattr(validation, 'traffic_total_samples', 0)
        success_samples = getattr(validation, 'traffic_successful_samples', 0)
        failed_samples = total_samples - success_samples if total_samples else getattr(summary, 'failed_samples', 0) or len(failures)
        if _strict_validator_loop_enabled():
            max_groups = max(1, int(os.getenv('STEP2_TRAFFIC_FAILURES_IN_PROMPT', '8')))
            examples_per_group = max(1, int(os.getenv('STEP2_TRAFFIC_GROUP_EXAMPLES', '2')))
            prefix_len = max(1, int(os.getenv('STEP2_TRAFFIC_GROUP_PREFIX_LEN', '16')))

            def _env_limit(name: str, default: Optional[int], *, min_value: int=1) -> Optional[int]:
                raw = os.getenv(name)
                if raw is None:
                    return default
                s = str(raw).strip().lower()
                if s in {'inf', 'infty', 'infinite', 'unlimited', 'none', 'null', 'no_limit', 'nolimit'}:
                    return None
                try:
                    val = int(s)
                except Exception:
                    return default
                if val <= 0:
                    return None
                return max(min_value, val)
            hex_max_bytes = _env_limit('STEP2_TRAFFIC_PACKET_HEX_MAX_BYTES', 128, min_value=1)
            max_failures_per_sample = _env_limit('STEP2_TRAFFIC_GROUP_SAMPLE_FAILURES', 4, min_value=1)
            max_variant_errors = max(1, int(os.getenv('STEP2_TRAFFIC_ROUTING_VARIANT_ERRORS', '6')))

            def _coerce_int(raw: Any) -> Optional[int]:
                try:
                    return int(raw)
                except Exception:
                    return None

            def _path_prefix_tuple(f: Any) -> Tuple[int, ...]:
                raw = getattr(f, 'path_node_ids', None) or []
                out: List[int] = []
                for nid in raw[:prefix_len]:
                    coerced = _coerce_int(nid)
                    if coerced is None:
                        continue
                    out.append(coerced)
                return tuple(out)

            def _infer_group_signature(f: Any) -> str:
                sig = getattr(f, 'group_signature', None)
                if sig:
                    sig_str = str(sig)
                    if len(sig_str) > 200:
                        sig_str = sig_str[:197] + '...'
                    return sig_str
                selector_id = _coerce_int(getattr(f, 'routing_selector_id', None))
                candidates_raw = getattr(f, 'routing_candidate_variant_ids', None) or []
                candidates: List[int] = []
                if isinstance(candidates_raw, list):
                    for item in candidates_raw[:10]:
                        coerced = _coerce_int(item)
                        if coerced is None:
                            continue
                        candidates.append(int(coerced))
                parts: List[str] = []
                if selector_id is not None:
                    parts.append(f'selector={selector_id}')
                if candidates:
                    parts.append(f'candidates={candidates}')
                if parts:
                    return 'routing:' + ' '.join(parts)
                path_prefix = _path_prefix_tuple(f)
                if path_prefix:
                    return f'path_prefix={list(path_prefix)}'
                return 'group=unknown'

            def _format_packet_hex(hex_str: Optional[str]) -> str:
                if not hex_str:
                    return '-'
                if hex_max_bytes is None:
                    return hex_str
                max_chars = int(hex_max_bytes) * 2
                if len(hex_str) <= max_chars:
                    return hex_str
                return hex_str[:max_chars] + '...'
            node_lookup: Dict[Any, Dict[str, Any]] = {}
            try:
                raw_nodes = getattr(state, 'tree', {}).get('nodes', []) if hasattr(state, 'tree') else []
                if not raw_nodes and isinstance(state, SimpleNamespace):
                    raw_nodes = state.tree.get('nodes', [])
                if isinstance(raw_nodes, list):
                    for n in raw_nodes:
                        if not isinstance(n, dict):
                            continue
                        nid = n.get('node_id')
                        if nid is None:
                            continue
                        node_lookup[nid] = n
                        node_lookup[str(nid)] = n
            except Exception:
                node_lookup = {}

            def _node_name(nid: Any) -> str:
                node = node_lookup.get(nid) or node_lookup.get(str(nid)) or {}
                name = node.get('name')
                return str(name) if name else ''

            def _format_ctx_fields(values: Dict[int, int], *, limit: int=14) -> str:
                if not values:
                    return '{}'
                interesting: List[Tuple[int, int]] = []
                rest: List[Tuple[int, int]] = []
                for k, v in values.items():
                    name = _node_name(k).lower()
                    if any((tok in name for tok in ('length', 'byte_count', 'function', 'unit', 'quantity', 'address'))):
                        interesting.append((k, v))
                    else:
                        rest.append((k, v))
                interesting.sort(key=lambda kv: kv[0])
                rest.sort(key=lambda kv: kv[0])
                items = interesting + rest
                shown = items if limit <= 0 else items[:limit]
                parts: List[str] = []
                for k, v in shown:
                    name = _node_name(k)
                    if name:
                        parts.append(f'{k}={v}({name})')
                    else:
                        parts.append(f'{k}={v}')
                suffix = ', ...' if limit > 0 and len(items) > limit else ''
                return '{' + ', '.join(parts) + suffix + '}'
            grouped: Dict[str, List[Any]] = {}
            for f in failures:
                grouped.setdefault(_infer_group_signature(f), []).append(f)
            pending_issues = getattr(state, 'pending_issues', None) or {}
            issue_desc_blob = ''
            issue_target_ids: set[int] = set()
            try:
                descs: List[str] = []
                for iss in pending_issues.values():
                    desc = getattr(iss, 'description', None)
                    if desc:
                        descs.append(str(desc))
                    target = getattr(iss, 'target', None)
                    ident = getattr(target, 'identifier', None) if target is not None else None
                    if ident is None:
                        continue
                    try:
                        issue_target_ids.add(int(str(ident)))
                    except Exception:
                        continue
                issue_desc_blob = '\n'.join(descs)
            except Exception:
                issue_desc_blob = ''
                issue_target_ids = set()

            def _is_relevant_group(sig: str, items: List[Any]) -> bool:
                if sig:
                    try:
                        if issue_desc_blob and sig in issue_desc_blob:
                            return True
                        if sig.startswith('routing:'):
                            sig2 = sig[len('routing:'):].strip()
                            if sig2 and issue_desc_blob and (sig2 in issue_desc_blob):
                                return True
                    except Exception:
                        pass
                if issue_target_ids:
                    for rec in items:
                        nid = _coerce_int(getattr(rec, 'node_id', None))
                        if nid is not None and int(nid) in issue_target_ids:
                            return True
                return False

            def _group_order(item: Tuple[str, List[Any]]) -> Tuple[int, int, int, str]:
                sig, items = item
                pkt_set: set[int] = set()
                for rec in items:
                    try:
                        pkt_set.add(int(getattr(rec, 'packet_index', 0) or 0))
                    except Exception:
                        continue
                pkt_count = len(pkt_set)
                min_pkt = min(pkt_set) if pkt_set else 0
                relevant = _is_relevant_group(sig, items)
                return (0 if relevant else 1, -pkt_count, min_pkt, sig)
            top_groups = sorted(grouped.items(), key=_group_order)[:max_groups]
            lines: List[str] = []
            lines.append('=== TRAFFIC FAILURE GROUPS (SAMPLES) ===')
            lines.append(f'samples: total={total_samples} success={success_samples} failed={failed_samples}')
            lines.append(f'grouping=group_signature group_prefix_len={prefix_len} groups_total={len(grouped)} groups_shown={len(top_groups)} examples_per_group={examples_per_group} hex_max_bytes={hex_max_bytes}')
            for idx, (sig, items) in enumerate(top_groups, 1):
                packet_indices = sorted({int(getattr(f, 'packet_index', 0) or 0) for f in items if getattr(f, 'packet_index', None) is not None})
                kind_counts = Counter()
                for f in items:
                    kind = str(getattr(f, 'failure_kind', '') or '')
                    if kind:
                        kind_counts[kind] += 1
                kind_summary = ', '.join((f'{kind}={count}' for kind, count in kind_counts.most_common(8)))
                header = f'- group#{idx}: sig={sig} | packets={len(packet_indices)} | records={len(items)}'
                if kind_summary:
                    header += f' | kinds: {kind_summary}'
                lines.append(header)
                for pkt in packet_indices[:examples_per_group]:
                    rep = next((f for f in items if int(getattr(f, 'packet_index', -1) or -1) == pkt), None)
                    pkt_len = getattr(rep, 'packet_len_bytes', None) if rep is not None else None
                    hex_str = getattr(rep, 'packet_hex', None) if rep is not None else None
                    if pkt_len is None and isinstance(hex_str, str) and hex_str:
                        pkt_len = len(hex_str) // 2
                    lines.append(f'  * pkt#{pkt} len_bytes={pkt_len} hex={_format_packet_hex(hex_str)}')
                    ctx_fields = getattr(rep, 'context_field_values', None) if rep is not None else None
                    if isinstance(ctx_fields, dict) and ctx_fields:
                        try:
                            ctx_fields_int: Dict[int, int] = {}
                            for k, v in ctx_fields.items():
                                try:
                                    ctx_fields_int[int(k)] = int(v)
                                except Exception:
                                    continue
                            if ctx_fields_int:
                                lines.append(f'    ctx_fields: {_format_ctx_fields(ctx_fields_int)}')
                        except Exception:
                            pass
                    pkt_failures = [f for f in items if int(getattr(f, 'packet_index', -1) or -1) == pkt]
                    pkt_failures.sort(key=lambda f: (str(getattr(f, 'failure_kind', '') or ''), _coerce_int(getattr(f, 'node_id', None)) or -1))
                    sample_failures = pkt_failures if max_failures_per_sample is None else pkt_failures[:int(max_failures_per_sample)]
                    for f in sample_failures:
                        kind = str(getattr(f, 'failure_kind', '') or '')
                        nid = _coerce_int(getattr(f, 'node_id', None))
                        bit_start = getattr(f, 'bit_start', None)
                        size_eval = getattr(f, 'size_bits_eval', None)
                        msg = str(getattr(f, 'message', '') or '').strip()
                        if len(msg) > 260:
                            msg = msg[:257] + '...'
                        lines.append(f'    - {kind} node={nid} bit_start={bit_start} size_bits_eval={size_eval} :: {msg}')
                        selector_id = getattr(f, 'routing_selector_id', None)
                        if selector_id is not None:
                            cands_raw = getattr(f, 'routing_candidate_variant_ids', None)
                            if cands_raw and isinstance(cands_raw, list):
                                cands_raw = cands_raw[:10]
                            lines.append(f'      . routing: selector={selector_id} candidates={cands_raw}')
                            variant_errors = getattr(f, 'routing_variant_errors', None)
                            if variant_errors and isinstance(variant_errors, list):
                                for detail in variant_errors[:max_variant_errors]:
                                    if not isinstance(detail, dict):
                                        continue
                                    vid = detail.get('variant_id')
                                    vname = str(detail.get('variant_name') or '')
                                    etype = detail.get('error_type')
                                    enid = detail.get('node_id')
                                    emsg = str(detail.get('message') or '').strip()
                                    if len(emsg) > 240:
                                        emsg = emsg[:237] + '...'
                                    label = f'{vname}({vid})' if vname and vid is not None else str(vid) if vid is not None else '?'
                                    lines.append(f'        . {label} err={etype} node={enid} :: {emsg}')
            repair_hints = getattr(validation, 'traffic_repair_hints', None) or []
            if repair_hints:
                raw_limit = os.getenv('STEP2_TRAFFIC_HINTS_IN_PROMPT', '8')
                try:
                    max_hints_in_prompt = int(str(raw_limit).strip())
                except Exception:
                    max_hints_in_prompt = 8
                if max_hints_in_prompt <= 0:
                    max_hints_in_prompt = 0
                    repair_hints = []
            if repair_hints:
                lines.append('=== TRAFFIC REPAIR HINTS (AUTO-INFERRED) ===')
                try:
                    hint_kind_counts = Counter((str(h.get('kind', '')) for h in repair_hints if isinstance(h, dict)))
                    lines.append(f'hints_total={len(repair_hints)} hints_shown={min(len(repair_hints), max_hints_in_prompt)} kinds_top={dict(hint_kind_counts.most_common(6))}')
                except Exception:
                    lines.append(f'hints_total={len(repair_hints)} hints_shown={min(len(repair_hints), max_hints_in_prompt)}')
                for i, hint in enumerate(repair_hints[:max_hints_in_prompt], 1):
                    if not isinstance(hint, dict):
                        continue
                    kind = str(hint.get('kind', '') or '')
                    score = hint.get('score', None)
                    conf = hint.get('confidence', None)
                    target = hint.get('target', None)
                    desc = hint.get('description', None)
                    header = f'- hint#{i}: kind={kind}'
                    if score is not None:
                        header += f' score={score}'
                    if conf is not None:
                        header += f' confidence={conf}'
                    if target:
                        header += f' target={target}'
                    lines.append(header)
                    if desc:
                        lines.append(f'  {str(desc)}')
                    if kind == 'add_length_of':
                        lines.append(f"  suggest: add length_of src={hint.get('src')} -> dst={hint.get('target')} formula={hint.get('formula')}")
                    elif kind == 'set_size_bits':
                        lines.append(f"  suggest: set {hint.get('target')} size_bits={hint.get('suggested_size_bits')}")
                    elif kind == 'set_variant_size_bits':
                        lines.append(f"  suggest: set {hint.get('target')} size_bits={hint.get('suggested_size_bits')}")
                    elif kind == 'shift_variant_subtree':
                        lines.append(f"  suggest: shift descendants of {hint.get('target')} by {hint.get('shift_bits')} bits")
                    evidence = hint.get('evidence', None)
                    if isinstance(evidence, dict) and evidence:
                        try:
                            packets = evidence.get('example_packets', None)
                            if packets:
                                lines.append(f'  evidence: example_packets={packets}')
                            matches = evidence.get('tail_gap_matches', None)
                            if matches:
                                lines.append(f'  evidence: tail_gap_matches={matches}')
                        except Exception:
                            pass
            merged = '\n'.join(lines)
            if base_feedback:
                return base_feedback + '\n\n' + merged
            return merged
        if total_samples == 0 and summary is not None:
            total_samples = getattr(summary, 'total_samples', 0) or total_samples
        if success_samples == 0 and summary is not None:
            try:
                success_samples = total_samples - (getattr(summary, 'failed_samples', 0) or 0)
            except Exception:
                success_samples = 0
        node_lookup: Dict[Any, Dict[str, Any]] = {}
        try:
            for n in state.tree.get('nodes', []) if isinstance(state, SimpleNamespace) else state.tree.get('nodes', []):
                nid = n.get('node_id')
                if nid is None:
                    continue
                node_lookup[nid] = n
                node_lookup[str(nid)] = n
        except Exception:
            try:
                for n in getattr(state, 'tree', {}).get('nodes', []):
                    nid = n.get('node_id')
                    if nid is None:
                        continue
                    node_lookup[nid] = n
                    node_lookup[str(nid)] = n
            except Exception:
                node_lookup = {}

        def _node_label(nid: Any) -> str:
            node = node_lookup.get(nid) or node_lookup.get(str(nid), {})
            name = node.get('name')
            ntype = node.get('node_type')
            if name and ntype:
                return f'{name} ({ntype})'
            if name:
                return str(name)
            if ntype:
                return f'{ntype}'
            return ''

        def _format_ctx_fields(values: Dict[int, int], limit: int=6) -> str:
            if not values:
                return '{}'
            items = sorted(values.items(), key=lambda kv: kv[0])[:limit]
            parts: List[str] = []
            for k, v in items:
                label = _node_label(k)
                if label:
                    parts.append(f'{k}:{v}({label})')
                else:
                    parts.append(f'{k}:{v}')
            payload = ', '.join(parts)
            if len(values) > limit:
                payload += ', ...'
            return '{' + payload + '}'

        def _format_path(path: List[int], limit: int=12) -> str:
            if not path:
                return '[]'
            trimmed = path[:limit]
            suffix = '...' if len(path) > limit else ''
            return '[' + ', '.join((str(p) for p in trimmed)) + suffix + ']'
        node_counts = Counter()
        if summary and getattr(summary, 'per_node_failure_counts', None):
            try:
                node_counts.update(getattr(summary, 'per_node_failure_counts'))
            except Exception:
                pass
        for f in failures:
            try:
                nid_int = int(getattr(f, 'node_id', -1))
            except Exception:
                continue
            node_counts[nid_int] += 1
        max_failures = max(1, int(os.getenv('STEP2_TRAFFIC_FAILURES_IN_PROMPT', '8')))
        ordered_failures = sorted(failures, key=lambda f: (-node_counts.get(getattr(f, 'node_id', None), 0), getattr(f, 'packet_index', 0)))[:max_failures]
        lines: List[str] = []
        lines.append('=== TRAFFIC FAILURES (STRUCTURED) ===')
        lines.append(f'samples: total={total_samples} success={success_samples} failed={failed_samples}')
        if node_counts:
            top_nodes = node_counts.most_common(5)
            lines.append(f'top_fail_nodes: {[(nid, cnt) for nid, cnt in top_nodes]}')
        length_of_targets: Set[int] = set()
        try:
            for e in state.tree.get('edges') or []:
                if not isinstance(e, dict):
                    continue
                if (e.get('rel') or '').strip().lower() != 'length_of':
                    continue
                dst = e.get('dst')
                if dst is None:
                    continue
                try:
                    length_of_targets.add(int(dst))
                except Exception:
                    continue
        except Exception:
            length_of_targets = set()

        def _is_variable_leaf_without_length_binding(node_id: Any) -> bool:
            try:
                nid_int = int(node_id)
            except Exception:
                return False
            node = node_lookup.get(nid_int) or node_lookup.get(str(nid_int))
            if not isinstance(node, dict):
                return False
            node_type = str(node.get('node_type') or '').lower()
            children = node.get('children_ids') or []
            is_leaf_like = node_type in {'field', 'selector', 'type', 'length', 'checksum'} or not children
            if not is_leaf_like:
                return False
            size_bits = node.get('size_bits')
            if size_bits is None:
                return nid_int not in length_of_targets
            if isinstance(size_bits, str) and size_bits.strip().lower() in {'variable', 'unknown', 'dynamic', ''}:
                return nid_int not in length_of_targets
            return False
        variable_leaf_counts: Counter[int] = Counter()
        for f in failures:
            for nid in (getattr(f, 'path_node_ids', None) or [])[:64]:
                if _is_variable_leaf_without_length_binding(nid):
                    try:
                        variable_leaf_counts[int(nid)] += 1
                    except Exception:
                        continue
        if variable_leaf_counts:
            top_variable = []
            for nid, cnt in variable_leaf_counts.most_common(5):
                top_variable.append((nid, cnt, _node_label(nid)))
            lines.append(f'top_variable_leaves_without_length_of: {top_variable}')
        routing_groups: Counter[Tuple[Any, Any, Tuple[int, ...], Tuple[int, ...]]] = Counter()
        for f in failures:
            if (getattr(f, 'failure_kind', '') or '').lower() != 'routing':
                continue
            try:
                node = int(getattr(f, 'node_id', -1))
            except Exception:
                node = getattr(f, 'node_id', None)
            selector_id = getattr(f, 'routing_selector_id', None)
            raw_cands = getattr(f, 'routing_candidate_variant_ids', None) or []
            try:
                cands = tuple((int(x) for x in raw_cands))
            except Exception:
                cands = tuple()
            prefix_raw = (getattr(f, 'path_node_ids', None) or [])[:8]
            try:
                prefix = tuple((int(x) for x in prefix_raw))
            except Exception:
                prefix = tuple()
            routing_groups[node, selector_id, cands, prefix] += 1
        if routing_groups:
            top_groups = routing_groups.most_common(3)
            rendered = []
            for (node, selector_id, cands, prefix), cnt in top_groups:
                rendered.append({'count': cnt, 'node': node, 'selector': selector_id, 'candidates': list(cands), 'prefix': list(prefix)})
            lines.append(f'top_routing_groups: {rendered}')

        def _as_int(value: Any) -> Optional[int]:
            if value is None:
                return None
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, int):
                return value
            if isinstance(value, float):
                try:
                    return int(value)
                except Exception:
                    return None
            if isinstance(value, str):
                candidate = value.strip()
                if not candidate:
                    return None
                if candidate.isdigit() or (candidate.startswith('-') and candidate[1:].isdigit()):
                    try:
                        return int(candidate, 10)
                    except Exception:
                        return None
            return None

        def _node_type(nid: Any) -> str:
            node = node_lookup.get(nid) or node_lookup.get(str(nid))
            if not isinstance(node, dict):
                return ''
            return str(node.get('node_type') or '').lower()
        selector_for_variant: Dict[int, int] = {}
        ambiguous_variants: Set[int] = set()
        try:
            for e in state.tree.get('edges') or []:
                if not isinstance(e, dict):
                    continue
                if (e.get('rel') or '').strip().lower() != 'condition_on':
                    continue
                src = _as_int(e.get('src'))
                dst = _as_int(e.get('dst'))
                if src is None or dst is None:
                    continue
                if dst in selector_for_variant and selector_for_variant[dst] != src:
                    ambiguous_variants.add(dst)
                else:
                    selector_for_variant[dst] = src
        except Exception:
            selector_for_variant = {}
            ambiguous_variants = set()
        for dst in ambiguous_variants:
            selector_for_variant.pop(dst, None)
        variant_hits: Counter[int] = Counter()
        for f in failures:
            for nid in (getattr(f, 'path_node_ids', None) or [])[:64]:
                try:
                    nid_int = int(nid)
                except Exception:
                    continue
                if _node_type(nid_int) == 'variant':
                    variant_hits[nid_int] += 1
        selector_double_count: List[Dict[str, Any]] = []
        selector_child_shift: List[Dict[str, Any]] = []
        for var_id, sel_id in selector_for_variant.items():
            var = node_lookup.get(var_id) or node_lookup.get(str(var_id))
            sel = node_lookup.get(sel_id) or node_lookup.get(str(sel_id))
            if not isinstance(var, dict) or not isinstance(sel, dict):
                continue
            if str(var.get('node_type') or '').lower() != 'variant':
                continue
            v_start = _as_int(var.get('bit_start'))
            v_size = _as_int(var.get('size_bits'))
            s_start = _as_int(sel.get('bit_start'))
            s_size = _as_int(sel.get('size_bits'))
            if v_start is None or v_size is None or s_start is None or (s_size is None):
                continue
            if v_start != s_start + s_size:
                continue
            child_ids = var.get('children_ids') or []
            if not isinstance(child_ids, list) or not child_ids:
                continue
            min_child_start: Optional[int] = None
            max_child_end: Optional[int] = None
            child_nodes: List[int] = []
            unknown = False
            for cid_raw in child_ids:
                cid = _as_int(cid_raw)
                if cid is None:
                    continue
                child = node_lookup.get(cid) or node_lookup.get(str(cid))
                if not isinstance(child, dict):
                    continue
                c_start = _as_int(child.get('bit_start'))
                c_size = _as_int(child.get('size_bits'))
                if c_start is None or c_size is None:
                    unknown = True
                    break
                child_nodes.append(cid)
                end = c_start + c_size
                min_child_start = c_start if min_child_start is None else min(min_child_start, c_start)
                max_child_end = end if max_child_end is None else max(max_child_end, end)
            if unknown or max_child_end is None or max_child_end <= v_start:
                continue
            span = max_child_end - v_start
            if span > 0 and v_size == span + s_size:
                selector_double_count.append({'variant': var_id, 'selector': sel_id, 'selector_bits': s_size, 'size_bits': v_size, 'children_span': span, 'suggested_size_bits': span, 'hits': int(variant_hits.get(var_id, 0))})
                continue
            if min_child_start is not None and min_child_start == v_start + s_size and (v_size == span) and (span > s_size):
                selector_child_shift.append({'variant': var_id, 'selector': sel_id, 'shift_bits': s_size, 'size_bits': v_size, 'children': child_nodes[:8], 'hits': int(variant_hits.get(var_id, 0))})
        count_prefixed: List[Dict[str, Any]] = []
        for dst_id, hit_count in variable_leaf_counts.most_common(5):
            if not _is_variable_leaf_without_length_binding(dst_id):
                continue
            dst_node = node_lookup.get(dst_id) or node_lookup.get(str(dst_id))
            if not isinstance(dst_node, dict):
                continue
            if str(dst_node.get('node_type') or '').lower() != 'field':
                continue
            dst_start = _as_int(dst_node.get('bit_start'))
            if dst_start is None:
                continue
            parent_id = _as_int(dst_node.get('parent_id'))
            parent = node_lookup.get(parent_id) or node_lookup.get(str(parent_id)) if parent_id is not None else None
            if not isinstance(parent, dict):
                continue
            siblings = parent.get('children_ids') or []
            if not isinstance(siblings, list):
                continue
            prefix_candidates: List[int] = []
            for sid_raw in siblings:
                sid = _as_int(sid_raw)
                if sid is None or sid == dst_id:
                    continue
                sib = node_lookup.get(sid) or node_lookup.get(str(sid))
                if not isinstance(sib, dict):
                    continue
                stype = str(sib.get('node_type') or '').lower()
                if stype not in {'field', 'length'}:
                    continue
                s_start = _as_int(sib.get('bit_start'))
                s_size = _as_int(sib.get('size_bits'))
                if s_start is None or s_size is None:
                    continue
                if s_size <= 0 or s_size > 32:
                    continue
                if s_start + s_size != dst_start:
                    continue
                prefix_candidates.append(sid)
            if prefix_candidates:
                count_prefixed.append({'dst': int(dst_id), 'prefix': prefix_candidates[:3], 'units_bits': [1, 8, 16, 32], 'hits': int(hit_count)})
        max_show = max(1, int(os.getenv('STEP2_TRAFFIC_HEURISTIC_HINTS', '4')))
        if selector_double_count:
            selector_double_count.sort(key=lambda d: (-int(d.get('hits', 0)), -int(d.get('selector_bits', 0))))
            shown = selector_double_count[:max_show]
            lines.append(f'heuristic_selector_double_counting: {shown}')
        if selector_child_shift:
            selector_child_shift.sort(key=lambda d: (-int(d.get('hits', 0)), -int(d.get('shift_bits', 0))))
            shown = selector_child_shift[:max_show]
            lines.append(f'heuristic_selector_child_offset: {shown}')
        if count_prefixed:
            count_prefixed.sort(key=lambda d: -int(d.get('hits', 0)))
            shown = count_prefixed[:max_show]
            lines.append(f'heuristic_count_prefixed_variable_field: {shown}')
        kind_counts = Counter()
        for f in failures:
            kind_counts[(getattr(f, 'failure_kind', '') or 'unknown').lower()] += 1
        guidance: List[str] = []
        if variable_leaf_counts:
            guidance.append('- variable_size_leaf(no_length_of): some leaf fields have size_bits missing/variable and no length_of binding, so they parse 0 bytes and create coverage gaps. Consult DOCUMENTATION CONTEXT to identify the controlling length/count field, then add a length_of edge src=<length_field> -> dst=<variable_leaf> with a bits formula (often *8 for bytes). Keep size_bits as "variable"; do NOT guess a fixed size.')
        if kind_counts.get('coverage_gap'):
            guidance.append('- coverage_gap: parsed content is smaller than the length-controlled region. FIRST check for structural problems (oob_seek/oob_read candidate variants, selector double-counting, child offset hints) and missing length_of bindings for variable leaves; fixing those often eliminates large gaps. Use traffic_payload_fill only as a LAST RESORT for genuinely opaque/undocumented bytes, and anchor formulas only to nodes on the active parse path.')
        if kind_counts.get('coverage_tail_gap') or kind_counts.get('coverage_internal_gap'):
            guidance.append('- coverage_tail_gap/internal_gap: parser did not cover all bytes on the visited path. Prefer adding missing leaf fields (or a trailing bytes field) under the nearest container on the active parse path; derive size from an existing length/byte_count field when available (avoid circular refs like child size depending on parent.size_bits).')
        if kind_counts.get('length_mismatch') or kind_counts.get('length_overflow'):
            guidance.append('- length_mismatch/overflow: length binding or size_bits is wrong on-wire. Prefer adjusting length_of formula and/or dst.size_bits (check bits vs bytes: *8). Avoid fixing by adding padding unless the issue is explicitly coverage_gap.')
        if kind_counts.get('routing'):
            guidance.append('- routing: selector/condition_on logic is wrong. Add/adjust condition_on edges or variant constraints so exactly one variant matches; keep variants mutually exclusive on the same selector.')
        if kind_counts.get('constraint'):
            guidance.append('- constraint: observed values violate enum/range/expr. Prefer widening constraints or correcting enum values; if constraint depends on message_type, ensure message_type is consistent along the parse path.')
        if kind_counts.get('oob_read') or kind_counts.get('oob_seek'):
            guidance.append("- oob_read/oob_seek: attempted to read/seek past end. Prefer fixing size_bits/length_of or variant selection so fields don't exceed the packet; avoid making containers larger than frame.")
        if kind_counts.get('node_error') or kind_counts.get('unknown'):
            guidance.append('- node_error/unknown: often caused by invalid bit_start/size_bits formulas (e.g., referencing missing node.attr). Prefer rewriting formulas to reference earlier nodes on the path, and keep arithmetic simple and monotonic.')
        if guidance:
            max_guidance = int(os.getenv('STEP2_TRAFFIC_GUIDANCE_LINES', '4'))
            lines.append('guidance:')
            lines.extend(guidance[:max(1, max_guidance)])
        lines.append(f'failures (up to {max_failures}):')
        for f in ordered_failures:
            nid = getattr(f, 'node_id', None)
            label = _node_label(nid)
            name_part = f' name="{label}"' if label else ''
            node_type = ''
            node_obj = node_lookup.get(nid) or node_lookup.get(str(nid), {})
            if node_obj:
                node_type_val = node_obj.get('node_type')
                if node_type_val:
                    node_type = f' type={node_type_val}'
            lines.append(f"- pkt#{getattr(f, 'packet_index', '?')} node={nid}{name_part}{node_type} kind={getattr(f, 'failure_kind', 'unknown')}")
            failure_kind = (getattr(f, 'failure_kind', '') or '').lower()
            if failure_kind == 'length_mismatch':
                src = getattr(f, 'length_mismatch_src', None) or getattr(f, 'length_src_node_id', None)
                dst = getattr(f, 'length_mismatch_dst', None) or nid
                lines.append(f'''  edge: {src}->{dst} formula="{getattr(f, 'length_formula', None)}" expected={getattr(f, 'length_expected_bits', None)} actual={getattr(f, 'length_actual_bits', None)}''')
            elif failure_kind == 'coverage_gap':
                src = getattr(f, 'length_mismatch_src', None) or getattr(f, 'length_src_node_id', None)
                dst = getattr(f, 'length_mismatch_dst', None) or nid
                lines.append(f"  edge: {src}->{dst} gap_bits={getattr(f, 'length_gap_bits', None)} content={getattr(f, 'length_content_bits', None)} wire={getattr(f, 'length_wire_bits', None)} expected={getattr(f, 'length_expected_bits', None)}")
            elif failure_kind == 'routing':
                selector_id = getattr(f, 'routing_selector_id', None)
                cands = getattr(f, 'routing_candidate_variant_ids', None)
                if selector_id is not None or cands:
                    lines.append(f'  routing: selector={selector_id} candidates={cands}')
                verrs = getattr(f, 'routing_variant_errors', None) or []
                if verrs:
                    try:
                        counts = Counter((d.get('error_type') or 'unknown' for d in verrs if isinstance(d, dict)))
                        lines.append(f'  variant_errors_summary: {dict(counts)}')
                    except Exception:
                        pass
                    max_show = max(1, int(os.getenv('STEP2_TRAFFIC_ROUTING_VARIANT_ERRORS_IN_PROMPT', '3')))
                    for d in verrs[:max_show]:
                        if not isinstance(d, dict):
                            continue
                        var_id = d.get('variant_id')
                        var_name = d.get('variant_name') or _node_label(var_id) if var_id is not None else None
                        var_txt = f' var={var_id}' + (f' name="{var_name}"' if var_name else '')
                        err_type = d.get('error_type') or 'unknown'
                        err_node = d.get('node_id')
                        msg = str(d.get('message') or '')
                        msg = msg.replace('\n', ' ').strip()
                        if len(msg) > 200:
                            msg = msg[:200] + '...'
                        nested_sel = d.get('routing_selector_id')
                        nested_cands = d.get('routing_candidate_variant_ids')
                        nested = ''
                        if nested_sel is not None or nested_cands:
                            nested = f' nested_selector={nested_sel} nested_candidates={nested_cands}'
                        lines.append(f'    -{var_txt} err={err_type} node={err_node}{nested} msg="{msg}"')
            elif failure_kind == 'constraint':
                lines.append(f"  constraint: {getattr(f, 'constraint_text', None)} value={getattr(f, 'constraint_value', None)} kind={getattr(f, 'constraint_kind', None)}")
            elif getattr(f, 'message', None):
                lines.append(f"  message: {getattr(f, 'message', '')}")
            lines.append(f"  bit_start={getattr(f, 'bit_start', None)} size_bits_eval={getattr(f, 'size_bits_eval', None)} total_bits={getattr(f, 'total_bits', None)} max_bit_reached={getattr(f, 'max_bit_reached', None)}")
            if failure_kind in {'oob_seek', 'oob_read'}:
                try:
                    bs = getattr(f, 'bit_start', None)
                    sz = getattr(f, 'size_bits_eval', None)
                    tb = getattr(f, 'total_bits', None)
                    if bs is not None and sz is not None and (tb is not None):
                        bs_i = int(bs)
                        sz_i = int(sz)
                        tb_i = int(tb)
                        overshoot = bs_i + sz_i - tb_i
                        if overshoot > 0:
                            if overshoot % 8 == 0:
                                lines.append(f'  oob_overshoot_bits={overshoot} (={overshoot // 8} bytes)')
                            else:
                                lines.append(f'  oob_overshoot_bits={overshoot}')
                except Exception:
                    pass
            path_val = getattr(f, 'path_node_ids', None) or []
            if path_val:
                lines.append(f'  path: {_format_path(path_val)}')
                variable_on_path: List[Tuple[int, str]] = []
                for pid in path_val:
                    if _is_variable_leaf_without_length_binding(pid):
                        try:
                            pid_int = int(pid)
                        except Exception:
                            continue
                        variable_on_path.append((pid_int, _node_label(pid_int)))
                    if len(variable_on_path) >= 3:
                        break
                if variable_on_path:
                    lines.append(f'  variable_leaves_without_length_of_on_path: {variable_on_path}')
            ctx_vals = getattr(f, 'context_field_values', None) or {}
            if ctx_vals:
                lines.append(f'  ctx_fields: {_format_ctx_fields(ctx_vals)}')
            cand_exprs: List[str] = []
            if self._size_bits_candidates:
                candidates = self._size_bits_candidates.get(nid) or self._size_bits_candidates.get(str(nid)) or []
                for cand in candidates:
                    expr = getattr(cand, 'expression', None) if hasattr(cand, 'expression') else None
                    if expr is None and isinstance(cand, str):
                        expr = cand
                    if expr:
                        cand_exprs.append(str(expr))
            if cand_exprs:
                lines.append(f'  size_bits_candidates(node {nid}): {cand_exprs}')
            fill_exprs: List[str] = []
            if self._payload_fill_candidates:
                fills = self._payload_fill_candidates.get(nid) or self._payload_fill_candidates.get(str(nid)) or []
                for cand in fills:
                    size_expr = getattr(cand, 'size_bits_expr', None)
                    gap_bits = getattr(cand, 'gap_bits', None)
                    bit_start_expr = getattr(cand, 'bit_start_expr', None)
                    parent_id = getattr(cand, 'parent_id', None)
                    fill_exprs.append(f'parent_id={parent_id} size_bits={size_expr} gap_bits={gap_bits} bit_start={bit_start_expr}')
            if fill_exprs:
                lines.append(f'  payload_fill_candidates(node {nid}): {fill_exprs}')
        failure_block = '\n'.join(lines)
        if base_feedback:
            return f'{base_feedback}\n\n{failure_block}'
        return failure_block

def add_attention_markers(sections: Sequence[Dict[str, Any]], batch_start: int, batch_size: int) -> List[Dict[str, Any]]:
    marked_sections: List[Dict[str, Any]] = []
    focus_end = batch_start + batch_size
    for index, section in enumerate(sections):
        section_copy = copy.deepcopy(section)
        content = section_copy.get('content', '')
        if batch_start <= index < focus_end:
            section_copy['content'] = f'<attention priority="high">\n{content}\n</attention>'
            section_copy['is_focused'] = True
        else:
            section_copy['content'] = content
            section_copy['is_focused'] = False
        marked_sections.append(section_copy)
    return marked_sections

def _normalize_formula_text(value: Any) -> Any:
    if isinstance(value, str):
        normalized = value.replace('||', ' or ').replace('&&', ' and ')
        return normalized
    return value

def _normalize_patch_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_patch_value(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_normalize_patch_value(item) for item in value]
    return _normalize_formula_text(value)

def _normalize_node_fields(node: Dict[str, Any]) -> None:
    if not isinstance(node, dict):
        return
    if 'constraints' in node and isinstance(node['constraints'], list):
        node['constraints'] = [_normalize_formula_text(item) for item in node['constraints']]
    if 'bit_start' in node:
        node['bit_start'] = _normalize_formula_text(node['bit_start'])
    if 'size_bits' in node:
        node['size_bits'] = _normalize_formula_text(node['size_bits'])

def _lookup_node(node_index: Dict[str, Dict[str, Any]], tree: Dict[str, Any], node_id: Any) -> Optional[Dict[str, Any]]:
    if node_id is None:
        return None
    key = str(node_id)
    node = node_index.get(key)
    if node is not None:
        return node
    for candidate in tree.get('nodes', []) or []:
        if not isinstance(candidate, dict):
            continue
        if str(candidate.get('node_id')) == key:
            node_index[key] = candidate
            return candidate
    return None

def _ensure_child_reference(parent: Dict[str, Any], child_id: Any) -> None:
    if parent is None or child_id is None:
        return
    children = parent.get('children_ids')
    if not isinstance(children, list):
        children = []
        parent['children_ids'] = children
    if child_id not in children:
        children.append(child_id)

def _remove_child_reference(parent: Optional[Dict[str, Any]], child_id: Any) -> None:
    if not parent or child_id is None:
        return
    children = parent.get('children_ids')
    if not isinstance(children, list):
        return
    try:
        while child_id in children:
            children.remove(child_id)
    except ValueError:
        pass

def _reassign_parent(node_index: Dict[str, Dict[str, Any]], tree: Dict[str, Any], child_id: Any, old_parent_id: Any, new_parent_id: Any) -> None:
    if old_parent_id == new_parent_id:
        return
    reparent_node(tree, child_id, new_parent_id)

def _sync_children_parent_links(node_index: Dict[str, Dict[str, Any]], tree: Dict[str, Any], parent_node: Dict[str, Any]) -> None:
    if not parent_node:
        return
    parent_id = parent_node.get('node_id')
    if parent_id is None:
        return
    children = parent_node.get('children_ids')
    if not isinstance(children, list):
        parent_node['children_ids'] = []
        children = parent_node['children_ids']
    desired = {str(child_id) for child_id in children if child_id is not None}
    for node in tree.get('nodes', []) or []:
        if not isinstance(node, dict):
            continue
        if str(node.get('parent_id')) == str(parent_id) and str(node.get('node_id')) not in desired:
            node['parent_id'] = None
    for child_id in children:
        child = _lookup_node(node_index, tree, child_id)
        if child is not None:
            child['parent_id'] = parent_id

def _node_lookup(tree: Dict[str, Any]) -> Dict[Any, Dict[str, Any]]:
    lookup: Dict[Any, Dict[str, Any]] = {}
    for node in tree.get('nodes', []) or []:
        if not isinstance(node, dict):
            continue
        nid = node.get('node_id')
        if nid is None:
            continue
        lookup[nid] = node
        lookup[str(nid)] = node
    return lookup

def _is_aggregator_node(node: Optional[Dict[str, Any]], lookup: Dict[Any, Dict[str, Any]]) -> bool:
    if not node:
        return False
    ntype = str(node.get('node_type', '') or '').lower()
    if ntype in {'protocol', 'message'}:
        return True
    children = node.get('children_ids') or []
    for cid in children:
        child = lookup.get(cid) or lookup.get(str(cid))
        if child and str(child.get('node_type', '')).lower() == 'variant':
            return True
    return False

def _is_protected_node(tree: Dict[str, Any], node_id: Any) -> bool:
    lookup = _node_lookup(tree)
    node = lookup.get(node_id) or lookup.get(str(node_id))
    root_id = tree.get('root_node_id')
    if root_id is not None and (node_id == root_id or str(node_id) == str(root_id)):
        return True
    return _is_aggregator_node(node, lookup)

def _is_payload_fill_patch(patch: Dict[str, Any]) -> bool:
    try:
        meta = patch.get('patch_metadata') or {}
        intent = str(meta.get('intent') or meta.get('description') or '').strip().lower()
    except Exception:
        intent = ''
    if intent != 'traffic_payload_fill':
        return False
    new_nodes = patch.get('new_nodes') or []
    if not isinstance(new_nodes, list) or not new_nodes:
        return False
    if patch.get('nodes_to_remove') or patch.get('edge_removes') or patch.get('edge_updates') or patch.get('new_edges') or patch.get('node_updates'):
        return False
    for node in new_nodes:
        if not isinstance(node, dict):
            return False
        if str(node.get('node_type', '')).lower() != 'field':
            return False
        dtype = str(node.get('data_type', '') or '').lower()
        if 'byte' not in dtype:
            return False
        parent_id = node.get('parent_id')
        if parent_id is None:
            return False
        for expr_key in ('bit_start', 'size_bits'):
            expr = node.get(expr_key)
            if not isinstance(expr, str):
                continue
            lowered = expr.lower()
            if 'max(' in lowered or 'min(' in lowered:
                return False
            try:
                if re.search(f'\\b{re.escape(str(parent_id))}\\.size_bits\\b', expr):
                    return False
            except Exception:
                return False
    return True

def _strip_payload_fill_child_link_updates(tree: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(patch, dict):
        return patch
    meta = patch.get('patch_metadata') or {}
    intent = str(meta.get('intent') or '').strip().lower() if isinstance(meta, dict) else ''
    if intent != 'traffic_payload_fill':
        return patch
    new_nodes = patch.get('new_nodes') or []
    if not isinstance(new_nodes, list) or not new_nodes:
        return patch
    node_updates = patch.get('node_updates') or []
    if not isinstance(node_updates, list) or not node_updates:
        return patch
    for key in ('new_edges', 'edge_updates', 'edge_removes', 'nodes_to_remove'):
        if patch.get(key):
            return patch
    new_ids_by_parent: Dict[str, List[str]] = {}
    for node in new_nodes:
        if not isinstance(node, dict):
            return patch
        node_id = node.get('node_id')
        parent_id = node.get('parent_id')
        if node_id is None or parent_id is None:
            return patch
        new_ids_by_parent.setdefault(str(parent_id), []).append(str(node_id))
    lookup = _node_lookup(tree)

    def _as_id_list(value: Any) -> Optional[List[str]]:
        if not isinstance(value, list):
            return None
        return [str(item) for item in value if item is not None]
    for update in node_updates:
        if not isinstance(update, dict):
            return patch
        if update.get('property') != 'children_ids':
            return patch
        if 'node_id' not in update or 'value' not in update:
            return patch
        parent_id = str(update.get('node_id'))
        expected_new = new_ids_by_parent.get(parent_id) or []
        if not expected_new:
            return patch
        parent = lookup.get(parent_id)
        if not isinstance(parent, dict):
            return patch
        old_children = _as_id_list(parent.get('children_ids') or []) or []
        new_children = _as_id_list(update.get('value'))
        if new_children is None:
            return patch
        if new_children[:len(old_children)] != old_children:
            return patch
        appended = new_children[len(old_children):]
        if len(appended) != len(expected_new) or set(appended) != set(expected_new):
            return patch
    sanitized = copy.deepcopy(patch)
    sanitized['node_updates'] = []
    return sanitized

def _is_structural_traffic_patch(patch: Dict[str, Any], tree: Dict[str, Any]) -> bool:
    if _is_payload_fill_patch(patch):
        return False
    allow_struct = os.getenv('STEP2_TRAFFIC_ALLOW_STRUCT', '0').lower() in {'1', 'true', 'yes'}
    if not isinstance(patch, dict):
        return True
    if not allow_struct and (patch.get('new_nodes') or patch.get('nodes_to_remove')):
        return True
    allowed_node_props = {'size_bits', 'bit_start', 'constraints', 'message_type', 'data_type', 'needs_length_binding'}
    for upd in patch.get('node_updates', []) or []:
        nid = upd.get('node_id')
        if _is_protected_node(tree, nid) and (not allow_struct):
            return True
        prop = upd.get('property') or upd.get('field')
        updates_block = upd.get('updates') if isinstance(upd, dict) else None
        props_to_check = set()
        if prop:
            props_to_check.add(prop)
        if isinstance(updates_block, dict):
            props_to_check.update(updates_block.keys())
        if not props_to_check:
            continue
        if not props_to_check.issubset(allowed_node_props):
            return True
        if not allow_struct and ('parent_id' in props_to_check or 'children_ids' in props_to_check):
            return True
    allowed_rels = {'length_of', 'condition_on', 'depends_on'}
    for edge in patch.get('new_edges', []) or []:
        if edge.get('rel') not in allowed_rels:
            return True
        dst = edge.get('dst')
        if _is_protected_node(tree, dst) and (not allow_struct):
            return True
    for edge in patch.get('edge_updates', []) or []:
        rel = None
        ident = edge.get('edge_identifier') or {}
        rel = ident.get('rel') or edge.get('rel')
        if rel and rel not in allowed_rels:
            return True
    for edge in patch.get('edge_removes', []) or []:
        if edge.get('rel') not in allowed_rels and (not allow_struct):
            return True
    return False

def reparent_node(tree: Dict[str, Any], child_id: Any, new_parent_id: Optional[Any]) -> None:
    node_index = {str(node.get('node_id')): node for node in tree.get('nodes', []) or [] if isinstance(node, dict) and node.get('node_id') is not None}
    child = _lookup_node(node_index, tree, child_id)
    if child is None:
        return
    old_parent_id = child.get('parent_id')
    if str(old_parent_id) == str(new_parent_id):
        return
    _remove_child_reference(_lookup_node(node_index, tree, old_parent_id), child_id)
    child['parent_id'] = new_parent_id
    new_parent = _lookup_node(node_index, tree, new_parent_id)
    _ensure_child_reference(new_parent, child_id)

def remove_node(tree: Dict[str, Any], node_id: Any) -> None:
    node_list = tree.get('nodes', [])
    if not isinstance(node_list, list):
        return
    node_index = {str(node.get('node_id')): node for node in node_list if isinstance(node, dict) and node.get('node_id') is not None}
    target = _lookup_node(node_index, tree, node_id)
    if target is None:
        return
    target_id_str = str(target.get('node_id'))
    parent = _lookup_node(node_index, tree, target.get('parent_id'))
    _remove_child_reference(parent, target.get('node_id'))
    for child in list(node_list):
        if not isinstance(child, dict):
            continue
        if str(child.get('parent_id')) == target_id_str:
            child['parent_id'] = None
    tree['nodes'] = [n for n in node_list if not isinstance(n, dict) or str(n.get('node_id')) != target_id_str]
    edges = tree.get('edges', [])
    if isinstance(edges, list):
        tree['edges'] = [e for e in edges if not isinstance(e, dict) or (str(e.get('src')) != target_id_str and str(e.get('dst')) != target_id_str)]

def apply_patch(tree: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    patched_tree = copy.deepcopy(tree)
    if not isinstance(patch, dict):
        return patched_tree
    strict_apply = os.getenv('STEP2_STRICT_APPLY_PATCH', '0').lower() in {'1', 'true', 'yes', 'on'}
    nodes_list = patched_tree.get('nodes')
    if not isinstance(nodes_list, list):
        nodes_list = []
        patched_tree['nodes'] = nodes_list
    node_index = {str(node.get('node_id')): node for node in nodes_list if isinstance(node, dict) and node.get('node_id') is not None}
    removed_nodes_raw = patch.get('nodes_to_remove', []) or []
    if removed_nodes_raw:
        removed_ids = []
        for entry in removed_nodes_raw:
            node_id = entry.get('node_id') if isinstance(entry, dict) else entry
            if node_id is None:
                continue
            removed_ids.append(str(node_id))
        if removed_ids:
            removed_set = set(removed_ids)
            logger.debug('Removing nodes via nodes_to_remove: %s', sorted(removed_set))
            for rid in removed_ids:
                remove_node(patched_tree, rid)
            node_index = {str(node.get('node_id')): node for node in patched_tree.get('nodes', []) or [] if isinstance(node, dict) and node.get('node_id') is not None}
    pending_links: List[Tuple[Any, Any]] = []
    new_nodes_raw = patch.get('new_nodes') or []
    if not isinstance(new_nodes_raw, list):
        new_nodes_raw = []
    for new_node in new_nodes_raw:
        if not isinstance(new_node, dict):
            continue
        node_id_value = new_node.get('node_id')
        if node_id_value is None:
            continue
        node_id = str(node_id_value)
        if node_id not in node_index:
            normalized_node = copy.deepcopy(new_node)
            _normalize_node_fields(normalized_node)
            patched_tree.setdefault('nodes', []).append(normalized_node)
            node_index[node_id] = normalized_node
            logger.debug('Added new node: %s (ID: %s)', new_node.get('name'), node_id)
            parent_id = normalized_node.get('parent_id')
            if parent_id is not None:
                parent = _lookup_node(node_index, patched_tree, parent_id)
                if parent is not None:
                    _ensure_child_reference(parent, normalized_node.get('node_id'))
                    logger.debug('Linked new node %s to parent %s.children_ids', node_id, str(parent.get('node_id')))
                else:
                    pending_links.append((parent_id, normalized_node.get('node_id')))
        else:
            logger.debug('Node %s already exists, skipping', node_id)
    for parent_id, child_id in pending_links:
        parent = _lookup_node(node_index, patched_tree, parent_id)
        child = _lookup_node(node_index, patched_tree, child_id)
        if parent is None or child is None:
            continue
        _ensure_child_reference(parent, child_id)
        logger.debug('Deferred link: new node %s attached to parent %s.children_ids', str(child_id), str(parent.get('node_id')))
    node_updates_raw = patch.get('node_updates') or []
    if not isinstance(node_updates_raw, list):
        node_updates_raw = []
    for update in node_updates_raw:
        if not isinstance(update, dict):
            continue
        node_id_value = update.get('node_id')
        if node_id_value is None:
            continue
        node_id = str(node_id_value)
        node = node_index.get(node_id)
        if not node:
            placeholder: Dict[str, Any] = {'node_id': int(node_id) if str(node_id).isdigit() else node_id}
            patched_tree.setdefault('nodes', []).append(placeholder)
            node_index[node_id] = placeholder
            node = placeholder
        update_type = update.get('update_type', 'single_field')
        if 'field' in update and 'new_value' in update:
            field = update['field']
            old_parent_id = node.get('parent_id')
            old_value = node.get(field)
            node[field] = _normalize_formula_text(update['new_value'])
            if field == 'parent_id':
                _reassign_parent(node_index, patched_tree, node.get('node_id'), old_parent_id, node.get('parent_id'))
            logger.debug('Updated node %s.%s: %s -> %s (%s)', node_id, field, old_value, update['new_value'], update.get('reason', 'no reason'))
            continue
        if 'property' in update and 'value' in update:
            prop = update.get('property')
            new_value = _normalize_patch_value(update.get('value'))
            old_parent_id = node.get('parent_id')
            old_value = node.get(prop)
            node[prop] = new_value
            if prop == 'parent_id':
                _reassign_parent(node_index, patched_tree, node.get('node_id'), old_parent_id, node.get('parent_id'))
            if prop == 'children_ids':
                _sync_children_parent_links(node_index, patched_tree, node)
            logger.debug('Updated node %s.%s via property/value: %s -> %s (%s)', node_id, prop, old_value, new_value, update.get('reason', 'no reason'))
            continue
        if 'changes' in update:
            changes = update['changes']
            updated_fields: List[str] = []
            for field_name, change_info in changes.items():
                old_parent_id = node.get('parent_id')
                if isinstance(change_info, dict) and 'new_value' in change_info:
                    old_value = node.get(field_name)
                    node[field_name] = _normalize_formula_text(change_info['new_value'])
                    updated_fields.append(f"{field_name}: {old_value} -> {change_info['new_value']}")
                else:
                    old_value = node.get(field_name)
                    node[field_name] = _normalize_formula_text(change_info)
                    updated_fields.append(f'{field_name}: {old_value} -> {change_info}')
                if field_name == 'parent_id':
                    _reassign_parent(node_index, patched_tree, node.get('node_id'), old_parent_id, node.get('parent_id'))
                if field_name == 'children_ids':
                    _sync_children_parent_links(node_index, patched_tree, node)
            logger.debug('Updated node %s (%s): %s (%s)', node_id, update_type, ', '.join(updated_fields), update.get('reason', 'no reason'))
            continue
        if 'updates' in update and isinstance(update['updates'], dict):
            updates_block = update['updates']
            updated_fields: List[str] = []
            for field_name, new_value in updates_block.items():
                normalized_value = _normalize_patch_value(new_value)
                old_parent_id = node.get('parent_id')
                old_value = node.get(field_name)
                node[field_name] = normalized_value
                updated_fields.append(f'{field_name}: {old_value} -> {normalized_value}')
                if field_name == 'parent_id':
                    _reassign_parent(node_index, patched_tree, node.get('node_id'), old_parent_id, node.get('parent_id'))
                if field_name == 'children_ids':
                    _sync_children_parent_links(node_index, patched_tree, node)
            logger.debug('Updated node %s (%s updates): %s', node_id, update_type, ', '.join(updated_fields))
            continue
        direct_updates = {key: value for key, value in update.items() if key not in {'node_id', 'update_type', 'reason', 'field', 'new_value', 'changes', 'updates', 'property', 'value'}}
        if direct_updates:
            updated_fields: List[str] = []
            for field_name, new_value in direct_updates.items():
                normalized_value = _normalize_patch_value(new_value)
                old_parent_id = node.get('parent_id')
                old_value = node.get(field_name)
                node[field_name] = normalized_value
                updated_fields.append(f'{field_name}: {old_value} -> {normalized_value}')
                if field_name == 'parent_id':
                    _reassign_parent(node_index, patched_tree, node.get('node_id'), old_parent_id, node.get('parent_id'))
                if field_name == 'children_ids':
                    _sync_children_parent_links(node_index, patched_tree, node)
            logger.debug('Updated node %s (%s direct fields): %s', node_id, update_type, ', '.join(updated_fields))
            continue
        logger.debug('Invalid update format for node %s', node_id)
    edges_list = patched_tree.get('edges')
    if not isinstance(edges_list, list):
        edges_list = []
        patched_tree['edges'] = edges_list
    for removal in patch.get('edge_removes', []) or []:
        if not isinstance(removal, dict):
            continue
        src = removal.get('src')
        dst = removal.get('dst')
        rel = removal.get('rel')
        if src is None or dst is None or (not rel):
            logger.debug('edge_removes entry missing src/dst/rel: %s', removal)
            continue
        message_type = removal.get('message_type')
        formula = removal.get('formula')
        src_str, dst_str = (str(src), str(dst))
        if rel == 'condition_on' and formula is None and strict_apply:
            logger.debug('edge_removes condition_on requires formula; skipping: %s', removal)
            continue
        removed_count = 0
        for index in range(len(edges_list) - 1, -1, -1):
            edge = edges_list[index]
            if str(edge.get('src')) != src_str or str(edge.get('dst')) != dst_str or edge.get('rel') != rel:
                continue
            if message_type is not None and edge.get('message_type') != message_type:
                continue
            if rel == 'condition_on':
                if formula is not None and edge.get('formula') != formula:
                    continue
            elif formula is not None and edge.get('formula') != formula:
                continue
            removed_edge = edges_list.pop(index)
            removed_count += 1
            logger.debug('Removed edge via edge_removes: %s -> %s (%s)%s%s', src_str, dst_str, rel, f", message_type={removed_edge.get('message_type')}" if removed_edge.get('message_type') else '', f", formula={removed_edge.get('formula')}" if removed_edge.get('formula') else '')
        if removed_count == 0:
            logger.debug('edge_removes entry did not match any edges: %s', removal)
    existing_edges = {(str(edge.get('src')), str(edge.get('dst')), edge.get('rel'), str(edge.get('formula') or ''), str(edge.get('message_type') or '')) for edge in edges_list}
    new_edges_raw = patch.get('new_edges') or []
    if not isinstance(new_edges_raw, list):
        new_edges_raw = []
    for new_edge in new_edges_raw:
        if not isinstance(new_edge, dict):
            continue
        if new_edge.get('rel') == 'length_of':
            dst = new_edge.get('dst')
            if strict_apply and _is_protected_node(patched_tree, dst):
                logger.debug('Blocking length_of targeting protected/aggregator node %s', dst)
                continue
            for idx in range(len(edges_list) - 1, -1, -1):
                edge = edges_list[idx]
                if edge.get('rel') == 'length_of' and str(edge.get('dst')) == str(dst):
                    edges_list.pop(idx)
            existing_edges = {(str(edge.get('src')), str(edge.get('dst')), edge.get('rel'), str(edge.get('formula') or ''), str(edge.get('message_type') or '')) for edge in edges_list}
        edge_key = (str(new_edge.get('src')), str(new_edge.get('dst')), new_edge.get('rel'), str(new_edge.get('formula') or ''), str(new_edge.get('message_type') or ''))
        if edge_key not in existing_edges:
            edge_copy = copy.deepcopy(new_edge)
            if 'formula' in edge_copy:
                edge_copy['formula'] = _normalize_formula_text(edge_copy['formula'])
            patched_tree.setdefault('edges', []).append(edge_copy)
            existing_edges.add(edge_key)
            if str(new_edge.get('src')) not in node_index or str(new_edge.get('dst')) not in node_index:
                logger.debug('Edge references non-existent node(s): %s -> %s (%s)', new_edge.get('src'), new_edge.get('dst'), new_edge.get('rel'))
            logger.debug('Added new edge: %s -> %s (%s)', new_edge.get('src'), new_edge.get('dst'), new_edge.get('rel'))
    edge_updates_raw = patch.get('edge_updates') or []
    if not isinstance(edge_updates_raw, list):
        edge_updates_raw = []
    for edge_update in edge_updates_raw:
        if not isinstance(edge_update, dict):
            continue
        update_type = edge_update.get('update_type', 'modify')
        edge_id = edge_update.get('edge_identifier', {})
        if not isinstance(edge_id, dict):
            edge_id = {}
        src, dst, rel = (str(edge_id.get('src', '')), str(edge_id.get('dst', '')), edge_id.get('rel', ''))
        target_formula = edge_id.get('formula')
        target_msg_type = edge_id.get('message_type')
        for index, edge in enumerate(patched_tree.get('edges', []) or []):
            if not isinstance(edge, dict):
                continue
            if str(edge.get('src')) != src or str(edge.get('dst')) != dst or edge.get('rel') != rel:
                continue
            if target_formula is not None and edge.get('formula') != target_formula:
                continue
            if target_msg_type is not None and edge.get('message_type') != target_msg_type:
                continue
            if update_type == 'remove':
                del patched_tree['edges'][index]
                logger.debug('Removed edge: %s -> %s (%s)', src, dst, rel)
            elif update_type == 'modify':
                for prop, value in edge_update.get('new_properties', {}).items():
                    old_value = edge.get(prop)
                    edge[prop] = _normalize_formula_text(value)
                    logger.debug('Updated edge %s->%s(%s).%s: %s -> %s', src, dst, rel, prop, old_value, value)
            break
        else:
            logger.debug('Edge to update not found: %s -> %s (%s)', src, dst, rel)
    return patched_tree

def _summarize_patch_for_prompt(patch: Dict[str, Any]) -> str:
    if not isinstance(patch, dict):
        return 'unavailable'
    summary_parts: List[str] = []
    metadata = patch.get('patch_metadata')
    if isinstance(metadata, dict):
        description = metadata.get('description')
        if isinstance(description, str) and description.strip():
            summary_parts.append(description.strip())
    counts: List[str] = []
    for key, label in (('new_nodes', 'new nodes'), ('node_updates', 'node updates'), ('new_edges', 'new edges'), ('edge_updates', 'edge updates'), ('nodes_to_remove', 'nodes removed')):
        items = patch.get(key)
        if isinstance(items, list) and items:
            counts.append(f'{len(items)} {label}')
    if counts:
        summary_parts.append(', '.join(counts))
    if summary_parts:
        return '; '.join(summary_parts)
    return 'without metadata'

def _is_boolean_expression(expr: str) -> bool:
    lowered = expr.lower()
    return any((token in lowered for token in ['==', '!=', ' and ', ' or ', '&&', '||', ' not ', ' xor ']))

def _is_patch_empty(patch: Dict[str, Any]) -> bool:
    if not isinstance(patch, dict):
        return False
    for key in ('new_nodes', 'node_updates', 'new_edges', 'edge_updates', 'nodes_to_remove'):
        items = patch.get(key)
        if isinstance(items, list) and items:
            return False
    return True

def _dedupe_preserve_order(items: Sequence[str]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered

def _issue_specific_templates(raw: str) -> Optional[List[str]]:
    if not raw:
        return None
    templates: List[str] = []
    m_len_ref = re.search('Graph: .*\\(ID:(?P<dst>\\d+)\\): length_of formula references \\[(?P<refs>[^\\]]+)\\] but src is (?P<src>\\d+)', raw)
    if m_len_ref:
        dst = m_len_ref.group('dst')
        src = m_len_ref.group('src')
        refs = m_len_ref.group('refs').strip()
        templates.extend([f'For node ID {dst}, rewrite the length_of edge formula or update src node id in edge array, so formula reference use the edge src {src} only (e.g., val({src})*8 if units are bytes).', f'If the intended sizing field is one of {refs}, then change the length_of edge src to that node instead of {src} to keep src and formula consistent.'])
    m_len_multi = re.search('Graph: .*\\(ID:(?P<dst>\\d+)\\): Multiple length_of bindings to node (?P=dst)', raw)
    if m_len_multi:
        dst = m_len_multi.group('dst')
        templates.extend([f'Collapse multiple length_of edges targeting node ID {dst} into a single binding.', f'If multiple sources are required, fold their formulas into one canonical length_of edge (e.g., val(a) + val(b)) instead of duplicating bindings.'])
    length_missing = re.search('Semantics: (?P<name>[\\w]+)\\(ID:(?P<id>\\d+)\\): Variable-length field lacks explicit length binding', raw)
    if length_missing:
        node_name = length_missing.group('name')
        node_id = length_missing.group('id')
        templates.extend([f'For {node_name}(ID:{node_id}), connect the governing prefix field with a length_of edge and mirror that arithmetic in size_bits (e.g., val(prefix) - payload_overhead).', f'If a prefix field already carries the size, add a length_of edge from that prefix to {node_name}(ID:{node_id}) so the dependency is explicit.', "Ensure the length_of formula and the target node's size_bits stay in sync so the validator sees a single source of truth."])
    missing_len_edge = re.search('references val\\((?P<src>\\d+)\\) but no length_of edge exists.*\\(id=(?P<dst>\\d+)\\)', raw)
    if missing_len_edge:
        src = missing_len_edge.group('src')
        dst = missing_len_edge.group('dst')
        templates.extend([f'Add a length_of edge from node ID {src} to node ID {dst} so the size_bits reference is backed by an explicit dependency.', f'Mirror the same expression (e.g., val({src})) on both the new length_of edge formula and the target size_bits to keep them aligned.'])
    parent_overflow = re.search('Layout: (?P<name>[\\w_]+)\\(ID:(?P<id>\\d+)\\): Children may exceed parent size', raw)
    if parent_overflow:
        label = parent_overflow.group('name')
        pid = parent_overflow.group('id')
        templates.extend([f"Re-evaluate {label}(ID:{pid}) children ordering: bump each child's bit_start by the previous child's size_bits and recompute the parent size_bits.", f'If a mis-parented field is causing overflow, detach it to the documented container before recalculating offsets.'])
    multiple_roots = re.search('Structure: Multiple root nodes found', raw)
    if multiple_roots:
        templates.extend(['Pick the canonical protocol root (typically MODBUS_Message/Protocol_Root) and reparent every other root beneath it, then delete the redundant root stub.', 'Confirm children_ids/parent_id fields are updated for each moved node so only one root remains.'])
    overlap = re.search('(overlap|boundary|conflict)', raw, re.IGNORECASE)
    if overlap:
        templates.extend(['Adjust bit_start expressions to advance by the exact size of the preceding node so no ranges intersect.', 'Recompute any derived size_bits formulas that still assume the old layout after shifting nodes.'])
    selector_issue = re.search('selector|variant|coverage', raw, re.IGNORECASE)
    if selector_issue:
        templates.extend(['Ensure each selector lists concrete enumerated outcomes and add condition_on edges mapping those values to variants.', 'Back-fill missing request/response variants so every documented branch is reachable.'])
    return _dedupe_preserve_order(templates) if templates else None

def _summarize_error_categories(errors: Sequence[str]) -> List[str]:
    if not errors:
        return []
    summaries: List[str] = []
    for raw in errors[:10]:
        templates = _issue_specific_templates(raw)
        if templates:
            summaries.extend(templates)
        else:
            summaries.append('Clear remaining structural violations reported by the validator before proceeding.')
    summaries = _dedupe_preserve_order(summaries)
    if len(errors) > 10:
        summaries.append('Additional validator findings remain; address them after the primary fixes above.')
    return summaries

def _summarize_coverage_hints(extras: Sequence[str]) -> List[str]:
    if not extras:
        return []
    hints: List[str] = []
    for entry in extras:
        if not isinstance(entry, str):
            continue
        lowered = entry.lower()
        if not lowered.startswith('coverage matrix'):
            continue
        if '(request)' in lowered:
            hints.append('Exercise additional request-side selector outcomes to satisfy coverage matrices.')
        elif '(response)' in lowered:
            hints.append('Exercise additional response-side selector outcomes to satisfy coverage matrices.')
        else:
            hints.append('Improve selector coverage across message flows so every branch receives an example.')
    return _dedupe_preserve_order(hints)

def _derive_structure_hints(tree: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(tree, dict):
        return []
    try:
        normalized = normalize_protocol_tree(copy.deepcopy(tree))
    except Exception:
        normalized = tree
    protocol_tree = normalized if isinstance(normalized, dict) and 'nodes' in normalized else normalized.get('protocol_tree', {})
    if not isinstance(protocol_tree, dict):
        return []
    nodes = protocol_tree.get('nodes') or []
    edges = protocol_tree.get('edges') or []
    if not isinstance(nodes, list):
        return []
    node_by_id: Dict[int, Dict[str, Any]] = {}
    for node in nodes:
        if isinstance(node, dict):
            node_id = node.get('node_id')
            if isinstance(node_id, int):
                node_by_id[node_id] = node
    length_bound_targets: Set[int] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if edge.get('rel') == 'length_of':
            dst_id = edge.get('dst')
            if isinstance(dst_id, int):
                length_bound_targets.add(dst_id)
    unbound_variable_nodes: Set[int] = set()
    bound_variable_nodes: Set[int] = set()
    for node_id, node in node_by_id.items():
        size_bits = node.get('size_bits')
        if isinstance(size_bits, str) and size_bits.strip().lower() == 'variable':
            if node_id in length_bound_targets:
                bound_variable_nodes.add(node_id)
            else:
                unbound_variable_nodes.add(node_id)
    hints: List[str] = []
    if unbound_variable_nodes:
        hints.append('Attach explicit length_of bindings from prefix/count fields to each variable-sized segment.')
    if bound_variable_nodes:
        hints.append("Replace placeholder 'variable' size_bits with explicit formulas tied to their controlling length fields.")
    unresolved_offset_refs = False
    if unbound_variable_nodes:
        pattern = re.compile('(\\d+)\\.size_bits')
        for node in nodes:
            if not isinstance(node, dict):
                continue
            bit_start = node.get('bit_start')
            if not isinstance(bit_start, str):
                continue
            for candidate in pattern.findall(bit_start):
                try:
                    ref_id = int(candidate)
                except ValueError:
                    continue
                if ref_id in unbound_variable_nodes:
                    unresolved_offset_refs = True
                    break
            if unresolved_offset_refs:
                break
    if unresolved_offset_refs:
        hints.append('Revisit bit_start expressions that rely on unresolved variable-sized siblings to keep offsets deterministic.')
    return _dedupe_preserve_order(hints)

def _build_patch_feedback(errors: List[str], extras: List[str], tree: Optional[Dict[str, Any]]=None) -> Optional[str]:
    error_hints = _summarize_error_categories(errors)
    coverage_hints: List[str] = []
    structure_hints = [] if _strict_validator_loop_enabled() else _derive_structure_hints(tree)
    segments: List[str] = []
    if error_hints:
        segments.append('Address outstanding validator findings:')
        segments.extend((f'- {hint}' for hint in error_hints))
    if coverage_hints:
        if segments:
            segments.append('')
        segments.append('Coverage improvements to target:')
        segments.extend((f'- {hint}' for hint in coverage_hints))
    if structure_hints:
        if segments:
            segments.append('')
        segments.append('Structural refinement opportunities:')
        segments.extend((f'- {hint}' for hint in structure_hints))
    if not segments:
        return None
    return '\n'.join(segments)

def validate_patch_consistency(tree: Dict[str, Any], patch: Dict[str, Any]) -> bool:
    strict = os.getenv('STEP2_STRICT_PATCH_CONSISTENCY', '0').lower() in {'1', 'true', 'yes', 'on'}
    if not isinstance(patch, dict):
        logger.warning('Patch is not a dict; skipping consistency check')
        return True
    if 'protocol_tree' in patch:
        logger.warning('Patch contains entire protocol_tree; skipping consistency check')
        return True
    required_fields = {'node_id', 'name', 'node_type'}
    has_failure = False
    new_nodes = patch.get('new_nodes') or []
    if not isinstance(new_nodes, list):
        new_nodes = []
    for idx, new_node in enumerate(new_nodes):
        if not isinstance(new_node, dict):
            logger.warning('new_nodes[%s] is not an object', idx)
            has_failure = True
            continue
        missing = required_fields - new_node.keys()
        if missing:
            logger.warning('new_nodes[%s] missing required fields: %s', idx, ', '.join(missing))
            has_failure = True
            if strict:
                return False
        bit_start = new_node.get('bit_start')
        if bit_start and (not _validate_position_expression(bit_start, new_node.get('parent_id'))):
            logger.warning('new_nodes[%s] has invalid bit_start expression: %s', idx, bit_start)
            has_failure = True
            if strict:
                return False
        size_bits = new_node.get('size_bits')
        if isinstance(size_bits, str) and _is_boolean_expression(size_bits):
            logger.warning('new_nodes[%s] has non-numeric size_bits expression: %s', idx, size_bits)
            has_failure = True
            if strict:
                return False
    existing_nodes = {str(node.get('node_id')): node for node in tree.get('nodes', []) or [] if isinstance(node, dict) and node.get('node_id') is not None}
    node_updates = patch.get('node_updates') or []
    if not isinstance(node_updates, list):
        node_updates = []
    for idx, update in enumerate(node_updates):
        if not isinstance(update, dict):
            logger.warning('node_updates[%s] is not an object', idx)
            has_failure = True
            if strict:
                return False
            continue
        node_id = str(update.get('node_id'))
        target = existing_nodes.get(node_id)
        if not target:
            logger.warning('node_updates[%s] references non-existent node ID: %s', idx, node_id)
            has_failure = True
            if strict:
                return False
        if 'field' in update and update['field'] == 'bit_start':
            new_value = update.get('new_value')
            if new_value and (not _validate_position_expression(new_value, target.get('parent_id'))):
                logger.warning('node_updates[%s] invalid bit_start expression: %s', idx, new_value)
                has_failure = True
                if strict:
                    return False
        if 'field' in update and update['field'] == 'size_bits':
            new_value = update.get('new_value')
            if isinstance(new_value, str) and _is_boolean_expression(new_value):
                logger.warning('node_updates[%s] invalid size_bits expression: %s', idx, new_value)
                has_failure = True
                if strict:
                    return False
        for field_name, change_info in update.get('changes', {}).items():
            if field_name == 'bit_start':
                new_value = change_info.get('new_value') if isinstance(change_info, dict) else change_info
                if new_value and (not _validate_position_expression(new_value, target.get('parent_id'))):
                    logger.warning('node_updates[%s].changes invalid bit_start expression: %s', idx, new_value)
                    has_failure = True
                    if strict:
                        return False
            if field_name == 'size_bits':
                new_value = change_info.get('new_value') if isinstance(change_info, dict) else change_info
                if isinstance(new_value, str) and _is_boolean_expression(new_value):
                    logger.warning('node_updates[%s].changes invalid size_bits expression: %s', idx, new_value)
                    has_failure = True
                    if strict:
                        return False
    nodes_to_remove = patch.get('nodes_to_remove') or []
    if not isinstance(nodes_to_remove, list):
        nodes_to_remove = []
    for idx, node_id in enumerate(nodes_to_remove):
        node_id_str = str(node_id.get('node_id') if isinstance(node_id, dict) else node_id)
        if node_id_str not in existing_nodes:
            logger.warning('nodes_to_remove[%s] references non-existent node ID: %s', idx, node_id)
            has_failure = True
            if strict:
                return False
    return not has_failure if strict else True

def _validate_position_expression(bit_start_expr: Any, parent_id: Optional[Any]) -> bool:
    if isinstance(bit_start_expr, int):
        return bit_start_expr >= 0
    if isinstance(bit_start_expr, str):
        import re
        expr = bit_start_expr.strip()
        if expr.isdigit():
            return int(expr) >= 0
        allowed_pattern = re.compile('^(?:\\d+\\.bit_start|val\\(\\d+\\))(?:\\s*[+\\-]\\s*(?:\\d+|\\d+\\.size_bits|val\\(\\d+\\)))*$')
        if allowed_pattern.match(expr):
            return True
        logger.warning('Unsupported bit_start expression: %s (parent: %s)', bit_start_expr, parent_id)
        return False
    return False

def run_full_validation(tree: Dict[str, Any]) -> ValidationReport:
    if _validator_disabled():
        return ValidationReport(ok=True, errors=[], warnings=[], extras=[], issues={})
    normalized = normalize_protocol_tree(copy.deepcopy(tree))
    try:
        serialized = json.dumps(normalized, ensure_ascii=False)
    except TypeError:
        serialized = json.dumps({'protocol_tree': normalized}, ensure_ascii=False)
    report = validate_protocol_tree(serialized)
    self_edge_errors: List[str] = []
    protocol_tree = normalized if 'nodes' in normalized else normalized.get('protocol_tree', {})
    edges = protocol_tree.get('edges', []) if isinstance(protocol_tree, dict) else []
    for edge in edges or []:
        if not isinstance(edge, dict):
            continue
        src = edge.get('src')
        dst = edge.get('dst')
        rel = edge.get('rel')
        if src is None or dst is None:
            continue
        if str(src) == str(dst):
            self_edge_errors.append(f'Edge {src}->{dst} ({rel}) is self-referential; selectors/relationships must target distinct nodes.')
    if not self_edge_errors:
        return ValidationReport(ok=report.ok, errors=list(report.errors), warnings=list(getattr(report, 'warnings', [])), extras=list(report.extras), issues=_filter_error_issues(report.issues), traffic_failures=list(getattr(report, 'traffic_failures', [])), traffic_repair_hints=list(getattr(report, 'traffic_repair_hints', []) or []))
    errors = list(report.errors) + self_edge_errors
    warnings = list(getattr(report, 'warnings', []))
    issues = _filter_error_issues(report.issues)
    issue_offset = len(issues)
    for idx, message in enumerate(self_edge_errors):
        issue_id = f'self_edge_{idx + issue_offset}'
        issues[issue_id] = Issue(id=issue_id, type=IssueType.STRUCTURE, severity=Severity.ERROR, description=message)
    return ValidationReport(ok=False, errors=errors, warnings=warnings, extras=report.extras, issues=issues, traffic_failures=list(getattr(report, 'traffic_failures', [])), traffic_repair_hints=list(getattr(report, 'traffic_repair_hints', []) or []))

def sequential_refine_tree(agent: 'EnhancedPureAIAgent', initial_tree: Dict[str, Any], sections: Sequence[Dict[str, Any]], raw_sections: Optional[Sequence[Dict[str, Any]]]=None, *, max_section_attempts: int=3) -> Dict[str, Any]:
    tree = normalize_protocol_tree(copy.deepcopy(initial_tree) if isinstance(initial_tree, dict) else initial_tree)
    enriched_sections = [copy.deepcopy(s) for s in sections or []]
    num_sections = len(enriched_sections)
    current_report = run_full_validation(tree)
    feedback = _build_patch_feedback(current_report.errors, current_report.extras, tree)
    audit_records: List[Dict[str, Any]] = []
    for idx, section in enumerate(enriched_sections):
        section_label = section.get('number') or section.get('title') or f'section_{idx}'
        log_prefix = f'Section {idx + 1}/{num_sections} ({section_label})'
        logger.info('%s: starting sequential refinement', log_prefix)
        baseline_issue_count = len(current_report.issues)
        baseline_ok = current_report.ok
        best_issue_count = baseline_issue_count
        best_ok = baseline_ok
        best_tree: Optional[Dict[str, Any]] = None
        best_report: Optional[ValidationReport] = None
        best_patch: Optional[Dict[str, Any]] = None
        best_summary: Optional[str] = None
        attempts_made = 0
        reused_cache = False
        cache_filename = f'sequential_section_{idx:03d}.json'
        cached_payload = agent._load_from_cache(cache_filename)
        if isinstance(cached_payload, dict):
            cached_patch = cached_payload.get('patch')
            if isinstance(cached_patch, dict) and (not _is_noop_patch(cached_patch)):
                candidate_tree = normalize_protocol_tree(apply_patch(tree, cached_patch))
                candidate_report = run_full_validation(candidate_tree)
                issue_count = len(candidate_report.issues)
                candidate_ok = candidate_report.ok
                better = False
                if issue_count < best_issue_count:
                    better = True
                elif issue_count == best_issue_count:
                    if candidate_ok and (not best_ok):
                        better = True
                    elif candidate_ok == best_ok:
                        better = True
                if better:
                    best_tree = candidate_tree
                    best_report = candidate_report
                    best_patch = cached_patch
                    best_summary = cached_payload.get('summary')
                    best_issue_count = issue_count
                    best_ok = candidate_ok
                    reused_cache = True
                    logger.info('%s: reused cached patch (issues %s -> %s)', log_prefix, baseline_issue_count, best_issue_count)
        supplier: Optional[BatchPatchSupplier] = None
        if best_tree is None:
            supplier = BatchPatchSupplier(agent, enriched_sections, batch_index=idx, batch_start=idx, batch_size=1, initial_feedback=feedback, cached_entries=None, max_calls=max(1, max_section_attempts), cache_filename=f'sequential_section_{idx:03d}_llm.json', payload_fill_candidates=payload_fill_candidates)
            max_calls = max(1, max_section_attempts)
            for attempt in range(max_calls):
                attempts_made = attempt + 1
                state = SimpleNamespace(tree=tree, pending_issues=dict(current_report.issues), validation=ValidationSummary.from_report(current_report), history=[], last_action=None, empty_patch_stop=False)
                patch = supplier._generate_patch_via_llm(state)
                if patch is None:
                    logger.info('%s: no patch generated on attempt %s', log_prefix, attempts_made)
                    break
                if _is_noop_patch(patch):
                    logger.info('%s: noop patch on attempt %s; stopping further attempts', log_prefix, attempts_made)
                    break
                if not validate_patch_consistency(tree, patch):
                    logger.warning('%s: patch failed consistency checks on attempt %s', log_prefix, attempts_made)
                    continue
                candidate_tree = normalize_protocol_tree(apply_patch(tree, patch))
                candidate_report = run_full_validation(candidate_tree)
                issue_count = len(candidate_report.issues)
                candidate_ok = candidate_report.ok
                better = False
                if issue_count < best_issue_count:
                    better = True
                elif issue_count == best_issue_count:
                    if candidate_ok and (not best_ok):
                        better = True
                    elif candidate_ok == best_ok:
                        better = True
                if better:
                    best_tree = candidate_tree
                    best_report = candidate_report
                    best_patch = copy.deepcopy(patch)
                    best_summary = _summarize_patch_for_prompt(patch)
                    best_issue_count = issue_count
                    best_ok = candidate_ok
                    logger.info('%s: issues improved %s -> %s on attempt %s', log_prefix, baseline_issue_count, best_issue_count, attempts_made)
                    if best_issue_count == 0:
                        logger.info('%s: validator reports zero outstanding issues', log_prefix)
                        supplier.feedback = None
                        break
                supplier.feedback = _build_patch_feedback(candidate_report.errors, candidate_report.extras, candidate_tree)
            if supplier.calls_made and supplier.generated_log:
                supplier.persist_cache()
        if supplier is not None:
            attempts_made = supplier.calls_made
        meaningful_patch = best_patch if isinstance(best_patch, dict) else None
        applied = False
        if best_tree is not None and (best_issue_count < baseline_issue_count or best_ok != baseline_ok or (meaningful_patch is not None and (not _is_noop_patch(meaningful_patch)))):
            tree = best_tree
            current_report = best_report if best_report is not None else current_report
            feedback = _build_patch_feedback(current_report.errors, current_report.extras, tree)
            applied = True
            agent._save_to_cache(cache_filename, {'patch': best_patch, 'summary': best_summary, 'section_index': idx, 'section_number': section.get('number'), 'section_title': section.get('title'), 'timestamp': datetime.now().isoformat()})
        audit_records.append({'section_index': idx, 'section_number': section.get('number'), 'section_title': section.get('title'), 'attempts': supplier.calls_made if supplier else attempts_made, 'baseline_issues': baseline_issue_count, 'result_issues': best_issue_count if applied else baseline_issue_count, 'applied': applied, 'used_cache': reused_cache, 'patch_summary': best_summary})
        if applied:
            logger.info('%s: applied patch; outstanding issues now %s', log_prefix, best_issue_count)
        else:
            logger.info('%s: no acceptable patch applied', log_prefix)
        feedback = _build_patch_feedback(current_report.errors, current_report.extras, tree)
    agent._save_to_cache('sequential_refinement_audit.json', {'timestamp': datetime.now().isoformat(), 'sections': audit_records})
    return tree

def strict_validator_llm_fix_tree(agent: 'EnhancedPureAIAgent', initial_tree: Dict[str, Any], sections: Sequence[Dict[str, Any]]=(), raw_sections: Optional[Sequence[Dict[str, Any]]]=None, batch_size: int=1, max_llm_calls: int=50, node_snapshot_dir: Optional[str]=None, *, validator_fn=run_full_validation, prompt_mode: str='traffic_fix', fix_history: Optional[List[Dict[str, Any]]]=None, size_bits_candidates: Optional[Dict[int, List[Any]]]=None, payload_fill_candidates: Optional[Dict[int, List[Any]]]=None) -> Dict[str, Any]:
    tree = copy.deepcopy(initial_tree) if isinstance(initial_tree, dict) else initial_tree
    tree = normalize_protocol_tree(tree)

    def _env_flag(name: str, default: bool=False) -> bool:
        raw = os.getenv(name)
        if raw is None:
            return default
        return raw.strip().lower() in {'1', 'true', 'yes', 'on', 'y'}

    def _shorten(text: Optional[str], limit: int=160) -> str:
        if not text:
            return ''
        cleaned = ' '.join(str(text).split())
        if len(cleaned) <= limit:
            return cleaned
        return cleaned[:max(0, limit - 3)] + '...'

    def _report_traffic_ok(report: ValidationReport) -> str:
        total_samples = int(getattr(report, 'traffic_total_samples', 0) or 0)
        success_samples = int(getattr(report, 'traffic_successful_samples', 0) or 0)
        if total_samples <= 0:
            return '?'
        return f'{success_samples}/{total_samples}'

    def _score(report: ValidationReport) -> Tuple[int, int, int, int, int]:
        issues = _filter_error_issues(getattr(report, 'issues', {}) or {})
        issue_count = len(issues)
        total_samples = int(getattr(report, 'traffic_total_samples', 0) or 0)
        success_samples = int(getattr(report, 'traffic_successful_samples', 0) or 0)
        failed_samples = total_samples - success_samples if total_samples else len(getattr(report, 'traffic_failures', []) or [])
        coverage_gap_bits = int(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0)
        length_abs_err_bits = int(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0)
        overflow_bits = int(getattr(report, 'traffic_overflow_length_bits', 0) or 0)
        return (issue_count, int(failed_samples), coverage_gap_bits, length_abs_err_bits, overflow_bits)
    strict_use_sections = os.getenv('STEP2_STRICT_USE_SECTIONS', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
    prompt_sections: Sequence[Dict[str, Any]] = [copy.deepcopy(s) for s in sections or []] if strict_use_sections else []
    prompt_mode_norm = (prompt_mode or 'traffic_fix').strip().lower()
    max_calls = max(1, int(os.getenv('STEP2_STRICT_LOOP_MAX_CALLS', str(max_llm_calls))))
    avoid_keep = max(0, int(os.getenv('STEP2_STRICT_AVOID_SUMMARIES_KEEP', '8')))
    snapshot_rejected = os.getenv('STEP2_STRICT_SNAPSHOT_REJECTED', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
    print_progress = _env_flag('STEP2_STRICT_LOOP_PRINT', default=prompt_mode_norm == 'traffic_fix')
    supplier = BatchPatchSupplier(agent, prompt_sections, batch_index=0, batch_start=0, batch_size=max(1, len(prompt_sections) or 1), initial_feedback=None, cached_entries=None, max_calls=max_calls, cache_filename='strict_validator_loop.json', prompt_mode=prompt_mode_norm, fix_history=fix_history, size_bits_candidates=size_bits_candidates, payload_fill_candidates=payload_fill_candidates)
    strict_cache_path: Optional[Path]
    try:
        strict_cache_path = Path(getattr(agent, 'cache_dir', '')).joinpath(supplier.cache_filename)
    except Exception:
        strict_cache_path = None
    best_tree = copy.deepcopy(tree)
    best_report = validator_fn(tree)
    best_score = _score(best_report)
    avoid_summaries: List[str] = []
    noop_streak = 0
    last_action = None
    accepted_count = 0
    rejected_count = 0
    def _persist_snapshot(iter_idx: int, current_tree: Dict[str, Any], report: ValidationReport, patch: Optional[Dict[str, Any]]) -> None:
        if not node_snapshot_dir:
            return
        try:
            out_dir = Path(node_snapshot_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            patch_hash = _hash_patch(patch)[:8] if isinstance(patch, dict) else 'nopatch'
            path = out_dir / f'strict_iter_{iter_idx:04d}_{patch_hash}.json'
            payload = {'timestamp': datetime.utcnow().isoformat(), 'iter': iter_idx, 'patch_hash': patch_hash, 'score': list(_score(report)), 'validation': {'ok': bool(getattr(report, 'ok', False)), 'errors': list(getattr(report, 'errors', []) or []), 'extras': list(getattr(report, 'extras', []) or []), 'issue_ids': list(_filter_error_issues(getattr(report, 'issues', {}) or {}).keys()), 'traffic_total_samples': int(getattr(report, 'traffic_total_samples', 0) or 0), 'traffic_successful_samples': int(getattr(report, 'traffic_successful_samples', 0) or 0), 'traffic_total_coverage_gap_bits': int(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0), 'traffic_length_total_abs_error_bits': int(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0), 'traffic_overflow_length_bits': int(getattr(report, 'traffic_overflow_length_bits', 0) or 0)}, 'protocol_tree': current_tree}
            path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        except Exception as exc:
            logger.warning('Strict loop: failed to persist snapshot: %s', exc)
    for attempt in range(max_calls):
        report_before = validator_fn(tree)
        issues_before = _filter_error_issues(getattr(report_before, 'issues', {}) or {})
        if not issues_before:
            logger.info('Strict loop: validator reports zero ERROR issues at attempt %s; stopping.', attempt + 1)
            supplier.feedback = None
            break
        validation_summary = ValidationSummary.from_report(report_before)
        state = SimpleNamespace(tree=tree, pending_issues=issues_before, validation=validation_summary, history=[], last_action=last_action, empty_patch_stop=False)
        score_before = _score(report_before)
        patches = supplier(state, 1, avoid_summaries=avoid_summaries)
        if not patches:
            logger.info('Strict loop: LLM returned no patch at attempt %s; stopping.', attempt + 1)
            break
        patch = patches[0]
        if patch is None or _is_noop_patch(patch):
            noop_streak += 1
            logger.info('Strict loop: noop patch at attempt %s (streak=%s)', attempt + 1, noop_streak)
            if noop_streak >= 2:
                break
            continue
        noop_streak = 0
        if not isinstance(patch, dict):
            logger.warning('Strict loop: patch is not a dict at attempt %s; skipping.', attempt + 1)
            continue
        candidate_tree = normalize_protocol_tree(apply_patch(tree, patch))
        candidate_report = validator_fn(candidate_tree)
        score_after = _score(candidate_report)
        patch_hash = _hash_patch(patch)[:8]
        patch_summary = _shorten(_summarize_patch_for_prompt(patch), 140)
        if score_after <= score_before:
            tree = candidate_tree
            last_action = SimpleNamespace(patch=patch, hash=_hash_patch(patch)[:16], summary=_summarize_patch_for_prompt(patch))
            _persist_snapshot(attempt, tree, candidate_report, patch)
            if score_after < best_score:
                best_score = score_after
                best_tree = copy.deepcopy(tree)
                best_report = candidate_report
                avoid_summaries = []
            elif avoid_keep > 0:
                avoid_summaries = avoid_summaries[-avoid_keep:]
            logger.info('Strict loop: accepted patch %s score %s -> %s', last_action.hash[:8], score_before, score_after)
            accepted_count += 1
            if not _filter_error_issues(getattr(candidate_report, 'issues', {}) or {}):
                logger.info('Strict loop: validator reports zero ERROR issues after attempt %s; stopping.', attempt + 1)
                supplier.feedback = None
                break
        else:
            summary_text = _summarize_patch_for_prompt(patch)
            if summary_text:
                avoid_summaries.append(summary_text)
                if avoid_keep > 0:
                    avoid_summaries = avoid_summaries[-avoid_keep:]
            logger.info('Strict loop: rejected patch score %s -> %s; retrying.', score_before, score_after)
            rejected_count += 1
            if snapshot_rejected:
                _persist_snapshot(attempt, candidate_tree, candidate_report, patch)
    if supplier.calls_made and supplier.generated_log:
        supplier.persist_cache()
    try:
        final_report = validator_fn(tree)
        if _score(final_report) > best_score:
            tree = best_tree
    except Exception:
        tree = best_tree
    return tree

def mcts_fix_tree(agent: 'EnhancedPureAIAgent', initial_tree: Dict[str, Any], sections: Sequence[Dict[str, Any]], raw_sections: Optional[Sequence[Dict[str, Any]]]=None, batch_size: int=5, max_llm_calls: int=100000, node_snapshot_dir: Optional[str]=None, *, validator_fn=run_full_validation, prompt_mode: str='fix', fix_history: Optional[List[Dict[str, Any]]]=None, size_bits_candidates: Optional[Dict[int, List[Any]]]=None, payload_fill_candidates: Optional[Dict[int, List[Any]]]=None) -> Dict[str, Any]:
    tree = copy.deepcopy(initial_tree) if isinstance(initial_tree, dict) else initial_tree
    tree = normalize_protocol_tree(tree)
    strict_enabled = _strict_validator_loop_enabled()
    prompt_mode_norm = (prompt_mode or '').strip().lower()
    traffic_patch_sanitize = os.getenv('STEP2_TRAFFIC_SANITIZE_PATCH', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
    strict_bypass_mcts = os.getenv('STEP2_STRICT_TRAFFIC_BYPASS_MCTS', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
    if strict_enabled and prompt_mode_norm == 'traffic_fix':
        try:
            env_cap = os.getenv('STEP2_STRICT_LOOP_MAX_CALLS')
            if env_cap is not None:
                cap_int = int(env_cap)
                if cap_int > 0:
                    max_llm_calls = min(max_llm_calls, cap_int)
        except Exception:
            pass
        if strict_bypass_mcts:
            logger.info('Strict traffic_fix: bypassing MCTS (STEP2_STRICT_TRAFFIC_BYPASS_MCTS=1) and running strict loop')
            return strict_validator_llm_fix_tree(agent, tree, sections=sections, raw_sections=raw_sections, batch_size=batch_size, max_llm_calls=max_llm_calls, node_snapshot_dir=node_snapshot_dir, validator_fn=validator_fn, prompt_mode=prompt_mode, fix_history=fix_history, size_bits_candidates=size_bits_candidates, payload_fill_candidates=payload_fill_candidates)
    enriched_sections = [copy.deepcopy(s) for s in sections or []]
    num_sections = len(enriched_sections)
    batch_count = (num_sections + batch_size - 1) // batch_size
    all_patch_paths: List[List[Dict[str, Any]]] = []
    batch_path_records: List[Dict[str, Any]] = []
    patch_audit: List[Dict[str, Any]] = []
    base_report = validator_fn(tree)
    best_tree = copy.deepcopy(tree)
    from ..validation_agent.syntax_validator import Severity as _Severity

    def _is_traffic_issue_id(issue_id: Any) -> bool:
        return str(issue_id).startswith('traffic_')

    def _error_count(report, *, only_static: bool=False) -> int:
        try:
            issues = getattr(report, 'issues', {}) or {}
            if only_static:
                return sum((1 for issue_id, issue in issues.items() if not _is_traffic_issue_id(issue_id) and getattr(issue, 'severity', None) == _Severity.ERROR))
            return sum((1 for issue in issues.values() if getattr(issue, 'severity', None) == _Severity.ERROR))
        except Exception:
            return len(report.errors or [])

    def _issue_breakdown(report, *, only_static: bool=False) -> Tuple[int, int, int, int]:
        struct_err = 0
        sem_err = 0
        invariant_err = 0
        issues = getattr(report, 'issues', {}) or {}
        for issue_id, issue in issues.items():
            if only_static and _is_traffic_issue_id(issue_id):
                continue
            if getattr(issue, 'severity', None) != _Severity.ERROR:
                continue
            if getattr(issue, 'type', None) == IssueType.STRUCTURE:
                struct_err += 1
                if getattr(issue, 'code', None) == 'INVARIANT_VIOLATION':
                    invariant_err += 1
            elif getattr(issue, 'type', None) == IssueType.SEMANTICS:
                sem_err += 1
        total_err = _error_count(report, only_static=only_static)
        return (struct_err, sem_err, total_err, invariant_err)

    def _traffic_failed_samples(report: Any) -> int:
        total = int(getattr(report, 'traffic_total_samples', 0) or 0)
        succ = int(getattr(report, 'traffic_successful_samples', 0) or 0)
        if total:
            return max(0, total - succ)
        try:
            return len(getattr(report, 'traffic_failures', []) or [])
        except Exception:
            return 0

    def _traffic_coverage_ratio(report: Any) -> float:
        ratios = getattr(report, 'traffic_content_coverage_ratio_per_sample', None) or ()
        if ratios:
            try:
                vals = [float(x) for x in ratios if x is not None]
                if vals:
                    return sum(vals) / float(len(vals))
            except Exception:
                pass
        content_bits = getattr(report, 'traffic_content_covered_bits_per_sample', None) or ()
        total_bits = getattr(report, 'traffic_total_bits_per_sample', None) or ()
        if content_bits and total_bits:
            cov_sum = 0.0
            count = 0
            for cb, tb in zip(content_bits, total_bits):
                try:
                    cb_val = float(cb)
                    tb_val = float(tb)
                except Exception:
                    continue
                if tb_val <= 0:
                    continue
                cov_sum += min(1.0, cb_val / tb_val)
                count += 1
            if count:
                return cov_sum / float(count)
        max_bits = getattr(report, 'traffic_max_bit_reached', None) or ()
        total_bits = total_bits or (getattr(report, 'traffic_total_bits_per_sample', None) or ())
        if not max_bits or not total_bits:
            return 0.0
        cov_sum = 0.0
        count = 0
        for mb, tb in zip(max_bits, total_bits):
            try:
                mb_val = float(mb)
                tb_val = float(tb)
            except Exception:
                continue
            if tb_val <= 0:
                continue
            mb_eff = mb_val if mb_val <= tb_val else tb_val
            cov_sum += mb_eff / tb_val
            count += 1
        return cov_sum / float(count) if count else 0.0

    def _traffic_accept_score(report: Any) -> Tuple[int, float, int, int, int, int]:
        failed = _traffic_failed_samples(report)
        coverage = _traffic_coverage_ratio(report)
        try:
            gap_bits = int(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0)
        except Exception:
            gap_bits = 0
        try:
            len_err = int(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0)
        except Exception:
            len_err = 0
        try:
            overflow = int(getattr(report, 'traffic_overflow_length_bits', 0) or 0)
        except Exception:
            overflow = 0
        return (failed, -coverage, gap_bits, len_err, overflow, _error_count(report))

    def _format_traffic_score(score: Tuple[int, float, int, int, int, int]) -> str:
        failed, neg_cov, gap_bits, len_err, overflow, issue_cnt = score
        return f'failed={failed} cov={-neg_cov:.3f} gap_bits={gap_bits} len_abs_err_bits={len_err} overflow_bits={overflow} error_issues={issue_cnt}'

    def _traffic_scalar_score(report: Any) -> float:
        try:
            total = int(getattr(report, 'traffic_total_samples', 0) or 0)
        except Exception:
            total = 0
        failed = _traffic_failed_samples(report)
        succ = max(0, total - failed)
        cov = _traffic_coverage_ratio(report)
        try:
            gap_bits = float(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0)
        except Exception:
            gap_bits = 0.0
        try:
            len_err = float(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0)
        except Exception:
            len_err = 0.0
        try:
            overflow = float(getattr(report, 'traffic_overflow_length_bits', 0) or 0)
        except Exception:
            overflow = 0.0

        def _w(env: str, default: float) -> float:
            raw = os.getenv(env)
            if raw is None or not str(raw).strip():
                return float(default)
            try:
                return float(raw)
            except Exception:
                return float(default)
        defaults = MCTSConfig()
        w_success = _w('STEP2_MCTS_TRAFFIC_WEIGHT_SUCCESS', defaults.weight_traffic_success)
        w_cov = _w('STEP2_MCTS_TRAFFIC_WEIGHT_COVERAGE', defaults.weight_traffic_fix)
        w_gap = _w('STEP2_MCTS_TRAFFIC_WEIGHT_GAP', defaults.weight_traffic_gap)
        w_len = _w('STEP2_MCTS_TRAFFIC_WEIGHT_LENGTH_ERROR', defaults.weight_traffic_length_error)
        w_new = _w('STEP2_MCTS_TRAFFIC_WEIGHT_NEW', defaults.weight_traffic_new)
        w_overflow = _w('STEP2_MCTS_TRAFFIC_WEIGHT_OVERFLOW', 0.0)
        return w_success * float(succ) + w_cov * float(cov) - w_gap * float(gap_bits) - w_len * float(len_err) - w_new * float(failed) - w_overflow * float(overflow)
    best_issue_count = _error_count(base_report)
    best_error_count = best_issue_count
    feedback = _build_patch_feedback(base_report.errors, base_report.extras, tree)
    patch_audit.append({'batch': -1, 'source': 'initial', 'ok': base_report.ok, 'errors': base_report.errors, 'extras': base_report.extras})
    logger.info('Starting MCTS fix with %s sections (batch size=%s)', num_sections, batch_size)
    for batch_idx in range(batch_count):
        batch_start = batch_idx * batch_size
        batch_end = min((batch_idx + 1) * batch_size, num_sections)
        logger.info('Processing batch %s/%s: sections %s to %s', batch_idx + 1, batch_count, batch_start, batch_end - 1)
        baseline_report = validator_fn(tree)
        baseline_struct_err, baseline_sem_err, baseline_total_err, baseline_invariant_err = _issue_breakdown(baseline_report)
        baseline_static_struct_err = baseline_struct_err
        baseline_static_sem_err = baseline_sem_err
        baseline_static_total_err = baseline_total_err
        baseline_static_invariant_err = baseline_invariant_err
        baseline_traffic_score: Optional[Tuple[int, float, int, int, int, int]] = None
        if prompt_mode_norm == 'traffic_fix':
            baseline_traffic_score = _traffic_accept_score(baseline_report)
            baseline_static_struct_err, baseline_static_sem_err, baseline_static_total_err, baseline_static_invariant_err = _issue_breakdown(baseline_report, only_static=True)
        cache_filename = f'patch_section_{batch_start}_to_{batch_end}_response.json'
        cached_data = agent._load_from_cache(cache_filename)
        cached_entries = _extract_cached_patch_entries(cached_data)
        supplier = BatchPatchSupplier(agent, enriched_sections, batch_index=batch_idx, batch_start=batch_start, batch_size=batch_size, initial_feedback=feedback, cached_entries=cached_entries, max_calls=max_llm_calls, cache_filename=cache_filename, prompt_mode=prompt_mode, fix_history=fix_history, size_bits_candidates=size_bits_candidates, payload_fill_candidates=payload_fill_candidates)
        remaining_batches = list(range(batch_idx + 1, batch_count))

        def _env_bool(name: str, default: bool) -> bool:
            val = os.getenv(name)
            if val is None:
                return default
            return val.strip().lower() in {'1', 'true', 'yes', 'on'}

        def _env_int(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, str(default)))
            except Exception:
                return default

        def _env_float(name: str, default: float) -> float:
            try:
                return float(os.getenv(name, str(default)))
            except Exception:
                return default
        default_ppi = 3 if prompt_mode == 'traffic_fix' else 1
        mcts_config = MCTSConfig(exploration_constant=_env_float('STEP2_MCTS_C', MCTSConfig().exploration_constant), patches_per_iteration=_env_int('STEP2_MCTS_PATCHES_PER_ITER', default_ppi), max_depth=_env_int('STEP2_MCTS_MAX_DEPTH', 16), log_details=True, simplified_logs=False, log_uct=_env_bool('STEP2_MCTS_LOG_UCT', True), empty_patch_early_stop=not _env_bool('STEP2_MCTS_NO_EARLY_STOP', False), reward_stagnation_limit=_env_int('STEP2_MCTS_STAGNATION', 5) or None, patch_step_penalty=_env_float('STEP2_MCTS_PATCH_STEP_PENALTY', 0.05), weight_traffic_fix=_env_float('STEP2_MCTS_TRAFFIC_WEIGHT_COVERAGE', MCTSConfig().weight_traffic_fix), weight_traffic_new=_env_float('STEP2_MCTS_TRAFFIC_WEIGHT_NEW', MCTSConfig().weight_traffic_new), weight_traffic_success=_env_float('STEP2_MCTS_TRAFFIC_WEIGHT_SUCCESS', MCTSConfig().weight_traffic_success), weight_traffic_gap=_env_float('STEP2_MCTS_TRAFFIC_WEIGHT_GAP', MCTSConfig().weight_traffic_gap), repeat_expansion_on_visit=_env_bool('STEP2_MCTS_REPEAT_EXPANSION', True if prompt_mode == 'traffic_fix' else False), progressive_widening_k=_env_float('STEP2_MCTS_PW_K', 0.0), progressive_widening_alpha=_env_float('STEP2_MCTS_PW_ALPHA', 0.5), progressive_widening_min_children=_env_int('STEP2_MCTS_PW_MIN', 1))
        apply_fn = apply_patch
        if prompt_mode_norm == 'traffic_fix' and traffic_patch_sanitize:

            def _safe_apply(tree_arg: Dict[str, Any], patch_arg: Dict[str, Any]) -> Dict[str, Any]:
                try:
                    meta = patch_arg.get('patch_metadata') if isinstance(patch_arg, dict) else None
                    intent = str(meta.get('intent') or '').strip().lower() if isinstance(meta, dict) else ''
                except Exception:
                    intent = ''
                if not isinstance(patch_arg, dict):
                    return copy.deepcopy(tree_arg)
                candidate = copy.deepcopy(patch_arg)
                if intent == 'traffic_payload_fill':
                    candidate = _strip_payload_fill_child_link_updates(tree_arg, candidate)
                return apply_patch(tree_arg, candidate)
            apply_fn = _safe_apply
        if prompt_mode_norm == 'traffic_fix':
            run_followup = os.getenv('STEP2_TRAFFIC_CANDIDATE_SYNTAX_FIX', '1').strip().lower() in {'1', 'true', 'yes', 'on'}
            if run_followup:
                base_apply_fn = apply_fn

                def _apply_with_syntax_followup(tree_arg: Dict[str, Any], patch_arg: Dict[str, Any]) -> Dict[str, Any]:
                    patched_tree = base_apply_fn(tree_arg, patch_arg)
                    try:
                        static_report = run_full_validation(patched_tree)
                    except Exception:
                        return patched_tree
                    static_errors = [iss for iss in getattr(static_report, 'issues', {}).values() if getattr(iss, 'severity', None) == Severity.ERROR]
                    if not static_errors:
                        return patched_tree
                    try:
                        max_calls = int(os.getenv('STEP2_TRAFFIC_CANDIDATE_SYNTAX_MAX_CALLS', '10'))
                    except Exception:
                        max_calls = 10
                    if max_calls <= 0:
                        return patched_tree
                    try:
                        default_bs = max(1, int(batch_size))
                    except Exception:
                        default_bs = 1
                    try:
                        followup_batch_size = int(os.getenv('STEP2_TRAFFIC_CANDIDATE_SYNTAX_BATCH_SIZE', str(default_bs)))
                    except Exception:
                        followup_batch_size = default_bs
                    try:
                        fixed_tree = mcts_fix_tree(agent, patched_tree, sections, raw_sections=raw_sections, batch_size=max(1, followup_batch_size), max_llm_calls=max(1, max_calls), node_snapshot_dir=node_snapshot_dir, validator_fn=run_full_validation, prompt_mode='fix', fix_history=fix_history)
                    except Exception:
                        return patched_tree
                    try:
                        final_report = run_full_validation(fixed_tree)
                        final_errors = [iss for iss in getattr(final_report, 'issues', {}).values() if getattr(iss, 'severity', None) == Severity.ERROR]
                    except Exception:
                        pass
                    return fixed_tree
                apply_fn = _apply_with_syntax_followup
        default_max_sims = 12 if prompt_mode_norm == 'traffic_fix' else 5
        outcome, stats = search_for_batch(tree, batch_idx, patch_supplier=supplier, validator=validator_fn, apply_patch_fn=apply_fn, remaining_batches=remaining_batches, config=mcts_config, max_simulations=_env_int('STEP2_MCTS_MAX_SIMS', default_max_sims), evaluation_callback=supplier.on_candidate_evaluated, node_snapshot_dir=node_snapshot_dir, normalizer=canonicalize_protocol_tree if prompt_mode != 'traffic_fix' else lambda t: t)
        supplier.persist_cache()
        patch_audit.extend(supplier.evaluation_records)
        if stats.simulations:
            logger.info('Batch %s MCTS stats: simulations=%s, expansions=%s, best_reward=%.3f, best_issues=%s', batch_idx + 1, stats.simulations, stats.expansions, stats.best_reward, stats.best_issue_count)
        if supplier.evaluation_records:
            total_candidates = len(supplier.evaluation_records)
            positive = sum((1 for record in supplier.evaluation_records if (record.get('reward') or 0) > 0))
            logger.info('Batch %s evaluation summary: candidates=%s, positive_rewards=%s', batch_idx + 1, total_candidates, positive)
        records = outcome.records if outcome else []
        path_hashes = [record.action.hash for record in records]
        if records:
            trace_lines = [f'[trace] root (issues={len(base_report.issues)}, reward=0.0)']
            for idx, record in enumerate(records, 1):
                trace_lines.append(f'   [sim {idx}] patch {record.action.hash[:8]}')
                trace_lines.append(f'     * resolved: {len(record.resolved)}')
                trace_lines.append(f'     * introduced: {len(record.introduced)}')
                trace_lines.append(f'     * issues_after: {len(record.issues_after)}')
                total_reward = record.reward + (record.rollout_reward or 0.0)
                reward_line = f'     * reward: {record.reward:.3f}'
                if record.rollout_reward:
                    reward_line += f' (+{record.rollout_reward:.3f} rollout)'
                reward_line += f' = {total_reward:.3f}'
                trace_lines.append(reward_line)
            logger.info('\n'.join(trace_lines))
        path_metadata: List[Dict[str, Any]] = []
        for record in records:
            info = supplier.get_action_info(record.action.hash) or {}
            summary = record.action.summary or info.get('summary')
            path_metadata.append({'hash': record.action.hash, 'summary': summary, 'source': info.get('source'), 'attempt': info.get('attempt'), 'reward': record.reward, 'introduced': len(record.introduced), 'resolved': len(record.resolved)})
        path_summaries = [meta.get('summary') for meta in path_metadata]
        path_summary = ' | '.join(filter(None, path_summaries)) or None
        path_patches = [copy.deepcopy(record.action.patch) for record in records]
        previous_best = best_issue_count
        previous_best_errors = best_error_count
        if outcome is not None:
            candidate_tree = normalize_protocol_tree(copy.deepcopy(outcome.final_tree))
            applied = True
        else:
            candidate_tree = normalize_protocol_tree(copy.deepcopy(tree))
            applied = False
        candidate_report = validator_fn(candidate_tree)
        candidate_struct_err, candidate_sem_err, candidate_issue_count, candidate_invariant_err = _issue_breakdown(candidate_report)
        candidate_static_struct_err, candidate_static_sem_err, candidate_static_total_err, candidate_static_invariant_err = _issue_breakdown(candidate_report, only_static=True)
        candidate_error_count = candidate_issue_count
        if prompt_mode_norm == 'traffic_fix':
            baseline_score = baseline_traffic_score or _traffic_accept_score(baseline_report)
            candidate_score = _traffic_accept_score(candidate_report)
            baseline_scalar = _traffic_scalar_score(baseline_report)
            candidate_scalar = _traffic_scalar_score(candidate_report)
            improved = candidate_score < baseline_score or candidate_scalar > baseline_scalar + 1e-09
            no_regression = candidate_static_struct_err <= baseline_static_struct_err and candidate_static_sem_err <= baseline_static_sem_err and (candidate_static_invariant_err == 0)
            try:
                max_failed_increase = int(os.getenv('STEP2_TRAFFIC_ACCEPT_MAX_FAILED_INCREASE', '10').strip())
            except Exception:
                max_failed_increase = 10
            max_failed_increase = max(0, max_failed_increase)
            baseline_failed = int(baseline_score[0])
            candidate_failed = int(candidate_score[0])
            within_failed_slack = candidate_failed <= baseline_failed + max_failed_increase
            accept_candidate = applied and no_regression and improved and within_failed_slack
        else:
            improved = candidate_issue_count < baseline_total_err or candidate_struct_err < baseline_struct_err or candidate_sem_err < baseline_sem_err
            no_regression = candidate_struct_err <= baseline_struct_err and candidate_sem_err <= baseline_sem_err and (candidate_invariant_err == 0)
            accept_candidate = applied and no_regression and improved
        if accept_candidate:
            tree = copy.deepcopy(candidate_tree)
            best_tree = copy.deepcopy(candidate_tree)
            best_issue_count = candidate_issue_count
            best_error_count = candidate_error_count
            if prompt_mode_norm == 'traffic_fix':
                logger.info('Batch %s candidate tree accepted (static_struct %s->%s, static_sem %s->%s, total %s->%s)', batch_idx + 1, baseline_static_struct_err, candidate_static_struct_err, baseline_static_sem_err, candidate_static_sem_err, baseline_total_err, candidate_issue_count)
            else:
                logger.info('Batch %s candidate tree accepted (struct %s->%s, sem %s->%s, total %s->%s)', batch_idx + 1, baseline_struct_err, candidate_struct_err, baseline_sem_err, candidate_sem_err, baseline_total_err, candidate_issue_count)
        else:
            if prompt_mode_norm == 'traffic_fix':
                if candidate_static_invariant_err > 0 or candidate_static_struct_err > baseline_static_struct_err or candidate_static_sem_err > baseline_static_sem_err:
                    logger.error('Batch %s candidate tree regressed static validation (struct %s->%s, sem %s->%s); retaining previous tree', batch_idx + 1, baseline_static_struct_err, candidate_static_struct_err, baseline_static_sem_err, candidate_static_sem_err)
                else:
                    logger.info('Batch %s candidate tree unchanged (static_struct %s->%s, static_sem %s->%s); retaining previous tree', batch_idx + 1, baseline_static_struct_err, candidate_static_struct_err, baseline_static_sem_err, candidate_static_sem_err)
            elif candidate_invariant_err > 0 or candidate_struct_err > baseline_struct_err or candidate_sem_err > baseline_sem_err:
                logger.error('Batch %s candidate tree regressed validation (struct %s->%s, sem %s->%s); retaining previous tree', batch_idx + 1, baseline_struct_err, candidate_struct_err, baseline_sem_err, candidate_sem_err)
            else:
                logger.info('Batch %s candidate tree unchanged (struct %s->%s, sem %s->%s); retaining previous tree', batch_idx + 1, baseline_struct_err, candidate_struct_err, baseline_sem_err, candidate_sem_err)
            applied = False
            candidate_tree = normalize_protocol_tree(copy.deepcopy(tree))
            candidate_report = baseline_report
            candidate_issue_count = baseline_total_err
        _persist_batch_tree(batch_idx, tree)
        feedback = _build_patch_feedback(candidate_report.errors, candidate_report.extras, candidate_tree)
        if candidate_issue_count == 0:
            feedback = None
        patch_audit.append({'batch': batch_idx, 'source': 'mcts_best', 'ok': candidate_report.ok, 'errors': candidate_report.errors, 'extras': candidate_report.extras, 'patch_summary': path_summary, 'path_summary': path_summary, 'path_hashes': path_hashes, 'simulations': stats.simulations, 'best_reward': stats.best_reward, 'best_issue_count': stats.best_issue_count, 'terminal_found': stats.terminal_found, 'applied': applied, 'accepted': accept_candidate, 'issue_count': candidate_issue_count, 'empty_patch_stop': stats.empty_patch_stop})
        record_patches = path_patches if accept_candidate else []
        all_patch_paths.append(record_patches)
        batch_path_records.append({'batch': batch_idx, 'applied': applied, 'accepted': accept_candidate, 'reward': outcome.reward if outcome else None, 'issue_count': candidate_issue_count, 'path_hashes': path_hashes, 'summaries': [meta.get('summary') for meta in path_metadata], 'path_length': len(records), 'terminal': outcome.terminal if outcome else False, 'patches': record_patches, 'introduced_counts': [len(record.introduced) for record in records], 'resolved_counts': [len(record.resolved) for record in records]})
        log_mcts_event({'event': 'batch_summary', 'batch_index': batch_idx, 'path_hashes': path_hashes, 'path_length': len(records), 'path_reward': outcome.reward if outcome else None, 'path_summary': path_summary, 'path_applied': applied, 'path_accepted': accept_candidate, 'issue_count': candidate_issue_count, 'tree_node_count': len(candidate_tree.get('nodes', [])), 'tree_edge_count': len(candidate_tree.get('edges', [])), 'simulations': stats.simulations, 'best_reward': stats.best_reward, 'best_issues': stats.best_issue_count, 'terminal': outcome.terminal if outcome else False, 'empty_patch_stop': stats.empty_patch_stop})
        if stats.terminal_found and candidate_issue_count == 0:
            logger.info('Batch %s reached zero-issue state via MCTS search', batch_idx + 1)
    tree = copy.deepcopy(best_tree)
    total_applied_patches = sum((len(path) for path in all_patch_paths))
    logger.info('Refinement complete. Applied %s patches.', total_applied_patches)
    logger.info('Final tree: %s nodes, %s edges', len(tree.get('nodes', [])), len(tree.get('edges', [])))
    flattened_patches: List[Dict[str, Any]] = [patch for path in all_patch_paths for patch in path]
    agent._save_to_cache('patch_history.json', {'paths': batch_path_records, 'patches': flattened_patches, 'timestamp': datetime.now().isoformat(), 'total_batches': batch_count, 'total_applied_patches': total_applied_patches})
    agent._save_to_cache('patch_validation_report.json', {'timestamp': datetime.now().isoformat(), 'entries': patch_audit, 'applied_patches': total_applied_patches})
    log_mcts_event({'event': 'refinement_complete', 'total_batches': batch_count, 'applied_patches': total_applied_patches, 'final_node_count': len(tree.get('nodes', [])), 'final_edge_count': len(tree.get('edges', [])), 'remaining_issue_count': best_issue_count})
    return tree

def refine_tree_with_raw_data(agent: 'EnhancedPureAIAgent', initial_tree: Dict[str, Any], sections: Sequence[Dict[str, Any]], raw_sections: Optional[Sequence[Dict[str, Any]]]=None, batch_size: int=5, max_llm_calls: int=100000, *, sequential_attempts: Optional[int]=None) -> Dict[str, Any]:
    enriched_sections = [copy.deepcopy(s) for s in sections or []]
    attempts = sequential_attempts
    if attempts is None:
        try:
            attempts = int(os.getenv('STEP2_SEQUENTIAL_ATTEMPTS', '3'))
        except ValueError:
            attempts = 3
    logger.info('Sequential refinement: max attempts per section set to %s', attempts)
    refined_tree = sequential_refine_tree(agent, initial_tree, enriched_sections, raw_sections=None, max_section_attempts=max(1, attempts))
    post_report = run_full_validation(refined_tree)
    remaining_issues = len(post_report.issues)
    if remaining_issues == 0 and post_report.ok:
        logger.info('Sequential refinement resolved all validator issues; skipping MCTS fix stage')
        return refined_tree
    if os.getenv('STEP2_SKIP_MCTS_FIX', '0') == '1':
        logger.info('STEP2_SKIP_MCTS_FIX=1; returning tree after sequential refinement without MCTS fix')
        return refined_tree
    logger.info('Sequential refinement complete with %s outstanding issues; invoking MCTS fix stage', remaining_issues)
    fixed_tree = mcts_fix_tree(agent, refined_tree, enriched_sections, raw_sections=None, batch_size=batch_size, max_llm_calls=max_llm_calls)
    return fixed_tree
