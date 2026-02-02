from __future__ import annotations
import copy
import hashlib
import json
import logging
import math
import os
import re
from collections import Counter
import random
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from ..tree_utils import normalize_protocol_tree
from ..validation_agent.syntax_validator import Issue, IssueType, Severity, ValidationReport, is_hard_error
from ..validation_agent.traffic_errors import TrafficParseFailure
from ...paths import LOGS_DIR
logger = logging.getLogger(__name__)
W_RESOLVE_STRUCT = 6.0
W_RESOLVE_SEM = 3.0
W_INTRO_STRUCT = 10.0
W_INTRO_SEM = 4.0
W_ISSUE_DELTA = 3.0
W_ACTION = 0.1
W_DELETE_VARIANT = 1.0
_MCTS_LOGGER: Optional[logging.Logger] = None
_MCTS_LOGGER_INITIALIZED = False
_MCTS_LOG_ENV = 'STEP2_ENABLE_MCTS_LOG'
_MCTS_LOG_FILE_ENV = 'STEP2_MCTS_LOG_FILE'
_MCTS_LOG_UCT_ENV = 'STEP2_MCTS_LOG_UCT'
_MCTS_TREE_DUMP_EVENTS_ENV = 'STEP2_MCTS_TREE_DUMP_EVENTS'
PatchSupplier = Callable[['TreeState', int, Optional[List[str]]], Sequence[Dict[str, Any]]]
ValidatorFn = Callable[[Dict[str, Any]], ValidationReport]
ApplyPatchFn = Callable[[Dict[str, Any], Dict[str, Any]], Dict[str, Any]]
EvaluationCallback = Callable[['PatchEvaluation'], None]

def _ensure_mcts_logger() -> Optional[logging.Logger]:
    global _MCTS_LOGGER_INITIALIZED, _MCTS_LOGGER
    if _MCTS_LOGGER_INITIALIZED:
        return _MCTS_LOGGER
    _MCTS_LOGGER_INITIALIZED = True
    if os.getenv(_MCTS_LOG_ENV, '1').lower() not in {'1', 'true'}:
        return None
    default_log_path = str(LOGS_DIR / 'mcts.log')
    log_path = os.getenv(_MCTS_LOG_FILE_ENV, default_log_path).strip()
    if not log_path:
        return None
    logger_obj = logging.getLogger('step2.mcts.trace')
    logger_obj.propagate = False
    if not logger_obj.handlers:
        handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger_obj.addHandler(handler)
    logger_obj.setLevel(logging.INFO)
    _MCTS_LOGGER = logger_obj
    return logger_obj

def log_mcts_event(payload: Dict[str, Any]) -> None:
    logger_obj = _ensure_mcts_logger()
    if logger_obj is None:
        return
    record = dict(payload)
    record.setdefault('timestamp', datetime.now().isoformat())
    try:
        logger_obj.info(json.dumps(record, ensure_ascii=False, sort_keys=True))
    except Exception:
        logger_obj.debug('Failed to serialize MCTS event', exc_info=True)

@dataclass
class MCTSConfig:
    exploration_constant: float = math.sqrt(2.0)
    patches_per_iteration: int = 1
    max_depth: int = 5
    weight_resolve: float = 5.0
    weight_resolve_struct: float = 6.0
    weight_intro: float = 8.0
    weight_intro_struct: float = 12.0
    weight_issue_delta: float = 3.0
    weight_action: float = 0.1
    variant_delete_penalty: float = 1.0
    patch_step_penalty: float = 0.05
    structural_penalty_remove_node: float = 0.2
    structural_penalty_remove_edge: float = 0.2
    empty_patch_bonus: float = 5.0
    empty_patch_early_stop: bool = True
    weight_traffic_fix: float = 1.0
    weight_traffic_new: float = 0.5
    weight_traffic_success: float = 5.0
    weight_traffic_length_error: float = 0.05
    weight_traffic_gap: float = 0.02
    allow_disk_cache: bool = True
    log_details: bool = False
    simplified_logs: bool = True
    log_uct: bool = False
    reward_stagnation_limit: Optional[int] = None
    min_reward_improvement: float = 1e-06
    repeat_expansion_on_visit: bool = False
    rollout_max_steps: int = 10
    rollout_random_policy_chance: float = 0.35
    rollout_terminal_bonus: float = 25.0
    rollout_step_penalty: float = 0.25
    progressive_widening_k: float = 0.0
    progressive_widening_alpha: float = 0.5
    progressive_widening_min_children: int = 1
    hard_error_increase_penalty: float = 5.0

def stable_hash(*values: Any) -> str:
    payload = json.dumps(values, ensure_ascii=True, sort_keys=True)
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()

def _hash_patch(patch: Dict[str, Any]) -> str:
    serialized = json.dumps(patch, ensure_ascii=True, sort_keys=True)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()

def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None

def _truthy_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'on'}
    return False

def _extract_structural_signature(tree: Dict[str, Any]) -> Dict[str, Any]:

    def _enum_field(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            stripped = value.strip()
            return stripped.lower()
        return str(value).lower()

    def _text_field(value: Any) -> Any:
        if isinstance(value, str):
            return value.strip()
        return value

    def _normalize_children(raw: Any) -> Tuple[Any, ...]:
        if not isinstance(raw, list):
            return tuple()
        normalized: List[Any] = []
        for child in raw:
            if child is None:
                continue
            coerced = _safe_int(child)
            if coerced is not None:
                normalized.append(coerced)
            else:
                normalized.append(str(child))
        return tuple(normalized)

    def _normalize_id(value: Any) -> Any:
        coerced = _safe_int(value)
        if coerced is not None:
            return coerced
        if value is None:
            return None
        if isinstance(value, str):
            return value.strip()
        return value

    def _sort_key(value: Any) -> Tuple[int, Any]:
        if value is None:
            return (2, '')
        if isinstance(value, (int, float)):
            return (0, value)
        return (1, str(value))
    signature_nodes: List[Dict[str, Any]] = []
    nodes = tree.get('nodes') if isinstance(tree, dict) else None
    if isinstance(nodes, list):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            signature_nodes.append({'node_id': _normalize_id(node.get('node_id')), 'parent_id': _normalize_id(node.get('parent_id')), 'node_type': _enum_field(node.get('node_type')), 'message_type': _enum_field(node.get('message_type')), 'bit_start': _text_field(node.get('bit_start')), 'size_bits': _text_field(node.get('size_bits')), 'data_type': _enum_field(node.get('data_type')), 'byte_order': _enum_field(node.get('byte_order')), 'children_ids': _normalize_children(node.get('children_ids'))})
    signature_nodes.sort(key=lambda item: _sort_key(item.get('node_id')))
    signature_edges: List[Dict[str, Any]] = []
    edges = tree.get('edges') if isinstance(tree, dict) else None
    if isinstance(edges, list):
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            signature_edges.append({'src': _normalize_id(edge.get('src')), 'dst': _normalize_id(edge.get('dst')), 'rel': _enum_field(edge.get('rel')), 'formula': _text_field(edge.get('formula')), 'message_type': _enum_field(edge.get('message_type'))})
    signature_edges.sort(key=lambda item: (_sort_key(item.get('src')), _sort_key(item.get('dst')), _sort_key(item.get('rel')), _sort_key(item.get('formula')), _sort_key(item.get('message_type'))))
    return {'root_node_id': _normalize_id(tree.get('root_node_id')), 'nodes': signature_nodes, 'edges': signature_edges}

def _is_optional_variant_node(node: Dict[str, Any]) -> bool:
    annotations = node.get('annotations') or node.get('metadata')
    if isinstance(annotations, dict):
        if _truthy_flag(annotations.get('optional_variant')) or _truthy_flag(annotations.get('allow_variant_removal')):
            return True
    if _truthy_flag(node.get('optional_variant')) or _truthy_flag(node.get('allow_variant_removal')):
        return True
    return False

def _variant_signature_counter(tree: Dict[str, Any]) -> Counter:
    nodes = tree.get('nodes') if isinstance(tree, dict) else None
    if isinstance(nodes, dict):
        nodes_iter = list(nodes.values())
    elif isinstance(nodes, list):
        nodes_iter = nodes
    else:
        nodes_iter = []
    node_map: Dict[int, Dict[str, Any]] = {}
    for node in nodes_iter:
        nid = _safe_int(node.get('node_id'))
        if nid is not None:
            node_map[nid] = node
    counter: Counter = Counter()
    for node in node_map.values():
        if str(node.get('node_type', '')).lower() != 'variant':
            continue
        if _is_optional_variant_node(node):
            continue
        parent = node_map.get(_safe_int(node.get('parent_id')))
        parent_name = (parent.get('name', '') or '').strip() if parent else ''
        parent_type = str(parent.get('node_type', '') or '').lower() if parent else ''
        signature = ((node.get('name', '') or '').strip(), str(node.get('message_type', '') or '').lower(), parent_name, parent_type)
        counter[signature] += 1
    return counter

def _count_missing_variants(before_tree: Dict[str, Any], after_tree: Dict[str, Any]) -> int:
    return 0

def _snapshot_issues(issues: Dict[str, Issue]) -> List[Tuple[str, str, str, str]]:
    return [(issue_id, issue.type.value, issue.severity.value, issue.description) for issue_id, issue in sorted(issues.items())]

def _filter_error_issues(issues: Dict[str, Issue]) -> Dict[str, Issue]:
    if not issues:
        return {}
    return {issue_id: issue for issue_id, issue in issues.items() if getattr(issue, 'severity', None) == Severity.ERROR}

def _count_hard_errors(summary: ValidationSummary) -> int:
    if summary.issues:
        return sum((1 for issue in summary.issues.values() if is_hard_error(issue)))
    return len(summary.errors)

def _count_variant_nodes(tree: Dict[str, Any]) -> int:
    nodes = tree.get('nodes', []) if isinstance(tree, dict) else []
    count = 0
    for node in nodes:
        try:
            if str(node.get('node_type', '')).lower() == 'variant':
                count += 1
        except Exception:
            continue
    return count

def _compute_traffic_coverage(summary: ValidationSummary) -> float:
    ratios = getattr(summary, 'traffic_content_coverage_ratio_per_sample', ()) or ()
    if ratios:
        try:
            vals = [float(r) for r in ratios if r is not None]
            return sum(vals) / len(vals) if vals else 0.0
        except Exception:
            pass
    content_bits = getattr(summary, 'traffic_content_covered_bits_per_sample', ()) or ()
    max_bits = getattr(summary, 'traffic_max_bit_reached', ()) or ()
    total_bits = getattr(summary, 'traffic_total_bits_per_sample', ()) or ()
    if content_bits and total_bits:
        cov_sum = 0.0
        count = 0
        for cb, tb in zip(content_bits, total_bits):
            try:
                tb_val = float(tb)
                cb_val = float(cb)
            except Exception:
                continue
            if tb_val <= 0:
                continue
            cov_sum += min(1.0, cb_val / tb_val)
            count += 1
        if count:
            return cov_sum / count
    if not max_bits or not total_bits:
        return 0.0
    cov_sum = 0.0
    count = 0
    for mb, tb in zip(max_bits, total_bits):
        try:
            tb_val = float(tb)
            mb_val = float(mb)
        except Exception:
            continue
        if tb_val <= 0:
            continue
        mb_eff = mb_val if mb_val <= tb_val else tb_val
        cov_sum += mb_eff / tb_val
        count += 1
    if count == 0:
        return 0.0
    return cov_sum / count

@dataclass
class ValidationSummary:
    ok: bool
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    extras: Tuple[str, ...]
    issues: Dict[str, Issue]
    traffic_repair_hints: Tuple[Dict[str, Any], ...] = tuple()
    traffic_successful_samples: int = 0
    traffic_total_samples: int = 0
    traffic_max_bit_reached: Tuple[int, ...] = tuple()
    traffic_total_bits_per_sample: Tuple[int, ...] = tuple()
    traffic_length_total_abs_error_bits: float = 0.0
    traffic_wire_length_total_abs_error_bits: float = 0.0
    traffic_total_coverage_gap_bits: float = 0.0
    traffic_coverage_gap_samples: int = 0
    traffic_overflow_length_bits: float = 0.0
    traffic_content_covered_bits_per_sample: Tuple[int, ...] = tuple()
    traffic_content_coverage_ratio_per_sample: Tuple[float, ...] = tuple()
    traffic_failures: Tuple[TrafficParseFailure, ...] = tuple()
    traffic_global_summary: Any = None

    @classmethod
    def from_report(cls, report: ValidationReport) -> 'ValidationSummary':
        issues = _filter_error_issues(getattr(report, 'issues', {}))
        hints_raw = list(getattr(report, 'traffic_repair_hints', None) or [])
        hints_env = os.getenv('STEP2_TRAFFIC_HINTS_IN_SUMMARY')
        if hints_env is None or not hints_env.strip():
            hints_limit = 50
        else:
            try:
                hints_limit = int(hints_env)
            except Exception:
                hints_limit = 50
        if hints_limit <= 0:
            hints_limit = len(hints_raw)
        hints: Tuple[Dict[str, Any], ...] = tuple([h for h in hints_raw if isinstance(h, dict)][:hints_limit])
        max_bits = tuple(getattr(report, 'traffic_max_bit_reached', []) or [])
        total_bits = tuple(getattr(report, 'traffic_total_bits_per_sample', []) or [])
        length_err = 0.0
        wire_len_err = 0.0
        coverage_gap_bits = 0.0
        overflow_bits = 0.0
        coverage_gap_samples = int(getattr(report, 'traffic_coverage_gap_samples', 0) or 0)
        if hasattr(report, 'traffic_length_total_abs_error_bits'):
            try:
                length_err = float(getattr(report, 'traffic_length_total_abs_error_bits', 0) or 0)
            except Exception:
                length_err = 0.0
        if hasattr(report, 'traffic_wire_length_total_abs_error_bits'):
            try:
                wire_len_err = float(getattr(report, 'traffic_wire_length_total_abs_error_bits', 0) or 0)
            except Exception:
                wire_len_err = 0.0
        if hasattr(report, 'traffic_total_coverage_gap_bits'):
            try:
                coverage_gap_bits = float(getattr(report, 'traffic_total_coverage_gap_bits', 0) or 0)
            except Exception:
                coverage_gap_bits = 0.0
        if hasattr(report, 'traffic_overflow_length_bits'):
            try:
                overflow_bits = float(getattr(report, 'traffic_overflow_length_bits', 0) or 0)
            except Exception:
                overflow_bits = 0.0
        else:
            summary = getattr(report, 'traffic_global_summary', None)
            if summary is not None:
                try:
                    length_err = float(getattr(summary, 'total_length_mismatch_abs_error_bits', 0) or 0)
                except Exception:
                    length_err = 0.0
                try:
                    wire_len_err = float(getattr(summary, 'total_length_wire_mismatch_abs_error_bits', 0) or 0)
                except Exception:
                    wire_len_err = 0.0
                try:
                    coverage_gap_bits = float(getattr(summary, 'total_length_coverage_gap_bits', 0) or 0)
                    coverage_gap_samples = int(getattr(summary, 'coverage_gap_samples', 0) or 0)
                except Exception:
                    pass
                try:
                    overflow_bits = float(getattr(summary, 'total_length_overflow_bits', 0) or 0)
                except Exception:
                    overflow_bits = 0.0
        content_bits = tuple(getattr(report, 'traffic_content_covered_bits_per_sample', []) or [])
        content_ratio = tuple(getattr(report, 'traffic_content_coverage_ratio_per_sample', []) or [])
        failure_limit = max(1, int(os.getenv('STEP2_TRAFFIC_FAILURE_LIMIT', '20')))
        failures_raw = getattr(report, 'traffic_failures', None) or []
        failures: Tuple[TrafficParseFailure, ...] = tuple(list(failures_raw)[:failure_limit])
        return cls(ok=report.ok, errors=tuple(report.errors), warnings=tuple(getattr(report, 'warnings', [])), extras=tuple(report.extras), issues=issues, traffic_repair_hints=hints, traffic_successful_samples=getattr(report, 'traffic_successful_samples', 0), traffic_total_samples=getattr(report, 'traffic_total_samples', 0), traffic_max_bit_reached=max_bits, traffic_total_bits_per_sample=total_bits, traffic_length_total_abs_error_bits=length_err, traffic_wire_length_total_abs_error_bits=wire_len_err, traffic_total_coverage_gap_bits=coverage_gap_bits, traffic_overflow_length_bits=overflow_bits, traffic_coverage_gap_samples=coverage_gap_samples, traffic_content_covered_bits_per_sample=content_bits, traffic_content_coverage_ratio_per_sample=content_ratio, traffic_failures=failures, traffic_global_summary=None)

@dataclass
class IssueDelta:
    introduced: Dict[str, Issue]
    resolved: Dict[str, Issue]
    persisted: Dict[str, Issue]

    @property
    def introduced_count(self) -> int:
        return len(self.introduced)

    @property
    def resolved_count(self) -> int:
        return len(self.resolved)

@dataclass
class PatchAction:
    patch: Dict[str, Any]
    hash: str
    summary: Optional[str] = None

    @property
    def is_empty(self) -> bool:
        if not self.patch:
            return True
        if len(self.patch) == 1 and 'noop' in self.patch:
            return bool(self.patch.get('noop'))
        metadata = self.patch.get('patch_metadata')
        if isinstance(metadata, dict) and metadata.get('intent') == 'noop':
            return True
        return False

@dataclass
class PatchRecord:
    action: PatchAction
    reward: float
    issues_before: Dict[str, Issue]
    issues_after: Dict[str, Issue]
    introduced: Dict[str, Issue]
    resolved: Dict[str, Issue]
    rollout_reward: float = 0.0
    rollout_steps: int = 0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class PatchEvaluation:
    action: PatchAction
    tree_after: Dict[str, Any]
    validation_after: ValidationSummary
    delta: IssueDelta
    reward: float

@dataclass
class TreeState:
    tree: Dict[str, Any]
    batch_index: int
    validation: ValidationSummary
    pending_issues: Dict[str, Issue]
    history: Tuple[PatchRecord, ...] = field(default_factory=tuple)
    applied_hashes: Tuple[str, ...] = field(default_factory=tuple)
    remaining_batches: Tuple[int, ...] = field(default_factory=tuple)
    last_action: Optional[PatchAction] = None
    empty_patch_stop: bool = False
    base_node_count: int = 0
    base_edge_count: int = 0
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        normalized = normalize_protocol_tree(copy.deepcopy(self.tree))
        object.__setattr__(self, 'tree', normalized)
        validation_snapshot = ValidationSummary(ok=self.validation.ok, errors=tuple(self.validation.errors), warnings=tuple(getattr(self.validation, 'warnings', ())), extras=tuple(self.validation.extras), issues=dict(self.validation.issues), traffic_repair_hints=tuple(getattr(self.validation, 'traffic_repair_hints', ()) or ()), traffic_successful_samples=getattr(self.validation, 'traffic_successful_samples', 0), traffic_total_samples=getattr(self.validation, 'traffic_total_samples', 0), traffic_max_bit_reached=tuple(getattr(self.validation, 'traffic_max_bit_reached', ()) or ()), traffic_total_bits_per_sample=tuple(getattr(self.validation, 'traffic_total_bits_per_sample', ()) or ()), traffic_length_total_abs_error_bits=getattr(self.validation, 'traffic_length_total_abs_error_bits', 0.0), traffic_wire_length_total_abs_error_bits=getattr(self.validation, 'traffic_wire_length_total_abs_error_bits', 0.0), traffic_total_coverage_gap_bits=getattr(self.validation, 'traffic_total_coverage_gap_bits', 0.0), traffic_coverage_gap_samples=getattr(self.validation, 'traffic_coverage_gap_samples', 0), traffic_overflow_length_bits=getattr(self.validation, 'traffic_overflow_length_bits', 0.0), traffic_content_covered_bits_per_sample=tuple(getattr(self.validation, 'traffic_content_covered_bits_per_sample', ()) or ()), traffic_content_coverage_ratio_per_sample=tuple(getattr(self.validation, 'traffic_content_coverage_ratio_per_sample', ()) or ()), traffic_failures=tuple(getattr(self.validation, 'traffic_failures', ()) or ()), traffic_global_summary=None)
        object.__setattr__(self, 'validation', validation_snapshot)
        history_snapshot = tuple(self.history or ())
        object.__setattr__(self, 'history', history_snapshot)
        object.__setattr__(self, 'applied_hashes', tuple(self.applied_hashes or ()))
        issue_map = dict(self.pending_issues or {})
        object.__setattr__(self, 'pending_issues', issue_map)
        node_count = len(normalized.get('nodes', [])) if isinstance(normalized.get('nodes'), list) else 0
        edge_count = len(normalized.get('edges', [])) if isinstance(normalized.get('edges'), list) else 0
        if not self.base_node_count:
            object.__setattr__(self, 'base_node_count', node_count)
        if not self.base_edge_count:
            object.__setattr__(self, 'base_edge_count', edge_count)
        structural = _extract_structural_signature(normalized)
        object.__setattr__(self, 'hash', stable_hash({'tree': structural, 'batch': self.batch_index, 'applied': list(self.applied_hashes), 'issues': _snapshot_issues(issue_map)}))

@dataclass
class MCTSNode:
    state: TreeState
    parent: Optional['MCTSNode'] = None
    incoming: Optional[PatchEvaluation] = None
    children: Dict[str, 'MCTSNode'] = field(default_factory=dict)
    unexpanded_actions: List[PatchAction] = field(default_factory=list)
    visits: int = 0
    total_value: float = 0.0
    path_reward: float = 0.0
    terminal: bool = False

    def depth(self) -> int:
        depth = 0
        node = self.parent
        while node is not None:
            depth += 1
            node = node.parent
        return depth

    def is_terminal(self, config: MCTSConfig) -> bool:
        if self.terminal or self.state.empty_patch_stop:
            return True
        if not self.state.pending_issues:
            return True
        if self.depth() >= config.max_depth:
            return True
        return False

    def value(self) -> float:
        return self.total_value / self.visits if self.visits else 0.0

    def best_child(self, config: MCTSConfig) -> 'MCTSNode':
        best_score = float('-inf')
        best_node: Optional[MCTSNode] = None
        for child in self.children.values():
            if child.is_terminal(config):
                continue
            if child.visits == 0:
                score = float('inf')
            else:
                explore = config.exploration_constant * math.sqrt(math.log(max(self.visits, 1)) / child.visits)
                score = child.value() + explore
            if score > best_score:
                best_score = score
                best_node = child
        if best_node is None:
            raise RuntimeError('No non-terminal child available for selection')
        return best_node

    def update(self, reward: float) -> None:
        self.visits += 1
        self.total_value += reward

@dataclass
class SearchStats:
    simulations: int = 0
    expansions: int = 0
    best_reward: float = float('-inf')
    best_issue_count: Optional[int] = None
    best_records: List[PatchRecord] = field(default_factory=list)
    best_state_hash: Optional[str] = None
    terminal_found: bool = False
    empty_patch_stop: bool = False
    stagnation_stop: bool = False

@dataclass
class SearchOutcome:
    records: List[PatchRecord]
    final_tree: Dict[str, Any]
    reward: float
    issue_count: int
    terminal: bool

    @property
    def patches(self) -> List[Dict[str, Any]]:
        return [record.action.patch for record in self.records]

class _ActionCache:

    def __init__(self, directory: str) -> None:
        self.directory = directory
        self.memory: Dict[Tuple[str, str], PatchEvaluation] = {}
        if directory:
            os.makedirs(directory, exist_ok=True)

    def get(self, state_hash: str, patch_hash: str) -> Optional[PatchEvaluation]:
        return self.memory.get((state_hash, patch_hash))

    def store(self, state_hash: str, patch_hash: str, evaluation: PatchEvaluation) -> None:
        self.memory[state_hash, patch_hash] = evaluation
_SEVERITY_WEIGHTS: Dict[Severity, float] = {Severity.ERROR: 1.0, Severity.WARN: 0.4, Severity.HINT: 0.1}
_TYPE_MULTIPLIERS: Dict[IssueType, float] = {IssueType.STRUCTURE: 1.6, IssueType.SEMANTICS: 1.3, IssueType.COVERAGE: 1.4, IssueType.WARNING: 0.6}

def _issue_weight(issue: Issue) -> float:
    import re as _re
    base = _SEVERITY_WEIGHTS.get(issue.severity, 0.2)
    multiplier = _TYPE_MULTIPLIERS.get(issue.type, 1.0)
    weight = base * multiplier
    if isinstance(issue.description, str):
        m = _re.search('total_hits=(\\d+)', issue.description)
        if m:
            try:
                hits = int(m.group(1))
                weight += min(2.0, hits / 50.0)
            except Exception:
                pass
    return weight

def _score_issues(issues: Dict[str, Issue]) -> float:
    return sum((_issue_weight(issue) for issue in issues.values()))

def _build_issue_delta(before: Dict[str, Issue], after: Dict[str, Issue]) -> IssueDelta:
    before_ids = set(before.keys())
    after_ids = set(after.keys())
    introduced = {issue_id: after[issue_id] for issue_id in after_ids - before_ids}
    resolved = {issue_id: before[issue_id] for issue_id in before_ids - after_ids}
    persisted = {issue_id: after[issue_id] for issue_id in after_ids & before_ids}
    return IssueDelta(introduced=introduced, resolved=resolved, persisted=persisted)

def _summarize_patch(patch: Dict[str, Any]) -> Optional[str]:
    metadata = patch.get('patch_metadata')
    if isinstance(metadata, dict):
        description = metadata.get('description')
        if isinstance(description, str) and description.strip():
            return description.strip()
    counts: List[str] = []
    for key, label in (('new_nodes', 'new nodes'), ('node_updates', 'node updates'), ('new_edges', 'new edges'), ('edge_updates', 'edge updates'), ('edge_removes', 'edges removed'), ('nodes_to_remove', 'nodes removed')):
        items = patch.get(key)
        if isinstance(items, list) and items:
            counts.append(f'{len(items)} {label}')
    if counts:
        return ', '.join(counts)
    return None

def _should_verbose_log(config: MCTSConfig) -> bool:
    try:
        from os import getenv
    except Exception:
        return config.log_details
    return config.log_details or getenv(_MCTS_LOG_UCT_ENV, '0').lower() in {'1', 'true'}

def _issue_brief(issue_id: str, issue: Issue) -> str:
    desc = (issue.description or '').replace('\n', ' ').strip()
    if len(desc) > 120:
        desc = desc[:117] + '...'
    return f'{issue_id}: {issue.type.value}/{issue.severity.value} - {desc}'

def _dump_patch_issues(state: TreeState, evaluation: PatchEvaluation, config: MCTSConfig) -> None:
    try:
        if not _should_verbose_log(config):
            return
        action = evaluation.action
        before = state.pending_issues
        after = evaluation.validation_after.issues
        introduced = evaluation.delta.introduced
        resolved = evaluation.delta.resolved
        errors = evaluation.validation_after.errors
        extras = evaluation.validation_after.extras
        traffic_skipped = any((isinstance(x, str) and 'TRAFFIC_VALIDATION_SKIPPED' in x for x in extras or []))

        def _partition_traffic(issue_map: Dict[str, Issue]) -> Tuple[Dict[str, Issue], Dict[str, Issue]]:
            traffic = {iid: issue for iid, issue in issue_map.items() if str(iid).startswith('traffic_')}
            static = {iid: issue for iid, issue in issue_map.items() if not str(iid).startswith('traffic_')}
            return (static, traffic)
        before_static, before_traffic = _partition_traffic(before)
        after_static, after_traffic = _partition_traffic(after)
        introduced_static, introduced_traffic = _partition_traffic(introduced)
        resolved_static, resolved_traffic = _partition_traffic(resolved)
        intent = None
        source = None
        try:
            meta = action.patch.get('patch_metadata') if isinstance(action.patch, dict) else None
            if isinstance(meta, dict):
                intent = meta.get('intent') or meta.get('action')
                source = meta.get('source') or meta.get('patch_source')
        except Exception:
            intent = None

        def _trim(v: Any, limit: int) -> str:
            s = str(v).replace('\n', ' ').strip()
            return s if len(s) <= limit else s[:limit - 3] + '...'
        if not source and intent in {'traffic_repair_hint', 'traffic_inference', 'traffic_payload_fill', 'traffic_length_fit'}:
            source = str(intent)
        source_str = f" source={_trim(source or 'unknown', 60)}"
        intent_str = f' intent={_trim(intent, 80)}' if intent else ''
        header = f'[PATCH {action.hash[:8]}]{source_str} reward={evaluation.reward:.6f}{intent_str}'
        if action.summary:
            header += f' | {action.summary}'
        logger.info(header)

        def _print_section(title: str, issues: Dict[str, Issue], prefix: str='  '):
            logger.info('%s%s (%d):', prefix, title, len(issues))
            try:
                limit = int(os.getenv('STEP2_MCTS_PRINT_ISSUES_LIMIT', '40'))
            except Exception:
                limit = 40
            limit = max(0, limit)
            for idx, (iid, issue) in enumerate(sorted(issues.items())):
                if limit and idx >= limit:
                    remaining = len(issues) - limit
                    if remaining > 0:
                        line = f'{prefix}  ... ({remaining} more)'
                        logger.info(line)
                    break
                line = f'{prefix}  ' + _issue_brief(iid, issue)
                logger.info(line)
        _print_section('Issues BEFORE [SYNTAX/STATIC]', before_static)
        if not traffic_skipped:
            _print_section('Issues BEFORE [TRAFFIC]', before_traffic)
        logger.info('  Resolved (%d), Introduced (%d):', len(resolved), len(introduced))
        for iid, issue in sorted(resolved_static.items()):
            line = '    RESOLVED -> ' + _issue_brief(iid, issue)
            logger.info(line)
        for iid, issue in sorted(introduced_static.items()):
            line = '    INTRODUCED -> ' + _issue_brief(iid, issue)
            logger.info(line)
        if traffic_skipped:
            line = '    NOTE: Traffic validation skipped due to static errors; traffic deltas not evaluated.'
            logger.info(line)
        else:
            for iid, issue in sorted(resolved_traffic.items()):
                line = '    RESOLVED [TRAFFIC] -> ' + _issue_brief(iid, issue)
                logger.info(line)
            for iid, issue in sorted(introduced_traffic.items()):
                line = '    INTRODUCED [TRAFFIC] -> ' + _issue_brief(iid, issue)
                logger.info(line)
        _print_section('Issues AFTER [SYNTAX/STATIC]', after_static)
        if not traffic_skipped:
            _print_section('Issues AFTER [TRAFFIC]', after_traffic)
        if errors:
            traffic_total = int(getattr(evaluation.validation_after, 'traffic_total_samples', 0) or 0)
            group_traffic_errors = traffic_total and os.getenv('STEP2_MCTS_GROUP_TRAFFIC_ERRORS', '1').strip().lower() in {'1', 'true', 'yes', 'on'}
            if group_traffic_errors:
                normalized: List[str] = []
                for err in errors:
                    text = str(err)
                    text = re.sub('^packet\\s*#\\d+\\s*:\\s*', '', text, flags=re.IGNORECASE)
                    text = re.sub('^Packet\\s*\\d+\\s*:\\s*', '', text)
                    normalized.append(text.strip())
                counts = Counter(normalized)
                logger.info('  Errors AFTER (%d) grouped (%d):', len(errors), len(counts))
                top_n = max(1, int(os.getenv('STEP2_MCTS_GROUPED_ERRORS_TOP', '8')))
                for msg, cnt in counts.most_common(top_n):
                    line = f'    {cnt}x {msg}'
                    logger.info(line)
                if os.getenv('STEP2_MCTS_PRINT_RAW_ERRORS', '0').strip().lower() in {'1', 'true', 'yes', 'on'}:
                    logger.info('  Raw Errors AFTER (%d):', len(errors))
                    for err in errors:
                        line = '    ' + str(err)
                        logger.info(line)
            else:
                logger.info('  Errors AFTER (%d):', len(errors))
                for err in errors:
                    line = '    ' + err
                    logger.info(line)

        def _serializable(issue_map: Dict[str, Issue]) -> Dict[str, Dict[str, str]]:
            return {k: {'type': v.type.value, 'severity': v.severity.value, 'description': v.description} for k, v in issue_map.items()}
        log_mcts_event({'event': 'patch_issues', 'patch_hash': action.hash, 'summary': action.summary, 'reward': evaluation.reward, 'issues_before': _serializable(before), 'issues_after': _serializable(after), 'introduced': _serializable(introduced), 'resolved': _serializable(resolved), 'errors': list(errors), 'extras': list(extras)})
    except Exception:
        logger.debug('Failed to dump patch issues', exc_info=True)

def _should_log_uct(config: MCTSConfig) -> bool:
    try:
        from os import getenv
    except Exception:
        return config.log_uct
    return config.log_uct or getenv(_MCTS_LOG_UCT_ENV, '0').lower() in {'1', 'true'}

def _uct_components(parent_visits: int, child_visits: int, child_value: float, c: float) -> Tuple[float, float, float]:
    if child_visits == 0:
        return (child_value, float('inf'), float('inf'))
    explore = c * math.sqrt(math.log(max(parent_visits, 1)) / child_visits)
    score = child_value + explore
    return (child_value, explore, score)

def _log_uct_table(node: 'MCTSNode', config: MCTSConfig) -> None:
    if not _should_log_uct(config):
        return
    header = f'[UCT] depth={node.depth()} parent_visits={node.visits} children={len(node.children)}'
    logger.info(header)
    for h, child in node.children.items():
        exploit, explore, score = _uct_components(node.visits, child.visits, child.value(), config.exploration_constant)
        last_action = getattr(child.incoming, 'action', None)
        action_hash = getattr(last_action, 'hash', '')[:8] if last_action else ''
        summary = getattr(last_action, 'summary', None) or ''
        line = f'  child={h[:8]} act={action_hash:8s} visits={child.visits:4d} value={child.value():.6f} exploit={exploit:.6f} explore={explore:.6f} score={score:.6f} issues={len(child.state.pending_issues)} {summary}'
        logger.info(line)

def _log_selection_choice(node: 'MCTSNode', chosen: 'MCTSNode', config: MCTSConfig) -> None:
    if not _should_log_uct(config):
        return
    chosen_key = ''
    for h, c in node.children.items():
        if c is chosen:
            chosen_key = h
            break
    last_action = getattr(chosen.incoming, 'action', None)
    action_hash = getattr(last_action, 'hash', '')[:8] if last_action else ''
    summary = getattr(last_action, 'summary', None) or ''
    msg = f'[SELECT] depth={node.depth()} -> child={chosen_key[:8]} act={action_hash} issues={len(chosen.state.pending_issues)} {summary}'
    logger.info(msg)

def _log_sim_event(event: str, payload: Dict[str, Any]) -> None:
    text = f'[{event}] ' + ' '.join((f'{k}={v}' for k, v in payload.items()))
    logger.info(text)
    log_mcts_event({'event': event, **payload})

def _compute_reward(delta: IssueDelta, validation_before: ValidationSummary, validation_after: ValidationSummary, patch: Dict[str, Any], is_empty: bool, config: MCTSConfig, *, node_count: int=0, edge_count: int=0, prev_node_count: int=0, prev_edge_count: int=0, base_node_count: int=0, base_edge_count: int=0, variant_deleted: int=0) -> float:
    issues_before = len(validation_before.issues)
    issues_after = len(validation_after.issues)
    introduced = delta.introduced_count
    resolved = delta.resolved_count
    introduced_struct = sum((1 for issue in delta.introduced.values() if getattr(issue, 'type', None) == IssueType.STRUCTURE))
    resolved_struct = sum((1 for issue in delta.resolved.values() if getattr(issue, 'type', None) == IssueType.STRUCTURE))

    def _count_actions(p: Dict[str, Any]) -> int:
        if not isinstance(p, dict):
            return 0
        action_keys = ('new_nodes', 'node_updates', 'new_edges', 'edge_updates', 'nodes_to_remove', 'edge_removes')
        total = 0
        for key in action_keys:
            items = p.get(key)
            if isinstance(items, list):
                total += len(items)
        return total
    delta_issues = max(0, issues_before - issues_after)
    action_count = _count_actions(patch)
    reward = 0.0
    reward += W_RESOLVE_STRUCT * float(resolved_struct)
    reward += W_RESOLVE_SEM * float(resolved - resolved_struct)
    reward += W_ISSUE_DELTA * float(delta_issues)
    reward -= W_INTRO_STRUCT * float(introduced_struct)
    reward -= W_INTRO_SEM * float(introduced - introduced_struct)
    reward -= W_ACTION * float(action_count)
    reward -= W_DELETE_VARIANT * float(max(0, variant_deleted))
    meta = patch.get('patch_metadata') if isinstance(patch, dict) else None
    try:
        patch_intent = str((meta or {}).get('intent') or '').strip().lower()
    except Exception:
        patch_intent = ''
    succ_before = getattr(validation_before, 'traffic_successful_samples', 0)
    succ_after = getattr(validation_after, 'traffic_successful_samples', 0)
    total_before = getattr(validation_before, 'traffic_total_samples', 0)
    total_after = getattr(validation_after, 'traffic_total_samples', 0)
    traffic_present = total_before or total_after or getattr(validation_after, 'traffic_max_bit_reached', ())
    traffic_component = 0.0
    if traffic_present:
        delta_succ = succ_after - succ_before
        traffic_component += config.weight_traffic_success * float(delta_succ)
        coverage_before = _compute_traffic_coverage(validation_before)
        coverage_after = _compute_traffic_coverage(validation_after)
        traffic_component += config.weight_traffic_fix * float(coverage_after - coverage_before)
        failed_before = max(0, total_before - succ_before)
        failed_after = max(0, total_after - succ_after)
        if failed_after > failed_before:
            traffic_component -= config.weight_traffic_new * float(failed_after - failed_before)
        len_err_before = getattr(validation_before, 'traffic_length_total_abs_error_bits', 0.0) or 0.0
        len_err_after = getattr(validation_after, 'traffic_length_total_abs_error_bits', 0.0) or 0.0
        try:
            len_err_before = float(len_err_before)
            len_err_after = float(len_err_after)
        except Exception:
            len_err_before = 0.0
            len_err_after = 0.0
        if len_err_before or len_err_after:
            delta_len_err = len_err_before - len_err_after
            if delta_len_err != 0.0:
                traffic_component += config.weight_traffic_length_error * delta_len_err
        gap_before = getattr(validation_before, 'traffic_total_coverage_gap_bits', 0.0) or 0.0
        gap_after = getattr(validation_after, 'traffic_total_coverage_gap_bits', 0.0) or 0.0
        try:
            gap_before = float(gap_before)
            gap_after = float(gap_after)
        except Exception:
            gap_before = 0.0
            gap_after = 0.0
        if gap_before or gap_after:
            traffic_component += config.weight_traffic_gap * (gap_before - gap_after)
        if patch_intent == 'traffic_payload_fill':
            struct_before = sum((1 for issue in (validation_before.issues or {}).values() if getattr(issue, 'type', None) == IssueType.STRUCTURE and getattr(issue, 'severity', None) == Severity.ERROR))
            struct_after = sum((1 for issue in (validation_after.issues or {}).values() if getattr(issue, 'type', None) == IssueType.STRUCTURE and getattr(issue, 'severity', None) == Severity.ERROR))
            if struct_before or struct_after:
                traffic_component *= 0.1
        reward += traffic_component
    if introduced_struct > 0 and reward >= 0:
        reward = -W_INTRO_STRUCT * float(introduced_struct or 1)
    if introduced == 0 and issues_after < issues_before and (reward <= 0):
        reward = max(reward, 0.1 + W_ISSUE_DELTA * float(delta_issues))
    if delta.resolved_count == 0 and delta.introduced_count == 0 and (issues_after == issues_before) and (action_count == 0) and (traffic_component == 0.0):
        reward = 0.0
    return reward

def _evaluate_patch(state: TreeState, patch: Dict[str, Any], apply_patch_fn: ApplyPatchFn, validator: ValidatorFn, normalizer: Callable[[Dict[str, Any]], Dict[str, Any]], config: MCTSConfig) -> Optional[PatchEvaluation]:
    patch_hash = _hash_patch(patch)
    action = PatchAction(patch=patch, hash=patch_hash, summary=_summarize_patch(patch))
    try:
        candidate_tree = apply_patch_fn(copy.deepcopy(state.tree), patch)
    except Exception as exc:
        error = f'apply_patch_failed: {type(exc).__name__}: {exc}'
        if len(error) > 500:
            error = error[:497] + '...'
        logger.debug('apply_patch encountered an exception for %s: %s', patch_hash[:8], error, exc_info=True)
        validation_after = replace(state.validation, ok=False, errors=tuple(state.validation.errors) + (error,), issues=dict(state.pending_issues))
        delta = _build_issue_delta(state.pending_issues, validation_after.issues)
        try:
            penalty = float(getattr(config, 'hard_error_increase_penalty', 5.0) or 5.0)
        except Exception:
            penalty = 5.0
        evaluation = PatchEvaluation(action=action, tree_after=copy.deepcopy(state.tree), validation_after=validation_after, delta=delta, reward=-abs(penalty))
        _dump_patch_issues(state, evaluation, config)
        return evaluation
    try:
        candidate_tree = normalizer(copy.deepcopy(candidate_tree))
    except Exception as exc:
        logger.warning('Normalizer failed for patch %s: %s; using unnormalized candidate tree', patch_hash[:8], exc)
    report = validator(candidate_tree)
    validation_after = ValidationSummary.from_report(report)
    delta = _build_issue_delta(state.pending_issues, validation_after.issues)
    node_count = len(candidate_tree.get('nodes', [])) if isinstance(candidate_tree.get('nodes'), list) else 0
    edge_count = len(candidate_tree.get('edges', [])) if isinstance(candidate_tree.get('edges'), list) else 0
    prev_node_count = len(state.tree.get('nodes', [])) if isinstance(state.tree.get('nodes'), list) else 0
    prev_edge_count = len(state.tree.get('edges', [])) if isinstance(state.tree.get('edges'), list) else 0
    variants_before = _count_variant_nodes(state.tree)
    variants_after = _count_variant_nodes(candidate_tree)
    reward = _compute_reward(delta, state.validation, validation_after, action.patch, action.is_empty, config, node_count=node_count, edge_count=edge_count, prev_node_count=prev_node_count, prev_edge_count=prev_edge_count, base_node_count=state.base_node_count, base_edge_count=state.base_edge_count, variant_deleted=max(0, variants_before - variants_after))
    evaluation = PatchEvaluation(action=action, tree_after=candidate_tree, validation_after=validation_after, delta=delta, reward=reward)
    _dump_patch_issues(state, evaluation, config)
    return evaluation

def _extend_history(state: TreeState, evaluation: PatchEvaluation) -> Tuple[TreeState, PatchRecord]:
    record = PatchRecord(action=evaluation.action, reward=evaluation.reward, issues_before=dict(state.pending_issues), issues_after=dict(evaluation.validation_after.issues), introduced=dict(evaluation.delta.introduced), resolved=dict(evaluation.delta.resolved))
    child_state = TreeState(tree=evaluation.tree_after, batch_index=state.batch_index, validation=evaluation.validation_after, pending_issues=dict(evaluation.validation_after.issues), history=state.history + (record,), applied_hashes=state.applied_hashes + (evaluation.action.hash,), remaining_batches=state.remaining_batches, last_action=evaluation.action, empty_patch_stop=state.empty_patch_stop or (evaluation.action.is_empty and (not evaluation.validation_after.issues)), base_node_count=state.base_node_count, base_edge_count=state.base_edge_count)
    return (child_state, record)

def _run_rollout(starting_state: TreeState, patch_supplier: PatchSupplier, apply_patch_fn: ApplyPatchFn, validator: ValidatorFn, normalizer: Callable[[Dict[str, Any]], Dict[str, Any]], config: MCTSConfig) -> Tuple[float, int]:
    if config.rollout_max_steps <= 0:
        return (0.0, 0)
    total_reward = 0.0
    steps = 0
    rollout_state = starting_state
    while steps < config.rollout_max_steps:
        if not rollout_state.pending_issues:
            total_reward += config.rollout_terminal_bonus
            break
        try:
            candidate_patches = patch_supplier(rollout_state, config.patches_per_iteration)
        except Exception as exc:
            logger.debug('Rollout patch supplier failed: %s', exc)
            break
        evaluations: List[PatchEvaluation] = []
        for patch in candidate_patches:
            if not isinstance(patch, dict):
                continue
            evaluation = _evaluate_patch(rollout_state, copy.deepcopy(patch), apply_patch_fn, validator, normalizer, config)
            if evaluation is not None:
                evaluations.append(evaluation)
        if not evaluations:
            break
        if config.rollout_random_policy_chance > 0 and random.random() < config.rollout_random_policy_chance:
            chosen = random.choice(evaluations)
        else:
            chosen = max(evaluations, key=lambda ev: ev.reward)
        rollout_state, _ = _extend_history(rollout_state, chosen)
        total_reward += chosen.reward
        steps += 1
        if config.rollout_step_penalty:
            total_reward -= config.rollout_step_penalty
        if not rollout_state.pending_issues:
            total_reward += config.rollout_terminal_bonus
            break
    return (total_reward, steps)

def _load_default_apply_patch() -> ApplyPatchFn:
    from refinement import apply_patch as _apply_patch
    return _apply_patch

def _default_validator(tree: Dict[str, Any]) -> ValidationReport:
    from refinement import run_full_validation
    return run_full_validation(tree)

def _persist_state_snapshot(state: TreeState, snapshot_root: Optional[str], batch_index: int, simulation: int, node_index: int) -> None:
    if not snapshot_root:
        return
    try:
        target_dir = os.path.join(snapshot_root, f'batch_{batch_index:03d}')
        os.makedirs(target_dir, exist_ok=True)
        filename = f'sim_{simulation:05d}_node_{node_index:05d}_{state.hash[:8]}.json'
        payload = {'timestamp': datetime.now().isoformat(), 'batch_index': batch_index, 'simulation': simulation, 'node_index': node_index, 'applied_hashes': list(state.applied_hashes), 'issues': _snapshot_issues(state.pending_issues), 'protocol_tree': state.tree}
        with open(os.path.join(target_dir, filename), 'w', encoding='utf-8') as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
    except Exception:
        logger.debug('Failed to persist MCTS node snapshot', exc_info=True)

def _allowed_children(node: MCTSNode, config: MCTSConfig) -> float:
    if config.progressive_widening_k <= 0:
        return float('inf')
    visits = max(node.visits, 1)
    allowed = config.progressive_widening_k * visits ** config.progressive_widening_alpha
    allowed_int = int(math.floor(allowed))
    return max(config.progressive_widening_min_children, allowed_int)

def _can_expand_node(node: MCTSNode, config: MCTSConfig) -> bool:
    return len(node.children) < _allowed_children(node, config)

def search_for_batch(tree: Dict[str, Any], batch_index: int, *, patch_supplier: PatchSupplier, validator: Optional[ValidatorFn]=None, apply_patch_fn: Optional[ApplyPatchFn]=None, remaining_batches: Optional[Sequence[int]]=None, config: Optional[MCTSConfig]=None, max_simulations: Optional[int]=30, normalizer: Callable[[Dict[str, Any]], Dict[str, Any]]=normalize_protocol_tree, cache_dir: str='cache', evaluation_callback: Optional[EvaluationCallback]=None, node_snapshot_dir: Optional[str]=None) -> Tuple[Optional[SearchOutcome], SearchStats]:
    if config is None:
        config = MCTSConfig()
    apply_patch_fn = apply_patch_fn or _load_default_apply_patch()
    validator = validator or _default_validator
    base_tree = normalize_protocol_tree(copy.deepcopy(tree))
    base_report = validator(base_tree)
    base_summary = ValidationSummary.from_report(base_report)
    base_state = TreeState(tree=base_tree, batch_index=batch_index, validation=base_summary, pending_issues=dict(base_summary.issues), remaining_batches=tuple(remaining_batches or []))
    cache_root = os.path.join(cache_dir, 'patches')
    cache = _ActionCache(cache_root if config.allow_disk_cache else '')

    def _extract_packet_idx_from_evaluation(ev: PatchEvaluation) -> Optional[int]:
        import re as _re
        for msg in ev.validation_after.errors:
            m = _re.search('packet #(\\d+)', msg)
            if m:
                try:
                    return int(m.group(1))
                except Exception:
                    return None
        for issue in ev.delta.resolved.values():
            if isinstance(issue.description, str):
                m = _re.search('packet #(\\d+)', issue.description)
                if m:
                    try:
                        return int(m.group(1))
                    except Exception:
                        return None
        return None
    root = MCTSNode(state=base_state)
    stats = SearchStats()
    stats.best_reward = 0.0
    stats.best_issue_count = len(base_state.pending_issues)
    baseline_outcome = SearchOutcome(records=[], final_tree=copy.deepcopy(base_state.tree), reward=0.0, issue_count=len(base_state.pending_issues), terminal=not bool(base_state.pending_issues))
    best_outcome: Optional[SearchOutcome] = baseline_outcome
    stats.best_records = []
    stats.best_state_hash = base_state.hash
    last_reward_improvement_sim = 0
    log_mcts_event({'event': 'batch_start', 'batch': batch_index, 'issues': len(base_state.pending_issues), 'errors': len(base_state.validation.errors), 'max_sim': max_simulations, 'depth_limit': config.max_depth})
    if not base_state.pending_issues:
        stats.simulations = 0
        stats.best_reward = 0.0
        stats.best_issue_count = 0
        stats.best_records = []
        stats.best_state_hash = base_state.hash
        stats.terminal_found = True
        log_mcts_event({'event': 'batch_end', 'batch': batch_index, 'simulations': stats.simulations, 'best_reward': stats.best_reward, 'best_issues': stats.best_issue_count, 'terminal': stats.terminal_found, 'empty_patch_stop': stats.empty_patch_stop})
        return (best_outcome, stats)
    node_snapshot_counter = 0
    _persist_state_snapshot(base_state, node_snapshot_dir, batch_index, 0, node_snapshot_counter)
    simulation = 0
    while True:
        if config.empty_patch_early_stop and stats.empty_patch_stop:
            break
        if max_simulations is not None and simulation >= max_simulations:
            break
        simulation += 1
        stats.simulations = simulation
        if _should_log_uct(config):
            _log_sim_event('sim_start', {'sim': simulation, 'root_issues': len(root.state.pending_issues)})
        node = root
        path: List[MCTSNode] = [node]
        consecutive_neg_declines = 0
        prev_eval_reward: Optional[float] = None
        abort_simulation = False
        stop_all_simulations = False
        while True:
            if node.is_terminal(config):
                break
            if node.unexpanded_actions:
                break
            next_node: Optional[MCTSNode] = None
            if node.children:
                try:
                    if node.children and _should_log_uct(config):
                        _log_uct_table(node, config)
                    next_node = node.best_child(config)
                    if next_node is not None and _should_log_uct(config):
                        _log_selection_choice(node, next_node, config)
                except RuntimeError:
                    next_node = None
            request_new_actions = False
            if next_node is not None and (not config.repeat_expansion_on_visit):
                node = next_node
                path.append(node)
                continue
            elif next_node is not None and config.repeat_expansion_on_visit:
                request_new_actions = True
            elif next_node is None:
                request_new_actions = True
            if request_new_actions and (not _can_expand_node(node, config)):
                request_new_actions = False
                if next_node is not None:
                    node = next_node
                    path.append(node)
                    continue
                elif node.children:
                    try:
                        fallback = node.best_child(config)
                    except RuntimeError:
                        node.terminal = True
                        break
                    node = fallback
                    path.append(node)
                    continue
                else:
                    break
            if not request_new_actions:
                break
            existing_summaries = []
            for child in node.children.values():
                if child.incoming and child.incoming.action and child.incoming.action.summary:
                    existing_summaries.append(child.incoming.action.summary)
            try:
                newly_suggested = patch_supplier(node.state, config.patches_per_iteration, existing_summaries)
            except Exception as exc:
                logger.warning('Patch supplier failed: %s', exc, exc_info=True)
                break
            actions: List[PatchAction] = []
            for patch in newly_suggested:
                if not isinstance(patch, dict):
                    continue
                action = PatchAction(patch=patch, hash=_hash_patch(patch), summary=_summarize_patch(patch))
                actions.append(action)
            if _should_log_uct(config):
                _log_sim_event('expand', {'sim': simulation, 'depth': node.depth(), 'admissible': len(actions)})
            if actions:
                node.unexpanded_actions.extend(actions)
                stats.expansions += 1
                break
            if not node.children or all((child.is_terminal(config) for child in node.children.values())):
                node.terminal = True
            break
        if node.is_terminal(config):
            node.terminal = True
            continue
        if not node.unexpanded_actions:
            node.terminal = True
            continue
        action = node.unexpanded_actions.pop(0)
        evaluation = cache.get(node.state.hash, action.hash)
        if evaluation is None:
            evaluation = _evaluate_patch(node.state, copy.deepcopy(action.patch), apply_patch_fn, validator, normalizer, config)
            if _should_log_uct(config) and evaluation is not None:
                _log_sim_event('rollout_eval', {'sim': simulation, 'reward': f'{evaluation.reward:.6f}', 'resolved': evaluation.delta.resolved_count, 'introduced': evaluation.delta.introduced_count, 'issues_after': len(evaluation.validation_after.issues), 'action': evaluation.action.hash[:8]})
            if evaluation is None:
                continue
            cache.store(node.state.hash, action.hash, evaluation)
        if evaluation_callback is not None:
            try:
                evaluation_callback(evaluation)
            except Exception as exc:
                logger.warning('Evaluation callback raised: %s', exc)
        if evaluation is not None:
            if evaluation.reward < 0 and prev_eval_reward is not None and (evaluation.reward < prev_eval_reward):
                consecutive_neg_declines += 1
            else:
                consecutive_neg_declines = 0
            prev_eval_reward = evaluation.reward
            if consecutive_neg_declines >= 3:
                logger.info('Aborting simulation %s after 3 consecutive decreasing negative rewards', simulation)
                abort_simulation = True
        if abort_simulation:
            break
        if evaluation.reward > 0 and evaluation.validation_after.ok and hasattr(patch_supplier, 'fix_history'):
            packet_idx = _extract_packet_idx_from_evaluation(evaluation)
            meta = evaluation.action.patch.get('patch_metadata') if isinstance(evaluation.action.patch, dict) else {}
            if isinstance(meta, dict):
                strategy_desc = meta.get('description') or meta.get('intent')
            else:
                strategy_desc = None
            resolved_issue = next(iter(evaluation.delta.resolved.values()), None)
            error_label = resolved_issue.description if resolved_issue else 'prior issue resolved'
            patch_supplier.fix_history.append({'packet_idx': packet_idx if packet_idx is not None else '?', 'error': error_label, 'action': evaluation.action.summary or strategy_desc or 'patch applied', 'strategy': strategy_desc or evaluation.action.summary})
        child_state, record = _extend_history(node.state, evaluation)
        if action.hash in node.children:
            child_node = node.children[action.hash]
            child_node.path_reward = node.path_reward + evaluation.reward
        else:
            child_node = MCTSNode(state=child_state, parent=node, incoming=evaluation, path_reward=node.path_reward + evaluation.reward)
            child_node.terminal = child_state.empty_patch_stop
            node.children[action.hash] = child_node
        path.append(child_node)
        node_snapshot_counter += 1
        _persist_state_snapshot(child_state, node_snapshot_dir, batch_index, simulation, node_snapshot_counter)
        if _should_log_uct(config):
            _log_sim_event('expand_attach', {'sim': simulation, 'child': evaluation.action.hash[:8], 'reward': f'{evaluation.reward:.6f}', 'issues_after': len(child_state.pending_issues)})
        if not child_state.pending_issues:
            best_outcome = SearchOutcome(records=list(child_state.history), final_tree=copy.deepcopy(child_state.tree), reward=child_node.path_reward, issue_count=0, terminal=True)
            stats.best_records = list(child_state.history)
            stats.best_reward = child_node.path_reward
            stats.best_issue_count = 0
            stats.best_state_hash = child_state.hash
            stats.terminal_found = True
            abort_simulation = True
            stop_all_simulations = True
        if abort_simulation:
            break
        rollout_reward, rollout_steps = _run_rollout(child_state, patch_supplier, apply_patch_fn, validator, normalizer, config)
        if _should_log_uct(config) and config.rollout_max_steps > 0:
            _log_sim_event('rollout', {'sim': simulation, 'steps': rollout_steps, 'rollout_reward': f'{rollout_reward:.6f}'})
        reward = evaluation.reward + rollout_reward
        record.rollout_reward = rollout_reward
        record.rollout_steps = rollout_steps
        child_node.path_reward = node.path_reward + reward
        if _should_log_uct(config):
            for visited in reversed(path):
                visited.update(reward)
                _log_sim_event('backprop', {'sim': simulation, 'depth': visited.depth(), 'visits': visited.visits, 'value': f'{visited.value():.6f}'})
        else:
            for visited in reversed(path):
                visited.update(reward)
        if child_state.empty_patch_stop and config.empty_patch_early_stop:
            stats.empty_patch_stop = True
        issue_count = len(child_state.pending_issues)
        should_update = False
        if best_outcome is None:
            should_update = True
        else:
            current_best_reward = stats.best_reward if stats.best_reward is not None else float('-inf')
            if child_node.path_reward > current_best_reward + config.min_reward_improvement:
                should_update = True
            elif child_node.is_terminal(config) and child_node.path_reward > current_best_reward - config.min_reward_improvement:
                should_update = True
        if should_update:
            best_outcome = SearchOutcome(records=list(child_state.history), final_tree=copy.deepcopy(child_state.tree), reward=child_node.path_reward, issue_count=issue_count, terminal=child_node.is_terminal(config))
            stats.best_records = list(child_state.history)
            stats.best_reward = child_node.path_reward
            stats.best_issue_count = issue_count
            stats.best_state_hash = child_state.hash
            last_reward_improvement_sim = simulation
            if child_node.is_terminal(config) and child_node.path_reward > 0:
                stats.terminal_found = True
        if config.reward_stagnation_limit is not None:
            window = simulation - last_reward_improvement_sim
            stats.stagnation_stop = window >= config.reward_stagnation_limit
        if _should_log_uct(config):
            _log_sim_event('sim_end', {'sim': simulation, 'best_reward': f'{stats.best_reward:.6f}' if stats.best_reward is not None else 'None', 'best_issue_count': stats.best_issue_count if stats.best_issue_count is not None else -1})
        if stats.terminal_found or stats.empty_patch_stop or stats.stagnation_stop:
            break
        if stats.best_issue_count == 0:
            logger.info('MCTS found a solution with 0 issues. Stopping early.')
            break
        if stop_all_simulations:
            break
    log_mcts_event({'event': 'batch_end', 'batch': batch_index, 'simulations': stats.simulations, 'best_reward': stats.best_reward, 'best_issues': stats.best_issue_count, 'terminal': stats.terminal_found, 'empty_patch_stop': stats.empty_patch_stop})
    return (best_outcome, stats)
