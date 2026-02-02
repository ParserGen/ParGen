import hashlib
import os
import json
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import ast
from collections import Counter
from .traffic_errors import TrafficParseFailure
try:
    from z3 import Solver, BitVec, BitVecVal, BoolVal, And, Or, Not, If, sat, unsat, ExprRef, BoolRef, Z3Exception
except ImportError:
    try:
        from z3 import z3 as z3_core
    except ImportError as exc:
        raise ImportError("The 'z3-solver' package is required; install it via `pip install z3-solver`.") from exc
    Solver = z3_core.Solver
    BitVec = z3_core.BitVec
    BitVecVal = z3_core.BitVecVal
    BoolVal = z3_core.BoolVal
    And = z3_core.And
    Or = z3_core.Or
    Not = z3_core.Not
    If = z3_core.If
    sat = z3_core.sat
    unsat = z3_core.unsat
    ExprRef = z3_core.ExprRef
    BoolRef = z3_core.BoolRef
    Z3Exception = z3_core.Z3Exception

class MessageType(Enum):
    REQUEST = 'request'
    RESPONSE = 'response'
    BIDIRECTIONAL = 'bidirectional'

@dataclass
class NodeContext:
    node_id: int
    name: str
    node_type: str
    message_type: MessageType
    parent_id: Optional[int]
    children_ids: List[int]
    start_sym: Any
    size_sym: Any
    is_variant: bool
    controlling_selector: Optional[int]
    activation_condition: Optional[Any]
    start_expr: Any
    size_expr: Any

class Severity(Enum):
    ERROR = 'ERROR'
    WARN = 'WARN'
    HINT = 'HINT'

@dataclass(frozen=True)
class ValidationError:
    category: str
    description: str
    code: Optional[str] = None
    severity: Severity = field(default=Severity.ERROR)
    node_id: Optional[int] = None
    edge_id: Optional[str] = None

class IssueType(Enum):
    STRUCTURE = 'STRUCTURE'
    SEMANTICS = 'SEMANTICS'
    COVERAGE = 'COVERAGE'
    WARNING = 'WARNING'

@dataclass(frozen=True)
class FixHint:
    action: str
    details: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class TargetRef:
    kind: str
    identifier: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Issue:
    id: str
    type: IssueType
    severity: Severity
    description: str
    code: Optional[str] = None
    target: Optional[TargetRef] = None
    suggestions: Tuple[FixHint, ...] = tuple()
HARD_ERROR_TYPES = {'STRUCTURE'}
HARD_ERROR_CODES = {'UNBOUND_LENGTH', 'PARENT_OVERFLOW', 'NEGATIVE_SIZE', 'INVALID_SELECTOR_PARENT', 'INVALID_VARIANT_PARENT'}
STRICT_COVERAGE = os.getenv('VALIDATOR_STRICT_COVERAGE', '0') == '1'

def _normalize_issue_type_name(t: Any) -> str:
    if isinstance(t, Enum):
        return t.name
    return str(t)

def _normalize_issue_code_name(code_raw: Any) -> str:
    if code_raw is None:
        return ''
    if isinstance(code_raw, Enum):
        return code_raw.name
    return str(code_raw)

def is_hard_error(issue: Issue) -> bool:
    t_name = _normalize_issue_type_name(getattr(issue, 'type', None))
    code_name = _normalize_issue_code_name(getattr(issue, 'code', None))
    if code_name == 'PARENT_CHILD_SIZE_RELATION_UNBOUND':
        return False
    if t_name in HARD_ERROR_TYPES:
        return True
    if code_name in HARD_ERROR_CODES:
        return True
    if t_name == 'COVERAGE' and STRICT_COVERAGE:
        return True
    return False

@dataclass
class ValidationReport:
    ok: bool
    errors: List[str]
    warnings: List[str]
    extras: List[str]
    issues: Dict[str, Issue]
    traffic_failures: List[TrafficParseFailure] = field(default_factory=list)
    traffic_repair_hints: List[Dict[str, Any]] = field(default_factory=list)
ALLOWED_PARENT_TYPES: Dict[str, Set[str]] = {'message': {'selector', 'variant', 'container', 'protocol', 'message'}, 'selector': {'container', 'protocol', 'message'}, 'variant': {'selector'}}

class SyntaxValidator:

    def __init__(self):
        self.nodes_by_id: Dict[int, Dict] = {}
        self.edges: List[Dict] = []
        self.errors: List[ValidationError] = []
        self.structured_issues: Dict[str, Issue] = {}
        self.solver = Solver()
        self.bit_starts = {}
        self.size_bits = {}
        self.values = {}
        self.contexts: Dict[int, NodeContext] = {}
        self.variant_groups: Dict[int, List[int]] = {}
        self.variant_conditions: Dict[int, Any] = {}
        self.variant_raw_formula: Dict[int, Optional[str]] = {}
        self.controlled_by_selector: Dict[int, int] = {}
        self.selector_aliases: Dict[Any, Any] = {}
        self.selector_alias_groups: Dict[Any, List[Any]] = {}
        self.expression_traces: Dict[int, List[Dict[str, Any]]] = {}
        self.coverage_matrices: Dict[int, Dict[MessageType, Dict[int, List[str]]]] = {}
        self.expression_report_lines: List[str] = []
        self.warning_report_lines: List[str] = []
        self._current_constraint_node: Optional[int] = None

    def _node_type_lower(self, node_id: Any) -> str:
        if node_id is None:
            return ''
        node = self.nodes_by_id.get(node_id)
        if node is None:
            node = self.nodes_by_id.get(str(node_id))
        if node is None:
            try:
                node = self.nodes_by_id.get(int(node_id))
            except Exception:
                node = None
        return str((node or {}).get('node_type') or '').lower()

    def _is_selector_node(self, node_id: Any) -> bool:
        return self._node_type_lower(node_id) == 'selector'

    @staticmethod
    def _extract_val_refs(expr: str) -> List[int]:
        refs: List[int] = []
        for match in re.finditer('val\\(\\s*(\\d+)\\s*\\)', expr):
            try:
                refs.append(int(match.group(1)))
            except Exception:
                continue
        return refs

    @staticmethod
    def _maybe_int(expr: Any) -> Optional[int]:
        if isinstance(expr, int):
            return expr
        if isinstance(expr, str):
            stripped = expr.strip()
            if not stripped:
                return None
            try:
                return int(stripped, 0)
            except ValueError:
                return None
        return None

    @staticmethod
    def _id_sort_key(value: Any) -> Tuple[int, Any]:
        try:
            return (0, int(value))
        except Exception:
            return (1, str(value))

    def _lookup_node_any(self, node_id: Any) -> Optional[Dict[str, Any]]:
        if node_id is None:
            return None
        if node_id in self.nodes_by_id:
            return self.nodes_by_id.get(node_id)
        try:
            as_int = int(node_id)
        except Exception:
            as_int = None
        if as_int is not None and as_int in self.nodes_by_id:
            return self.nodes_by_id.get(as_int)
        as_str = str(node_id)
        return self.nodes_by_id.get(as_str)

    def _compute_selector_aliases(self) -> None:
        self.selector_aliases = {}
        self.selector_alias_groups = {}
        selector_ids: Set[Any] = set()
        for edge in self.edges:
            if edge.get('rel') != 'condition_on':
                continue
            src = edge.get('src')
            if src is not None:
                selector_ids.add(src)
        groups: Dict[Tuple[str, int, int, str], List[Any]] = {}
        for sid in selector_ids:
            node = self._lookup_node_any(sid)
            if not node:
                continue
            start = self._maybe_int(node.get('bit_start'))
            size = self._maybe_int(node.get('size_bits'))
            if start is None or size is None:
                continue
            msg = str(node.get('message_type') or 'bidirectional').lower()
            dtype = str(node.get('data_type') or '').lower()
            sig = (msg, start, size, dtype)
            groups.setdefault(sig, []).append(sid)
        for sig, ids in groups.items():
            if len(ids) < 2:
                continue
            selector_like = [i for i in ids if self._node_type_lower(i) == 'selector']
            if selector_like:
                canonical = sorted(selector_like, key=self._id_sort_key)[0]
            else:
                canonical = sorted(ids, key=self._id_sort_key)[0]
            self.selector_alias_groups[canonical] = sorted(ids, key=self._id_sort_key)
            for sid in ids:
                self.selector_aliases[sid] = canonical

    def _canonical_selector_id(self, selector_id: Any) -> Any:
        if selector_id is None:
            return None
        return self.selector_aliases.get(selector_id, selector_id)

    def _add_selector_alias_value_constraints(self) -> None:
        for sid, canonical in self.selector_aliases.items():
            if sid == canonical:
                continue
            if sid not in self.values or canonical not in self.values:
                continue
            try:
                self.solver.add(self.values[sid] == self.values[canonical])
            except Exception:
                continue

    def _add_error(self, category: str, description: str, *, node_id: Optional[int]=None, edge_id: Optional[str]=None, severity: Severity=Severity.ERROR, code: Optional[str]=None):
        self.errors.append(ValidationError(category=category, description=description, code=code, severity=severity, node_id=node_id, edge_id=edge_id))

    @staticmethod
    def _classify_issue_type(category: str, severity: Severity) -> IssueType:
        lowered = (category or '').lower()
        if 'coverage' in lowered:
            return IssueType.COVERAGE
        if 'semantic' in lowered or 'constraint' in lowered:
            return IssueType.SEMANTICS
        if severity != Severity.ERROR:
            return IssueType.WARNING
        return IssueType.STRUCTURE

    @staticmethod
    def _build_issue_target(node_id: Optional[int], edge_id: Optional[str]) -> Optional[TargetRef]:
        if node_id is not None:
            return TargetRef('node', str(node_id))
        if edge_id:
            return TargetRef('edge', edge_id)
        return None

    @staticmethod
    def _make_issue_id(issue_type: IssueType, severity: Severity, description: str, target: Optional[TargetRef]) -> str:
        target_payload = {'kind': target.kind if target else None, 'id': target.identifier if target else None}
        payload = json.dumps({'type': issue_type.value, 'severity': severity.value, 'description': description, 'target': target_payload}, ensure_ascii=False, sort_keys=True)
        digest = hashlib.sha1(payload.encode('utf-8')).hexdigest()[:12]
        return f'issue_{digest}'

    def validate(self, tree: Dict[str, Any]) -> Tuple[bool, List[str]]:
        self.errors = []
        self.expression_traces = {}
        self.coverage_matrices = {}
        self.coverage_report_lines = []
        self.coverage_gap_lines = []
        self.expression_report_lines = []
        self.warning_report_lines = []
        self.structured_issues = {}
        self.nodes_by_id = {n['node_id']: n for n in tree.get('nodes', [])}
        self.edges = tree.get('edges', [])
        if not self.nodes_by_id:
            return (False, ['Empty protocol tree'])
        self._validate_tree_invariants(tree)
        self._compute_selector_aliases()
        self._initialize_z3()
        self._add_selector_alias_value_constraints()
        self._analyze_variants()
        self._build_contexts()
        self._add_constraints()
        self._validate_structure()
        self._validate_references()
        self._validate_semantic_overlaps()
        self._validate_branch_references()
        self._validate_layout_boundaries()
        self._validate_continuity()
        self._validate_size_consistency()
        self._validate_variant_exclusivity()
        self._validate_selector_variants()
        self._validate_variant_alignment()
        self._validate_condition_on_formulas()
        self._validate_selector_constraint_compatibility()
        self._build_coverage_matrices()
        self._validate_length_strategies()
        self._validate_constraints()
        self._validate_reachability()
        self._validate_circular_dependencies()
        self._validate_length_edges_semantics()
        error_descriptions: List[str] = []
        warning_descriptions: List[str] = []
        issues: Dict[str, Issue] = {}
        for error in self.errors:
            desc = f'{error.category}: '
            if error.node_id is not None:
                node = self.nodes_by_id.get(error.node_id, {})
                name = node.get('name', f'node_{error.node_id}')
                desc += f'{name}(ID:{error.node_id}): '
            elif error.edge_id:
                desc += f'{error.edge_id}: '
            desc += error.description
            issue_type = self._classify_issue_type(error.category, error.severity)
            target = self._build_issue_target(error.node_id, error.edge_id)
            base_issue_id = self._make_issue_id(issue_type, error.severity, desc, target)
            issue_id = base_issue_id
            dedupe_index = 1
            while issue_id in issues:
                issue_id = f'{base_issue_id}_{dedupe_index}'
                dedupe_index += 1
            header_parts = [f'[{issue_type.value}]', f'[{error.severity.value}]', f"[{error.code or 'UNKNOWN'}]"]
            node_label = ''
            if error.node_id is not None:
                node = self.nodes_by_id.get(error.node_id, {})
                name = node.get('name', f'node_{error.node_id}')
                node_label = f' node={name}(ID:{error.node_id})'
            formatted_desc = ''.join(header_parts) + node_label + '\n' + error.description
            issue = Issue(id=issue_id, type=issue_type, severity=error.severity, code=error.code, description=formatted_desc, target=target)
            issues[issue_id] = issue
            if error.severity == Severity.ERROR:
                error_descriptions.append(formatted_desc)
            else:
                warning_descriptions.append(formatted_desc)
        passes = len(error_descriptions) == 0
        self.coverage_report_lines = self._format_coverage_reports()
        self.expression_report_lines = self._format_expression_reports()
        if warning_descriptions:
            self.warning_report_lines = [f'WARNING: {msg}' for msg in warning_descriptions]
        coverage_severity = Severity.ERROR if STRICT_COVERAGE else Severity.WARN
        for line in self.coverage_gap_lines:
            issue_type = IssueType.COVERAGE
            base_issue_id = self._make_issue_id(issue_type, coverage_severity, line, None)
            issue_id = base_issue_id
            dedupe_index = 1
            while issue_id in issues:
                issue_id = f'{base_issue_id}_{dedupe_index}'
                dedupe_index += 1
            issues[issue_id] = Issue(id=issue_id, type=issue_type, severity=coverage_severity, description=line)
        for line in self.warning_report_lines:
            issue_type = IssueType.WARNING
            base_issue_id = self._make_issue_id(issue_type, Severity.WARN, line, None)
            issue_id = base_issue_id
            dedupe_index = 1
            while issue_id in issues:
                issue_id = f'{base_issue_id}_{dedupe_index}'
                dedupe_index += 1
            issues[issue_id] = Issue(id=issue_id, type=issue_type, severity=Severity.WARN, description=line)
        error_descriptions = [iss.description for iss in issues.values() if is_hard_error(iss)]
        self.structured_issues = issues
        return (len(error_descriptions) == 0, error_descriptions)

    def _validate_selector_constraint_compatibility(self) -> None:

        def _parse_enum_values(constraints: Any) -> Optional[Set[int]]:
            if not isinstance(constraints, list):
                return None
            allowed: Set[int] = set()
            for raw in constraints:
                if not isinstance(raw, str):
                    continue
                text = raw.strip()
                if not text:
                    continue
                m = re.search('enum\\s*:\\s*(.+)', text, flags=re.IGNORECASE)
                if not m:
                    continue
                for part in re.split('[|,]', m.group(1)):
                    token = part.strip()
                    if not token:
                        continue
                    try:
                        allowed.add(int(token, 0))
                    except Exception:
                        continue
            return allowed if allowed else None

        def _extract_condition_values(selector_id: int, formula: Any) -> Set[int]:
            if not isinstance(formula, str) or not formula.strip():
                return set()
            pattern = f'val\\(\\s*{re.escape(str(selector_id))}\\s*\\)\\s*==\\s*(-?(?:0x[0-9a-fA-F]+|\\d+))'
            values: Set[int] = set()
            for m in re.finditer(pattern, formula):
                token = m.group(1)
                try:
                    values.add(int(token, 0))
                except Exception:
                    continue
            return values
        selector_nodes: List[int] = []
        for nid, node in (self.nodes_by_id or {}).items():
            try:
                if str(node.get('node_type', '') or '').lower() == 'selector':
                    selector_nodes.append(int(nid))
            except Exception:
                continue
        for sid in selector_nodes:
            node = self.nodes_by_id.get(sid) or {}
            allowed = _parse_enum_values(node.get('constraints'))
            if not allowed:
                continue
            referenced: Set[int] = set()
            dsts: List[int] = []
            for e in self.edges or []:
                if not isinstance(e, dict):
                    continue
                if str(e.get('rel', '') or '').lower() != 'condition_on':
                    continue
                try:
                    if int(e.get('src')) != sid:
                        continue
                except Exception:
                    continue
                referenced |= _extract_condition_values(sid, e.get('formula'))
                try:
                    dsts.append(int(e.get('dst')))
                except Exception:
                    continue
            missing = referenced - allowed if referenced else set()
            if not missing:
                continue
            shown_missing = sorted(missing)[:10]
            suffix = '...' if len(missing) > len(shown_missing) else ''
            desc = f'Selector enum constraint excludes values referenced by outgoing condition_on edges. enum_allowed={sorted(allowed)} missing={shown_missing}{suffix} condition_dsts={sorted(set(dsts))[:10]}'
            self._add_error('CONSTRAINT', desc, node_id=sid, severity=Severity.ERROR, code='ENUM_EXCLUDES_CONDITION_VALUES')

    def _validate_tree_invariants(self, tree: Dict[str, Any]) -> None:
        nodes = tree.get('nodes', []) or []
        edges = tree.get('edges', []) or []
        id_counter: Counter[str] = Counter()
        for node in nodes:
            nid = node.get('node_id')
            if nid is None:
                continue
            id_counter[str(nid)] += 1
        for nid_str, count in id_counter.items():
            if count > 1:
                self._add_error(category='Structure', description=f'Duplicate node_id detected: {nid_str} appears {count} times', code='INVARIANT_VIOLATION')
        node_lookup: Dict[str, Dict[str, Any]] = {str(n.get('node_id')): n for n in nodes if n.get('node_id') is not None}
        root_candidates = [n for n in nodes if n.get('parent_id') in (None, '', -1)]
        if len(root_candidates) > 1:
            self._add_error(category='Structure', description=f"Multiple root nodes found: {[n.get('node_id') for n in root_candidates]}", code='INVARIANT_VIOLATION')
        for node in nodes:
            nid = node.get('node_id')
            nid_str = str(nid)
            children = node.get('children_ids')
            if children is None:
                continue
            if not isinstance(children, list):
                self._add_error(category='Structure', description=f'children_ids of node {nid} is not a list', node_id=nid, code='INVARIANT_VIOLATION')
                continue
            seen_children: Set[str] = set()
            for child_id in children:
                child_key = str(child_id)
                if child_key in seen_children:
                    self._add_error(category='Structure', description=f'Duplicate child_id {child_id} found in children_ids of node {nid}', node_id=nid, code='INVARIANT_VIOLATION')
                    continue
                seen_children.add(child_key)
                child = node_lookup.get(child_key)
                if child is None:
                    self._add_error(category='Structure', description=f'Child {child_id} listed under parent {nid} does not exist', node_id=nid, code='INVARIANT_VIOLATION')
                    continue
                if str(child.get('parent_id')) != nid_str:
                    self._add_error(category='Structure', description=f"Child {child_id} parent_id={child.get('parent_id')} inconsistent with parent {nid}", node_id=nid, code='INVARIANT_VIOLATION')
        for node in nodes:
            parent_id = node.get('parent_id')
            if parent_id is None or parent_id == '':
                continue
            if str(parent_id) not in node_lookup:
                self._add_error(category='Structure', description=f"Node {node.get('node_id')} references missing parent_id {parent_id}", node_id=node.get('node_id'), code='INVARIANT_VIOLATION')
                continue
            parent = node_lookup[str(parent_id)]
            children = parent.get('children_ids') or []
            if str(node.get('node_id')) not in {str(c) for c in children}:
                self._add_error(category='Structure', description=f"Node {node.get('node_id')} has parent {parent_id} but is not present in parent.children_ids", node_id=node.get('node_id'), code='INVARIANT_VIOLATION')
        for edge in edges:
            src = edge.get('src')
            dst = edge.get('dst')
            missing: List[str] = []
            if src is None or str(src) not in node_lookup:
                missing.append(f'src {src}')
            if dst is None or str(dst) not in node_lookup:
                missing.append(f'dst {dst}')
            if missing:
                self._add_error(category='Structure', description=f"Edge {edge.get('rel')} references missing node(s): {', '.join(missing)}", code='INVARIANT_VIOLATION')

    def _initialize_z3(self):
        for node_id in self.nodes_by_id:
            self.bit_starts[node_id] = BitVec(f'start_{node_id}', 32)
            self.size_bits[node_id] = BitVec(f'size_{node_id}', 32)
            self.values[node_id] = BitVec(f'val_{node_id}', 32)
            self.solver.add(self.bit_starts[node_id] >= 0)
            self.solver.add(self.size_bits[node_id] >= 0)
            self.solver.add(self.values[node_id] >= 0)
            self.solver.add(self.values[node_id] <= 65535)

    def _analyze_variants(self):
        for edge in self.edges:
            if edge.get('rel') == 'condition_on':
                src = self._canonical_selector_id(edge.get('src'))
                dst = edge.get('dst')
                formula = edge.get('formula', '')
                if src not in self.variant_groups:
                    self.variant_groups[src] = []
                self.variant_groups[src].append(dst)
                self.controlled_by_selector[dst] = src
                if formula:
                    condition = self._parse_condition(formula)
                    if condition is not None:
                        if dst in self.variant_conditions and self.variant_conditions[dst] is not None:
                            self.variant_conditions[dst] = Or(self.variant_conditions[dst], condition)
                            if self.variant_raw_formula.get(dst):
                                self.variant_raw_formula[dst] = f'({self.variant_raw_formula[dst]}) OR ({self._normalize_condition_formula(formula)})'
                            else:
                                self.variant_raw_formula[dst] = self._normalize_condition_formula(formula)
                        else:
                            self.variant_conditions[dst] = condition
                            self.variant_raw_formula[dst] = self._normalize_condition_formula(formula)
                    else:
                        self.variant_raw_formula[dst] = self._normalize_condition_formula(formula)
                else:
                    self.variant_conditions[dst] = None
                    self.variant_raw_formula[dst] = None

    def _parse_condition(self, formula: str) -> Any:
        try:
            prepared = self._expand_condition_shortcuts(formula)
            prepared = re.sub('val\\((\\d+)\\)', 'values[\\1]', prepared)
            prepared = prepared.replace('&&', ' and ')
            prepared = prepared.replace('||', ' or ')
            prepared = re.sub('\\bAND\\b', ' and ', prepared, flags=re.IGNORECASE)
            prepared = re.sub('\\bOR\\b', ' or ', prepared, flags=re.IGNORECASE)
            prepared = re.sub('\\bNOT\\b', ' not ', prepared, flags=re.IGNORECASE)
            prepared = re.sub('(?<![=!<>])!(?!=)', ' not ', prepared)
            tree = ast.parse(prepared, mode='eval')
            return self._eval_condition_ast(tree.body)
        except Exception:
            return None

    def _split_logic_args(self, expr: str) -> List[str]:
        args: List[str] = []
        depth = 0
        buf: List[str] = []
        for ch in expr:
            if ch == '(':
                depth += 1
                buf.append(ch)
            elif ch == ')':
                if depth > 0:
                    depth -= 1
                buf.append(ch)
            elif ch == ',' and depth == 0:
                item = ''.join(buf).strip()
                if item:
                    args.append(item)
                buf = []
            else:
                buf.append(ch)
        tail = ''.join(buf).strip()
        if tail:
            args.append(tail)
        return args

    def _rewrite_logic_function_calls(self, formula: str) -> str:
        if not formula:
            return formula
        pattern = re.compile('\\b(OR|AND)\\s*\\(', re.IGNORECASE)
        result = formula
        search_from = 0
        while True:
            match = pattern.search(result, search_from)
            if not match:
                break
            func = match.group(1).lower()
            joiner = ' or ' if func == 'or' else ' and '
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
            pieces = self._split_logic_args(args_blob)
            cleaned = [p.strip() for p in pieces if p.strip()]
            if len(cleaned) < 2:
                search_from = match.end()
                continue
            replacement = '(' + joiner.join(cleaned) + ')'
            result = result[:start] + replacement + result[args_end + 1:]
            search_from = start + len(replacement)
        return result

    def _normalize_condition_formula(self, formula: str) -> str:
        if not isinstance(formula, str):
            return formula
        text = formula.strip()
        if not text:
            return text
        text = text.replace('&&', ' and ').replace('||', ' or ')
        text = self._rewrite_logic_function_calls(text)
        text = re.sub('\\bAND\\b', ' and ', text, flags=re.IGNORECASE)
        text = re.sub('\\bOR\\b', ' or ', text, flags=re.IGNORECASE)
        text = re.sub('(?<![<>=!])=(?!=)', '==', text)
        return text

    def _expand_condition_shortcuts(self, formula: str) -> str:

        def expand_match(match: re.Match) -> str:
            node_id = match.group('node')
            first = match.group('first')
            rest = match.group('rest')
            values = [first]
            values.extend(re.findall('-?\\d+', rest))
            return ' || '.join([f'val({node_id}) == {value}' for value in values])
        pattern = re.compile('val\\((?P<node>\\d+)\\)\\s*==\\s*(?P<first>-?\\d+)\\s*(?P<rest>(?:\\|\\|\\s*-?\\d+)+)')
        expanded = pattern.sub(expand_match, formula)
        return self._normalize_condition_formula(expanded)

    def _eval_condition_ast(self, node: ast.AST) -> Any:
        if isinstance(node, ast.BoolOp):
            values = [self._eval_condition_ast(v) for v in node.values]
            values = [self._ensure_bool(v) for v in values]
            if isinstance(node.op, ast.And):
                return And(*values) if values else True
            if isinstance(node.op, ast.Or):
                return Or(*values) if values else False
            raise ValueError('Unsupported boolean operator')
        if isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                return Not(self._ensure_bool(self._eval_condition_ast(node.operand)))
            if isinstance(node.op, ast.USub):
                return -self._ensure_numeric(self._eval_condition_ast(node.operand))
            raise ValueError('Unsupported unary operator')
        if isinstance(node, ast.Compare):
            left = self._eval_condition_ast(node.left)
            result = None
            current_left = left
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval_condition_ast(comparator)
                expr = self._apply_comparison(op, current_left, right)
                result = expr if result is None else And(result, expr)
                current_left = right
            return result
        if isinstance(node, ast.IfExp):
            condition = self._eval_condition_ast(node.test)
            true_expr = self._eval_condition_ast(node.body)
            false_expr = self._eval_condition_ast(node.orelse)
            return self._build_if_expression(condition, true_expr, false_expr)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == 'If':
                if len(node.args) != 3:
                    raise ValueError('If() requires three arguments')
                cond = self._eval_condition_ast(node.args[0])
                true_expr = self._eval_condition_ast(node.args[1])
                false_expr = self._eval_condition_ast(node.args[2])
                return self._build_if_expression(cond, true_expr, false_expr)
            if isinstance(node.func, ast.Name) and node.func.id in {'max', 'min'}:
                if not node.args:
                    raise ValueError(f'{node.func.id}() requires at least one argument')
                args = [self._ensure_numeric(self._eval_condition_ast(arg)) for arg in node.args]
                acc = args[0]
                for nxt in args[1:]:
                    if node.func.id == 'max':
                        acc = If(acc >= nxt, acc, nxt)
                    else:
                        acc = If(acc <= nxt, acc, nxt)
                return acc
            if isinstance(node.func, ast.Name) and node.func.id == 'abs':
                if len(node.args) != 1:
                    raise ValueError('abs() requires exactly one argument')
                val = self._ensure_numeric(self._eval_condition_ast(node.args[0]))
                return If(val >= 0, val, -val)
            if isinstance(node.func, ast.Name) and node.func.id == 'ceil':
                if len(node.args) != 1:
                    raise ValueError('ceil() requires exactly one argument')
                arg = node.args[0]
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Div):
                    numerator = self._eval_condition_ast(arg.left)
                    denominator = self._eval_condition_ast(arg.right)
                    num_val = self._ensure_numeric(numerator)
                    den_val = self._ensure_numeric(denominator)
                    return (num_val + den_val - BitVecVal(1, 32)) / den_val
                return self._ensure_numeric(self._eval_condition_ast(arg))
            raise ValueError('Unsupported function call in expression')
        if isinstance(node, ast.BinOp):
            left = self._eval_condition_ast(node.left)
            right = self._eval_condition_ast(node.right)
            return self._apply_binop(node.op, left, right)
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                target = node.value.id
                index = self._extract_int_from_ast(node.slice)
                if target == 'values':
                    return self.values.get(index, BitVecVal(index, 32))
                if target == 'bit_starts':
                    return self.bit_starts.get(index, BitVecVal(index, 32))
                if target == 'size_bits':
                    return self.size_bits.get(index, BitVecVal(index, 32))
            raise ValueError('Unsupported subscript expression')
        if isinstance(node, ast.Name):
            identifier = node.id.lower()
            if identifier == 'true':
                return BoolVal(True)
            if identifier == 'false':
                return BoolVal(False)
            if identifier == 'value':
                if self._current_constraint_node is not None:
                    return self.values.get(self._current_constraint_node, BitVecVal(0, 32))
                raise ValueError("'value' used outside of constraint context")
            raise ValueError(f"Unknown identifier '{node.id}' in condition")
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, bool):
                return BoolVal(value)
            if isinstance(value, (int, float)):
                return BitVecVal(int(value), 32)
            raise ValueError('Unsupported constant in condition')
        if hasattr(ast, 'NameConstant') and isinstance(node, ast.NameConstant):
            value = node.value
            if isinstance(value, bool):
                return BoolVal(value)
            if isinstance(value, (int, float)):
                return BitVecVal(int(value), 32)
            raise ValueError('Unsupported constant in condition')
        raise ValueError('Unsupported AST node in condition expression')

    def _ensure_numeric(self, expr: Any) -> Any:
        if isinstance(expr, int):
            return BitVecVal(expr, 32)
        if isinstance(expr, ExprRef) and (not isinstance(expr, BoolRef)):
            return expr
        if isinstance(expr, BoolRef):
            raise TypeError('Boolean expression used where numeric expected')
        raise TypeError(f'Unsupported numeric expression: {expr}')

    def _ensure_bool(self, expr: Any) -> Any:
        if isinstance(expr, bool):
            return BoolVal(expr)
        if isinstance(expr, BoolRef):
            return expr
        if isinstance(expr, ExprRef):
            return expr
        raise TypeError(f'Unsupported boolean expression: {expr}')

    def _build_if_expression(self, condition: Any, true_branch: Any, false_branch: Any) -> Any:
        cond = self._ensure_bool(condition)
        try:
            true_num = self._ensure_numeric(true_branch)
            false_num = self._ensure_numeric(false_branch)
            return If(cond, true_num, false_num)
        except TypeError:
            true_bool = self._ensure_bool(true_branch)
            false_bool = self._ensure_bool(false_branch)
            return If(cond, true_bool, false_bool)

    def _apply_binop(self, op: ast.AST, left: Any, right: Any) -> Any:
        left_num = self._ensure_numeric(left)
        right_num = self._ensure_numeric(right)
        if isinstance(op, ast.Add):
            return left_num + right_num
        if isinstance(op, ast.Sub):
            return left_num - right_num
        if isinstance(op, ast.Mult):
            return left_num * right_num
        if isinstance(op, ast.Div):
            return left_num / right_num
        if isinstance(op, ast.FloorDiv):
            return left_num / right_num
        if isinstance(op, ast.Mod):
            return left_num % right_num
        if isinstance(op, ast.BitOr):
            return left_num | right_num
        if isinstance(op, ast.BitAnd):
            return left_num & right_num
        if isinstance(op, ast.BitXor):
            return left_num ^ right_num
        if isinstance(op, ast.LShift):
            return left_num << right_num
        if isinstance(op, ast.RShift):
            return left_num >> right_num
        raise ValueError('Unsupported binary operator in condition')

    def _apply_comparison(self, op: ast.AST, left: Any, right: Any) -> Any:
        left_num = self._ensure_numeric(left)
        right_num = self._ensure_numeric(right)
        if isinstance(op, ast.Eq):
            return left_num == right_num
        if isinstance(op, ast.NotEq):
            return left_num != right_num
        if isinstance(op, ast.Lt):
            return left_num < right_num
        if isinstance(op, ast.LtE):
            return left_num <= right_num
        if isinstance(op, ast.Gt):
            return left_num > right_num
        if isinstance(op, ast.GtE):
            return left_num >= right_num
        raise ValueError('Unsupported comparison operator in condition')

    def _extract_int_from_ast(self, node: ast.AST) -> int:
        if isinstance(node, ast.Index):
            return self._extract_int_from_ast(node.value)
        if isinstance(node, ast.Constant):
            return int(node.value)
        if hasattr(ast, 'Num') and isinstance(node, ast.Num):
            return int(node.n)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -self._extract_int_from_ast(node.operand)
        raise ValueError('Unsupported index expression in condition')

    def _selector_domain_constraints(self, selector_id: int) -> List[Any]:
        selector = self.nodes_by_id.get(selector_id, {})
        constraints = selector.get('constraints') or []
        value_sym = self.values.get(selector_id)
        if value_sym is None:
            return []
        domain: List[Any] = []

        def _parse_int(val: str) -> Optional[int]:
            try:
                return int(val.strip(), 0)
            except Exception:
                return None
        for raw in constraints:
            if not isinstance(raw, str):
                continue
            text = raw.strip()
            if not text:
                continue
            lower = text.lower()
            if lower.startswith('enum'):
                m = re.search('enum\\s*:\\s*(.+)', text, flags=re.IGNORECASE)
                if m:
                    values = []
                    for part in re.split('[|,]', m.group(1)):
                        parsed = _parse_int(part)
                        if parsed is not None:
                            values.append(parsed)
                    if values:
                        domain.append(Or(*[value_sym == BitVecVal(v, 32) for v in values]))
                continue
            if lower.startswith('min:') or lower.startswith('max:') or lower.startswith('>') or lower.startswith('<'):
                min_val: Optional[int] = None
                max_val: Optional[int] = None
                m_min = re.search('min\\s*:\\s*(-?\\d+)', text, flags=re.IGNORECASE)
                m_max = re.search('max\\s*:\\s*(-?\\d+)', text, flags=re.IGNORECASE)
                if m_min:
                    min_val = _parse_int(m_min.group(1))
                if m_max:
                    max_val = _parse_int(m_max.group(1))
                if re.match('>=\\s*-?\\d+', lower):
                    min_val = _parse_int(text.split('>=')[1])
                if re.match('>\\s*-?\\d+', lower) and min_val is None:
                    parsed = _parse_int(text.split('>')[1])
                    if parsed is not None:
                        min_val = parsed + 1
                if re.match('<=\\s*-?\\d+', lower):
                    max_val = _parse_int(text.split('<=')[1])
                if re.match('<\\s*-?\\d+', lower) and max_val is None:
                    parsed = _parse_int(text.split('<')[1])
                    if parsed is not None:
                        max_val = parsed - 1
                if min_val is not None:
                    domain.append(value_sym >= BitVecVal(min_val, 32))
                if max_val is not None:
                    domain.append(value_sym <= BitVecVal(max_val, 32))
                continue
            m_eq = re.search('(?:==|=)\\s*(-?\\d+)', text)
            if m_eq:
                parsed = _parse_int(m_eq.group(1))
                if parsed is not None:
                    domain.append(value_sym == BitVecVal(parsed, 32))
        return domain

    def _selector_domain_range(self, selector_id: int) -> Tuple[int, int]:
        return (0, 255)

    def _selector_domain_values(self, selector_id: int) -> List[int]:
        start, end = self._selector_domain_range(selector_id)
        if end < start:
            start, end = (end, start)
        span = end - start + 1
        if span > 256:
            end = start + 255
        return list(range(start, end + 1))

    def _data_type_bounds(self, data_type: str) -> Optional[Tuple[int, int]]:
        mapping = {'uint8': (0, 255), 'uint16': (0, 65535), 'uint32': (0, 4294967295), 'int8': (-128, 127), 'int16': (-32768, 32767), 'int32': (-2147483648, 2147483647)}
        return mapping.get((data_type or '').lower())

    def _build_contexts(self):
        for node_id, node in self.nodes_by_id.items():
            node_type = node.get('node_type', '')
            msg_type_str = node.get('message_type', 'bidirectional')
            try:
                msg_type = MessageType(msg_type_str)
            except:
                msg_type = MessageType.BIDIRECTIONAL
            is_variant = node_type == 'variant'
            controlling_selector = self.controlled_by_selector.get(node_id)
            activation_condition = self.variant_conditions.get(node_id)
            self.contexts[node_id] = NodeContext(node_id=node_id, name=node.get('name', f'node_{node_id}'), node_type=node_type, message_type=msg_type, parent_id=node.get('parent_id'), children_ids=node.get('children_ids', []), start_sym=self.bit_starts[node_id], size_sym=self.size_bits[node_id], is_variant=is_variant, controlling_selector=controlling_selector, activation_condition=activation_condition, start_expr=node.get('bit_start'), size_expr=node.get('size_bits'))

    def _add_constraints(self):
        for node_id, ctx in self.contexts.items():
            if ctx.start_expr is not None:
                raw_constraint = self._expression_to_z3(ctx.start_expr, owner_id=node_id, field='bit_start')
                status = self._expression_status(node_id, 'bit_start')
                if raw_constraint is None and status == 'failed':
                    self._add_expression_issue(node_id, 'bit_start', ctx.start_expr, 'could not be evaluated into a numeric bit offset')
                    continue
                constraint = self._normalize_expression_result(raw_constraint, owner_id=node_id, field='bit_start', expr=ctx.start_expr)
                self._safe_add_equation(ctx.start_sym, constraint, owner_id=node_id, field='bit_start', expr=ctx.start_expr)
            if ctx.size_expr is not None:
                if not self._validate_numeric_formula(ctx.size_expr, owner_id=node_id, field='size_bits', original=ctx.size_expr):
                    continue
                raw_constraint = self._expression_to_z3(ctx.size_expr, owner_id=node_id, field='size_bits')
                status = self._expression_status(node_id, 'size_bits')
                if raw_constraint is None and status == 'failed':
                    self._add_expression_issue(node_id, 'size_bits', ctx.size_expr, 'could not be evaluated into a numeric bit length')
                    continue
                constraint = self._normalize_expression_result(raw_constraint, owner_id=node_id, field='size_bits', expr=ctx.size_expr)
                self._safe_add_equation(ctx.size_sym, constraint, owner_id=node_id, field='size_bits', expr=ctx.size_expr)
        for edge in self.edges:
            if edge.get('rel') == 'length_of':
                src = edge.get('src')
                dst = edge.get('dst')
                if src in self.contexts and dst in self.contexts:
                    formula = edge.get('formula', f'val({src}) * 8')
                    if not self._validate_numeric_formula(formula, owner_id=dst, field='length_of', original=formula):
                        continue
                    raw_expr = self._expression_to_z3(formula, owner_id=dst, field='length_of')
                    status = self._expression_status(dst, 'length_of')
                    if raw_expr is None and status == 'failed':
                        self._add_expression_issue(dst, 'length_of', formula, 'could not be evaluated into a length expression (use bit-based arithmetic like val(<length_field>)*8; avoid max()/ceil/((val+7)/8) style formulas)')
                        continue
                    normalized = self._normalize_expression_result(raw_expr, owner_id=dst, field='length_of', expr=formula)
                    self._safe_add_equation(self.size_bits[dst], normalized, owner_id=dst, field='length_of', expr=formula)

    def _safe_add_equation(self, left: Any, right: Optional[Any], *, owner_id: Optional[int], field: Optional[str], expr: Any) -> None:
        if right is None:
            return
        try:
            self.solver.add(left == right)
        except Z3Exception as exc:
            message = f"expression '{expr}' caused solver error: {exc}"
            self._add_expression_issue(owner_id, field, expr, message)

    def _normalize_expression_result(self, value: Any, *, owner_id: Optional[int], field: Optional[str], expr: Any) -> Optional[Any]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return BitVecVal(int(value), 32)
        if isinstance(value, bool) or (BoolRef is not None and isinstance(value, BoolRef)):
            allowed_boolean_fields = {'constraint', 'condition', 'selector_condition', 'edge_condition'}
            if field in allowed_boolean_fields:
                return value
            self._add_expression_issue(owner_id, field, expr, 'evaluates to a boolean; expected a numeric BitVec expression (move selector-style predicates to a condition_on edge)')
            return None
        if ExprRef is not None and isinstance(value, ExprRef):
            sort_name = str(value.sort())
            allowed_boolean_fields = {'constraint', 'condition', 'selector_condition', 'edge_condition'}
            if sort_name.startswith('Bool') and field in allowed_boolean_fields:
                return value
            if not sort_name.startswith('BitVec'):
                self._add_expression_issue(owner_id, field, expr, f'evaluates to {sort_name}; expected BitVec(32) - try describing the predicate via a condition_on edge instead')
                return None
            return value
        self._add_expression_issue(owner_id, field, expr, f'returned unsupported result type {type(value).__name__}')
        return None

    def _add_expression_issue(self, owner_id: Optional[int], field: Optional[str], expr: Any, message: str) -> None:
        if owner_id is not None:
            traces = self.expression_traces.get(owner_id, [])
            for trace in reversed(traces):
                if trace.get('field') == field:
                    trace['status'] = 'failed'
                    notes = trace.setdefault('notes', [])
                    notes.append(message)
                    break
        expr_text = expr if isinstance(expr, str) else repr(expr)
        human_field = field or 'expression'
        detail = f"{human_field} '{expr_text}' {message}."
        self._add_error(category='Expression', description=detail, node_id=owner_id)

    def _expression_status(self, owner_id: Optional[int], field: Optional[str]) -> Optional[str]:
        if owner_id is None or field is None:
            return None
        traces = self.expression_traces.get(owner_id, [])
        for trace in reversed(traces):
            if trace.get('field') == field:
                return trace.get('status')
        return None

    @staticmethod
    def _normalize_formula_tokens(expr: str) -> str:
        if not isinstance(expr, str):
            return expr
        normalized = expr.replace('||', ' or ').replace('&&', ' and ')
        if '?' in normalized and ':' in normalized:
            pattern = re.compile('^(?P<cond>[^?]+)\\?(?P<true>[^:]+):(?P<false>.+)$')
            match = pattern.match(normalized.strip())
            if match:
                cond = match.group('cond').strip()
                true_part = match.group('true').strip()
                false_part = match.group('false').strip()
                normalized = f'If(({cond}), ({true_part}), ({false_part}))'
        return normalized

    def _validate_numeric_formula(self, expr: Any, *, owner_id: Optional[int], field: str, original: Optional[str]=None, severity: Severity=Severity.ERROR) -> bool:
        if not isinstance(expr, str):
            return True
        stripped = expr.strip()
        if not stripped:
            return True
        if stripped.lower() in {'variable', 'varint'}:
            return True
        normalized = self._normalize_formula_tokens(stripped)
        ast_ready = re.sub('(\\d+)\\.(size_bits|bit_start)', '\\2_\\1', normalized)
        try:
            tree = ast.parse(ast_ready, mode='eval')
        except SyntaxError as exc:
            context = original or stripped
            self._add_error(category='Semantics', description=f'{field} expression "{context}" could not be parsed (syntax error: {exc.msg}). Please rewrite it using supported arithmetic forms such as val() or If().', node_id=owner_id, severity=severity)
            return False
        return self._validate_numeric_formula_tree(tree.body, owner_id=owner_id, field=field, original=stripped, severity=severity)

    def _validate_numeric_formula_tree(self, node: ast.AST, *, owner_id: Optional[int], field: str, original: str, severity: Severity=Severity.ERROR) -> bool:
        allowed_calls = {'val', 'If', 'max', 'min', 'abs', 'simplify', 'IntVal', 'ceil'}
        allowed_names = allowed_calls | {'value'}

        def fail(reason: str) -> bool:
            self._add_error(category='Semantics', description=f'{field} expression "{original}" uses unsupported syntax: {reason}', node_id=owner_id, severity=severity)
            return False
        for current in ast.walk(node):
            if isinstance(current, ast.Attribute):
                return fail('attribute access is not allowed (e.g., X.size_bits)')
            if isinstance(current, (ast.Assign, ast.AugAssign, ast.NamedExpr)):
                return fail('assignment expressions are not allowed')
            if isinstance(current, (ast.Dict, ast.List, ast.Set, ast.Tuple, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                return fail('collection literals are not allowed')
            if isinstance(current, ast.Subscript):
                return fail('subscript access is not allowed (e.g., values[3])')
            if isinstance(current, ast.Call):
                if not isinstance(current.func, ast.Name):
                    return fail('only val()/If()/max()/min()/abs()/simplify()/IntVal calls are supported')
                func_name = current.func.id
                if func_name not in allowed_calls:
                    return fail(f'function {func_name} is not supported')
                if current.keywords:
                    return fail(f'{func_name} calls must not use keyword arguments')
                if func_name == 'val':
                    if len(current.args) != 1:
                        return fail('val() requires exactly one argument')
                    arg = current.args[0]
                    if not isinstance(arg, ast.Constant) or not isinstance(arg.value, (int, float)):
                        return fail('val() arguments must be numeric literals')
                elif func_name == 'If':
                    if len(current.args) != 3:
                        return fail('If(cond, a, b) requires exactly three arguments')
                for arg in current.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        return fail('string literals are not supported')
            if isinstance(current, ast.Name):
                if current.id not in allowed_names:
                    if re.fullmatch('(size_bits|bit_start)_\\d+', current.id):
                        continue
                    return fail(f'identifier {current.id} is not allowed')
            if isinstance(current, ast.Constant):
                if isinstance(current.value, str):
                    return fail('string literals are not supported')
        return True

    def _expression_to_z3(self, expr: Any, owner_id: Optional[int]=None, field: Optional[str]=None) -> Any:
        trace: Optional[Dict[str, Any]] = None

        def record_trace(result: Any, status: str) -> Any:
            nonlocal trace
            if owner_id is None:
                return result
            if trace is None:
                trace = {'node_id': owner_id, 'field': field, 'expr': expr, 'dependencies': [], 'status': status}
            else:
                trace['status'] = status
            trace['result'] = str(result) if result is not None else None
            self.expression_traces.setdefault(owner_id, []).append(trace)
            return result
        if isinstance(expr, (int, float)):
            return record_trace(BitVecVal(int(expr), 32), 'ok')
        if isinstance(expr, str):
            original_expr = expr
            expr = expr.strip()
            expr = self._normalize_formula_tokens(expr)
            if expr in ['variable', 'varint']:
                return record_trace(None, 'dynamic')
            trace = {'node_id': owner_id, 'field': field, 'expr': original_expr, 'dependencies': [], 'status': 'pending'} if owner_id is not None else None
            bit_refs: List[int] = []
            size_refs: List[int] = []
            val_refs: List[int] = []

            def replace_bit_start(match: re.Match) -> str:
                node_id = int(match.group(1))
                if node_id in self.bit_starts:
                    bit_refs.append(node_id)
                    return f'bit_starts[{node_id}]'
                return match.group(0)

            def replace_size_bits(match: re.Match) -> str:
                node_id = int(match.group(1))
                if node_id in self.size_bits:
                    size_refs.append(node_id)
                    return f'size_bits[{node_id}]'
                return match.group(0)

            def replace_val(match: re.Match) -> str:
                node_id = int(match.group(1))
                if node_id in self.values:
                    val_refs.append(node_id)
                    return f'values[{node_id}]'
                return match.group(0)
            z3_expr = re.sub('(\\d+)\\.bit_start', replace_bit_start, expr)
            z3_expr = re.sub('(\\d+)\\.size_bits', replace_size_bits, z3_expr)
            z3_expr = re.sub('val\\((\\d+)\\)', replace_val, z3_expr)
            if trace is not None:
                for ref in bit_refs:
                    trace['dependencies'].append({'type': 'bit_start', 'node_id': ref})
                for ref in size_refs:
                    trace['dependencies'].append({'type': 'size_bits', 'node_id': ref})
                for ref in val_refs:
                    trace['dependencies'].append({'type': 'val', 'node_id': ref})
            try:
                result = self._parse_expression_ast(z3_expr)
                return record_trace(result, 'ok')
            except Exception:
                result = self._parse_expression_fallback(expr, owner_id, field, trace)
                status = 'ok' if result is not None else 'failed'
                return record_trace(result, status)
        return record_trace(None, 'failed')

    def _parse_expression_ast(self, expr: str) -> Any:
        try:
            tree = ast.parse(expr, mode='eval')
        except SyntaxError as exc:
            raise ValueError('Invalid expression syntax') from exc
        return self._eval_condition_ast(tree.body)

    def _parse_expression_fallback(self, expr: str, owner_id: Optional[int], field: Optional[str], trace: Optional[Dict[str, Any]]) -> Any:
        try:
            match = re.match('^val\\((\\d+)\\)\\s*\\*\\s*(\\d+)', expr)
            if match:
                node_id = int(match.group(1))
                multiplier = int(match.group(2))
                if node_id in self.values:
                    if trace is not None:
                        trace['dependencies'].append({'type': 'val', 'node_id': node_id})
                    return self.values[node_id] * multiplier
            return None
        except Exception:
            return None

    def _validate_structure(self):
        root_id = None
        for node_id, node in self.nodes_by_id.items():
            if node.get('parent_id') is None:
                if root_id is not None:
                    self._add_error(category='Structure', description='Multiple root nodes found')
                root_id = node_id
        if root_id is None:
            self._add_error(category='Structure', description='No root node found')
        for node_id, node in self.nodes_by_id.items():
            parent_id = node.get('parent_id')
            if parent_id is not None:
                if parent_id not in self.nodes_by_id:
                    self._add_error(category='Structure', description=f'Parent node {parent_id} does not exist', node_id=node_id)
                else:
                    parent = self.nodes_by_id[parent_id]
                    if node_id not in parent.get('children_ids', []):
                        self._add_error(category='Structure', description=f"Not listed in parent's children_ids", node_id=node_id)
                    else:
                        self._validate_parent_child_types(parent_id, parent, node_id, node)
            for child_id in node.get('children_ids', []):
                if child_id not in self.nodes_by_id:
                    self._add_error(category='Structure', description=f'Child {child_id} does not exist', node_id=node_id)
                else:
                    child = self.nodes_by_id[child_id]
                    if child.get('parent_id') != node_id:
                        self._add_error(category='Structure', description=f'Child {child_id} has different parent', node_id=node_id)

    def _validate_parent_child_types(self, parent_id: int, parent: Dict[str, Any], child_id: int, child: Dict[str, Any]) -> None:
        return
        required_fields = ['name', 'node_type', 'message_type', 'bit_start', 'size_bits']
        for node_id, node in self.nodes_by_id.items():
            for field in required_fields:
                if field not in node or node[field] is None:
                    self._add_error(category='Structure', description=f'Missing required field: {field}', node_id=node_id)

    def _validate_references(self):
        for node_id, node in self.nodes_by_id.items():
            bit_start = node.get('bit_start')
            if isinstance(bit_start, str):
                refs = re.findall('(\\d+)\\.(?:bit_start|size_bits)', bit_start)
                for ref in refs:
                    ref_id = int(ref)
                    if ref_id not in self.nodes_by_id:
                        self._add_error(category='Structure', description=f'bit_start references non-existent node {ref_id}', node_id=node_id)
                val_refs = re.findall('val\\((\\d+)\\)', bit_start)
                for ref in val_refs:
                    ref_id = int(ref)
                    if ref_id not in self.nodes_by_id:
                        self._add_error(category='Structure', description=f'bit_start references non-existent node in val({ref})', node_id=node_id)
            size_bits = node.get('size_bits')
            if isinstance(size_bits, str) and size_bits not in ['variable', 'varint']:
                refs = re.findall('(\\d+)\\.(?:bit_start|size_bits)', size_bits)
                for ref in refs:
                    ref_id = int(ref)
                    if ref_id not in self.nodes_by_id:
                        self._add_error(category='Structure', description=f'size_bits references non-existent node {ref_id}', node_id=node_id)
                val_refs = re.findall('val\\((\\d+)\\)', size_bits)
                for ref in val_refs:
                    ref_id = int(ref)
                    if ref_id not in self.nodes_by_id:
                        self._add_error(category='Structure', description=f'size_bits references non-existent node in val({ref})', node_id=node_id)
        for edge in self.edges:
            src = edge.get('src')
            dst = edge.get('dst')
            if src not in self.nodes_by_id:
                self._add_error(category='Graph', description=f'Edge source {src} does not exist', edge_id=f'edge_{src}_to_{dst}')
            if dst not in self.nodes_by_id:
                self._add_error(category='Graph', description=f'Edge destination {dst} does not exist', edge_id=f'edge_{src}_to_{dst}')

    def _validate_semantic_overlaps(self):
        siblings_by_parent: Dict[int, List[int]] = {}
        for node_id, ctx in self.contexts.items():
            if ctx.parent_id is not None:
                if ctx.parent_id not in siblings_by_parent:
                    siblings_by_parent[ctx.parent_id] = []
                siblings_by_parent[ctx.parent_id].append(node_id)

        def _same_variant_group(a: int, b: int) -> bool:
            for variants in self.variant_groups.values():
                if a in variants and b in variants:
                    return True
            return False
        for parent_id, sibling_ids in siblings_by_parent.items():
            for i, id1 in enumerate(sibling_ids):
                ctx1 = self.contexts[id1]
                for id2 in sibling_ids[i + 1:]:
                    ctx2 = self.contexts[id2]
                    if self._is_overlap_allowed(ctx1, ctx2):
                        continue
                    if self._check_overlap(ctx1, ctx2):
                        if _same_variant_group(id1, id2):
                            self._add_error(category='Semantic', description=f'Overlap with sibling {ctx2.name} is allowed: both are variants selected by the same selector.', node_id=id1, severity=Severity.WARN, code='VARIANT_OVERLAP')
                            continue
                        self._add_error(category='Layout', description=f'Invalid overlap with sibling {ctx2.name}', node_id=id1)

    def _validate_branch_references(self) -> None:
        for node_id, ctx in self.contexts.items():
            refs: Set[int] = set()
            refs.update(self._expression_references(ctx.start_expr))
            refs.update(self._expression_references(ctx.size_expr))
            if not refs:
                continue
            for ref_id in refs:
                if ref_id == node_id:
                    continue
                ref_ctx = self.contexts.get(ref_id)
                if not ref_ctx:
                    continue
                if ref_ctx.message_type == MessageType.BIDIRECTIONAL:
                    continue
                if ctx.message_type == MessageType.BIDIRECTIONAL:
                    continue
                conflict = False
                if ctx.message_type != MessageType.BIDIRECTIONAL and ref_ctx.message_type != MessageType.BIDIRECTIONAL and (ctx.message_type != ref_ctx.message_type):
                    conflict = True
                if ctx.parent_id == ref_ctx.parent_id and ctx.parent_id is not None and (ctx.controlling_selector is not None) and (ctx.controlling_selector == ref_ctx.controlling_selector):
                    conflict = True
                if conflict:
                    ref_name = ref_ctx.name
                    self._add_error(category='Layout', description=f'Expression references sibling {ref_name} from a different branch', node_id=node_id, severity=Severity.ERROR)

    def _conditions_are_mutually_exclusive(self, cond1: Any, cond2: Any) -> bool:
        if cond1 is None or cond2 is None:
            return False
        try:
            s = Solver()
            s.add(self.solver.assertions())
            s.add(cond1)
            s.add(cond2)
            return s.check() == unsat
        except Exception:
            return False

    def _raw_condition_strings(self, node_a: int, node_b: int) -> Tuple[Optional[str], Optional[str]]:
        raw_a = self.variant_raw_formula.get(node_a)
        raw_b = self.variant_raw_formula.get(node_b)

        def normalize(raw: Optional[str]) -> Optional[str]:
            if raw is None:
                return None
            return re.sub('\\s+', ' ', raw.strip())
        return (normalize(raw_a), normalize(raw_b))

    def _raw_conditions_clearly_disjoint(self, node_a: int, node_b: int) -> bool:
        raw_a, raw_b = self._raw_condition_strings(node_a, node_b)
        if not raw_a or not raw_b:
            return False
        if raw_a == raw_b:
            return False
        return True

    def _is_overlap_allowed(self, ctx1: NodeContext, ctx2: NodeContext) -> bool:
        mt1 = ctx1.message_type
        mt2 = ctx2.message_type
        if mt1 == MessageType.REQUEST and mt2 == MessageType.RESPONSE or (mt1 == MessageType.RESPONSE and mt2 == MessageType.REQUEST):
            return True

        def is_controlled_variant(ctx: NodeContext) -> bool:
            return ctx.is_variant and ctx.controlling_selector is not None
        if ctx1.is_variant or ctx2.is_variant:
            ctrl1 = ctx1.controlling_selector if ctx1.is_variant else None
            ctrl2 = ctx2.controlling_selector if ctx2.is_variant else None
            if ctx1.node_type == 'selector' or ctx2.node_type == 'selector':
                return True
            if not is_controlled_variant(ctx1) and (not is_controlled_variant(ctx2)):
                return False
            if is_controlled_variant(ctx1) and is_controlled_variant(ctx2):
                if ctrl1 != ctrl2:
                    return False
                if self._conditions_are_mutually_exclusive(ctx1.activation_condition, ctx2.activation_condition) or self._raw_conditions_clearly_disjoint(ctx1.node_id, ctx2.node_id):
                    return True
                if ctx1.message_type != MessageType.BIDIRECTIONAL and ctx2.message_type != MessageType.BIDIRECTIONAL and (ctx1.message_type != ctx2.message_type):
                    return True
                return False
            return True
        if ctx1.controlling_selector is not None and ctx1.controlling_selector == ctx2.controlling_selector and (self._conditions_are_mutually_exclusive(ctx1.activation_condition, ctx2.activation_condition) or self._raw_conditions_clearly_disjoint(ctx1.node_id, ctx2.node_id)):
            return True
        cond_presence_1 = ctx1.controlling_selector is not None or self.variant_raw_formula.get(ctx1.node_id)
        cond_presence_2 = ctx2.controlling_selector is not None or self.variant_raw_formula.get(ctx2.node_id)
        if bool(cond_presence_1) != bool(cond_presence_2):
            return True
        if ctx1.node_type == 'selector' or ctx2.node_type == 'selector':
            return True
        if ctx1.message_type != MessageType.BIDIRECTIONAL and ctx2.message_type != MessageType.BIDIRECTIONAL and (ctx1.message_type != ctx2.message_type):
            return True
        return False

    def _check_overlap(self, ctx1: NodeContext, ctx2: NodeContext) -> bool:
        s = Solver()
        s.add(self.solver.assertions())
        overlap = And(ctx1.start_sym < ctx2.start_sym + ctx2.size_sym, ctx2.start_sym < ctx1.start_sym + ctx1.size_sym, ctx1.size_sym > 0, ctx2.size_sym > 0)
        s.add(overlap)
        return s.check() == sat

    def _expression_references(self, expr: Any) -> Set[int]:
        refs: Set[int] = set()
        if isinstance(expr, str):
            for match in re.findall('(\\d+)\\.(?:bit_start|size_bits)', expr):
                refs.add(int(match))
            for match in re.findall('val\\((\\d+)\\)', expr):
                refs.add(int(match))
        return refs

    def _is_unknown_length_expr(self, expr: Any) -> bool:
        if expr is None:
            return True
        if isinstance(expr, str):
            token = expr.strip().lower()
            if token in {'variable', 'varint'}:
                return True
            if re.search('val\\(', expr):
                return True
            if re.search('\\d+\\.(?:size_bits|bit_start)', expr):
                return True
            try:
                int(token, 0)
                return False
            except ValueError:
                return True
        return False

    def _is_unknown_offset_expr(self, expr: Any) -> bool:
        if expr is None:
            return True
        if isinstance(expr, (int, float)):
            return False
        if isinstance(expr, str):
            token = expr.strip().lower()
            try:
                int(token, 0)
                return False
            except ValueError:
                pass
            if re.search('val\\(|bit_start|size_bits', token):
                return True
            if any((op in token for op in ['+', '-', '*', '/', '%', '<<', '>>', ' and ', ' or '])):
                return True
        return True

    def _size_unit(self, ctx: NodeContext) -> str:
        node = self.nodes_by_id.get(ctx.node_id, {})
        data_type = (node.get('data_type') or '').lower()
        if 'byte' in data_type:
            return 'bytes'
        if 'bit' in data_type:
            return 'bits'
        return 'unknown'

    def _layout_overflow_reason(self, parent_ctx: NodeContext, child_ctx: NodeContext) -> str:
        if self._is_unknown_length_expr(parent_ctx.size_expr):
            return 'parent length unknown'
        parent_unit = self._size_unit(parent_ctx)
        child_unit = self._size_unit(child_ctx)
        if parent_unit != 'unknown' and child_unit != 'unknown' and (parent_unit != child_unit):
            return 'size unit mismatch'
        if self._is_unknown_length_expr(child_ctx.size_expr):
            return 'child length indeterminate'
        return 'child length indeterminate'

    def _report_gap(self, curr_ctx: NodeContext, next_ctx: NodeContext, gap_bits: int, curr_end: Optional[int]=None, next_start: Optional[int]=None, severity_override: Optional[Severity]=None) -> None:
        curr_type = (curr_ctx.node_type or '').lower()
        next_type = (next_ctx.node_type or '').lower()
        next_name = (next_ctx.name or '').lower()
        is_header = 'header' in curr_type
        is_body = 'payload' in next_type or 'container' in next_type
        looks_like_payload = 'pdu' in next_name or 'body' in next_name
        severity = severity_override
        if severity is None:
            if is_header and (is_body or looks_like_payload) and (gap_bits > 0):
                severity = Severity.ERROR
            elif gap_bits >= 8:
                severity = Severity.WARN
            else:
                return
        if curr_end is not None and next_start is not None:
            description = f'Detected {gap_bits}-bit GAP between {curr_ctx.name} (ends at {curr_end}) and {next_ctx.name} (starts at {next_start}). '
        else:
            description = f'Detected ~{gap_bits}-bit GAP between {curr_ctx.name} and {next_ctx.name} based on bit_start/size_bits formulas. '
        if is_header and (is_body or looks_like_payload):
            description += 'Header and Body/Container must be contiguous.'
        elif severity == Severity.WARN:
            description += 'This may indicate missing fields or misaligned offsets.'
        self._add_error(category='Layout', description=description, node_id=next_ctx.node_id, severity=severity)

    def _symbolic_gap_bits(self, ctx1: NodeContext, ctx2: NodeContext, *, min_gap_bits: int=1, enforce_order: bool=True) -> Optional[int]:
        try:
            s = Solver()
            s.add(self.solver.assertions())
            end1 = ctx1.start_sym + ctx1.size_sym
            s.add(ctx1.size_sym > 0, ctx2.size_sym > 0)
            if enforce_order:
                s.add(ctx1.start_sym <= ctx2.start_sym)
            s.add(ctx2.start_sym >= end1 + BitVecVal(min_gap_bits, 32))
            if s.check() != sat:
                return None
            model = s.model()
            start1 = model.eval(ctx1.start_sym, model_completion=True).as_long()
            size1 = model.eval(ctx1.size_sym, model_completion=True).as_long()
            start2 = model.eval(ctx2.start_sym, model_completion=True).as_long()
            gap = start2 - (start1 + size1)
            return max(gap, min_gap_bits)
        except Exception:
            return None

    def _validate_continuity(self):
        children_by_parent: Dict[int, List[NodeContext]] = {}
        for ctx in self.contexts.values():
            if ctx.parent_id is not None:
                children_by_parent.setdefault(ctx.parent_id, []).append(ctx)
        for parent_id, children in children_by_parent.items():
            parent_ctx = self.contexts.get(parent_id)
            parent_order: List[Union[str, int]] = parent_ctx.children_ids if parent_ctx else []
            base_children = [c for c in children if not c.is_variant]
            if not base_children:
                continue
            if parent_ctx:
                parent_start = self._maybe_int(parent_ctx.start_expr)
                if parent_start is not None:
                    min_child_start: Optional[int] = None
                    min_child_ctx: Optional[NodeContext] = None
                    for ctx in base_children:
                        start_val = self._maybe_int(ctx.start_expr)
                        if start_val is None:
                            continue
                        if min_child_start is None or start_val < min_child_start:
                            min_child_start = start_val
                            min_child_ctx = ctx
                    if min_child_start is not None and min_child_ctx is not None:
                        lead_gap = min_child_start - parent_start
                        if lead_gap >= 8 or (parent_ctx.is_variant and lead_gap > 0):
                            severity = Severity.ERROR if parent_ctx.is_variant and lead_gap >= 8 else Severity.WARN
                            self._add_error(category='Layout', description=f'Detected {lead_gap}-bit leading GAP inside container {parent_ctx.name}: container starts at {parent_start} but earliest child {min_child_ctx.name} starts at {min_child_start}. This usually indicates the child subtree should be shifted to start at {parent_start} or a missing field should be inserted to cover the gap.', node_id=parent_ctx.node_id, severity=severity, code='LEADING_GAP_IN_CONTAINER')
            if len(base_children) < 2:
                continue
            literal_nodes: List[Tuple[int, int, NodeContext]] = []
            for ctx in base_children:
                start_val = self._maybe_int(ctx.start_expr)
                size_val = self._maybe_int(ctx.size_expr)
                if start_val is not None and size_val is not None:
                    literal_nodes.append((start_val, size_val, ctx))
            literal_nodes.sort(key=lambda x: x[0])
            for i in range(len(literal_nodes) - 1):
                curr_start, curr_size, curr_ctx = literal_nodes[i]
                next_start, _, next_ctx = literal_nodes[i + 1]
                curr_end = curr_start + curr_size
                gap = next_start - curr_end
                if gap > 0:
                    self._report_gap(curr_ctx=curr_ctx, next_ctx=next_ctx, gap_bits=gap, curr_end=curr_end, next_start=next_start, severity_override=None)
            if len(literal_nodes) >= len(base_children):
                continue
            try:
                order_solver = Solver()
                order_solver.add(self.solver.assertions())
                if order_solver.check() != sat:
                    continue
                model = order_solver.model()
            except Exception:
                continue

            def _model_int(expr: Any) -> Optional[int]:
                try:
                    v = model.eval(expr, model_completion=True)
                    if v is None:
                        return None
                    return int(v.as_long())
                except Exception:
                    return None
            literal_id_set = {ctx.node_id for _, _, ctx in literal_nodes}
            ordered_children = list(base_children)
            if parent_order:
                order_index = {str(cid): idx for idx, cid in enumerate(parent_order)}
                ordered_children.sort(key=lambda ctx: (order_index.get(str(ctx.node_id), 10 ** 12), _model_int(ctx.start_sym) if _model_int(ctx.start_sym) is not None else 10 ** 12))
            else:
                ordered_children.sort(key=lambda ctx: _model_int(ctx.start_sym) if _model_int(ctx.start_sym) is not None else 10 ** 12)
            if len(ordered_children) < 2:
                continue
            for i in range(len(ordered_children) - 1):
                curr_ctx = ordered_children[i]
                next_ctx = ordered_children[i + 1]
                if curr_ctx.node_id in literal_id_set and next_ctx.node_id in literal_id_set:
                    continue
                gap_expr = next_ctx.start_sym - (curr_ctx.start_sym + curr_ctx.size_sym)
                try:
                    gap_solver = Solver()
                    gap_solver.add(self.solver.assertions())
                    gap_solver.add(gap_expr > 0)
                    has_gap_model = gap_solver.check() == sat
                except Exception:
                    continue
                if not has_gap_model:
                    continue
                try:
                    no_gap_solver = Solver()
                    no_gap_solver.add(self.solver.assertions())
                    no_gap_solver.add(gap_expr <= 0)
                    has_no_gap_model = no_gap_solver.check() == sat
                except Exception:
                    has_no_gap_model = True
                forced_gap = not has_no_gap_model
                approx_gap: Optional[int] = None
                try:
                    gap_model = gap_solver.model()
                    approx_gap = int(gap_model.eval(gap_expr, model_completion=True).as_long())
                except Exception:
                    approx_gap = None
                if approx_gap is None or approx_gap < 0:
                    approx_gap = 0
                severity = Severity.ERROR if forced_gap else Severity.WARN
                self._report_gap(curr_ctx=curr_ctx, next_ctx=next_ctx, gap_bits=approx_gap, curr_end=None, next_start=None, severity_override=severity)

    def _validate_layout_boundaries(self):
        for parent_id, parent_ctx in self.contexts.items():
            if not parent_ctx.children_ids:
                continue
            parent_name = parent_ctx.name
            for child_id in parent_ctx.children_ids:
                child_ctx = self.contexts.get(child_id)
                if not child_ctx:
                    continue
                child_name = child_ctx.name
                s = Solver()
                s.add(self.solver.assertions())
                s.add(child_ctx.start_sym < parent_ctx.start_sym)
                if s.check() == sat:
                    self._add_error(category='Layout', description=f'{child_name} starts before parent {parent_name}', node_id=child_id)
                s = Solver()
                s.add(self.solver.assertions())
                parent_end = parent_ctx.start_sym + parent_ctx.size_sym
                child_end = child_ctx.start_sym + child_ctx.size_sym
                s.add(child_end > parent_end)
                s.add(parent_ctx.size_sym > 0, child_ctx.size_sym > 0)
                if s.check() == sat:
                    severity = Severity.WARN if parent_ctx.size_expr == 'variable' else Severity.ERROR
                    reason = self._layout_overflow_reason(parent_ctx, child_ctx)
                    if reason == 'parent length unknown':
                        continue
                    detail = f'{child_name} may extend beyond parent {parent_name}'
                    if reason:
                        detail += f' ({reason})'
                    self._add_error(category='Layout', description=detail, node_id=child_id, severity=severity)

    def _validate_size_consistency(self):
        for parent_id, parent_ctx in self.contexts.items():
            if not parent_ctx.children_ids:
                continue
            total_size = BitVecVal(0, 32)
            numeric_possible = True
            numeric_sum = 0
            child_hints: List[str] = []
            for child_id in parent_ctx.children_ids:
                if child_id not in self.contexts:
                    continue
                child_ctx = self.contexts[child_id]
                if child_ctx.is_variant:
                    continue
                child_const = self._maybe_int(child_ctx.size_expr)
                if child_const is not None:
                    numeric_sum += child_const
                else:
                    numeric_possible = False
                child_hints.append(f'{child_ctx.name}(ID:{child_id}, size={child_ctx.size_expr})')
                total_size = total_size + child_ctx.size_sym
            parent_const = self._maybe_int(parent_ctx.size_expr)
            if numeric_possible and parent_const is not None:
                if numeric_sum > parent_const:
                    hint = ''
                    if child_hints:
                        hint = ' Offending children: ' + ', '.join(child_hints[:4])
                    self._add_error(category='Layout', description="Children may exceed parent size (consider increasing the parent's size_bits formula or moving misattached child fields/variants to the correct container)." + hint, node_id=parent_id)
                continue
            s = Solver()
            s.add(self.solver.assertions())
            s.add(total_size > parent_ctx.size_sym)
            s.add(parent_ctx.size_sym > 0)
            if s.check() == sat:
                hint = ''
                if child_hints:
                    hint = ' Offending children: ' + ', '.join(child_hints[:4])
                self._add_error(category='Semantics', description='Children may exceed parent size (prefer parent.size_bits = sum(children) or bind via length_of; avoid using max(variant sizes) or fixed constants when children are variable).' + hint, node_id=parent_id, severity=Severity.WARN, code='PARENT_CHILD_SIZE_RELATION_UNBOUND')

    def _validate_variant_exclusivity(self):
        for selector_id, variant_ids in self.variant_groups.items():
            if not self._is_selector_node(selector_id):
                continue
            if len(variant_ids) < 2:
                continue
            for i, v1_id in enumerate(variant_ids):
                v1_cond = self.variant_conditions.get(v1_id)
                if v1_cond is None:
                    continue
                for v2_id in variant_ids[i + 1:]:
                    v2_cond = self.variant_conditions.get(v2_id)
                    if v2_cond is None:
                        continue
                    ctx1 = self.contexts.get(v1_id)
                    ctx2 = self.contexts.get(v2_id)
                    if ctx1 and ctx2:
                        if ctx1.message_type != ctx2.message_type and MessageType.BIDIRECTIONAL not in (ctx1.message_type, ctx2.message_type):
                            continue
                    s = Solver()
                    s.add(And(v1_cond, v2_cond))
                    if s.check() == sat:
                        v1_ctx = self.contexts.get(v1_id)
                        v2_ctx = self.contexts.get(v2_id)
                        v1_name = v1_ctx.name if v1_ctx else f'node_{v1_id}'
                        v2_name = v2_ctx.name if v2_ctx else f'node_{v2_id}'
                        hint = ' (resolve by giving each variant a single mutually exclusive condition_on, or remove generic/unconditional variants that overlap)'
                        self._add_error(category='Semantics', description=f'Non-exclusive conditions with {v2_name}{hint}', node_id=v1_id, severity=Severity.ERROR, code='NON_EXCLUSIVE_VARIANT_CONDITIONS')

    def _validate_variant_alignment(self) -> None:
        for selector_id, variant_ids in self.variant_groups.items():
            if not self._is_selector_node(selector_id):
                continue
            selector_ctx = self.contexts.get(selector_id)
            if not selector_ctx:
                continue
            selector_parent = selector_ctx.parent_id
            buckets: Dict[MessageType, List[NodeContext]] = {}
            for vid in variant_ids:
                ctx = self.contexts.get(vid)
                if not ctx:
                    continue
                if not ctx.is_variant:
                    continue
                if ctx.parent_id != selector_parent:
                    continue
                buckets.setdefault(ctx.message_type, []).append(ctx)
            selector_name = selector_ctx.name or f'node_{selector_id}'
            for mt, vctxs in buckets.items():
                literal_starts: List[Tuple[int, NodeContext]] = []
                for vctx in vctxs:
                    v_start = self._maybe_int(vctx.start_expr)
                    if v_start is None:
                        continue
                    literal_starts.append((v_start, vctx))
                if len(literal_starts) < 2:
                    continue
                unique_starts = sorted({s for s, _ in literal_starts})
                if len(unique_starts) < 2:
                    continue
                expected_start = unique_starts[0]
                for v_start, vctx in literal_starts:
                    if v_start == expected_start:
                        continue
                    self._add_error(category='Structure', description=f'Selector-controlled variants should overlap for routing stability, but found {mt.value} variant {vctx.name} bit_start={v_start} while other variants start at {expected_start} under selector {selector_name}. This often indicates variants were sequentialized, making specific branches unreachable.', node_id=vctx.node_id, code='MISALIGNED_VARIANT_START')

    def _validate_selector_variants(self):
        for selector_id, variant_ids in self.variant_groups.items():
            if not self._is_selector_node(selector_id):
                continue
            selector = self.nodes_by_id.get(selector_id)
            if not selector:
                continue
            selector_name = selector.get('name', f'node_{selector_id}')
            selector_parent = selector.get('parent_id')
            domain_constraints = self._selector_domain_constraints(selector_id)
            constraints_text = ' | '.join(selector.get('constraints', []) or [])
            if not constraints_text:
                constraints_text = 'none'
            variants_by_type: Dict[MessageType, List[int]] = {}
            formula_buckets: Dict[Tuple[MessageType, str], List[int]] = {}
            for variant_id in variant_ids:
                variant_node = self.nodes_by_id.get(variant_id)
                if not variant_node:
                    self._add_error(category='Structure', description=f'Selector {selector_name} references missing variant {variant_id}', node_id=selector_id)
                    continue
                variant_name = variant_node.get('name', f'node_{variant_id}')
                variant_parent = variant_node.get('parent_id')
                if variant_parent != selector_parent:
                    controller = self.controlled_by_selector.get(variant_id)
                    if controller == selector_id:
                        pass
                    else:
                        variant_ctx = self.contexts.get(variant_id)
                        parent_ctx = self.contexts.get(variant_parent) if variant_parent is not None else None
                        severity = Severity.WARN
                        if variant_ctx and parent_ctx:
                            for sibling_id in parent_ctx.children_ids:
                                if sibling_id == variant_id:
                                    continue
                                sibling_ctx = self.contexts.get(sibling_id)
                                if not sibling_ctx:
                                    continue
                                if self._check_overlap(variant_ctx, sibling_ctx) and (not self._is_overlap_allowed(variant_ctx, sibling_ctx)):
                                    severity = Severity.ERROR
                                    break
                        self._add_error(category='Structure', description=f'Variant {variant_name} parent differs from selector parent and lacks a condition_on edge from selector {selector_name}; exclusivity cannot be verified.', node_id=variant_id, severity=severity)
                try:
                    mt = MessageType(variant_node.get('message_type', 'bidirectional'))
                except Exception:
                    mt = MessageType.BIDIRECTIONAL
                variants_by_type.setdefault(mt, []).append(variant_id)
                raw_formula = self.variant_raw_formula.get(variant_id)
                if raw_formula is not None:
                    formula_buckets.setdefault((mt, raw_formula.strip()), []).append(variant_id)
                condition = self.variant_conditions.get(variant_id)
                if condition is not None:
                    if domain_constraints:
                        s = Solver()
                        s.add(self.solver.assertions())
                        for constraint in domain_constraints:
                            s.add(constraint)
                        s.add(condition)
                        if s.check() == unsat:
                            self._add_error(category='Semantics', description=f'Variant condition "{self.variant_raw_formula.get(variant_id) or condition}" is UNSAT under selector constraints "{constraints_text}".', node_id=variant_id, severity=Severity.WARN, code='UNSAT_VARIANT_SELECTOR')
                    else:
                        self._add_error(category='Semantics', description=f'Validator has no domain constraints for selector "{selector_name}"; cannot prove whether condition "{self.variant_raw_formula.get(variant_id) or condition}" is satisfiable or not.', node_id=variant_id, severity=Severity.WARN, code='UNKNOWN_VARIANT_SELECTOR_DOMAIN')
            for (mt, formula), vids in formula_buckets.items():
                if len(vids) > 1:
                    names = []
                    for vid in vids:
                        ctx = self.contexts.get(vid)
                        names.append(ctx.name if ctx else f'node_{vid}')
                    self._add_error(category='Semantics', description=f"Multiple {mt.value} variants share identical condition '{formula}': " + ', '.join(names), node_id=selector_id, severity=Severity.ERROR, code='DUPLICATE_VARIANT_CONDITIONS')
            for mt, vids in variants_by_type.items():
                conditions = [self.variant_conditions.get(v) for v in vids if self.variant_conditions.get(v) is not None]
                has_default = any((self.variant_conditions.get(v) is None for v in vids))
                if has_default:
                    continue
                if not conditions:
                    self._add_error(category='Semantics', description=f'Selector {selector_name} lacks activation conditions for {mt.value} variants', node_id=selector_id, severity=Severity.WARN)
                    continue
                s = Solver()
                s.add(self.solver.assertions())
                for constraint in domain_constraints:
                    s.add(constraint)
                s.add(Not(Or(conditions)))
                if s.check() == sat:
                    pass

    def _build_coverage_matrices(self):
        self.coverage_matrices = {}

    def _extract_condition_values(self, selector_id: int, formula: str) -> Set[int]:
        if not formula:
            return set()
        expanded = self._expand_condition_shortcuts(formula)
        pattern = re.compile(f'val\\(\\s*{selector_id}\\s*\\)\\s*==\\s*(-?\\d+)')
        values = {int(match.group(1)) for match in pattern.finditer(expanded)}
        return values

    def _format_selector_value(self, value: int) -> str:
        if 0 <= value <= 255:
            return f'0x{value:02X}'
        return str(value)

    def _variant_names(self, variant_ids: Set[int]) -> List[str]:
        names: List[str] = []
        for vid in sorted(variant_ids):
            node = self.nodes_by_id.get(vid, {})
            names.append(node.get('name', f'node_{vid}'))
        return names

    def _should_warn_missing_request(self, selector_value: int, variant_ids: Set[int]) -> bool:
        if selector_value >= 128:
            return False
        if not variant_ids:
            return True
        nodes = [self.nodes_by_id.get(vid, {}) for vid in variant_ids]
        nodes = [n for n in nodes if n]
        if not nodes:
            return True
        if all((n.get('message_type', '').lower() == MessageType.RESPONSE.value for n in nodes)):
            name_blob = ' '.join(((n.get('name', '') or '').lower() for n in nodes))
            if any((keyword in name_blob for keyword in ('error', 'exception', 'fault'))):
                return False
        return True

    def _validate_length_strategies(self):
        length_edges_by_src: Dict[int, List[Dict[str, Any]]] = {}
        length_edges_by_dst: Dict[int, List[Dict[str, Any]]] = {}
        for edge in self.edges:
            if edge.get('rel') == 'length_of':
                try:
                    src = int(edge.get('src'))
                except Exception:
                    src = edge.get('src')
                try:
                    dst = int(edge.get('dst'))
                except Exception:
                    dst = edge.get('dst')
                length_edges_by_src.setdefault(src, []).append(edge)
                length_edges_by_dst.setdefault(dst, []).append(edge)

        def _looks_like_length_field(name: str) -> bool:
            lowered = (name or '').strip().lower()
            if not lowered:
                return False
            tokens = re.split('[^a-z0-9]+', lowered)
            keywords = {'length', 'message_length', 'payload_length', 'pdu_length', 'byte_count', 'bytecount', 'payload_len', 'pdu_len'}
            return any((token in keywords for token in tokens if token))

        def _is_referenced_elsewhere(length_id: int) -> bool:
            token = f'val({length_id})'
            for ctx in self.contexts.values():
                for expr in (ctx.start_expr, ctx.size_expr):
                    if isinstance(expr, str) and token in expr:
                        return True
            for node in self.nodes_by_id.values():
                for constraint in node.get('constraints') or []:
                    if isinstance(constraint, str) and token in constraint:
                        return True
            for edge in self.edges or []:
                formula = edge.get('formula')
                if isinstance(formula, str) and token in formula:
                    return True
            return False
        missing_length_bindings: List[int] = []
        for node_id, ctx in self.contexts.items():
            node = self.nodes_by_id.get(node_id, {})
            size_expr = ctx.size_expr
            raw_size_bits = node.get('size_bits')
            raw_is_variable = isinstance(raw_size_bits, str) and raw_size_bits.strip().lower() == 'variable'
            is_variable_literal = isinstance(size_expr, str) and size_expr.strip().lower() == 'variable'
            if raw_is_variable or is_variable_literal:
                if node_id in length_edges_by_dst:
                    edges = length_edges_by_dst.get(node_id, [])
                    for edge in edges:
                        continue
                    resolved = True
                else:
                    resolved = self._has_deterministic_children(node_id, length_edges_by_dst)
                if not resolved:
                    self._add_error(category='Semantics', description='Variable-length field lacks explicit length binding', node_id=node_id, severity=Severity.WARN)
        for node_id, ctx in self.contexts.items():
            node = self.nodes_by_id.get(node_id, {})
            size_expr = ctx.size_expr
            if not isinstance(size_expr, str):
                continue
            refs = self._extract_val_refs(size_expr)
            if not refs:
                continue
            for ref_id in refs:
                edges_for_ref = length_edges_by_src.get(ref_id, [])
                if any((int(edge.get('dst')) == node_id for edge in edges_for_ref)):
                    continue
                ref_node = self.nodes_by_id.get(ref_id, {})
                ref_name = ref_node.get('name', f'node_{ref_id}')
                node_name = node.get('name', f'node_{node_id}')
                continue
        for node_id, node in self.nodes_by_id.items():
            continue
        for src_id, edges in length_edges_by_src.items():
            src_node = self.nodes_by_id.get(src_id, {})
            if not src_node:
                continue
            constraints = src_node.get('constraints') or []
            constraints_map = src_node.get('constraints_map') or {}
            has_numeric_constraint = bool(constraints) or bool(constraints_map)
            if has_numeric_constraint:
                continue
            src_name = src_node.get('name', f'node_{src_id}')
            dst_names = []
            for edge in edges:
                dst_id = edge.get('dst')
                dst_node = self.nodes_by_id.get(dst_id, {})
                dst_names.append(dst_node.get('name', f'node_{dst_id}'))
            dst_desc = ', '.join(dst_names)
            self._add_error(category='Semantics', description=f'Suggestion: Field "{src_name}" (id={src_id}) feeds length_of edges for {dst_desc} but has no numeric constraints. Please check the source specification-if a valid range is documented, consider adding it.', node_id=src_id, severity=Severity.HINT)

    def _has_deterministic_children(self, node_id: int, length_edges_by_dst: Dict[int, List[Dict[str, Any]]], seen: Optional[Set[int]]=None) -> bool:
        if seen is None:
            seen = set()
        if node_id in seen:
            return False
        seen.add(node_id)
        ctx = self.contexts.get(node_id)
        if not ctx or not ctx.children_ids:
            return False
        for child_id in ctx.children_ids:
            child_ctx = self.contexts.get(child_id)
            if not child_ctx:
                continue
            child_size = child_ctx.size_expr
            if isinstance(child_size, str):
                if child_size in ['variable', 'varint']:
                    if child_id in length_edges_by_dst:
                        continue
                    if not self._has_deterministic_children(child_id, length_edges_by_dst, seen):
                        return False
                else:
                    continue
            else:
                continue
        return True

    def _validate_condition_on_formulas(self) -> None:
        for edge in self.edges or []:
            if str(edge.get('rel')) != 'condition_on':
                continue
            formula = str(edge.get('formula') or '').strip()
            if not formula:
                continue
            src = edge.get('src')
            dst = edge.get('dst')
            try:
                src_id_int = int(src)
            except Exception:
                src_id_int = None
            try:
                dst_id_int = int(dst)
            except Exception:
                dst_id_int = None
            canonical_src = self._canonical_selector_id(src_id_int) if src_id_int is not None else src
            if canonical_src is not None and self._is_selector_node(canonical_src):
                if self._parse_condition(formula) is None:
                    self._add_error(category='Structure', description=f'Invalid condition_on formula for selector routing. Formulas must be a valid boolean expression using explicit operators (and/or/not) and must not concatenate clauses (e.g., `A (B)` is invalid; use `A or (B)`). edge={src}->{dst} formula={formula}', node_id=dst_id_int, severity=Severity.ERROR, code='INVALID_CONDITION_FORMULA')
            if '||' in formula or ' or ' in formula.lower():
                src_node = self.nodes_by_id.get(src_id_int) if src_id_int is not None else {}
                dst_node = self.nodes_by_id.get(dst_id_int) if dst_id_int is not None else {}
                src_name = src_node.get('name', f'node_{src}')
                dst_name = dst_node.get('name', f'node_{dst}')
                warning_msg = f'Condition_on edge from "{src_name}" (id={src}) to "{dst_name}" (id={dst}) uses a combined formula "{formula}". Consider modeling each selector value with a separate condition_on edge, or ensure downstream tooling can interpret compound expressions.'
                self.warning_report_lines.append(f'WARNING: {warning_msg}')

    def _validate_constraints(self):
        for node_id, node in self.nodes_by_id.items():
            constraints = node.get('constraints', []) or []
            ctx = self.contexts.get(node_id)
            if not ctx:
                continue
            for idx, raw in enumerate(constraints):
                normalized = raw.strip()
                if normalized.lower().startswith('formula'):
                    if ctx.node_type == 'selector':
                        continue
                    self._check_formula_constraint(node_id, ctx, normalized, constraint_index=idx, constraint_full=raw)

    def _check_formula_constraint(self, node_id: int, ctx: NodeContext, constraint: str, *, constraint_index: Optional[int]=None, constraint_full: Optional[str]=None):
        try:
            _, expr = constraint.split(':', 1)
        except ValueError:
            self._add_error(category='Semantics', description='Malformed formula constraint', node_id=node_id, severity=Severity.WARN)
            return
        original_expr = expr.strip()
        rhs = original_expr
        import re as _re
        assign_match = _re.match('^\\s*value\\s*=(?!=)', rhs)
        if assign_match:
            parts = rhs.split('=', 1)
            if len(parts) != 2:
                self._add_error(category='Semantics', description='Formula constraint missing assignment', node_id=node_id, severity=Severity.WARN)
                return
            rhs = parts[1].strip()
        referenced_nodes = [int(ref) for ref in re.findall('val\\((\\d+)\\)', rhs)]
        extra_constraints: List[Any] = []
        for ref_id in referenced_nodes:
            if ref_id not in self.nodes_by_id:
                self._add_error(category='Structure', description=f'Constraint references missing node {ref_id}', node_id=node_id)
                return
            ref_ctx = self.contexts.get(ref_id)
            if ref_ctx and ctx.message_type != MessageType.BIDIRECTIONAL:
                if ref_ctx.message_type != MessageType.BIDIRECTIONAL and ref_ctx.message_type != ctx.message_type:
                    self._add_error(category='Semantics', description=f'Constraint references val({ref_id}) with incompatible message type', node_id=node_id, severity=Severity.WARN)
            extra_constraints.extend(self._selector_domain_constraints(ref_id))
        prev_constraint_node = self._current_constraint_node
        self._current_constraint_node = node_id
        try:
            if not self._validate_numeric_formula(rhs, owner_id=node_id, field='constraint', original=original_expr):
                return
            z3_expr = self._expression_to_z3(rhs, owner_id=node_id, field='constraint')
        finally:
            self._current_constraint_node = prev_constraint_node
        status = self._expression_status(node_id, 'constraint')
        if z3_expr is None:
            if status == 'failed':
                self._add_expression_issue(node_id, f'constraints[{constraint_index}]' if constraint_index is not None else 'constraint', constraint_full or original_expr, 'could not be evaluated into a comparable value')
            else:
                self._add_error(category='Semantics', description=f'Unable to interpret formula constraint at constraints[{constraint_index}]' if constraint_index is not None else 'Unable to interpret formula constraint', node_id=node_id, severity=Severity.WARN)
            return
        equality_solver = Solver()
        equality_solver.add(self.solver.assertions())
        for constraint in extra_constraints:
            equality_solver.add(constraint)
        try:
            if isinstance(z3_expr, BoolRef):
                equality_solver.add(z3_expr)
            else:
                equality_solver.add(self.values[node_id] == z3_expr)
        except Exception:
            try:
                equality_solver.add(self.values[node_id] == z3_expr)
            except Exception:
                self._add_error(category='Semantics', description=f'Unable to compose solver constraint from formula at constraints[{constraint_index}]' if constraint_index is not None else 'Unable to compose solver constraint from formula', node_id=node_id, severity=Severity.WARN)
                return
        if equality_solver.check() == unsat:
            self._add_error(category='Semantics', description='Formula constraint cannot be satisfied', node_id=node_id)
            return
        bounds = self._data_type_bounds(self.nodes_by_id[node_id].get('data_type'))
        if bounds and (not isinstance(z3_expr, BoolRef)):
            lo, hi = bounds
            lower_solver = Solver()
            lower_solver.add(self.solver.assertions())
            for constraint in extra_constraints:
                lower_solver.add(constraint)
            lower_solver.add(z3_expr < BitVecVal(lo, 32))
            if lower_solver.check() == sat:
                self._add_error(category='Semantics', description=f'Formula may underflow data type bounds ({lo})', node_id=node_id, severity=Severity.WARN)
            upper_solver = Solver()
            upper_solver.add(self.solver.assertions())
            for constraint in extra_constraints:
                upper_solver.add(constraint)
            upper_solver.add(z3_expr > BitVecVal(hi, 32))
            if upper_solver.check() == sat:
                self._add_error(category='Semantics', description=f'Formula may overflow data type bounds ({hi})', node_id=node_id, severity=Severity.WARN)

    def _validate_reachability(self):
        root_ids = [node_id for node_id, node in self.nodes_by_id.items() if node.get('parent_id') is None]
        if not root_ids:
            return
        visited: Set[int] = set()
        stack = list(root_ids)
        while stack:
            node_id = stack.pop()
            if node_id in visited:
                continue
            visited.add(node_id)
            ctx = self.contexts.get(node_id)
            if not ctx:
                continue
            stack.extend(ctx.children_ids)
        for node_id in self.nodes_by_id:
            if node_id not in visited:
                self._add_error(category='Graph', description='Node is not reachable from any root', node_id=node_id, severity=Severity.WARN)

    def _validate_length_edges_semantics(self) -> None:
        import re

        def nearest_variant(nid: int):
            try:
                cur = nid
                seen = set()
                while True:
                    if cur in seen:
                        return None
                    seen.add(cur)
                    cur = self.parent_by_id.get(cur)
                    if cur is None:
                        return None
                    t = (self.nodes_by_id.get(cur) or {}).get('node_type')
                    if t == 'variant':
                        return cur
            except Exception:
                return None

        def msg_type(nid: int):
            try:
                return (self.nodes_by_id.get(nid) or {}).get('message_type')
            except Exception:
                return None

        def node_exists(nid: int) -> bool:
            return isinstance(nid, int) and nid in self.nodes_by_id
        local_errors = []

        def push(desc: str, node_id: int, severity) -> None:
            local_errors.append(dict(category='Graph', description=desc, node_id=node_id, severity=severity))
        by_dst = {}
        seen_keys = set()
        try:
            edge_list = list(self.edges) if isinstance(self.edges, (list, tuple)) else []
        except Exception:
            edge_list = []
        for e in edge_list:
            try:
                if not isinstance(e, dict) or e.get('rel') != 'length_of':
                    continue
                src, dst = (e.get('src'), e.get('dst'))
                if not (node_exists(src) and node_exists(dst)):
                    key = ('invalid_endpoints', dst, 'WARN', src, dst)
                    if key not in seen_keys:
                        push(f'length_of edge has invalid endpoints: src={src}, dst={dst}', node_id=dst if isinstance(dst, int) else src if isinstance(src, int) else -1, severity=Severity.WARN)
                        seen_keys.add(key)
                    continue
                by_dst.setdefault(dst, []).append(e)
                expr = e.get('expr') or e.get('formula') or e.get('size_expr') or ''
                try:
                    ids = {int(m) for m in re.findall('val\\((\\d+)\\)', str(expr))}
                except Exception:
                    ids = set()
                if ids and ids != {src}:
                    key = ('formula_refs', dst, 'ERROR', tuple(sorted(ids)), src)
                    if key not in seen_keys:
                        push(f'length_of formula references {sorted(ids)} but src is {src}. length_of.formula may only reference val(src); move other terms into dst.size_bits or constraints, or remove extra val() references.', node_id=dst, severity=Severity.ERROR)
                        seen_keys.add(key)
                v_src, v_dst = (nearest_variant(src), nearest_variant(dst))
                if v_src is not None and v_dst is not None and (v_src != v_dst):
                    key = ('cross_variant', dst, 'ERROR', v_src, v_dst, src)
                    if key not in seen_keys:
                        push(f'length_of crosses variants: src {src} (variant {v_src}) -> dst {dst} (variant {v_dst})', node_id=dst, severity=Severity.ERROR)
                        seen_keys.add(key)
                ts, td = (msg_type(src), msg_type(dst))
                tolerant = {None, 'both', 'bidirectional'}
                if ts not in tolerant and td not in tolerant and (ts != td):
                    key = ('msg_type_mismatch', dst, 'WARN', ts, td, src)
                    if key not in seen_keys:
                        push(f'message_type mismatch on length_of: src {src} ({ts}) -> dst {dst} ({td})', node_id=dst, severity=Severity.WARN)
                        seen_keys.add(key)
            except Exception:
                continue
        for dst, edges in by_dst.items():
            try:
                if len(edges) > 1:
                    key = ('multi_bind_dst', dst, 'ERROR', len(edges))
                    if key not in seen_keys:
                        push(f'Multiple length_of bindings to node {dst}', node_id=dst, severity=Severity.ERROR)
                        seen_keys.add(key)
            except Exception:
                continue
        for err in local_errors:
            self._add_error(**err)

    def _validate_circular_dependencies(self):
        import re
        for node_id, ctx in self.contexts.items():
            parent_id = getattr(ctx, 'parent_id', None)
            if parent_id is None:
                continue
            exprs = []
            if isinstance(getattr(ctx, 'start_expr', None), str):
                exprs.append(ctx.start_expr)
            if isinstance(getattr(ctx, 'size_expr', None), str):
                exprs.append(ctx.size_expr)
            circular = False
            for expr in exprs:
                for m in re.finditer('(\\d+)\\.size_bits\\b', expr):
                    ref_id = int(m.group(1))
                    if ref_id == parent_id:
                        circular = True
                        break
                if circular:
                    break
            if circular:
                self._add_error(category='Graph', description="Circular dependency: child references parent's size_bits", node_id=node_id)

    def _format_coverage_reports(self) -> List[str]:
        reports: List[str] = []
        for selector_id, matrix in self.coverage_matrices.items():
            selector = self.nodes_by_id.get(selector_id, {})
            selector_name = selector.get('name', f'node_{selector_id}')
            observed_values: Set[int] = set()
            for mt_map in matrix.values():
                if mt_map:
                    observed_values.update(mt_map.keys())
            if observed_values:
                domain_values = sorted(observed_values)
            else:
                domain_values = self._selector_domain_values(selector_id)
            for mt_label, mt in [('request', MessageType.REQUEST), ('response', MessageType.RESPONSE)]:
                coverage = matrix.get(mt, {})
                if not domain_values:
                    continue
                paired = []
                for value in sorted(coverage.keys()):
                    variant_ids = coverage[value]
                    variant_names = self._variant_names(variant_ids)
                    variant_label = ', '.join(variant_names) if variant_names else 'no matching variants'
                    paired.append(f'{value}->{variant_label}')
                missing = [str(v) for v in domain_values if v not in coverage]
                line = f'Coverage matrix {selector_name} ({mt_label}): '
                line += ', '.join(paired) if paired else 'no covered values'
                if missing:
                    if len(missing) > 10:
                        missing = missing[:10] + ['...']
                    line += f"; missing values: {', '.join(missing)}"
                reports.append(line)
        return reports

    def _format_expression_reports(self) -> List[str]:
        reports: List[str] = []
        status_map = {'ok': 'solved', 'failed': 'failed', 'dynamic': 'dynamic length', 'pending': 'pending'}
        for node_id, traces in self.expression_traces.items():
            node = self.nodes_by_id.get(node_id, {})
            node_name = node.get('name', f'node_{node_id}')
            for trace in traces:
                deps = trace.get('dependencies', []) or []
                if not deps and trace.get('status') == 'ok':
                    continue
                dep_labels = []
                for dep in deps:
                    dep_node_id = dep.get('node_id')
                    dep_node = self.nodes_by_id.get(dep_node_id, {})
                    dep_name = dep_node.get('name', f'node_{dep_node_id}')
                    dep_type = dep.get('type')
                    dep_labels.append(f'{dep_type}:{dep_name}(ID:{dep_node_id})')
                dep_text = ', '.join(dep_labels) if dep_labels else 'no explicit dependency'
                field = trace.get('field') or 'expression'
                status = status_map.get(trace.get('status'), trace.get('status'))
                expr = trace.get('expr')
                result = trace.get('result')
                result_text = f' -> {result}' if result else ''
                reports.append(f'Evaluation trace {node_name}(ID:{node_id}, {field}): {expr}{result_text} | dependencies: {dep_text} | status: {status}')
        return reports

def validate_protocol_tree(tree_json: str) -> ValidationReport:
    try:
        tree = json.loads(tree_json)
        while isinstance(tree, dict) and 'protocol_tree' in tree:
            tree = tree['protocol_tree']
        validator = SyntaxValidator()
        passes, errors = validator.validate(tree)
        extras = validator.coverage_gap_lines + validator.coverage_report_lines + validator.expression_report_lines + validator.warning_report_lines
        issues = dict(validator.structured_issues)
        all_issues = list(issues.values())
        hard_errors = [iss.description for iss in all_issues if is_hard_error(iss)]
        warnings = [iss.description for iss in all_issues if not is_hard_error(iss)]
        ok = len(hard_errors) == 0
        return ValidationReport(ok=ok and passes, errors=hard_errors, warnings=warnings, extras=extras, issues=issues)
    except json.JSONDecodeError as e:
        return ValidationReport(ok=False, errors=[f'Invalid JSON: {str(e)}'], warnings=[], extras=[], issues={})
    except Exception as e:
        return ValidationReport(ok=False, errors=[f'Validation error: {str(e)}'], warnings=[], extras=[], issues={})
