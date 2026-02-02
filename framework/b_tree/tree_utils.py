from __future__ import annotations
import logging
from typing import Any, Dict, List
logger = logging.getLogger(__name__)

def _coerce_int(value: Any) -> Any:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return value
        try:
            return int(candidate, 0)
        except ValueError:
            return value
    return value

def normalize_protocol_tree(tree_like: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(tree_like, dict):
        return tree_like
    tree = tree_like
    seen: set[int] = set()
    while isinstance(tree, dict) and 'protocol_tree' in tree and isinstance(tree['protocol_tree'], dict):
        identifier = id(tree)
        if identifier in seen:
            break
        seen.add(identifier)
        tree = tree['protocol_tree']
    if not isinstance(tree, dict):
        return tree_like
    nodes = tree.get('nodes')
    if not isinstance(nodes, list):
        nodes = []
        tree['nodes'] = nodes
    edges = tree.get('edges')
    if not isinstance(edges, list):
        edges = []
        tree['edges'] = edges
    if 'root_node_id' in tree:
        tree['root_node_id'] = _coerce_int(tree.get('root_node_id'))
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if 'node_id' in node:
            node['node_id'] = _coerce_int(node.get('node_id'))
        if 'parent_id' in node:
            node['parent_id'] = _coerce_int(node.get('parent_id'))
        children = node.get('children_ids')
        if isinstance(children, list):
            node['children_ids'] = [_coerce_int(child) for child in children]
        elif children is None:
            node['children_ids'] = []
        if 'length_strategy' in node:
            node.pop('length_strategy', None)
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        if 'src' in edge:
            edge['src'] = _coerce_int(edge.get('src'))
        if 'dst' in edge:
            edge['dst'] = _coerce_int(edge.get('dst'))
    return tree
_SELECTOR_ALLOWED_PARENT_TYPES = {'container', 'protocol', 'message'}
_SELECTOR_FALLBACK_PARENT_TYPE = 'container'
_SELECTOR_PARENT_SKIP_TYPES = {'variant', 'selector'}

def auto_fix_selector_parent_types(tree: Dict[str, Any]) -> bool:
    nodes = tree.get('nodes')
    if not isinstance(nodes, list):
        return False
    lookup: Dict[Any, Dict[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_id = node.get('node_id')
        candidates = {node_id, _coerce_int(node_id)}
        for candidate in list(candidates):
            if candidate is None:
                candidates.discard(candidate)
                continue
            candidates.add(str(candidate))
        for candidate in candidates:
            if candidate is None:
                continue
            lookup[candidate] = node
    changed = False
    for node in nodes:
        if not isinstance(node, dict):
            continue
        child_type = (node.get('node_type') or '').strip().lower()
        if child_type != 'selector':
            continue
        parent_id = node.get('parent_id')
        parent = None
        for key in (parent_id, _coerce_int(parent_id), str(parent_id) if parent_id is not None else None):
            if key is None:
                continue
            parent = lookup.get(key)
            if parent:
                break
        if not parent:
            continue
        parent_type_raw = parent.get('node_type')
        parent_type = (parent_type_raw or '').strip().lower()
        if parent_type in _SELECTOR_ALLOWED_PARENT_TYPES:
            continue
        if parent_type in _SELECTOR_PARENT_SKIP_TYPES:
            logger.debug('Auto-fix skipped for selector %s (ID:%s) with parent type %s', node.get('name', f"node_{node.get('node_id')}") or 'selector', node.get('node_id'), parent_type or '<none>')
            continue
        parent_name = parent.get('name', f"node_{parent.get('node_id')}")
        child_name = node.get('name', f"node_{node.get('node_id')}")
        logger.info('Auto-fix: updated parent %s (ID:%s) node_type %s -> %s to host selector %s (ID:%s)', parent_name, parent.get('node_id'), parent_type_raw or '<unset>', _SELECTOR_FALLBACK_PARENT_TYPE, child_name, node.get('node_id'))
        parent['node_type'] = _SELECTOR_FALLBACK_PARENT_TYPE
        changed = True
    return changed
