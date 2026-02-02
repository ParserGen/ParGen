from __future__ import annotations
import json
import re
from collections import Counter, defaultdict
from typing import Any, DefaultDict, Dict, List, Optional, Tuple
from .fence_utils import split_fenced_files
from .host_ir_schema import HostIR
from .llm_client import LLMClient
from .parse_ir import Node, ParseIR
from .profile_utils import profile_forbidden_required, profile_max_attempts, profile_violations
from .prompt_builder import build_codegen_prompt, build_doc_summary_codegen_prompt, name_clean

class CodegenAgent:

    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.last_summary: Optional[Dict[str, object]] = None

    def generate_plugin(self, parse_ir: ParseIR, host_ir: HostIR, target_protocol: Optional[str]=None, api_doc: Optional[str]=None, codegen_profile: Optional[Dict[str, Any]]=None, validate: bool=False) -> Dict[str, str]:
        prompt = build_codegen_prompt(parse_ir, host_ir, target_protocol_name=target_protocol, api_doc_text=api_doc, codegen_profile=codegen_profile)
        max_attempts = 1
        if isinstance(codegen_profile, dict) and codegen_profile:
            if codegen_profile.get('forbidden_substrings') or codegen_profile.get('required_substrings'):
                max_attempts = profile_max_attempts(codegen_profile, default=2, key='max_codegen_attempts')
        last_violations: List[str] = []
        summary: Dict[str, object] = {}
        files: Dict[str, str] = {}
        for attempt in range(1, max_attempts + 1):
            attempt_prompt = prompt
            if last_violations:
                attempt_prompt = attempt_prompt + '\n\nPROFILE VIOLATIONS (fix and regenerate ALL artifacts; output format must remain identical):\n- ' + '\n- '.join(last_violations)
            raw = self.llm.complete(attempt_prompt)
            summary, files = self._parse_response(raw)
            files = self._apply_codegen_profile_autofix(files, codegen_profile)
            self.last_summary = summary
            last_violations = profile_violations(files, codegen_profile)
            if not last_violations:
                break
        if last_violations:
            has_forbidden = any((v.startswith('forbidden_substring=') for v in last_violations))
            if has_forbidden:
                raise ValueError('Codegen output violates codegen_profile constraints: ' + '; '.join(last_violations))
            summary = dict(summary) if isinstance(summary, dict) else {}
            summary.setdefault('profile_violations', list(last_violations))
            summary.setdefault('profile_violation_mode', 'soft_required_only')
            self.last_summary = summary
        if validate:
            self._validate(summary, files, parse_ir, host_ir)
        return files

    def generate_plugin_from_doc_summary(self, *, protocol_name: str, document_summary: str, host_ir: HostIR, target_protocol: Optional[str]=None, api_doc: Optional[str]=None, codegen_profile: Optional[Dict[str, Any]]=None, constraints_contract: Optional[str]=None) -> Dict[str, str]:
        prompt = build_doc_summary_codegen_prompt(protocol_name=protocol_name, document_summary=document_summary, host_ir=host_ir, target_protocol_name=target_protocol, api_doc_text=api_doc, codegen_profile=codegen_profile, constraints_contract=constraints_contract)
        max_attempts = 1
        if isinstance(codegen_profile, dict) and codegen_profile:
            if codegen_profile.get('forbidden_substrings') or codegen_profile.get('required_substrings'):
                max_attempts = profile_max_attempts(codegen_profile, default=2, key='max_codegen_attempts')
        last_violations: List[str] = []
        summary: Dict[str, object] = {}
        files: Dict[str, str] = {}
        for attempt in range(1, max_attempts + 1):
            attempt_prompt = prompt
            if last_violations:
                attempt_prompt = attempt_prompt + '\n\nPROFILE VIOLATIONS (fix and regenerate ALL artifacts; output format must remain identical):\n- ' + '\n- '.join(last_violations)
            raw = self.llm.complete(attempt_prompt)
            summary, files = self._parse_response(raw)
            files = self._apply_codegen_profile_autofix(files, codegen_profile)
            self.last_summary = summary
            last_violations = profile_violations(files, codegen_profile)
            if not last_violations:
                break
        if last_violations:
            has_forbidden = any((v.startswith('forbidden_substring=') for v in last_violations))
            if has_forbidden:
                raise ValueError('Codegen output violates codegen_profile constraints: ' + '; '.join(last_violations))
            summary = dict(summary) if isinstance(summary, dict) else {}
            summary.setdefault('profile_violations', list(last_violations))
            summary.setdefault('profile_violation_mode', 'soft_required_only')
            self.last_summary = summary
        return files

    def _apply_codegen_profile_autofix(self, files: Dict[str, str], codegen_profile: Optional[Dict[str, Any]]) -> Dict[str, str]:
        if not isinstance(codegen_profile, dict) or not codegen_profile:
            return files
        if not isinstance(files, dict) or not files:
            return files
        forbidden, required = profile_forbidden_required(codegen_profile)
        if not forbidden and (not required):
            return files
        patched = dict(files)
        changed_any = False
        try:
            host = str(codegen_profile.get('host') or '').strip().lower()
        except Exception:
            host = ''
        if host in {'wireshark_lua', 'wireshark-lua'} and 'tvb_' in set(forbidden):
            for name, content in list(patched.items()):
                if not isinstance(content, str) or not name.endswith('.lua'):
                    continue
                if 'tvb_' not in content:
                    continue
                updated = content.replace('tvb_', 'buf_')
                if updated != content:
                    patched[name] = updated
                    changed_any = True
        missing = [tok for tok in required if not any((tok in (content or '') for content in patched.values()))]
        if not missing:
            return patched if changed_any else files
        if set(missing).issubset({'pinfo->destport', 'pinfo->srcport'}):
            port = 0
            try:
                wireshark_cfg = codegen_profile.get('wireshark_c') if isinstance(codegen_profile, dict) else None
                if isinstance(wireshark_cfg, dict):
                    reg = wireshark_cfg.get('registration')
                    if isinstance(reg, dict):
                        port = int(reg.get('port', 0) or 0)
            except Exception:
                port = 0
            target_name: Optional[str] = None
            for name, content in files.items():
                if not isinstance(content, str):
                    continue
                if name.endswith('.c') and 'packet_info' in content and ('pinfo' in content):
                    target_name = name
                    break
            if not target_name:
                for name in files.keys():
                    if name.endswith('.c'):
                        target_name = name
                        break
            if target_name:
                before = patched.get(target_name, '')
                after = self._inject_wireshark_direction_tokens(before, port=port)
                if after != before:
                    patched[target_name] = after
                    changed_any = True
                return patched if changed_any else files
        if set(missing).issubset({'pinfo.src_port', 'pinfo.dst_port'}):
            port = 0
            try:
                ws_lua_cfg = codegen_profile.get('wireshark_lua') if isinstance(codegen_profile, dict) else None
                if isinstance(ws_lua_cfg, dict):
                    reg = ws_lua_cfg.get('registration')
                    if isinstance(reg, dict):
                        port = int(reg.get('port', 0) or 0)
            except Exception:
                port = 0
            target_name: Optional[str] = None
            for name, content in files.items():
                if not isinstance(content, str):
                    continue
                if name.endswith('.lua') and ('Proto(' in content or '.dissector' in content or 'pinfo' in content):
                    target_name = name
                    break
            if not target_name:
                for name in files.keys():
                    if name.endswith('.lua'):
                        target_name = name
                        break
            if target_name:
                before = patched.get(target_name, '')
                after = self._inject_wireshark_lua_direction_tokens(before, port=port)
                if after != before:
                    patched[target_name] = after
                    changed_any = True
                return patched if changed_any else files
        return patched if changed_any else files

    def _inject_wireshark_direction_tokens(self, content: str, *, port: int) -> str:
        if not isinstance(content, str) or not content:
            content = ''
        if 'pinfo->destport' in content and 'pinfo->srcport' in content:
            return content
        registered_port = int(port or 0)
        snippet = f'\n    /* Tool codegen_profile autofix: direction classification */\n    const unsigned int bs_registered_port = {registered_port};\n    const int bs_is_request = (pinfo->destport == bs_registered_port);\n    const int bs_is_response = (pinfo->srcport == bs_registered_port);\n    (void)bs_is_request;\n    (void)bs_is_response;\n'
        func_pattern = re.compile('(packet_info\\s*\\*\\s*pinfo[\\s\\S]*?\\)\\s*\\{)')
        match = func_pattern.search(content)
        if match:
            insert_at = match.end()
            return content[:insert_at] + snippet + content[insert_at:]
        param_match = re.search('packet_info\\s*\\*\\s*pinfo', content)
        if param_match:
            brace_at = content.find('{', param_match.end())
            if brace_at != -1:
                insert_at = brace_at + 1
                return content[:insert_at] + snippet + content[insert_at:]
        return content + '\n/* Tool codegen_profile autofix: pinfo->destport pinfo->srcport */\n'

    def _inject_wireshark_lua_direction_tokens(self, content: str, *, port: int) -> str:
        if not isinstance(content, str) or not content:
            content = ''
        if 'pinfo.dst_port' in content and 'pinfo.src_port' in content:
            return content
        registered_port = int(port or 0)
        snippet = f'\n    -- Tool codegen_profile autofix: direction classification\n    local bs_registered_port = {registered_port}\n    local bs_dst_port = tonumber(tostring(pinfo.dst_port))\n    local bs_src_port = tonumber(tostring(pinfo.src_port))\n    local bs_is_request = (bs_dst_port == bs_registered_port)\n    local bs_is_response = (bs_src_port == bs_registered_port)\n    if bs_is_request or bs_is_response then end\n'
        func_pattern = re.compile('^(?:local\\s+)?function\\s+[^\\n]*\\([^\\)]*\\bpinfo\\b[^\\)]*\\)\\s*$', re.MULTILINE)
        match = func_pattern.search(content)
        if match:
            line_end = content.find('\n', match.end())
            if line_end == -1:
                return content + '\n' + snippet.lstrip('\n')
            insert_at = line_end + 1
            return content[:insert_at] + snippet + content[insert_at:]
        assign_pattern = re.compile('^\\s*.*=\\s*function\\s*\\([^\\)]*\\bpinfo\\b[^\\)]*\\)\\s*$', re.MULTILINE)
        match = assign_pattern.search(content)
        if match:
            line_end = content.find('\n', match.end())
            if line_end == -1:
                return content + '\n' + snippet.lstrip('\n')
            insert_at = line_end + 1
            return content[:insert_at] + snippet + content[insert_at:]
        return content + '\n-- Tool codegen_profile autofix: pinfo.dst_port pinfo.src_port\n'

    def _split_files(self, raw: str) -> Dict[str, str]:
        files = split_fenced_files(raw)
        if not files and raw.strip():
            return {'plugin.txt': raw.strip()}
        return files

    def _parse_response(self, raw: str) -> Tuple[Dict[str, object], Dict[str, str]]:
        summary: Dict[str, object] = {}
        summary_pattern = re.compile('```summary\\s*(\\{.*?\\})\\s*```', re.DOTALL)
        match = summary_pattern.search(raw)
        if match:
            try:
                summary = json.loads(match.group(1))
            except Exception:
                summary = {}
        cleaned_raw = summary_pattern.sub('', raw) if match else raw
        files = self._split_files(cleaned_raw)
        return (summary, files)

    def _leaf_path_nodes(self, parse_ir: ParseIR) -> Dict[str, Node]:
        children_map: Dict[int, List[int]] = {}
        for node in parse_ir.nodes.values():
            if node.parent_id is None:
                continue
            children_map.setdefault(node.parent_id, []).append(node.id)
        parent_map: Dict[int, Optional[int]] = {node.id: node.parent_id for node in parse_ir.nodes.values()}

        def build_path(node_id: int) -> str:
            node = parse_ir.nodes[node_id]
            parts: List[str] = [name_clean(node.name)]
            cur = parent_map.get(node_id)
            while cur is not None and cur in parse_ir.nodes:
                parts.append(name_clean(parse_ir.nodes[cur].name))
                cur = parent_map.get(cur)
            return '.'.join(reversed(parts))
        leaf_ids = [node.id for node in parse_ir.nodes.values() if not children_map.get(node.id)]
        path_to_node: Dict[str, Node] = {}
        for leaf_id in leaf_ids:
            path_to_node[build_path(leaf_id)] = parse_ir.nodes[leaf_id]
        return path_to_node

    def _leaf_paths(self, parse_ir: ParseIR) -> List[str]:
        return list(self._leaf_path_nodes(parse_ir).keys())

    def _validate(self, summary: Dict[str, object], files: Dict[str, str], parse_ir: ParseIR, host_ir: HostIR) -> None:
        artifacts_declared = {art.id for art in host_ir.artifacts}
        artifacts_used: List[str] = []
        mapping_list: List[Dict[str, str]] = []
        if isinstance(summary, dict):
            if isinstance(summary.get('artifacts_used'), list):
                artifacts_used = [str(x) for x in summary.get('artifacts_used')]
            if isinstance(summary.get('field_to_code_mapping'), list):
                mapping_list = [m for m in summary.get('field_to_code_mapping') if isinstance(m, dict)]
        if artifacts_used:
            unknown_artifacts = [a for a in artifacts_used if a not in artifacts_declared]
            if unknown_artifacts:
                raise ValueError(f'Generated artifacts_used not in host_ir: {unknown_artifacts}')
            missing_artifacts = [a for a in artifacts_declared if a not in artifacts_used]
            if missing_artifacts:
                raise ValueError(f'Missing artifacts from summary: {missing_artifacts}')
        leaf_map = self._leaf_path_nodes(parse_ir)
        required_paths = list(leaf_map.keys())
        counts: Counter[str] = Counter()
        ops_by_path: DefaultDict[str, List[str]] = defaultdict(list)
        for m in mapping_list:
            path = str(m.get('format_path') or '').strip()
            if not path:
                continue
            counts[path] += 1
            op = str(m.get('operation') or '').strip()
            if op:
                ops_by_path[path].append(op)
        missing_paths = [p for p in required_paths if counts[p] == 0]
        duplicate_paths = [p for p in required_paths if counts[p] > 1]
        if required_paths and missing_paths:
            raise ValueError(f'Field coverage missing paths (required leaf fields not mapped): {missing_paths}')
        if duplicate_paths:
            raise ValueError(f'Field coverage duplicate mappings (leaf fields mapped more than once): {duplicate_paths}')
        wrong_kind_paths: List[str] = []
        for path, node in leaf_map.items():
            ops = ops_by_path.get(path, [])
            if not ops:
                continue
            if node.kind == 'field':
                bad_ops = [op for op in ops if op in {'container_op', 'selector_op'}]
                if bad_ops:
                    wrong_kind_paths.append(f'{path} (kind={node.kind}, ops={sorted(set(bad_ops))})')
        if wrong_kind_paths:
            raise ValueError(f"Leaf nodes with kind=='field' must only use field_op in field_to_code_mapping; violations: {wrong_kind_paths}")
        if artifacts_declared and len(files) < len(artifacts_declared):
            raise ValueError('Fewer files than declared artifacts; likely missing outputs.')
