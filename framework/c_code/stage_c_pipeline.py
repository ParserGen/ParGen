from __future__ import annotations
import json
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from framework.paths import DATA_DIR, LOGS_DIR
from .code_repair_agent import CodeRepairAgent, RepairDiagnostics
from .codegen_agent import CodegenAgent
from .constraint_contract import build_contract, find_missing_tags, format_contract_for_prompt
from .host_docs import load_host_docs
from .host_ir_agent import HostIRAgent
from .llm_client import LLMClient, LLMConfig, create_llm_client
from .parse_ir import build_parse_ir

@dataclass
class StageCConfig:
    format_tree_path: Path
    host_name: str
    protocol_family: Optional[str]
    host_docs_dir: Path
    output_dir: Path
    host_ir_cache_path: Optional[Path] = None
    codegen_profile_path: Optional[Path] = None
    api_doc_paths: Optional[List[Path]] = None
    doc_summary_text: Optional[str] = None
    verify: bool = False
    llm_config: Optional[LLMConfig] = None
    contract_repair_max_rounds: int = 2

def _infer_protocol_root(*, tree_path: Path, protocol_family: Optional[str]) -> Path:
    family = (protocol_family or '').strip()
    if family:
        cand = DATA_DIR / family
        if cand.exists():
            return cand.resolve()
        for parent in tree_path.parents:
            if parent.name == family:
                return parent
    for parent in tree_path.parents:
        if (parent / 'inputs').exists() and (parent / 'outputs').exists():
            return parent
    for parent in tree_path.parents:
        if parent.name == 'outputs':
            return parent.parent
    return tree_path.parent.parent

def run_stage_c(cfg: StageCConfig, llm_client: Optional[LLMClient]=None) -> Dict[str, Any]:
    out_dir = cfg.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    llm = llm_client or create_llm_client(cfg.llm_config)
    docs = load_host_docs(cfg.host_docs_dir)
    doc_summary = str(getattr(cfg, 'doc_summary_text', '') or '').strip()
    if doc_summary:
        api_doc_text = _load_api_docs_explicit_only(cfg)
    else:
        api_doc_text = _load_api_docs(cfg)
    if not docs and (not (cfg.host_ir_cache_path and cfg.host_ir_cache_path.exists())):
        raise RuntimeError(f'No host docs found under {cfg.host_docs_dir} and no Host-IR cache specified; cannot learn Host-IR.')
    host_ir_agent = HostIRAgent(llm)
    try:
        host_ir = host_ir_agent.build_host_ir(host_name=cfg.host_name, docs=docs, cache_path=cfg.host_ir_cache_path)
    except Exception:
        raw = getattr(host_ir_agent, 'last_raw_host_ir', None)
        if raw:
            stage_c_logs = LOGS_DIR / 'stage_c'
            stage_c_logs.mkdir(parents=True, exist_ok=True)
            fail_path = stage_c_logs / 'host_ir_raw_failed.yaml'
            fail_path.write_text(raw, encoding='utf-8')
        raise
    codegen_profile = _load_codegen_profile(cfg.codegen_profile_path)
    code_agent = CodegenAgent(llm)
    if doc_summary:
        constraints_mode = 'codegen'
        target_proto = cfg.protocol_family or 'unknown_protocol'
        files = code_agent.generate_plugin_from_doc_summary(protocol_name=target_proto, document_summary=doc_summary, host_ir=host_ir, target_protocol=target_proto, api_doc=api_doc_text, codegen_profile=codegen_profile)
        plugin_dir = out_dir / 'plugin' / cfg.host_name
        if plugin_dir.exists():
            shutil.rmtree(plugin_dir)
        plugin_dir.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            path = plugin_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
        meta = {'host': cfg.host_name, 'protocol': target_proto, 'target_protocol': target_proto, 'constraints_mode': constraints_mode, 'input_spec': 'doc_summary', 'doc_summary_chars': len(doc_summary), 'generated_at': int(time.time())}
        if cfg.codegen_profile_path:
            meta['codegen_profile_path'] = str(cfg.codegen_profile_path)
        try:
            (plugin_dir / '_stage_c_meta.json').write_text(json.dumps(meta, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
        except Exception:
            pass
        summary: Dict[str, Any] = {'host': cfg.host_name, 'protocol': target_proto, 'target_protocol': target_proto, 'plugin_dir': str(plugin_dir), 'files': sorted(files.keys()), 'docs_loaded': len(docs), 'constraints_mode': constraints_mode, 'input_spec': 'doc_summary', 'doc_summary_chars': len(doc_summary)}
        if cfg.codegen_profile_path:
            summary['codegen_profile_path'] = str(cfg.codegen_profile_path)
        if getattr(code_agent, 'last_summary', None):
            summary['llm_summary'] = code_agent.last_summary
        if cfg.verify:
            summary['verify'] = 'pending'
        summary_path = out_dir / 'stage_c_summary.json'
        summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding='utf-8')
        return summary
    tree_json = json.loads(cfg.format_tree_path.read_text(encoding='utf-8'))
    parse_ir = build_parse_ir(tree_json)
    target_proto = cfg.protocol_family or parse_ir.protocol_name
    files = code_agent.generate_plugin(parse_ir, host_ir, target_protocol=target_proto, api_doc=api_doc_text, codegen_profile=codegen_profile, validate=cfg.verify)
    contract_items = build_contract(parse_ir)
    mode = 'codegen'
    missing = find_missing_tags(files=files, items=contract_items, host_name=cfg.host_name)
    contract_repaired = False
    contract_repair_rounds = 0
    if mode == 'codegen' and missing:
        repair_agent = CodeRepairAgent(llm)
        protocol_root = _infer_protocol_root(tree_path=cfg.format_tree_path, protocol_family=cfg.protocol_family)
        logs_dir = protocol_root / 'logs' / 'stage_c' / 'contract_repair' / cfg.host_name
        logs_dir.mkdir(parents=True, exist_ok=True)
        for round_idx in range(max(1, int(getattr(cfg, 'contract_repair_max_rounds', 2) or 2))):
            contract_repair_rounds = round_idx + 1
            missing_items = [it for it in contract_items if it.id in set(missing)]
            contract_text = format_contract_for_prompt(host_name=cfg.host_name, items=missing_items)
            ts = time.strftime('%Y%m%d_%H%M%S')
            prompt_path = logs_dir / f'round{round_idx:02d}_{ts}_prompt.txt'
            response_path = logs_dir / f'round{round_idx:02d}_{ts}_response.txt'
            diagnostics = RepairDiagnostics(tool_name='constraint_contract', protocol_name=parse_ir.protocol_name, errors=tuple([f"Missing constraint tags ({len(missing)}): {', '.join(missing[:25])}"]), log_tail='', host_docs=contract_text)
            extra_rules = 'Constraint contract repair (STRICT):\n- Add/repair runtime validation so that every missing contract item emits its tag.\n- Keep existing parsing logic and field offsets intact.\n- Do NOT remove deterministic constraint checks if they already exist.\n'
            changed = repair_agent.repair_files(files=files, diagnostics=diagnostics, codegen_profile=codegen_profile, extra_rules=extra_rules, max_attempts=2, prompt_path=prompt_path, response_path=response_path, allow_new_files=False)
            if not changed:
                break
            files = dict(files)
            files.update(changed)
            missing = find_missing_tags(files=files, items=contract_items, host_name=cfg.host_name)
            contract_repaired = True
            if not missing:
                break
    plugin_dir = out_dir / 'plugin' / cfg.host_name
    if plugin_dir.exists():
        shutil.rmtree(plugin_dir)
    plugin_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = plugin_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    meta = {'host': cfg.host_name, 'protocol': parse_ir.protocol_name, 'target_protocol': target_proto, 'constraints_mode': mode, 'generated_at': int(time.time())}
    if contract_items:
        meta['constraint_contract_total'] = len(contract_items)
    if missing:
        meta['constraint_contract_missing_count'] = len(missing)
        meta['constraint_contract_missing_sample'] = list(missing[:50])
    if contract_repaired:
        meta['constraint_contract_repaired'] = True
        meta['constraint_contract_repair_rounds'] = int(contract_repair_rounds)
    if cfg.codegen_profile_path:
        meta['codegen_profile_path'] = str(cfg.codegen_profile_path)
    try:
        (plugin_dir / '_stage_c_meta.json').write_text(json.dumps(meta, ensure_ascii=True, indent=2) + '\n', encoding='utf-8')
    except Exception:
        pass
    summary: Dict[str, Any] = {'host': cfg.host_name, 'protocol': parse_ir.protocol_name, 'target_protocol': target_proto, 'plugin_dir': str(plugin_dir), 'files': sorted(files.keys()), 'docs_loaded': len(docs), 'constraints_mode': mode}
    if contract_items:
        summary['constraint_contract_total'] = len(contract_items)
    if missing:
        summary['constraint_contract_missing_count'] = len(missing)
        summary['constraint_contract_missing_sample'] = list(missing[:50])
    if contract_repaired:
        summary['constraint_contract_repaired'] = True
        summary['constraint_contract_repair_rounds'] = int(contract_repair_rounds)
    if cfg.codegen_profile_path:
        summary['codegen_profile_path'] = str(cfg.codegen_profile_path)
    if getattr(code_agent, 'last_summary', None):
        summary['llm_summary'] = code_agent.last_summary
    if cfg.verify:
        summary['verify'] = 'pending'
    summary_path = out_dir / 'stage_c_summary.json'
    summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding='utf-8')
    if mode == 'codegen' and missing:
        raise RuntimeError(f'Stage C constraint contract not satisfied in constraints_mode=codegen; missing_tags={len(missing)}. See {summary_path} and logs under {out_dir}.')
    return summary

def _load_codegen_profile(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    profile_path = Path(path)
    if not profile_path.exists() or not profile_path.is_file():
        return None
    try:
        payload = json.loads(profile_path.read_text(encoding='utf-8'))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload

def _load_api_docs_explicit_only(cfg: StageCConfig) -> str:
    texts: List[str] = []
    max_total_chars = 20000
    for path in cfg.api_doc_paths or []:
        if path and Path(path).is_file():
            try:
                texts.append(Path(path).read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
        if sum((len(t) for t in texts)) > max_total_chars:
            break
    return '\n\n'.join(texts).strip()

def _load_api_docs(cfg: StageCConfig) -> str:
    texts: List[str] = []
    max_total_chars = 20000
    for path in cfg.api_doc_paths or []:
        if path and Path(path).is_file():
            try:
                texts.append(Path(path).read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
    base_dir = cfg.format_tree_path.parent
    candidates = list(base_dir.glob('traffic_*.txt')) + list(base_dir.glob('*.md')) + list(base_dir.glob('*.txt'))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            texts.append(path.read_text(encoding='utf-8', errors='ignore'))
        except Exception:
            continue
        if sum((len(t) for t in texts)) > max_total_chars:
            break
    protocol_root = _infer_protocol_root(tree_path=cfg.format_tree_path, protocol_family=cfg.protocol_family)
    traffic_dir = protocol_root / 'inputs' / 'traffic'
    if traffic_dir.exists():
        for path in sorted(traffic_dir.glob('traffic*.txt')):
            try:
                texts.append(path.read_text(encoding='utf-8', errors='ignore'))
            except Exception:
                continue
            if sum((len(t) for t in texts)) > max_total_chars:
                break
    stage_a_dir = protocol_root / 'outputs' / 'stage_a'
    if stage_a_dir.exists():
        json_candidates = list(stage_a_dir.glob('*_document_sections_subset.json'))
        if not json_candidates:
            json_candidates = list(stage_a_dir.glob('*_document_sections.json'))
        if not json_candidates:
            json_candidates = list(stage_a_dir.glob('*.json'))
        for path in sorted(json_candidates):
            try:
                rendered = _render_stage_a_sections(path, max_chars=max_total_chars - sum((len(t) for t in texts)))
            except Exception:
                continue
            if rendered:
                texts.append(rendered)
            if sum((len(t) for t in texts)) > max_total_chars:
                break
    return '\n\n'.join(texts).strip()

def _render_stage_a_sections(path: Path, max_chars: int=12000) -> str:
    if max_chars <= 0:
        return ''
    try:
        payload = json.loads(path.read_text(encoding='utf-8', errors='ignore'))
    except Exception:
        return ''
    if isinstance(payload, dict):
        for key in ('sections', 'items', 'data'):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
    if not isinstance(payload, list):
        return ''

    def score(sec: dict) -> int:
        title = f"{sec.get('number', '')} {sec.get('title', '')}".lower()
        s = 0
        if 'mbap' in title:
            s += 10
        if 'pdu' in title:
            s += 8
        if 'function' in title or re.search('\\b0x[0-9a-f]+\\b', title):
            s += 6
        if 'request' in title:
            s += 3
        if 'response' in title:
            s += 3
        if sec.get('packet_formats'):
            s += 5
        return -s
    sections = [sec for sec in payload if isinstance(sec, dict)]
    sections.sort(key=score)
    out_lines: list[str] = [f'[StageASections] source={path.name}']
    used = 0
    for sec in sections:
        number = str(sec.get('number') or '').strip()
        title = str(sec.get('title') or '').strip()
        content = str(sec.get('content') or '').strip()
        header = f'\n[Section {number}] {title}'.strip()
        block_lines = [header]
        if content:
            block_lines.append(content)
        pf_list = sec.get('packet_formats') or []
        if isinstance(pf_list, list):
            for pf in pf_list:
                if not isinstance(pf, dict):
                    continue
                fmt_name = str(pf.get('format_name') or '').strip()
                fmt_desc = str(pf.get('description') or '').strip()
                total_size = str(pf.get('total_size') or '').strip()
                if fmt_name:
                    block_lines.append(f'- Format: {fmt_name} ({total_size})')
                if fmt_desc:
                    block_lines.append(f'  {fmt_desc}')
                fields = pf.get('fields') or []
                if isinstance(fields, list) and fields:
                    block_lines.append('  Fields:')
                    for f in fields:
                        if not isinstance(f, dict):
                            continue
                        fname = str(f.get('field_name') or '').strip()
                        ftype = str(f.get('data_type') or '').strip()
                        bpos = str(f.get('byte_position') or '').strip()
                        size = str(f.get('size') or '').strip()
                        desc = str(f.get('description') or '').strip()
                        if not fname:
                            continue
                        line = f'    - {fname} | {ftype} | bytes {bpos} | {size}'
                        if desc:
                            desc_short = re.sub('\\s+', ' ', desc)
                            if len(desc_short) > 160:
                                desc_short = desc_short[:157] + '...'
                            line += f' | {desc_short}'
                        block_lines.append(line)
        block = '\n'.join(block_lines).strip() + '\n'
        if used + len(block) > max_chars:
            remaining = max_chars - used
            if remaining > 0:
                out_lines.append(block[:remaining])
            break
        out_lines.append(block)
        used += len(block)
    return '\n'.join(out_lines).strip()
