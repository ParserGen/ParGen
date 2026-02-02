from __future__ import annotations
import json
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .fence_utils import split_fenced_files
from .llm_client import LLMClient
from .profile_utils import profile_max_attempts, profile_violations

@dataclass(frozen=True)
class RepairDiagnostics:
    tool_name: str
    protocol_name: str
    errors: Tuple[str, ...] = tuple()
    log_tail: str = ''
    log_tail_max_chars: int = 12000
    host_docs: str = ''
    host_docs_max_chars: int = 20000

class CodeRepairAgent:

    def __init__(self, llm: LLMClient):
        self.llm = llm
        self.last_prompt: Optional[str] = None
        self.last_raw_response: Optional[str] = None
        self.last_violations: List[str] = []

    def repair_files(self, *, files: Dict[str, str], diagnostics: RepairDiagnostics, codegen_profile: Optional[Dict[str, Any]]=None, extra_rules: Optional[str]=None, max_attempts: Optional[int]=None, prompt_path: Optional[Path]=None, response_path: Optional[Path]=None, allow_new_files: bool=False) -> Optional[Dict[str, str]]:
        if not files:
            return None
        allowed_names = set(files.keys())
        attempts = max_attempts
        if attempts is None:
            attempts = profile_max_attempts(codegen_profile, default=2, key='max_repair_attempts')
            if attempts == 2 and isinstance(codegen_profile, dict) and ('max_repair_attempts' not in codegen_profile):
                attempts = profile_max_attempts(codegen_profile, default=2, key='max_codegen_attempts')
            attempts = max(1, min(3, int(attempts)))
        base_prompt = self._build_prompt(files=files, diagnostics=diagnostics, codegen_profile=codegen_profile, extra_rules=extra_rules)
        last_problem: List[str] = []
        for attempt in range(1, attempts + 1):
            prompt = base_prompt
            if last_problem:
                prompt += '\n\nREPAIR VIOLATIONS (fix and regenerate ALL provided files; output format must remain identical):\n- ' + '\n- '.join(last_problem)
            self.last_prompt = prompt
            if prompt_path:
                self._try_write(prompt_path, prompt, attempt=attempt)
            try:
                raw = self.llm.complete(prompt)
            except Exception as exc:
                self.last_raw_response = f'[LLM ERROR] {type(exc).__name__}: {exc}'
                if response_path:
                    self._try_write(response_path, self.last_raw_response, attempt=attempt)
                return None
            self.last_raw_response = raw
            if response_path:
                self._try_write(response_path, raw, attempt=attempt)
            patched = split_fenced_files(raw)
            if not patched:
                last_problem = ['no ```file:...``` blocks found in LLM output']
                continue
            if not allow_new_files:
                patched = {k: v for k, v in patched.items() if k in allowed_names}
            if not patched:
                last_problem = ['LLM output did not include any allowed filenames']
                continue
            changed: Dict[str, str] = {}
            merged = dict(files)
            for name, content in patched.items():
                if not (content or '').strip():
                    continue
                if content.strip() != (files.get(name) or '').strip():
                    merged[name] = content.rstrip() + '\n'
                    changed[name] = content.rstrip() + '\n'
            if not changed:
                last_problem = ['LLM output made no changes to any allowed files']
                continue
            violations = profile_violations(merged, codegen_profile)
            if violations:
                self.last_violations = violations
                last_problem = violations
                continue
            self.last_violations = []
            return changed
        return None

    def _build_prompt(self, *, files: Dict[str, str], diagnostics: RepairDiagnostics, codegen_profile: Optional[Dict[str, Any]], extra_rules: Optional[str]) -> str:
        err_block = '\n'.join(diagnostics.errors).strip() or '(no extracted error lines)'
        tail = (diagnostics.log_tail or '').strip()
        try:
            tail_max = int(getattr(diagnostics, 'log_tail_max_chars', 12000) or 0)
        except Exception:
            tail_max = 12000
        if tail_max > 0 and len(tail) > tail_max:
            tail = tail[-tail_max:]
        host_docs = (getattr(diagnostics, 'host_docs', '') or '').strip()
        try:
            docs_max = int(getattr(diagnostics, 'host_docs_max_chars', 20000) or 0)
        except Exception:
            docs_max = 20000
        if docs_max > 0 and len(host_docs) > docs_max:
            head_n = max(0, docs_max // 2)
            tail_n = max(0, docs_max - head_n)
            host_docs = (host_docs[:head_n] + '\n\n...(host docs truncated)...\n\n' + (host_docs[-tail_n:] if tail_n else '')).strip()
        profile_json = '(none)'
        if isinstance(codegen_profile, dict) and codegen_profile:
            profile_json = json.dumps(codegen_profile, ensure_ascii=False, indent=2)
        file_blocks = []
        for name, content in files.items():
            file_blocks.append(f"```file:{name}\n{(content or '').rstrip()}\n```")
        rules = textwrap.dedent('\nYou are a code repair agent.\n\nGoals:\n- Make the code compile/run under the given toolchain.\n- Apply the MINIMAL changes needed for correctness.\n\nHard constraints:\n- Do NOT rename files.\n- Do NOT invent new files unless explicitly allowed.\n- Only edit the existing files provided below.\n- Output ONLY complete updated files as ```file:filename``` fences; no prose, no extra text.\n            ').strip()
        extra = (extra_rules or '').strip()
        if extra:
            rules += '\n\n' + extra
        files_block = '\n\n'.join(file_blocks)
        docs_block = ''
        if host_docs:
            docs_block = f'\n\nHost API docs (reference):\n<host_docs>\n{host_docs}\n</host_docs>\n'
        return textwrap.dedent(f'\n{rules}\n\nTool: {diagnostics.tool_name}\nProtocol under test: {diagnostics.protocol_name}\n\n<codegen_profile>\n{profile_json}\n\n{docs_block}\nTool errors (primary signal):\n{err_block}\n\nTool log tail (context):\n{tail}\n\nCurrent files:\n{files_block}\n\nOutput format (strict):\n```file:filename\n<complete file content>\n```\n            ').strip()

    def _try_write(self, path: Path, text: str, *, attempt: int) -> None:
        try:
            out_path = path
            if attempt > 1:
                out_path = Path(str(path).replace('.txt', f'_attempt{attempt:02d}.txt'))
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(text, encoding='utf-8')
        except Exception:
            return
