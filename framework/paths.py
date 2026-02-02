from __future__ import annotations
import os
from pathlib import Path
from typing import Iterable
PARGEN_ROOT = Path(__file__).resolve().parent
DATA_DIR = PARGEN_ROOT / 'data'
CONFIG_DIR = PARGEN_ROOT / 'config'
ARTIFACTS_ROOT = DATA_DIR / '_artifacts'
LOGS_DIR = DATA_DIR / 'logs'
DOC_CACHE_DIR = ARTIFACTS_ROOT / 'doc_cache'
DOC_CHUNKS_DIR = ARTIFACTS_ROOT / 'doc_chunks'
STEP2_CACHE_DIR = ARTIFACTS_ROOT / 'step2_cache'
STEP2_RESULTS_DIR = ARTIFACTS_ROOT / 'step2_results'

def _sanitize_cache_namespace(value: str) -> str:
    cleaned = []
    for ch in value.strip():
        if ch.isalnum() or ch in '._-':
            cleaned.append(ch)
        else:
            cleaned.append('_')
    out = ''.join(cleaned).strip('_')
    return out or 'default'
_STEP2_FIX_CACHE_BASE_DIR = ARTIFACTS_ROOT / 'step2_fix_cache'
_step2_namespace = os.getenv('PARGEN_STEP2_CACHE_NAMESPACE')
STEP2_FIX_CACHE_DIR = _STEP2_FIX_CACHE_BASE_DIR / _sanitize_cache_namespace(_step2_namespace) if _step2_namespace else _STEP2_FIX_CACHE_BASE_DIR
STEP3_LOG_DIR = LOGS_DIR / 'step3_runs'
REALFLOW_REPORT_DIR = LOGS_DIR / 'realflow_reports'
PCAP_DIR = ARTIFACTS_ROOT / 'pcap_samples'
DEFAULT_API_CONFIG = CONFIG_DIR / 'api_config.json'
EXAMPLE_API_CONFIG = CONFIG_DIR / 'api_config.example.json'

def _ensure_dirs(paths: Iterable[Path]) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
_ensure_dirs((ARTIFACTS_ROOT, CONFIG_DIR, LOGS_DIR, DOC_CACHE_DIR, DOC_CHUNKS_DIR, STEP2_CACHE_DIR, STEP2_RESULTS_DIR, STEP2_FIX_CACHE_DIR, STEP3_LOG_DIR, REALFLOW_REPORT_DIR, PCAP_DIR, DATA_DIR))
__all__ = ['PARGEN_ROOT', 'CONFIG_DIR', 'ARTIFACTS_ROOT', 'DOC_CACHE_DIR', 'DOC_CHUNKS_DIR', 'STEP2_CACHE_DIR', 'STEP2_RESULTS_DIR', 'STEP2_FIX_CACHE_DIR', 'LOGS_DIR', 'STEP3_LOG_DIR', 'REALFLOW_REPORT_DIR', 'PCAP_DIR', 'DATA_DIR', 'DEFAULT_API_CONFIG', 'EXAMPLE_API_CONFIG']
