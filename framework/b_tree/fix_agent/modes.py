from __future__ import annotations
from typing import Callable, Dict, Tuple
ValidatorFn = Callable[[dict], 'ValidationReport']

def get_mode(mode: str) -> Tuple[ValidatorFn, str]:
    normalized = (mode or 'syntax').strip().lower()
    if normalized == 'semantic':
        from ..traffic_agent.semantic_validator import run_hybrid_validation as semantic_validator
        return (semantic_validator, 'traffic_fix')
    from .refinement import run_full_validation as syntax_validator
    return (syntax_validator, 'fix')
MODE_VALIDATORS: Dict[str, ValidatorFn] = {'syntax': lambda tree: get_mode('syntax')[0](tree), 'semantic': lambda tree: get_mode('semantic')[0](tree)}
MODE_PROMPTS: Dict[str, str] = {'syntax': 'fix', 'semantic': 'traffic_fix'}
