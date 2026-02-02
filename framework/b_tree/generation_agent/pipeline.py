from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from .step2_format_graph_builder import UniversalProtocolAnalyzer

@dataclass
class FormatTreeConfig:
    sections_file: Path
    raw_file: Path
    initial_llm_provider: Optional[str] = None
    initial_llm_model: Optional[str] = None
    initial_llm_temperature: Optional[float] = None
    initial_llm_max_tokens: Optional[int] = None
    refine_llm_provider: Optional[str] = None
    refine_llm_model: Optional[str] = None
    refine_llm_temperature: Optional[float] = None
    refine_llm_max_tokens: Optional[int] = None

class FormatTreePipeline:

    def __init__(self, config: FormatTreeConfig):
        self.config = config
        self._analyzer = UniversalProtocolAnalyzer(initial_provider=config.initial_llm_provider, initial_model=config.initial_llm_model, initial_temperature=config.initial_llm_temperature, initial_max_tokens=config.initial_llm_max_tokens, refine_provider=config.refine_llm_provider, refine_model=config.refine_llm_model, refine_temperature=config.refine_llm_temperature, refine_max_tokens=config.refine_llm_max_tokens)

    def build(self) -> Any:
        return self._analyzer.analyze_protocol(sections_file=str(self.config.sections_file), raw_file=str(self.config.raw_file))
