from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional
from .step1_pdf_extract import AutomatedPDFExtractor, TOCEntry

@dataclass
class DocumentPipelineConfig:
    llm_api_key: str
    section_strategy: str = 'leaf_only'

class DocumentPipeline:

    def __init__(self, config: DocumentPipelineConfig):
        self.config = config
        self._extractor = AutomatedPDFExtractor(llm_api_key=config.llm_api_key)

    def extract_toc(self, pdf_path: Path) -> List[TOCEntry]:
        return self._extractor.extract_toc_with_regex(str(pdf_path))

    def select_sections(self, toc_entries: List[TOCEntry], strategy: Optional[str]=None) -> List[TOCEntry]:
        strategy = strategy or self.config.section_strategy
        return self._extractor.section_processor.filter_sections_for_processing(toc_entries, strategy=strategy)

    def process_pdf(self, pdf_path: Path) -> Dict[str, Any]:
        return self._extractor.process_pdf_automated_enhanced(str(pdf_path))

    def cached_status(self, pdf_path: Path) -> Dict[str, Any]:
        pdf_name = pdf_path.stem
        return self._extractor.check_pdf_cache_status(pdf_name)

    def summarize(self, result: Dict[str, Any]) -> Dict[str, Any]:
        return {'from_cache': result.get('from_cache', False), 'llm_sections': result.get('llm_processed_sections', 0), 'raw_sections': result.get('raw_sections', 0), 'cost_summary': result.get('cost_summary', {})}
