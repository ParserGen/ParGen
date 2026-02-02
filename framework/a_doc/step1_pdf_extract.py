import anthropic
import base64
import json
import logging
import PyPDF2
import pdfplumber
import re
import os
import hashlib
import time
import requests
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass
from collections import defaultdict
from PyPDF2 import PdfWriter
from ..paths import DOC_CACHE_DIR, DOC_CHUNKS_DIR
logger = logging.getLogger(__name__)
try:
    import tiktoken
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False
    logger.info('tiktoken not available, using alternative token calculation')
MODEL_PRICING = {'model-default': {'input_price': 3.0, 'output_price': 15.0, 'name': 'Vision LLM'}}

@dataclass
class TOCEntry:
    number: str
    title: str
    page: int
    level: int
    parent_number: Optional[str] = None
    children: Optional[List['TOCEntry']] = None
    is_leaf: bool = False
    is_in_page_header: bool = False

    def __post_init__(self):
        if self.children is None:
            self.children = []

@dataclass
class ProcessingStep:
    step_id: str
    section_number: str
    section_title: str
    api_used: str
    input_tokens: int
    output_tokens: int
    input_cost: float
    output_cost: float
    total_cost: float
    processing_time: float
    cache_file: str
    retry_count: int = 0
    json_fixed: bool = False

class JSONRecoveryUtil:

    @staticmethod
    def attempt_json_recovery(broken_json: str) -> Optional[Dict]:
        try:
            last_brace = broken_json.rfind('}')
            if last_brace != -1:
                truncated = broken_json[:last_brace + 1]
                return json.loads(truncated)
        except:
            pass
        try:
            lines = broken_json.split('\n')
            for i in range(len(lines) - 1, -1, -1):
                line = lines[i].strip()
                if line.endswith('},') or line.endswith('}'):
                    candidate = '\n'.join(lines[:i + 1])
                    if candidate.count('{') <= candidate.count('}'):
                        return json.loads(candidate)
        except:
            pass
        try:
            fixed = broken_json
            fixed = re.sub(',(\\s*[}\\]])', '\\1', fixed)
            fixed = re.sub('(\\w+):', '"\\1":', fixed)
            fixed = re.sub('"([^"]*?)$', '"\\1"', fixed, flags=re.MULTILINE)
            return json.loads(fixed)
        except:
            pass
        try:
            extracted_data = {'title': '', 'number': '', 'content': '', 'packet_formats': [], 'field_definitions': [], 'constraints': {'field_constraints': [], 'validation_rules': []}, 'children': []}
            title_match = re.search('"title":\\s*"([^"]*)"', broken_json)
            if title_match:
                extracted_data['title'] = title_match.group(1)
            number_match = re.search('"number":\\s*"([^"]*)"', broken_json)
            if number_match:
                extracted_data['number'] = number_match.group(1)
            content_match = re.search('"content":\\s*"([^"]*)"', broken_json)
            if content_match:
                extracted_data['content'] = content_match.group(1)
            return extracted_data
        except:
            pass
        return None

class InPageHeaderDetector:

    def __init__(self):
        self.header_patterns = [re.compile('^(\\d+(?:\\.\\d+){2,6})\\s+(.+)$'), re.compile('^(\\d+(?:\\.\\d+)*\\.[a-zA-Z])\\s+(.+)$'), re.compile('^\\(([0-9a-zA-Z]+)\\)\\s+(.+)$'), re.compile('^[-*]\\s*(\\d+(?:\\.\\d+)*)\\s+(.+)$')]
        self.exclude_patterns = [re.compile('^\\d+\\s*$'), re.compile('^Page\\s+\\d+', re.IGNORECASE), re.compile('^Figure\\s+\\d+', re.IGNORECASE), re.compile('^Table\\s+\\d+', re.IGNORECASE)]

    def detect_headers_in_text(self, text: str, base_section_number: str) -> List[TOCEntry]:
        if not text:
            return []
        detected_headers = []
        lines = text.split('\n')
        base_level = base_section_number.count('.') + 1
        for line in lines:
            line = line.strip()
            if len(line) < 3 or len(line) > 100:
                continue
            if any((pattern.search(line) for pattern in self.exclude_patterns)):
                continue
            for pattern in self.header_patterns:
                match = pattern.match(line)
                if match:
                    header_number = match.group(1)
                    header_title = match.group(2).strip()
                    if header_number.startswith(base_section_number + '.'):
                        level = header_number.count('.') + 1
                        if level > base_level:
                            header_entry = TOCEntry(number=header_number, title=header_title, page=0, level=level, is_in_page_header=True)
                            detected_headers.append(header_entry)
                    break
        return detected_headers

class CostCalculator:

    def __init__(self):
        if TIKTOKEN_AVAILABLE:
            try:
                self.encoding = tiktoken.get_encoding('cl100k_base')
                self.use_tiktoken = True
            except:
                self.use_tiktoken = False
        else:
            self.use_tiktoken = False
        if not self.use_tiktoken:
            logger.info('Using alternative token calculation method')

    def estimate_tokens(self, text: str) -> int:
        if not text:
            return 0
        try:
            if self.use_tiktoken:
                return len(self.encoding.encode(text))
            else:
                return max(1, len(text) // 3)
        except Exception as e:
            logger.info(f'Token calculation failed: {e}')
            return max(1, len(text) // 4)

    def calculate_cost(self, model_name: str, input_tokens: int, output_tokens: int) -> Dict[str, float]:
        if model_name not in MODEL_PRICING:
            return {'input_cost': 0.0, 'output_cost': 0.0, 'total_cost': 0.0}
        pricing = MODEL_PRICING[model_name]
        input_mtok = input_tokens / 1000000
        output_mtok = output_tokens / 1000000
        input_cost = input_mtok * pricing['input_price']
        output_cost = output_mtok * pricing['output_price']
        total_cost = input_cost + output_cost
        return {'input_cost': input_cost, 'output_cost': output_cost, 'total_cost': total_cost}

    def estimate_section_cost(self, text_length: int, has_visual: bool) -> Dict[str, Any]:
        estimated_input_tokens = max(text_length // 4, 1000)
        estimated_output_tokens = min(estimated_input_tokens // 2, 4000)
        model_name = 'model-default'
        cost_breakdown = self.calculate_cost(model_name, estimated_input_tokens, estimated_output_tokens)
        return {'model': model_name, 'estimated_input_tokens': estimated_input_tokens, 'estimated_output_tokens': estimated_output_tokens, 'estimated_cost': cost_breakdown['total_cost'], 'cost_breakdown': cost_breakdown}

class DocumentChunker:

    def __init__(self, max_pages_per_chunk: int=25):
        self.max_pages_per_chunk = max_pages_per_chunk
        self.temp_dir = str(DOC_CHUNKS_DIR)
        try:
            os.makedirs(self.temp_dir, exist_ok=True)
            test_file = os.path.join(self.temp_dir, 'test_write.tmp')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            logger.info(f'Temp directory created: {self.temp_dir}')
        except Exception as e:
            logger.info(f'Temp directory creation failed: {e}')
            import tempfile
            self.temp_dir = tempfile.mkdtemp(prefix='pdf_chunks_')
            logger.info(f'Using system temp directory: {self.temp_dir}')

    def create_section_chunk(self, pdf_path: str, start_page: int, end_page: int, section_id: str) -> Optional[str]:
        try:
            if not os.path.exists(pdf_path):
                logger.info(f'PDF file not found: {pdf_path}')
                return None
            if not os.access(pdf_path, os.R_OK):
                logger.info(f'PDF file not readable: {pdf_path}')
                return None
            safe_section_id = re.sub('[^\\w\\-_]', '_', str(section_id))
            safe_section_id = safe_section_id[:50]
            timestamp = int(time.time())
            chunk_filename = f'section_{safe_section_id}_{start_page}_{end_page}_{timestamp}.pdf'
            chunk_path = os.path.join(self.temp_dir, chunk_filename)
            if not os.access(self.temp_dir, os.W_OK):
                logger.info(f'Temp directory not writable: {self.temp_dir}')
                return None
            pdf_writer = PdfWriter()
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                total_pages = len(pdf_reader.pages)
                logger.info(f'PDF total pages: {total_pages}, extracting pages: {start_page}-{end_page}')
                actual_start = max(1, start_page)
                actual_end = min(end_page, total_pages)
                if actual_start > total_pages:
                    logger.info(f'Start page exceeds total: {actual_start} > {total_pages}')
                    return None
                pages_added = 0
                for page_num in range(actual_start - 1, actual_end):
                    if page_num < len(pdf_reader.pages):
                        try:
                            pdf_writer.add_page(pdf_reader.pages[page_num])
                            pages_added += 1
                        except Exception as page_error:
                            logger.info(f'Failed to add page {page_num + 1}: {page_error}')
                if pages_added == 0:
                    logger.info('No pages were successfully added')
                    return None
                logger.info(f'Successfully added {pages_added} pages to chunk')
            with open(chunk_path, 'wb') as output_file:
                pdf_writer.write(output_file)
            if os.path.exists(chunk_path) and os.path.getsize(chunk_path) > 0:
                logger.info(f'Chunk created successfully: {chunk_filename} ({os.path.getsize(chunk_path)} bytes)')
                return chunk_path
            else:
                logger.info('Chunk file creation failed or empty')
                return None
        except Exception as e:
            logger.info(f'Section chunk creation failed: {e}')
            import traceback
            logger.info(f'Detailed error: {traceback.format_exc()}')
            return None

    def cleanup_chunks(self):
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f'Cleaned up temporary chunks: {self.temp_dir}')
        except Exception as e:
            logger.info(f'Cleanup warning: {e}')

class HybridContentAnalyzer:

    def should_use_claude(self, page_content: Dict[str, Any]) -> tuple[bool, str]:
        has_images = len(page_content.get('images', [])) > 0
        has_tables = len(page_content.get('tables', [])) > 0
        text = page_content.get('text', '')
        has_ascii_diagrams = self._detect_ascii_diagrams(text)
        has_complex_layout = self._detect_complex_layout(page_content)
        visual_elements = []
        if has_images:
            visual_elements.append(f"images({len(page_content.get('images', []))})")
        if has_ascii_diagrams:
            visual_elements.append('ascii_diagrams')
        if has_complex_layout:
            visual_elements.append('complex_layout')
        should_use_claude = len(visual_elements) > 0
        if should_use_claude:
            reason = f"Visual elements: {', '.join(visual_elements)}"
        else:
            table_count = len(page_content.get('tables', []))
            reason = f'Text+tables only ({table_count} tables)'
        return (should_use_claude, reason)

    def _detect_ascii_diagrams(self, text: str) -> bool:
        if not text or len(text) < 50:
            return False
        ascii_patterns = ['[+\\-|=]{6,}', '[]', '^\\s*\\|.*\\|.*\\|\\s*$', 'bit\\s*\\d+.*bit\\s*\\d+', 'byte\\s*\\d+.*byte\\s*\\d+', 'MSB.*LSB|LSB.*MSB']
        lines = text.split('\n')
        ascii_line_count = 0
        for line in lines:
            if any((re.search(pattern, line, re.IGNORECASE) for pattern in ascii_patterns)):
                ascii_line_count += 1
        return len(lines) > 5 and ascii_line_count / len(lines) > 0.15

    def _detect_complex_layout(self, page_content: Dict[str, Any]) -> bool:
        lines_count = page_content.get('lines_count', 0)
        rects_count = page_content.get('rects_count', 0)
        return lines_count > 100 or rects_count > 50

class PDFPlumberRawExtractor:

    def __init__(self):
        self.header_detector = InPageHeaderDetector()

    def extract_page_content(self, page) -> Dict[str, Any]:
        text = page.extract_text() or ''
        tables = []
        try:
            page_tables = page.extract_tables()
            if page_tables:
                for table in page_tables:
                    cleaned_table = []
                    for row in table:
                        cleaned_row = [cell if cell else '' for cell in row]
                        cleaned_table.append(cleaned_row)
                    tables.append(cleaned_table)
        except Exception as e:
            logger.info(f'Error extracting tables: {e}')
        images = []
        try:
            if hasattr(page, 'images'):
                for img in page.images:
                    img_info = {'x0': float(img.get('x0', 0)), 'y0': float(img.get('y0', 0)), 'x1': float(img.get('x1', 0)), 'y1': float(img.get('y1', 0)), 'width': float(img.get('width', 0)), 'height': float(img.get('height', 0)), 'name': img.get('name', 'unnamed')}
                    images.append(img_info)
        except Exception as e:
            logger.info(f'Error extracting images: {e}')
        lines = []
        rects = []
        try:
            if hasattr(page, 'lines'):
                for line in (page.lines or [])[:100]:
                    line_info = {'x0': float(line.get('x0', 0)), 'y0': float(line.get('y0', 0)), 'x1': float(line.get('x1', 0)), 'y1': float(line.get('y1', 0))}
                    lines.append(line_info)
        except Exception as e:
            logger.info(f'Error extracting lines: {e}')
        try:
            if hasattr(page, 'rects'):
                for rect in (page.rects or [])[:100]:
                    rect_info = {'x0': float(rect.get('x0', 0)), 'y0': float(rect.get('y0', 0)), 'x1': float(rect.get('x1', 0)), 'y1': float(rect.get('y1', 0))}
                    rects.append(rect_info)
        except Exception as e:
            logger.info(f'Error extracting rectangles: {e}')
        return {'page_number': page.page_number, 'text': text, 'tables': tables, 'images': images, 'lines': lines, 'rects': rects, 'lines_count': len(lines), 'rects_count': len(rects), 'page_height': float(page.height), 'page_width': float(page.width)}

    def extract_section_raw_content_with_headers(self, pdf_path: str, toc_entry: TOCEntry, next_page: Optional[int]=None) -> Dict[str, Any]:
        start_page = toc_entry.page
        end_page = next_page - 1 if next_page else start_page + 2
        end_page = max(end_page, start_page)
        section_raw_data = {'number': toc_entry.number, 'title': toc_entry.title, 'level': toc_entry.level, 'start_page': start_page, 'end_page': end_page, 'pages': [], 'combined_text': '', 'all_tables': [], 'all_images': [], 'page_count': 0, 'extraction_success': True, 'extraction_errors': [], 'detected_sub_headers': []}
        try:
            with pdfplumber.open(pdf_path) as pdf:
                combined_text_parts = []
                for page_num in range(start_page - 1, min(end_page, len(pdf.pages))):
                    if page_num < len(pdf.pages):
                        page = pdf.pages[page_num]
                        page_data = self.extract_page_content(page)
                        section_raw_data['pages'].append(page_data)
                        combined_text_parts.append(page_data['text'])
                        section_raw_data['all_tables'].extend(page_data['tables'])
                        section_raw_data['all_images'].extend(page_data['images'])
                        section_raw_data['page_count'] += 1
                section_raw_data['combined_text'] = '\n'.join(combined_text_parts)
                detected_headers = self.header_detector.detect_headers_in_text(section_raw_data['combined_text'], toc_entry.number)
                if detected_headers:
                    logger.info(f'Detected {len(detected_headers)} sub-headers:')
                    for header in detected_headers:
                        logger.info(f'  [L{header.level}] {header.number} - {header.title}')
                        section_raw_data['detected_sub_headers'].append({'number': header.number, 'title': header.title, 'level': header.level})
                section_raw_data['stats'] = {'total_text_length': len(section_raw_data['combined_text']), 'total_tables': len(section_raw_data['all_tables']), 'total_images': len(section_raw_data['all_images']), 'pages_processed': section_raw_data['page_count'], 'sub_headers_detected': len(detected_headers)}
                return section_raw_data
        except Exception as e:
            section_raw_data['extraction_success'] = False
            section_raw_data['extraction_errors'].append(str(e))
            logger.info(f'Raw content extraction failed for {toc_entry.number}: {e}')
            return section_raw_data

class HybridAPIExtractor:

    def __init__(self, llm_api_key: str):
        import anthropic
        self.llm_client = anthropic.Anthropic(api_key=llm_api_key)
        self.analyzer = HybridContentAnalyzer()
        self.cost_calculator = CostCalculator()
        self.json_recovery = JSONRecoveryUtil()
        self.processing_steps = []
        self.total_cost = 0.0
        self.max_retries = 3
        self.retry_delay = 2

    def extract_with_claude_vision_with_retry(self, chunk_path: str, toc_entry, start_page: int, end_page: int) -> Dict[str, Any]:
        for attempt in range(self.max_retries):
            logger.info(f'LLM attempt {attempt + 1}/{self.max_retries}')
            result = self._extract_with_claude_vision_single_attempt(chunk_path, toc_entry, start_page, end_page, attempt)
            if result is not None:
                if hasattr(result, 'get') and result.get('cost_info'):
                    result['cost_info']['retry_count'] = attempt
                return result
            if attempt < self.max_retries - 1:
                logger.info(f'Waiting {self.retry_delay} seconds before retry...')
                time.sleep(self.retry_delay)
        logger.info(f'LLM processing failed after {self.max_retries} attempts')
        return None

    def _extract_with_claude_vision_single_attempt(self, chunk_path: str, toc_entry, start_page: int, end_page: int, attempt: int) -> Dict[str, Any]:
        start_time = time.time()
        try:
            with open(chunk_path, 'rb') as f:
                pdf_data = base64.b64encode(f.read()).decode('utf-8')
            if len(pdf_data) > 20 * 1024 * 1024:
                logger.info(f'PDF chunk too large for LLM: {len(pdf_data)} bytes')
                return None
            llm_prompt = f'''\nAnalyze this technical protocol documentation section to extract PACKET FORMAT and DATA STRUCTURE information with visual analysis.\n\nSection: {toc_entry.number} - {toc_entry.title}\nPages: {start_page} to {end_page}\n\nFocus EXCLUSIVELY on packet formats, message structures, field definitions, and visual elements that show data organization:\n1. **Visual Elements**: ASCII diagrams, packet format tables, bit layout diagrams, field mapping charts\n2. **Field Definitions**: Individual field specifications with detailed constraints and relationships\n3. **Packet Structures**: Complete message/packet format organization and hierarchy\n4. **Field Relationships**: Dependencies, constraints, and hierarchical relationships between fields\n\nReturn JSON with comprehensive packet format analysis:\n{{\n  "title": "{toc_entry.title}",\n  "number": "{toc_entry.number}",\n  "content": "Detailed description of packet formats, data structures, and field definitions found in this section",\n  "packet_formats": [\n    {{\n      "format_name": "Name of the packet/message format",\n      "description": "Purpose and usage of this packet format",\n      "total_size": "Total packet size in bytes/bits",\n      "structure_type": "header|payload|trailer|complete_message|sub_structure",\n      "visual_representation": "Description of how this format is visually represented",\n      "fields": [\n        {{\n          "field_name": "Field identifier",\n          "data_type": "uint8|uint16|uint32|uint64|int8|int16|int32|int64|string|bytes|bitfield|enum|boolean|reserved",\n          "bit_position": "Bit offset or range (e.g., '0-7', '8-15')",\n          "byte_position": "Byte offset or range",\n          "size": "Field size in bits or bytes",\n          "description": "Field purpose and meaning",\n          "constraints": {{\n            "valid_values": ["List of valid values or ranges"],\n            "min_value": "Minimum allowed value",\n            "max_value": "Maximum allowed value",\n            "required": "Whether field is mandatory",\n            "conditional": "Conditions when this field is present",\n            "reserved_values": ["Values that are reserved or forbidden"],\n            "default_value": "Default value if applicable"\n          }},\n          "encoding": "How field is encoded (binary, ASCII, BCD, 2's complement, etc.)",\n          "endianness": "big|little|network|host order",\n          "source": "visual_diagram|table|text_description"\n        }}\n      ]\n    }}\n  ],\n  "field_definitions": [\n    {{\n      "field_name": "Field identifier",\n      "data_type": "uint8|uint16|uint32|uint64|int8|int16|int32|int64|string|bytes|bitfield|enum|boolean|reserved",\n      "bit_position": "Bit offset or range",\n      "byte_position": "Byte offset or range",\n      "size": "Field size in bits or bytes",\n      "description": "Field purpose and meaning",\n      "constraints": {{\n        "valid_values": ["List of valid values or ranges"],\n        "min_value": "Minimum allowed value", \n        "max_value": "Maximum allowed value",\n        "required": "Whether field is mandatory",\n        "conditional": "Conditions when this field is present",\n        "reserved_values": ["Values that are reserved or forbidden"],\n        "alignment": "Byte or bit alignment requirements"\n      }},\n      "encoding": "Field encoding method",\n      "endianness": "Byte order for multi-byte fields",\n      "parent_field": "Parent field name if this is a sub-field",\n      "child_fields": ["List of child field names"],\n      "access_mode": "read_only|write_only|read_write|reserved",\n      "source": "visual_diagram|table|text_description"\n    }}\n  ],\n  "summary": "Summary focusing exclusively on packet formats, field structures, and data organization",\n  "section_type": "packet_specification|field_definition|data_format|message_structure|register_definition",\n  "position": {{"page": {start_page}, "start_page": {start_page}, "end_page": {end_page}}},\n  "constraints": {{\n    "packet_constraints": ["Packet-level constraints (size, alignment, ordering, etc.)"],\n    "field_constraints": ["Field-level constraints from visual and text analysis"],\n    "validation_rules": ["Data validation rules for fields and packets"],\n    "encoding_constraints": ["Constraints on how data should be encoded/decoded"],\n    "structural_constraints": ["Constraints on packet structure and field organization"]\n  }},\n  "children": []\n}}\n\nCRITICAL: Return ONLY valid JSON. Ensure all brackets and quotes are properly matched.\nExtract ONLY packet format, message structure, and field definition information.\n'''
            input_text = llm_prompt
            estimated_input_tokens = self.cost_calculator.estimate_tokens(input_text)
            request_messages = [{'role': 'user', 'content': [{'type': 'document', 'source': {'type': 'base64', 'media_type': 'application/pdf', 'data': pdf_data}}, {'type': 'text', 'text': llm_prompt}]}]
            response = None
            result_text = ''
            try:
                if hasattr(self.llm_client, 'messages') and hasattr(self.llm_client.messages, 'stream'):
                    with self.llm_client.messages.stream(model='model-default', max_tokens=64000, messages=request_messages) as stream:
                        result_text = stream.get_final_text().strip()
                        response = stream.get_final_message()
                else:
                    response = self.llm_client.messages.create(model='model-default', max_tokens=64000, messages=request_messages)
                    result_text = response.content[0].text.strip()
            except ValueError as e:
                if 'Streaming is required' in str(e) and hasattr(self.llm_client, 'messages') and hasattr(self.llm_client.messages, 'stream'):
                    with self.llm_client.messages.stream(model='model-default', max_tokens=64000, messages=request_messages) as stream:
                        result_text = stream.get_final_text().strip()
                        response = stream.get_final_message()
                else:
                    raise
            usage = getattr(response, 'usage', None) if response is not None else None
            actual_input_tokens = getattr(usage, 'input_tokens', None) or estimated_input_tokens
            actual_output_tokens = getattr(usage, 'output_tokens', None) or self.cost_calculator.estimate_tokens(result_text)
            cost_breakdown = self.cost_calculator.calculate_cost('model-default', actual_input_tokens, actual_output_tokens)
            processing_time = time.time() - start_time
            enhanced_content = self._parse_json_with_recovery(result_text, f'LLM attempt {attempt + 1}')
            if enhanced_content is not None:
                step = ProcessingStep(step_id=f'llm_{toc_entry.number}', section_number=toc_entry.number, section_title=toc_entry.title, api_used='model-default', input_tokens=actual_input_tokens, output_tokens=actual_output_tokens, input_cost=cost_breakdown['input_cost'], output_cost=cost_breakdown['output_cost'], total_cost=cost_breakdown['total_cost'], processing_time=processing_time, cache_file='', retry_count=attempt, json_fixed=enhanced_content.get('_json_was_fixed', False))
                self.processing_steps.append(step)
                self.total_cost += cost_breakdown['total_cost']
                self._ensure_required_fields(enhanced_content, toc_entry)
                enhanced_content['api_used'] = 'model-default'
                enhanced_content['processing_method'] = 'visual_analysis'
                enhanced_content['cost_info'] = {'input_tokens': actual_input_tokens, 'output_tokens': actual_output_tokens, 'total_cost': cost_breakdown['total_cost'], 'processing_time': processing_time, 'retry_count': attempt, 'json_fixed': enhanced_content.get('_json_was_fixed', False)}
                if '_json_was_fixed' in enhanced_content:
                    del enhanced_content['_json_was_fixed']
                return enhanced_content
            else:
                logger.info(f'Attempt {attempt + 1}: JSON parsing failed')
                step = ProcessingStep(step_id=f'llm_{toc_entry.number}_failed_{attempt}', section_number=toc_entry.number, section_title=toc_entry.title, api_used='model-default', input_tokens=actual_input_tokens, output_tokens=actual_output_tokens, input_cost=cost_breakdown['input_cost'], output_cost=cost_breakdown['output_cost'], total_cost=cost_breakdown['total_cost'], processing_time=processing_time, cache_file='', retry_count=attempt, json_fixed=False)
                self.processing_steps.append(step)
                self.total_cost += cost_breakdown['total_cost']
        except Exception as e:
            logger.info(f'Attempt {attempt + 1}: LLM extraction exception: {e}')
        return None

    def _parse_json_with_recovery(self, text: str, context: str) -> Optional[Dict]:
        json_start = text.find('{')
        json_end = text.rfind('}') + 1
        if json_start != -1 and json_end != -1:
            clean_json = text[json_start:json_end]
            try:
                return json.loads(clean_json)
            except json.JSONDecodeError as e:
                logger.info(f'{context}: JSON parsing error: {str(e)[:100]}...')
                logger.info('Attempting JSON recovery...')
                recovered = self.json_recovery.attempt_json_recovery(clean_json)
                if recovered:
                    logger.info('JSON recovery successful!')
                    recovered['_json_was_fixed'] = True
                    return recovered
                else:
                    logger.info('JSON recovery failed')
        return None

    def extract_with_claude_text_with_retry(self, text_content: str, extracted_tables: List[Dict], toc_entry, start_page: int, end_page: int) -> Optional[Dict[str, Any]]:
        for attempt in range(self.max_retries):
            logger.info(f'LLM text attempt {attempt + 1}/{self.max_retries}')
            result = self._extract_with_claude_text_single_attempt(text_content, extracted_tables, toc_entry, start_page, end_page, attempt)
            if result is not None:
                if result.get('cost_info'):
                    result['cost_info']['retry_count'] = attempt
                return result
            if attempt < self.max_retries - 1:
                logger.info(f'Waiting {self.retry_delay} seconds before retry...')
                time.sleep(self.retry_delay)
        logger.info(f'LLM text processing failed after {self.max_retries} attempts')
        return None

    def _extract_with_claude_text_single_attempt(self, text_content: str, extracted_tables: List[Dict], toc_entry, start_page: int, end_page: int, attempt: int) -> Optional[Dict[str, Any]]:
        start_time = time.time()
        try:
            if len(text_content) > 15000:
                text_content = text_content[:15000] + '...[content truncated for processing]'
            tables_text = ''
            if extracted_tables:
                tables_text = '\n\nEXTRACTED TABLE DATA:\n'
                for i, table in enumerate(extracted_tables):
                    tables_text += f"\nTable {i + 1} ({table['rows']}x{table['cols']}):\n"
                    if table.get('headers'):
                        tables_text += f"Headers: {table['headers']}\n"
                    data_rows = table.get('data', [])
                    if data_rows:
                        tables_text += 'Sample data rows:\n'
                        for row in data_rows[:5]:
                            tables_text += f'  {row}\n'
                        if len(data_rows) > 5:
                            tables_text += f'  ... and {len(data_rows) - 5} more rows\n'
            text_prompt = f'\nAnalyze this technical documentation section to extract PACKET FORMAT and DATA STRUCTURE information only.\n\nSection: {toc_entry.number} - {toc_entry.title}\nPages: {start_page} to {end_page}\n\nTEXT CONTENT:\n{text_content}\n\n{tables_text}\n\nFocus EXCLUSIVELY on packet formats, message structures, and field definitions.\n\nReturn JSON with packet format analysis:\n{{\n  "title": "{toc_entry.title}",\n  "number": "{toc_entry.number}",\n  "content": "Description of packet formats and data structures found in this section",\n  "packet_formats": [\n    {{\n      "format_name": "Name of the packet/message format",\n      "description": "Purpose and usage of this packet format",\n      "total_size": "Total packet size in bytes/bits",\n      "fields": [\n        {{\n          "field_name": "Field identifier",\n          "data_type": "uint8|uint16|uint32|uint64|int8|int16|int32|int64|string|bytes|bitfield|enum|boolean",\n          "bit_position": "Bit offset or range",\n          "byte_position": "Byte offset or range",\n          "size": "Field size in bits or bytes",\n          "description": "Field purpose and meaning",\n          "constraints": {{\n            "valid_values": ["List of valid values or ranges"],\n            "min_value": "Minimum allowed value",\n            "max_value": "Maximum allowed value",\n            "required": "Whether field is mandatory",\n            "default_value": "Default value if applicable"\n          }},\n          "encoding": "How field is encoded (binary, ASCII, BCD, etc.)",\n          "endianness": "big|little|network order",\n          "source": "text|table_N (source of this information)"\n        }}\n      ]\n    }}\n  ],\n  "field_definitions": [],\n  "summary": "Summary focusing only on packet formats and field structures",\n  "section_type": "packet_specification|field_definition|data_format|message_structure",\n  "position": {{"page": {start_page}, "start_page": {start_page}, "end_page": {end_page}}},\n  "constraints": {{\n    "packet_constraints": ["Packet-level constraints"],\n    "field_constraints": ["Field-level constraints"],\n    "validation_rules": ["Data validation rules"],\n    "encoding_constraints": ["Encoding constraints"]\n  }},\n  "children": []\n}}\n\nCRITICAL: Return ONLY valid JSON. Ensure all brackets and quotes are properly matched.\nOnly extract packet format and field structure information.\n'
            estimated_input_tokens = self.cost_calculator.estimate_tokens(text_prompt)
            response = self.llm_client.messages.create(model='model-default', max_tokens=8000, messages=[{'role': 'user', 'content': text_prompt}])
            result_text = response.content[0].text.strip()
            usage = getattr(response, 'usage', None) if response is not None else None
            actual_input_tokens = getattr(usage, 'input_tokens', None) or estimated_input_tokens
            actual_output_tokens = getattr(usage, 'output_tokens', None) or self.cost_calculator.estimate_tokens(result_text)
            cost_breakdown = self.cost_calculator.calculate_cost('model-default', actual_input_tokens, actual_output_tokens)
            processing_time = time.time() - start_time
            enhanced_content = self._parse_json_with_recovery(result_text, f'LLM text attempt {attempt + 1}')
            if enhanced_content is not None:
                step = ProcessingStep(step_id=f'llm_text_{toc_entry.number}', section_number=toc_entry.number, section_title=toc_entry.title, api_used='model-default', input_tokens=actual_input_tokens, output_tokens=actual_output_tokens, input_cost=cost_breakdown['input_cost'], output_cost=cost_breakdown['output_cost'], total_cost=cost_breakdown['total_cost'], processing_time=processing_time, cache_file='', retry_count=attempt, json_fixed=enhanced_content.get('_json_was_fixed', False))
                self.processing_steps.append(step)
                self.total_cost += cost_breakdown['total_cost']
                self._ensure_required_fields(enhanced_content, toc_entry)
                enhanced_content['api_used'] = 'model-default'
                enhanced_content['processing_method'] = 'text_table_analysis'
                enhanced_content['tables_processed'] = len(extracted_tables)
                enhanced_content['cost_info'] = {'input_tokens': actual_input_tokens, 'output_tokens': actual_output_tokens, 'total_cost': cost_breakdown['total_cost'], 'processing_time': processing_time, 'retry_count': attempt, 'json_fixed': enhanced_content.get('_json_was_fixed', False)}
                if '_json_was_fixed' in enhanced_content:
                    del enhanced_content['_json_was_fixed']
                return enhanced_content
            logger.info(f'Attempt {attempt + 1}: JSON parsing failed')
            return None
        except Exception as e:
            logger.info(f'Attempt {attempt + 1}: LLM text extraction exception: {e}')
            return None

    def print_cost_summary(self):
        if not self.processing_steps:
            logger.info('No cost data available')
            return
        llm_steps = [s for s in self.processing_steps if 'llm' in s.api_used and (not s.step_id.endswith('_failed'))]
        failed_steps = [s for s in self.processing_steps if s.step_id.endswith('_failed') or '_failed_' in s.step_id]
        llm_cost = sum((s.total_cost for s in llm_steps))
        failed_cost = sum((s.total_cost for s in failed_steps))
        llm_retries = sum((s.retry_count for s in llm_steps))
        llm_json_fixes = sum((1 for s in llm_steps if s.json_fixed))
        logger.info(f'\nDetailed cost report (with retry statistics):')
        if llm_steps:
            logger.info(f'  Vision LLM: ${llm_cost:.6f}')
            logger.info(f'    Successful requests: {len(llm_steps)}')
            logger.info(f'    Retry count: {llm_retries}')
            logger.info(f'    JSON fixes: {llm_json_fixes}')
        if failed_steps:
            logger.info(f'  Failed request cost: ${failed_cost:.6f} ({len(failed_steps)} requests)')
        logger.info(f'  Total cost: ${self.total_cost:.6f}')
        logger.info(f'  Total retries: {llm_retries}')
        logger.info(f'  Total JSON fixes: {llm_json_fixes}')

    def _ensure_required_fields(self, content: Dict, toc_entry):
        content['number'] = toc_entry.number
        content['title'] = toc_entry.title
        content['level'] = toc_entry.level
        required_fields = {'constraints': {'field_constraints': [], 'validation_rules': []}, 'children': [], 'field_definitions': []}
        for field, default_value in required_fields.items():
            if field not in content:
                content[field] = default_value

class SectionProcessor:

    def __init__(self):
        self.cost_calculator = CostCalculator()
        self.header_detector = InPageHeaderDetector()

    def filter_sections_for_processing(self, toc_entries: List[TOCEntry], strategy: str='leaf_only') -> List[TOCEntry]:
        if not toc_entries:
            return []
        self._build_hierarchy(toc_entries)
        if strategy == 'leaf_only':
            return self._filter_leaf_only(toc_entries)
        elif strategy == 'fine_grained':
            return self._filter_with_fine_grained_detection(toc_entries)
        else:
            return toc_entries

    def _build_hierarchy(self, toc_entries: List[TOCEntry]):
        toc_entries.sort(key=lambda x: self._section_sort_key(x.number))
        for i, entry in enumerate(toc_entries):
            for j in range(i + 1, len(toc_entries)):
                other = toc_entries[j]
                if other.level == entry.level + 1 and other.number.startswith(entry.number + '.'):
                    entry.children.append(other)
                    other.parent_number = entry.number
        for entry in toc_entries:
            entry.is_leaf = len(entry.children) == 0

    def _section_sort_key(self, section_number: str) -> tuple:
        try:
            if section_number.lower().startswith('appendix'):
                return (999, 0, 0, 0, 0)
            parts = section_number.split('.')
            nums = []
            for i in range(4):
                if i < len(parts):
                    try:
                        nums.append(int(parts[i]))
                    except ValueError:
                        nums.append(0)
                else:
                    nums.append(0)
            return tuple(nums)
        except:
            return (0, 0, 0, 0)

    def _filter_leaf_only(self, toc_entries: List[TOCEntry]) -> List[TOCEntry]:
        leaf_entries = [entry for entry in toc_entries if entry.is_leaf]
        logger.info(f'Leaf node strategy: {len(toc_entries)} -> {len(leaf_entries)} sections')
        return leaf_entries

    def _filter_with_fine_grained_detection(self, toc_entries: List[TOCEntry]) -> List[TOCEntry]:
        return self._filter_leaf_only(toc_entries)

    def estimate_processing_cost(self, sections: List[TOCEntry], pdf_path: str) -> Dict[str, Any]:
        logger.info('Analyzing content types for cost estimation...')
        total_estimated_cost = 0.0
        llm_sections = 0
        total_estimated_tokens = 0
        with pdfplumber.open(pdf_path) as pdf:
            for section in sections:
                try:
                    start_page = section.page - 1
                    end_page = min(start_page + 3, len(pdf.pages))
                    combined_text = ''
                    for page_num in range(start_page, end_page):
                        if page_num < len(pdf.pages):
                            page = pdf.pages[page_num]
                            text = page.extract_text() or ''
                            combined_text += text
                    section_estimate = self.cost_calculator.estimate_section_cost(len(combined_text), True)
                    total_estimated_cost += section_estimate['estimated_cost']
                    total_estimated_tokens += section_estimate['estimated_input_tokens'] + section_estimate['estimated_output_tokens']
                    llm_sections += 1
                except Exception as e:
                    logger.info(f'Warning: Could not analyze section {section.number}: {e}')
                    default_estimate = self.cost_calculator.estimate_section_cost(5000, True)
                    total_estimated_cost += default_estimate['estimated_cost']
                    llm_sections += 1
        return {'total_sections': len(sections), 'llm_sections': llm_sections, 'estimated_total_cost': total_estimated_cost, 'estimated_tokens': total_estimated_tokens}

class RegexTOCExtractor:

    def __init__(self):
        self.toc_patterns = [re.compile('^(\\d+)\\.?\\s+(.+?)\\.{3,}\\s*(\\d+)\\s*$'), re.compile('^(\\d+(?:\\.\\d+){1,8})\\.?\\s+(.+?)\\.{3,}\\s*(\\d+)\\s*$'), re.compile('^(\\d+(?:\\.\\d+)*)\\.?\\s+(.+?)\\s+(\\d+)\\s*$'), re.compile('^(\\d+(?:\\.\\d+)*)\\.?\\s+(.+?)\\s*[-]{2,}\\s*(\\d+)\\s*$'), re.compile('^(\\d+(?:\\.\\d+)*)\\.?\\s+(.+)$'), re.compile('^(Appendix\\s+[A-Z](?:\\.\\d+)*)\\.?\\s+(.+?)(?:\\.{3,}\\s*|\\s+)(\\d+)\\s*$', re.IGNORECASE), re.compile('^(Chapter\\s+\\d+(?:\\.\\d+)*)\\.?\\s+(.+?)(?:\\.{3,}\\s*|\\s+)(\\d+)\\s*$', re.IGNORECASE)]
        self.exclude_patterns = [re.compile('^\\s*table\\s+of\\s+contents\\s*$', re.IGNORECASE), re.compile('^\\s*contents\\s*$', re.IGNORECASE), re.compile('^\\s*list\\s+of\\s+figures\\s*$', re.IGNORECASE), re.compile('^\\s*list\\s+of\\s+tables\\s*$', re.IGNORECASE), re.compile('^\\s*index\\s*$', re.IGNORECASE), re.compile('^\\s*bibliography\\s*$', re.IGNORECASE), re.compile('^\\s*references\\s*$', re.IGNORECASE)]

    def extract_toc_from_text(self, text: str, max_pages: int=None) -> List[TOCEntry]:
        if not text:
            return []
        lines = text.split('\n')
        toc_entries = []
        seen_sections = set()
        for line in lines:
            line = line.strip()
            if len(line) < 3:
                continue
            if any((pattern.search(line) for pattern in self.exclude_patterns)):
                continue
            for pattern in self.toc_patterns:
                match = pattern.match(line)
                if match:
                    section_number = match.group(1).strip().rstrip('.')
                    title = match.group(2).strip()
                    if not self._is_valid_section_number(section_number):
                        continue
                    page_num = None
                    if len(match.groups()) >= 3 and match.group(3):
                        try:
                            page_num = int(match.group(3))
                        except:
                            continue
                    if not page_num:
                        continue
                    if max_pages and page_num > max_pages:
                        continue
                    clean_title = self._clean_title(title)
                    if len(clean_title) < 2:
                        continue
                    if not any((ch.isalpha() for ch in clean_title)):
                        continue
                    section_key = f'{section_number}:{clean_title}'
                    if section_key in seen_sections:
                        continue
                    seen_sections.add(section_key)
                    level = self._calculate_level_from_number(section_number)
                    toc_entry = TOCEntry(number=section_number, title=clean_title, page=page_num, level=level)
                    toc_entries.append(toc_entry)
                    break
        toc_entries.sort(key=lambda x: (x.page, x.number))
        return toc_entries

    def _is_valid_section_number(self, section_number: str) -> bool:
        if not section_number:
            return False
        section_number = section_number.rstrip('.')
        patterns = [re.compile('^\\d+(?:\\.\\d+){0,8}$'), re.compile('^Appendix\\s+[A-Z](?:\\.\\d+)*$', re.IGNORECASE), re.compile('^Chapter\\s+\\d+(?:\\.\\d+)*$', re.IGNORECASE)]
        return any((pattern.match(section_number) for pattern in patterns))

    def _clean_title(self, title: str) -> str:
        if not title:
            return ''
        title = title.strip()
        title = re.sub('[.-]+\\s*$', '', title)
        title = re.sub('\\s+', ' ', title)
        title = re.sub('[....]{2,}', '', title)
        return title.strip()

    def _calculate_level_from_number(self, section_number: str) -> int:
        if not section_number:
            return 1
        dot_count = section_number.count('.')
        if section_number.lower().startswith(('appendix', 'chapter')):
            return dot_count + 1
        return dot_count + 1

class AutomatedPDFExtractor:

    def __init__(self, llm_api_key: str):
        self.llm_api_key = llm_api_key
        self.cache_dir = str(DOC_CACHE_DIR)
        os.makedirs(self.cache_dir, exist_ok=True)
        self.regex_toc_extractor = RegexTOCExtractor()
        self.section_processor = SectionProcessor()
        self.chunker = DocumentChunker()
        self.raw_extractor = PDFPlumberRawExtractor()
        self.hybrid_extractor = HybridAPIExtractor(llm_api_key)

    def extract_toc_with_regex(self, pdf_path: str) -> List[TOCEntry]:
        logger.info('Regex-based TOC extraction...')
        try:
            with pdfplumber.open(pdf_path) as pdf:
                total_pages = len(pdf.pages)
                toc_text_combined = []
                toc_pages_scanned = min(25, total_pages)
                for page_num in range(toc_pages_scanned):
                    page = pdf.pages[page_num]
                    text = page.extract_text() or ''
                    toc_text_combined.append(text)
                combined_text = '\n'.join(toc_text_combined)
                toc_entries = self.regex_toc_extractor.extract_toc_from_text(combined_text, total_pages)
                if not toc_entries:
                    logger.info('Warning: No regex matches found')
                    return []
                filtered_entries = []
                for entry in toc_entries:
                    if 1 <= entry.page <= total_pages:
                        filtered_entries.append(entry)
                logger.info(f'TOC extraction results: {len(filtered_entries)} sections found')
                return filtered_entries
        except Exception as e:
            logger.info(f'TOC extraction failed: {e}')
            return []

    def extract_toc_from_page_headings(self, pdf_path: str) -> List[TOCEntry]:
        logger.info('Fallback TOC extraction (page headings)...')
        noise_prefixes = ('rfc ', 'request for comments', 'network working group', 'updates:', 'updates ', 'internet-draft')
        noise_exact = {'contents', 'table of contents'}
        strong_keywords = ('introduction', 'message', 'address', 'format', 'summary', 'reference')
        try:
            with pdfplumber.open(pdf_path) as pdf:
                total_pages = len(pdf.pages)
                candidates: List[Tuple[int, str, bool]] = []
                seen_titles: Set[str] = set()
                for page_num, page in enumerate(pdf.pages, start=1):
                    text = page.extract_text() or ''
                    lines = [ln.strip() for ln in text.split('\n') if ln.strip()]
                    scan_lines = lines[:25]
                    page_candidates: List[str] = []
                    for line in scan_lines:
                        lower = line.lower().strip()
                        if lower.startswith(noise_prefixes):
                            continue
                        if lower.startswith(('page ', '[page')):
                            continue
                        if lower in noise_exact:
                            continue
                        if lower in {'description'}:
                            continue
                        if len(line) < 3 or len(line) > 90:
                            continue
                        if line.endswith('.'):
                            continue
                        if not any((ch.isalpha() for ch in line)):
                            continue
                        if any((tok in line for tok in ('+-+-+-+-+-+-+-+-', '+-+-', '|'))):
                            continue
                        if line.startswith(('0 1 2 3', '0 1 2 3 4 5 6 7 8 9')):
                            continue
                        digit_ratio = sum((ch.isdigit() for ch in line)) / max(1, len(line))
                        if digit_ratio > 0.2:
                            continue
                        if not line[0].isupper():
                            continue
                        words = [w.strip('()[],:;') for w in line.split() if w.strip('()[],:;')]
                        if not words:
                            continue
                        titlecase = sum((1 for w in words if w and w[0].isupper()))
                        titlecase_ratio = titlecase / len(words)
                        is_all_caps = line.isupper() and any((ch.isalpha() for ch in line))
                        if titlecase_ratio < 0.6 and (not (is_all_caps and len(words) <= 8)):
                            continue
                        page_candidates.append(line)
                    if not page_candidates:
                        continue
                    chosen: Optional[str] = None
                    for cand in page_candidates:
                        is_all_caps = cand.isupper() and any((ch.isalpha() for ch in cand))
                        if not is_all_caps:
                            chosen = cand
                            break
                    if chosen is None:
                        chosen = page_candidates[0]
                    normalized = ' '.join(chosen.split())
                    norm_key = normalized.lower()
                    if norm_key in seen_titles:
                        continue
                    seen_titles.add(norm_key)
                    strong = any((keyword in norm_key for keyword in strong_keywords))
                    candidates.append((page_num, normalized, strong))
                if not candidates:
                    logger.info('Fallback TOC extraction: no headings detected')
                    return []
                strong_only = [(p, t) for p, t, strong in candidates if strong]
                selected = strong_only if len(strong_only) >= 3 else [(p, t) for p, t, _ in candidates]
                selected.sort(key=lambda item: item[0])
                entries: List[TOCEntry] = []
                for idx, (page_num, title) in enumerate(selected, start=1):
                    if not 1 <= page_num <= total_pages:
                        continue
                    entries.append(TOCEntry(number=str(idx), title=title, page=page_num, level=1))
                logger.info(f'Fallback TOC extraction results: {len(entries)} sections found')
                return entries
        except Exception as e:
            logger.info(f'Fallback TOC extraction failed: {e}')
            return []

    def save_step_to_cache(self, step_name: str, data: Any, pdf_name: str) -> str:
        timestamp = int(time.time())
        cache_filename = f'{pdf_name}_{step_name}_{timestamp}.json'
        cache_path = os.path.join(self.cache_dir, cache_filename)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f'Step cached: {cache_filename}')
            return cache_path
        except Exception as e:
            logger.info(f'Cache save failed: {e}')
            return ''

    def find_latest_cache(self, step_name: str, pdf_name: str) -> Optional[str]:
        if not os.path.exists(self.cache_dir):
            return None
        pattern = f'{pdf_name}_{step_name}_'
        matching_files = []
        for filename in os.listdir(self.cache_dir):
            if filename.startswith(pattern) and filename.endswith('.json'):
                try:
                    timestamp_str = filename.replace(pattern, '').replace('.json', '')
                    timestamp = int(timestamp_str)
                    matching_files.append((timestamp, os.path.join(self.cache_dir, filename)))
                except:
                    continue
        if matching_files:
            matching_files.sort(key=lambda x: x[0], reverse=True)
            latest_file = matching_files[0][1]
            logger.info(f'Found cached data: {os.path.basename(latest_file)}')
            return latest_file
        return None

    def load_from_cache(self, cache_path: str) -> Optional[Any]:
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.info(f'Loaded from cache: {os.path.basename(cache_path)}')
            return data
        except Exception as e:
            logger.info(f'Cache load failed: {e}')
            return None

    def find_section_caches(self, pdf_name: str) -> Dict[str, str]:
        if not os.path.exists(self.cache_dir):
            return {}
        import glob
        from collections import defaultdict
        cache_pattern = os.path.join(self.cache_dir, f'{pdf_name}_section_*_*.json')
        cache_files = glob.glob(cache_pattern)
        sections_by_timestamp = defaultdict(list)
        for cache_file in cache_files:
            basename = os.path.basename(cache_file)
            parts = basename.replace('.json', '').split('_')
            if len(parts) >= 2 and parts[-1].isdigit():
                timestamp = int(parts[-1])
                section_id = '_'.join(parts[:-1])
                sections_by_timestamp[section_id].append((timestamp, cache_file))
        latest_sections = {}
        for section_id, files in sections_by_timestamp.items():
            files.sort(key=lambda x: x[0], reverse=True)
            latest_timestamp, latest_file = files[0]
            latest_sections[section_id] = latest_file
        return latest_sections

    def reconstruct_final_results_from_sections(self, pdf_name: str, section_caches: Dict[str, str]) -> Optional[Dict[str, Any]]:
        if not section_caches:
            return None
        logger.info(f'  Reconstructing final results from {len(section_caches)} section caches...')
        llm_processed_sections = []
        raw_extracted_sections = []
        processing_steps = []
        for section_id, cache_file in sorted(section_caches.items()):
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                if 'llm_result' in cache_data and cache_data['llm_result']:
                    llm_result = cache_data['llm_result']
                    llm_result['source_file'] = pdf_name
                    llm_processed_sections.append(llm_result)
                    cost_info = llm_result.get('cost_info', {})
                    if cost_info:
                        step = {'step_id': f"{pdf_name}_{llm_result.get('number', 'unknown')}", 'section_number': llm_result.get('number', 'unknown'), 'section_title': llm_result.get('title', 'unknown'), 'api_used': llm_result.get('api_used', 'unknown'), 'input_tokens': cost_info.get('input_tokens', 0), 'output_tokens': cost_info.get('output_tokens', 0), 'input_cost': cost_info.get('total_cost', 0) * 0.2, 'output_cost': cost_info.get('total_cost', 0) * 0.8, 'total_cost': cost_info.get('total_cost', 0), 'processing_time': cost_info.get('processing_time', 0), 'cache_file': cache_file, 'retry_count': cost_info.get('retry_count', 0), 'json_fixed': cost_info.get('json_fixed', False)}
                        processing_steps.append(step)
                if 'raw_data' in cache_data and cache_data['raw_data']:
                    raw_data = cache_data['raw_data']
                    raw_data['source_file'] = pdf_name
                    raw_extracted_sections.append(raw_data)
            except Exception as e:
                logger.info(f'  Warning: Could not load section cache {os.path.basename(cache_file)}: {e}')
        if not llm_processed_sections and (not raw_extracted_sections):
            return None
        total_cost = sum((step['total_cost'] for step in processing_steps))
        final_results = {'llm_processed_sections': llm_processed_sections, 'raw_extracted_sections': raw_extracted_sections, 'processing_steps': processing_steps, 'success_statistics': {'successful_llm_extractions': len(llm_processed_sections), 'failed_llm_extractions': 0, 'raw_data_success_rate': len(raw_extracted_sections) / max(1, len(raw_extracted_sections)), 'llm_success_rate': 1.0 if len(llm_processed_sections) > 0 else 0.0}, 'cost_summary': {'estimated_cost': total_cost, 'actual_cost': total_cost, 'cost_accuracy': 100.0, 'error_percentage': 0.0, 'accuracy_status': 'Reconstructed from section cache'}, 'enhancement_features': {'fine_grained_headers': True, 'json_recovery': True, 'retry_mechanism': True, 'max_retries': 3}}
        timestamp = int(time.time())
        final_cache_file = os.path.join(self.cache_dir, f'{pdf_name}_final_results_enhanced_{timestamp}.json')
        try:
            with open(final_cache_file, 'w', encoding='utf-8') as f:
                json.dump(final_results, f, indent=2, ensure_ascii=False)
            logger.info(f'  Reconstructed final results cached: {os.path.basename(final_cache_file)}')
        except Exception as e:
            logger.info(f'  Warning: Could not save reconstructed cache: {e}')
        return final_results

    def check_pdf_cache_status(self, pdf_name: str) -> Dict[str, Any]:
        cache_status = {'toc_extraction': None, 'section_selection': None, 'cost_estimate': None, 'final_results_enhanced': None, 'section_caches': {}, 'has_complete_cache': False, 'can_reconstruct_from_sections': False}
        for step_name in ['toc_extraction', 'section_selection', 'cost_estimate', 'final_results_enhanced']:
            cache_file = self.find_latest_cache(step_name, pdf_name)
            cache_status[step_name] = cache_file
        section_caches = self.find_section_caches(pdf_name)
        cache_status['section_caches'] = section_caches
        cache_status['can_reconstruct_from_sections'] = len(section_caches) > 0
        cache_status['has_complete_cache'] = cache_status['toc_extraction'] is not None and cache_status['final_results_enhanced'] is not None
        return cache_status

    def extract_section_with_hybrid_api_enhanced(self, pdf_path: str, toc_entry: TOCEntry, next_page: Optional[int]=None) -> Dict[str, Any]:
        start_page = toc_entry.page
        end_page = next_page - 1 if next_page else start_page + 2
        end_page = max(end_page, start_page)
        logger.info(f'Processing: [L{toc_entry.level}] {toc_entry.number} - {toc_entry.title}')
        try:
            with pdfplumber.open(pdf_path) as pdf:
                all_extracted_tables = []
                combined_text = []
                for page_num in range(start_page - 1, min(end_page, len(pdf.pages))):
                    if page_num < len(pdf.pages):
                        page = pdf.pages[page_num]
                        page_content = self.raw_extractor.extract_page_content(page)
                        all_extracted_tables.extend(page_content.get('tables', []))
                        combined_text.append(page_content.get('text', ''))
                enhanced_content = None
                chunk_path = self.chunker.create_section_chunk(pdf_path, start_page, end_page, toc_entry.number)
                if chunk_path:
                    enhanced_content = self.hybrid_extractor.extract_with_claude_vision_with_retry(chunk_path, toc_entry, start_page, end_page)
                    try:
                        os.remove(chunk_path)
                    except:
                        pass
                if enhanced_content is None:
                    text_content = '\n'.join(combined_text)
                    formatted_tables = []
                    for i, table_data in enumerate(all_extracted_tables):
                        formatted_table = {'index': i, 'rows': len(table_data), 'cols': len(table_data[0]) if table_data else 0, 'data': table_data, 'headers': table_data[0] if table_data else []}
                        formatted_tables.append(formatted_table)
                    enhanced_content = self.hybrid_extractor.extract_with_claude_text_with_retry(text_content, formatted_tables, toc_entry, start_page, end_page)
                cost_info = enhanced_content.get('cost_info', {}) if enhanced_content else {}
                if cost_info:
                    retry_info = f" (retries: {cost_info.get('retry_count', 0)})" if cost_info.get('retry_count', 0) > 0 else ''
                    json_fix_info = ' [JSON fixed]' if cost_info.get('json_fixed', False) else ''
                    logger.info(f"  Cost: ${cost_info.get('total_cost', 0):.6f} (input: {cost_info.get('input_tokens', 0):,}, output: {cost_info.get('output_tokens', 0):,}){retry_info}{json_fix_info}")
                return enhanced_content
        except Exception as e:
            logger.info(f'Enhanced hybrid extraction failed: {e}')
            return None

    def _calculate_section_end_page(self, current_section: TOCEntry, all_sections: List[TOCEntry]) -> Optional[int]:
        current_page = current_section.page
        next_section_page = None
        for section in all_sections:
            if section.page > current_page:
                if next_section_page is None or section.page < next_section_page:
                    next_section_page = section.page
        if next_section_page:
            return next_section_page
        if current_section.level > 2:
            return current_page + 2
        else:
            return current_page + 5

    def validate_pdf_file(self, pdf_path: str) -> Dict[str, Any]:
        validation_result = {'is_valid': False, 'file_exists': False, 'is_readable': False, 'total_pages': 0, 'file_size': 0, 'error_message': ''}
        try:
            if not os.path.exists(pdf_path):
                validation_result['error_message'] = f'File not found: {pdf_path}'
                return validation_result
            validation_result['file_exists'] = True
            validation_result['file_size'] = os.path.getsize(pdf_path)
            if not os.access(pdf_path, os.R_OK):
                validation_result['error_message'] = f'File not readable: {pdf_path}'
                return validation_result
            validation_result['is_readable'] = True
            with pdfplumber.open(pdf_path) as pdf:
                validation_result['total_pages'] = len(pdf.pages)
                if validation_result['total_pages'] == 0:
                    validation_result['error_message'] = 'PDF file is empty or corrupted'
                    return validation_result
                first_page = pdf.pages[0]
                test_text = first_page.extract_text()
                validation_result['is_valid'] = True
                validation_result['error_message'] = 'PDF file validation successful'
                return validation_result
        except Exception as e:
            validation_result['error_message'] = f'PDF validation failed: {str(e)}'
            return validation_result

    def process_pdf_automated_enhanced(self, pdf_path: str) -> Dict[str, Any]:
        pdf_name = os.path.basename(pdf_path).replace('.pdf', '')
        logger.info(f'Enhanced automated PDF processing: {pdf_name}')
        logger.info('=' * 60)
        logger.info('New features: Fine-grained header detection + JSON error recovery + retry mechanism + cache support')
        logger.info(f'\nChecking cache status for {pdf_name}...')
        cache_status = self.check_pdf_cache_status(pdf_name)
        if cache_status['has_complete_cache']:
            logger.info(f'[OK] Complete cache found for {pdf_name}')
            logger.info(f"  TOC extraction: {os.path.basename(cache_status['toc_extraction'])}")
            logger.info(f"  Final results: {os.path.basename(cache_status['final_results_enhanced'])}")
            logger.info(f'Loading from cache instead of reprocessing...')
            cached_results = self.load_from_cache(cache_status['final_results_enhanced'])
        elif cache_status['can_reconstruct_from_sections']:
            logger.info(f'[OK] Section caches found for {pdf_name}')
            logger.info(f"  Available section caches: {len(cache_status['section_caches'])}")
            logger.info(f'Reconstructing final results from section caches...')
            cached_results = self.reconstruct_final_results_from_sections(pdf_name, cache_status['section_caches'])
        else:
            cached_results = None
        if cached_results:
            logger.info(f'[OK] Successfully loaded cached results')
            processed_sections = cached_results.get('llm_processed_sections', [])
            raw_sections = cached_results.get('raw_extracted_sections', [])
            processing_steps = cached_results.get('processing_steps', [])
            self.hybrid_extractor.processing_steps = []
            for step_data in processing_steps:
                step = ProcessingStep(step_id=step_data['step_id'], section_number=step_data['section_number'], section_title=step_data['section_title'], api_used=step_data['api_used'], input_tokens=step_data['input_tokens'], output_tokens=step_data['output_tokens'], input_cost=step_data['input_cost'], output_cost=step_data['output_cost'], total_cost=step_data['total_cost'], processing_time=step_data['processing_time'], cache_file=step_data.get('cache_file', ''), retry_count=step_data.get('retry_count', 0), json_fixed=step_data.get('json_fixed', False))
                self.hybrid_extractor.processing_steps.append(step)
            total_cost = sum((s['total_cost'] for s in processing_steps))
            self.hybrid_extractor.total_cost = total_cost
            temp_llm_file = f'temp_{pdf_name}_sections.json'
            temp_raw_file = f'temp_{pdf_name}_raw.json'
            temp_steps_file = f'temp_{pdf_name}_steps.json'
            with open(temp_llm_file, 'w', encoding='utf-8') as f:
                json.dump(processed_sections, f, indent=2, ensure_ascii=False)
            with open(temp_raw_file, 'w', encoding='utf-8') as f:
                json.dump({'sections': raw_sections}, f, indent=2, ensure_ascii=False)
            with open(temp_steps_file, 'w', encoding='utf-8') as f:
                json.dump(processing_steps, f, indent=2, ensure_ascii=False)
            success_stats = cached_results.get('success_statistics', {})
            cost_summary = cached_results.get('cost_summary', {})
            enhancement_stats = cached_results.get('enhancement_features', {})
            return {'success': True, 'from_cache': True, 'llm_processed_sections': len(processed_sections), 'raw_extracted_sections': len(raw_sections), 'api_switches': 0, 'total_cost': total_cost, 'cost_accuracy': cost_summary.get('accuracy_status', 'From cache'), 'enhancement_stats': {'total_retries': sum((s.get('retry_count', 0) for s in processing_steps)), 'json_fixes': sum((1 for s in processing_steps if s.get('json_fixed', False))), 'sub_headers_detected': 0}, 'output_files': {'llm_results': temp_llm_file, 'raw_data': temp_raw_file, 'processing_steps': temp_steps_file}}
        else:
            logger.info(f'[X] Failed to load/reconstruct cached results, proceeding with fresh processing')
            missing_cache = []
            if not cache_status['toc_extraction']:
                missing_cache.append('TOC extraction')
            if not cache_status['final_results_enhanced']:
                missing_cache.append('Final results')
            if not cache_status['can_reconstruct_from_sections']:
                missing_cache.append('Section caches')
            logger.info(f'[X] No usable cache for {pdf_name}')
            if missing_cache:
                logger.info(f"  Missing: {', '.join(missing_cache)}")
            logger.info(f'Proceeding with fresh processing...')
        logger.info(f'\nStep 0: Validate PDF file')
        validation = self.validate_pdf_file(pdf_path)
        logger.info(f"  File size: {validation['file_size']:,} bytes")
        logger.info(f"  Total pages: {validation['total_pages']}")
        logger.info(f"  Status: {validation['error_message']}")
        if not validation['is_valid']:
            return {'error': validation['error_message'], 'success': False, 'validation': validation}
        logger.info('\nStep 1: Extract TOC structure')
        toc_entries = self.extract_toc_with_regex(pdf_path)
        if not toc_entries:
            toc_entries = self.extract_toc_from_page_headings(pdf_path)
        if not toc_entries:
            return {'error': 'TOC extraction failed', 'success': False}
        toc_cache_path = self.save_step_to_cache('toc_extraction', [entry.__dict__ for entry in toc_entries], pdf_name)
        logger.info('\nStep 2: Apply leaf node filtering strategy')
        selected_sections = self.section_processor.filter_sections_for_processing(toc_entries, strategy='leaf_only')
        if not selected_sections:
            return {'error': 'No leaf sections found', 'success': False}
        selected_cache_path = self.save_step_to_cache('section_selection', [entry.__dict__ for entry in selected_sections], pdf_name)
        logger.info(f'\nStep 3: Cost estimation')
        cost_estimate = self.section_processor.estimate_processing_cost(selected_sections, pdf_path)
        logger.info(f"  Estimated sections to process: {cost_estimate['total_sections']}")
        logger.info(f"  LLM sections: {cost_estimate['llm_sections']}")
        logger.info(f"  Estimated total cost: ${cost_estimate['estimated_total_cost']:.6f}")
        logger.info(f"  Estimated total tokens: {cost_estimate['estimated_tokens']:,}")
        estimate_cache_path = self.save_step_to_cache('cost_estimate', cost_estimate, pdf_name)
        logger.info(f'\nStep 4: Begin processing {len(selected_sections)} leaf sections (enhanced)...')
        processed_sections = []
        raw_sections = []
        successful_extractions = 0
        failed_extractions = 0
        for i, section in enumerate(selected_sections):
            logger.info(f'\nProcessing {i + 1}/{len(selected_sections)}: [L{section.level}] {section.number} - {section.title}')
            next_page = self._calculate_section_end_page(section, toc_entries)
            logger.info(f'  Extracting raw data...')
            raw_section_data = self.raw_extractor.extract_section_raw_content_with_headers(pdf_path, section, next_page)
            raw_section_data['source_file'] = pdf_name
            if raw_section_data['extraction_success']:
                raw_sections.append(raw_section_data)
                sub_headers_count = raw_section_data['stats']['sub_headers_detected']
                logger.info(f"  Raw data extraction successful: {raw_section_data['stats']['total_text_length']} chars, {raw_section_data['stats']['total_tables']} tables, {raw_section_data['stats']['total_images']} images{(f', {sub_headers_count} sub-headers' if sub_headers_count > 0 else '')}")
            else:
                logger.info(f"  Raw data extraction failed: {raw_section_data['extraction_errors']}")
                raw_sections.append(raw_section_data)
            llm_result = None
            if raw_section_data['extraction_success'] and raw_section_data['stats']['total_text_length'] > 0:
                logger.info(f'  LLM processing (enhanced)...')
                llm_result = self.extract_section_with_hybrid_api_enhanced(pdf_path, section, next_page)
                if llm_result is not None:
                    llm_result['source_file'] = pdf_name
                    processed_sections.append(llm_result)
                    successful_extractions += 1
                    logger.info(f'  LLM processing successful')
                else:
                    logger.info(f'  LLM processing failed, skipping section')
                    failed_extractions += 1
            else:
                logger.info(f'  Insufficient raw data, skipping LLM processing')
                failed_extractions += 1
            if raw_section_data['extraction_success']:
                section_cache_path = self.save_step_to_cache(f"section_{section.number.replace('.', '_')}", {'raw_data': raw_section_data, 'llm_result': llm_result}, pdf_name)
        logger.info(f'\nStep 5: Save final results')
        llm_output_path = 'document_sections.json'
        with open(llm_output_path, 'w', encoding='utf-8') as f:
            json.dump(processed_sections, f, indent=2, ensure_ascii=False)
        if processed_sections:
            logger.info(f'LLM processing results saved: {llm_output_path} ({len(processed_sections)} sections)')
        else:
            logger.info(f'No successful LLM processing results, wrote empty {llm_output_path}')
        raw_output_path = 'document_sections_raw.json'
        raw_data = {'metadata': {'extraction_tool': 'pdfplumber_enhanced', 'extraction_type': 'raw_content_extraction_with_headers', 'source_file': pdf_name, 'total_sections': len(raw_sections), 'successful_extractions': len([s for s in raw_sections if s.get('extraction_success')]), 'failed_extractions': len([s for s in raw_sections if not s.get('extraction_success')]), 'processing_strategy': 'leaf_node_sections_with_fine_grained_headers', 'features': ['fine_grained_header_detection', 'json_error_recovery', 'retry_mechanism']}, 'sections': raw_sections}
        with open(raw_output_path, 'w', encoding='utf-8') as f:
            json.dump(raw_data, f, indent=2, ensure_ascii=False)
        logger.info(f'Raw data saved: {raw_output_path} ({len(raw_sections)} sections)')
        processing_steps_data = []
        for step in self.hybrid_extractor.processing_steps:
            processing_steps_data.append({'step_id': step.step_id, 'section_number': step.section_number, 'section_title': step.section_title, 'api_used': step.api_used, 'input_tokens': step.input_tokens, 'output_tokens': step.output_tokens, 'input_cost': step.input_cost, 'output_cost': step.output_cost, 'total_cost': step.total_cost, 'processing_time': step.processing_time, 'retry_count': step.retry_count, 'json_fixed': step.json_fixed})
        steps_output_path = f'{pdf_name}_processing_steps_enhanced.json'
        with open(steps_output_path, 'w', encoding='utf-8') as f:
            json.dump(processing_steps_data, f, indent=2, ensure_ascii=False)
        actual_cost = self.hybrid_extractor.total_cost
        estimated_cost = cost_estimate['estimated_total_cost']
        accuracy = 0
        error_percentage = 0
        accuracy_status = 'No cost data'
        if actual_cost > 0:
            error_percentage = abs(estimated_cost - actual_cost) / actual_cost * 100
            accuracy = max(0, 100 - error_percentage)
            if error_percentage > 50:
                accuracy_status = f'Estimation deviation too large ({error_percentage:.1f}%)'
            elif error_percentage > 20:
                accuracy_status = f'Estimation deviation large ({error_percentage:.1f}%)'
            else:
                accuracy_status = f'Estimation accurate ({error_percentage:.1f}% error)'
        elif estimated_cost > 0:
            error_percentage = 100
            accuracy = 0
            accuracy_status = f'All LLM processing failed'
        else:
            accuracy_status = f'No cost data'
        final_cache_path = self.save_step_to_cache('final_results_enhanced', {'llm_processed_sections': processed_sections, 'raw_extracted_sections': raw_sections, 'processing_steps': processing_steps_data, 'success_statistics': {'successful_llm_extractions': successful_extractions, 'failed_llm_extractions': failed_extractions, 'raw_data_success_rate': len([s for s in raw_sections if s['extraction_success']]) / len(raw_sections) if raw_sections else 0, 'llm_success_rate': successful_extractions / len(selected_sections) if selected_sections else 0}, 'cost_summary': {'estimated_cost': estimated_cost, 'actual_cost': actual_cost, 'cost_accuracy': accuracy, 'error_percentage': error_percentage, 'accuracy_status': accuracy_status}, 'enhancement_features': {'fine_grained_headers': True, 'json_recovery': True, 'retry_mechanism': True, 'max_retries': self.hybrid_extractor.max_retries}}, pdf_name)
        logger.info(f'\nStep 6: Cost analysis report (enhanced)')
        if hasattr(self.hybrid_extractor, 'processing_steps') and self.hybrid_extractor.processing_steps:
            self.hybrid_extractor.print_cost_summary()
        else:
            logger.info('No LLM processing cost data')
        logger.info(f'\nCost estimation analysis:')
        logger.info(f'  Estimated cost: ${estimated_cost:.6f}')
        logger.info(f'  Actual cost: ${actual_cost:.6f}')
        logger.info(f'  Estimation status: {accuracy_status}')
        if actual_cost > estimated_cost:
            overage = (actual_cost - estimated_cost) / estimated_cost * 100 if estimated_cost > 0 else 0
            logger.info(f'  Budget overrun: +${actual_cost - estimated_cost:.6f} ({overage:.1f}%)')
        elif actual_cost < estimated_cost and estimated_cost > 0:
            savings = (estimated_cost - actual_cost) / estimated_cost * 100
            logger.info(f'  Cost savings: -${estimated_cost - actual_cost:.6f} ({savings:.1f}%)')
        logger.info(f'\nEnhanced automated processing complete!')
        logger.info(f'LLM processing results: {llm_output_path} ({len(processed_sections)} sections)')
        logger.info(f'Raw data file: {raw_output_path} ({len(raw_sections)} sections)')
        logger.info(f'Processing steps: {steps_output_path}')
        logger.info(f'Cache files saved in: {self.cache_dir}/')
        logger.info(f'Processing success statistics:')
        logger.info(f"  Raw data extraction: {len([s for s in raw_sections if s['extraction_success']])}/{len(raw_sections)} successful")
        logger.info(f'  LLM processing: {successful_extractions}/{len(selected_sections)} successful')
        logger.info(f'Total cost: ${actual_cost:.6f}')
        total_retries = sum((step.retry_count for step in self.hybrid_extractor.processing_steps))
        total_json_fixes = sum((1 for step in self.hybrid_extractor.processing_steps if step.json_fixed))
        logger.info(f'Enhancement feature statistics:')
        logger.info(f'  Total retry count: {total_retries}')
        logger.info(f'  JSON fix count: {total_json_fixes}')
        logger.info(f'  Fine-grained header detection: enabled')
        logger.info(f"  In-page sub-headers: {sum((len(s.get('detected_sub_headers', [])) for s in raw_sections))} detected")
        return {'success': True, 'llm_processed_sections': len(processed_sections), 'raw_extracted_sections': len(raw_sections), 'total_cost': actual_cost, 'cost_accuracy': accuracy_status, 'enhancement_stats': {'total_retries': total_retries, 'json_fixes': total_json_fixes, 'sub_headers_detected': sum((len(s.get('detected_sub_headers', [])) for s in raw_sections))}, 'output_files': {'llm_results': llm_output_path, 'raw_data': raw_output_path, 'processing_steps': steps_output_path}}

def main():
    try:
        llm_api_key = os.getenv('CLAUDE_API_KEY') or os.getenv('ANTHROPIC_API_KEY')
        if not llm_api_key:
            raise SystemExit('Missing CLAUDE_API_KEY/ANTHROPIC_API_KEY')
        pdf_dir = 'pdf'
        pdf_files = []
        if os.path.exists(pdf_dir):
            for filename in sorted(os.listdir(pdf_dir)):
                if filename.endswith('.pdf'):
                    pdf_files.append(os.path.join(pdf_dir, filename))
        if not pdf_files:
            pdf_files = ['pdf/modbus_1.pdf', 'pdf/modbus_2.pdf']
        logger.info('Enhanced Automated PDF Processing Tool')
        logger.info('=' * 60)
        logger.info('New features:')
        logger.info('  Fine-grained header detection - detect deeper header structures within pages')
        logger.info('  JSON error recovery - automatically fix corrupted JSON output')
        logger.info('  Retry mechanism - up to 3 retries for improved success rate')
        logger.info('  Cache support - reuse existing results when available')
        logger.info('  Merged output - all PDF results combined into single files')
        logger.info('Pricing basis: Vision LLM')
        logger.info('Output files: document_sections.json + document_sections_raw.json (merged)')
        logger.info(f'Cache location: {DOC_CACHE_DIR}/')
        extractor = AutomatedPDFExtractor(llm_api_key)
        all_processed_sections = []
        all_raw_sections = []
        all_processing_steps = []
        total_cost = 0.0
        all_results = []
        for pdf_path in pdf_files:
            if os.path.exists(pdf_path):
                logger.info(f"\n{'=' * 60}")
                logger.info(f'Processing file: {pdf_path}')
                logger.info(f"{'=' * 60}")
                result = extractor.process_pdf_automated_enhanced(pdf_path)
                if result.get('success'):
                    logger.info(f'\nFile {os.path.basename(pdf_path)} processing successful!')
                    logger.info(f"  LLM processing: {result['llm_processed_sections']} sections")
                    logger.info(f"  Raw data: {result['raw_extracted_sections']} sections")
                    logger.info(f"  Total cost: ${result['total_cost']:.6f}")
                    all_results.append(result)
                    total_cost += result['total_cost']
                    enhancement_stats = result.get('enhancement_stats', {})
                    if enhancement_stats.get('total_retries', 0) > 0:
                        logger.info(f"  Retry count: {enhancement_stats['total_retries']}")
                    if enhancement_stats.get('json_fixes', 0) > 0:
                        logger.info(f"  JSON fixes: {enhancement_stats['json_fixes']}")
                    if enhancement_stats.get('sub_headers_detected', 0) > 0:
                        logger.info(f"  Sub-header detection: {enhancement_stats['sub_headers_detected']} detected")
                else:
                    logger.info(f'\nFile {os.path.basename(pdf_path)} processing failed!')
                    logger.info(f"  Error: {result.get('error', 'Unknown error')}")
        if all_results:
            logger.info(f"\n{'=' * 60}")
            logger.info('Merging results from all processed PDFs...')
            logger.info(f"{'=' * 60}")
            merged_result = merge_pdf_results(all_results, extractor)
            logger.info(f'\nMerged results summary:')
            logger.info(f"  Total LLM processed sections: {len(merged_result['all_processed_sections'])}")
            logger.info(f"  Total raw data sections: {len(merged_result['all_raw_sections'])}")
            logger.info(f"  Total processing steps: {len(merged_result['all_processing_steps'])}")
            logger.info(f"  Combined total cost: ${merged_result['total_cost']:.6f}")
            for pdf_name, sections_count in merged_result['sections_by_pdf'].items():
                logger.info(f'    {pdf_name}: {sections_count} sections')
        else:
            logger.info('\nNo successful processing results to merge.')
    except KeyboardInterrupt:
        logger.info(f'\nUser interrupted processing')
    except Exception as e:
        logger.info(f'\nProcessing failed: {e}')
        import traceback
        traceback.print_exc()

def merge_pdf_results(all_results, extractor):
    all_processed_sections = []
    all_raw_sections = []
    all_processing_steps = []
    total_cost = 0.0
    sections_by_pdf = {}
    for result in all_results:
        if result.get('success'):
            llm_file = result['output_files']['llm_results']
            raw_file = result['output_files']['raw_data']
            steps_file = result['output_files']['processing_steps']
            try:
                if os.path.exists(llm_file):
                    with open(llm_file, 'r', encoding='utf-8') as f:
                        llm_sections = json.load(f)
                    all_processed_sections.extend(llm_sections)
                    for section in llm_sections:
                        pdf_name = section.get('source_file', 'unknown')
                        sections_by_pdf[pdf_name] = sections_by_pdf.get(pdf_name, 0) + 1
            except Exception as e:
                logger.info(f'Warning: Could not load LLM results from {llm_file}: {e}')
            try:
                if os.path.exists(raw_file):
                    with open(raw_file, 'r', encoding='utf-8') as f:
                        raw_data = json.load(f)
                    if 'sections' in raw_data:
                        all_raw_sections.extend(raw_data['sections'])
                    else:
                        all_raw_sections.extend(raw_data)
            except Exception as e:
                logger.info(f'Warning: Could not load raw data from {raw_file}: {e}')
            try:
                if os.path.exists(steps_file):
                    with open(steps_file, 'r', encoding='utf-8') as f:
                        steps_data = json.load(f)
                    all_processing_steps.extend(steps_data)
            except Exception as e:
                logger.info(f'Warning: Could not load processing steps from {steps_file}: {e}')
            total_cost += result['total_cost']
    llm_output_path = 'document_sections.json'
    if all_processed_sections:
        with open(llm_output_path, 'w', encoding='utf-8') as f:
            json.dump(all_processed_sections, f, indent=2, ensure_ascii=False)
        logger.info(f'Merged LLM processing results saved: {llm_output_path} ({len(all_processed_sections)} sections)')
    else:
        logger.info(f'No LLM processing results to merge')
    raw_output_path = 'document_sections_raw.json'
    if all_raw_sections:
        merged_raw_data = {'metadata': {'extraction_tool': 'pdfplumber_enhanced', 'extraction_type': 'raw_content_extraction_with_headers', 'source_files': list(sections_by_pdf.keys()), 'total_sections': len(all_raw_sections), 'successful_extractions': len([s for s in all_raw_sections if s.get('extraction_success', False)]), 'failed_extractions': len([s for s in all_raw_sections if not s.get('extraction_success', True)]), 'processing_strategy': 'leaf_node_sections_with_fine_grained_headers', 'features': ['fine_grained_header_detection', 'json_error_recovery', 'retry_mechanism', 'merged_output'], 'sections_by_pdf': sections_by_pdf}, 'sections': all_raw_sections}
        with open(raw_output_path, 'w', encoding='utf-8') as f:
            json.dump(merged_raw_data, f, indent=2, ensure_ascii=False)
        logger.info(f'Merged raw data saved: {raw_output_path} ({len(all_raw_sections)} sections)')
    else:
        logger.info(f'No raw data to merge')
    steps_output_path = 'merged_processing_steps_enhanced.json'
    if all_processing_steps:
        with open(steps_output_path, 'w', encoding='utf-8') as f:
            json.dump(all_processing_steps, f, indent=2, ensure_ascii=False)
        logger.info(f'Merged processing steps saved: {steps_output_path} ({len(all_processing_steps)} steps)')
    temp_files_cleaned = 0
    for result in all_results:
        if result.get('from_cache') and result.get('output_files'):
            for file_type, file_path in result['output_files'].items():
                if file_path.startswith('temp_') and os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                        temp_files_cleaned += 1
                    except Exception as e:
                        logger.info(f'Warning: Could not clean up temp file {file_path}: {e}')
    if temp_files_cleaned > 0:
        logger.info(f'Cleaned up {temp_files_cleaned} temporary files')
    return {'all_processed_sections': all_processed_sections, 'all_raw_sections': all_raw_sections, 'all_processing_steps': all_processing_steps, 'total_cost': total_cost, 'sections_by_pdf': sections_by_pdf, 'output_files': {'llm_results': llm_output_path, 'raw_data': raw_output_path, 'processing_steps': steps_output_path}}
if __name__ == '__main__':
    main()
