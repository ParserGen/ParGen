from __future__ import annotations
import json
import logging
import os
import time
import re
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
import requests
from ..generation_agent.step2_format_graph_builder import ProtocolNode, canonicalize_node_type
from ...paths import STEP2_CACHE_DIR
logger = logging.getLogger(__name__)

class NumpyEncoder(json.JSONEncoder):

    def default(self, obj):
        import numpy as np
        if isinstance(obj, np.integer):
            return int(obj)
        if isinstance(obj, np.floating):
            return float(obj)
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        return super().default(obj)

class EnhancedPureAIAgent:

    def __init__(self, provider: str='anthropic', cache_dir: Optional[Path]=None, api_key: Optional[str]=None) -> None:
        self.provider = 'anthropic'
        self.api_key = (api_key or os.getenv('CLAUDE_API_KEY') or os.getenv('ANTHROPIC_API_KEY') or '').strip()
        if not self.api_key:
            raise ValueError('CLAUDE_API_KEY/ANTHROPIC_API_KEY environment variable must be set')
        self.base_url = os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com/v1/messages').strip()
        self.headers = {'x-api-key': self.api_key, 'Content-Type': 'application/json', 'anthropic-version': os.getenv('ANTHROPIC_VERSION', '2023-06-01'), 'anthropic-beta': os.getenv('ANTHROPIC_BETA', 'prompt-caching-2024-07-31')}
        self.default_model = (os.getenv('ANTHROPIC_MODEL') or os.getenv('CLAUDE_MODEL') or 'model-default').strip()
        self.connect_timeout = int(os.getenv('AI_CONNECT_TIMEOUT', '10'))
        self.read_timeout = int(os.getenv('AI_READ_TIMEOUT', '180'))
        self.timeout = self.read_timeout
        self.max_retries = int(os.getenv('AI_MAX_RETRIES', '2'))
        self.retry_delay = int(os.getenv('AI_RETRY_DELAY', '3'))
        cache_root = cache_dir or STEP2_CACHE_DIR
        self.cache_dir = str(cache_root)
        os.makedirs(self.cache_dir, exist_ok=True)
        self.api_call_times: List[Dict[str, Any]] = []
        self.total_api_time = 0.0
        self.step2_start_time: Optional[float] = None
        self.structural_validator = None
        self.validator_integration = None
        self._current_learning_feedback_history: List[Dict[str, Any]] = []

    def _clean_raw_response(self, raw_response: str) -> str:
        if not raw_response:
            return ''
        clean_text = raw_response.strip()
        if clean_text.startswith('```json'):
            clean_text = clean_text[7:]
        elif clean_text.startswith('```'):
            clean_text = clean_text[3:]
        if clean_text.endswith('```'):
            clean_text = clean_text[:-3]
        clean_text = clean_text.strip()
        if clean_text.startswith('"') and clean_text.endswith('"'):
            clean_text = clean_text[1:-1]
        elif clean_text.startswith("'") and clean_text.endswith("'"):
            clean_text = clean_text[1:-1]
        clean_text = _strip_js_comments(clean_text)
        clean_text = clean_text.strip()
        try:
            clean_text = re.sub('[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]', '', clean_text)
        except Exception:
            pass
        return clean_text

    def _structured_response_format(self) -> Optional[Dict[str, Any]]:
        return None

    def _load_from_cache(self, filename: str) -> Optional[Any]:
        if os.getenv('PARGEN_STEP2_FORCE_REBUILD', '').strip().lower() in {'1', 'true', 'yes', 'on'}:
            return None
        cache_path = os.path.join(self.cache_dir, filename)
        if not os.path.exists(cache_path):
            return None
        try:
            with open(cache_path, 'r', encoding='utf-8') as handle:
                data = json.load(handle)
            logger.info('Loaded from cache: %s', cache_path)
            return data
        except Exception as exc:
            logger.warning('Failed to load cache %s: %s', cache_path, exc)
            return None

    def _save_to_cache(self, filename: str, data: Any) -> None:
        cache_path = os.path.join(self.cache_dir, filename)
        os.makedirs(self.cache_dir, exist_ok=True)
        try:
            output_data: Any = data
            if isinstance(data, dict) and 'raw_response' in data:
                raw_response = data['raw_response']
                if isinstance(raw_response, str):
                    clean_response = self._clean_raw_response(raw_response)
                    try:
                        parsed_response = json.loads(clean_response) if clean_response else None
                    except (json.JSONDecodeError, ValueError):
                        parsed_response = None
                    if parsed_response is not None:
                        if isinstance(parsed_response, dict) and 'protocol_tree' in parsed_response:
                            output_data = {'protocol_tree': parsed_response['protocol_tree'], 'timestamp': data.get('timestamp', datetime.now().isoformat()), 'section_info': data.get('section_info')}
                        else:
                            output_data = {'protocol_tree': parsed_response, 'timestamp': data.get('timestamp', datetime.now().isoformat()), 'section_info': data.get('section_info')}
                    else:
                        output_data = {'raw_response': raw_response, 'timestamp': data.get('timestamp', datetime.now().isoformat()), 'section_info': data.get('section_info')}
            elif isinstance(data, dict) and ('nodes' in data or 'root_node_id' in data):
                output_data = {'protocol_tree': data, 'timestamp': datetime.now().isoformat(), 'section_info': None}
            with open(cache_path, 'w', encoding='utf-8') as handle:
                json.dump(output_data, handle, indent=2, ensure_ascii=False, cls=NumpyEncoder)
            logger.info('Saved to cache: %s', cache_path)
        except Exception as exc:
            logger.error('Failed to save cache %s: %s', filename, exc)
            raise

    def _update_node(self, node: ProtocolNode, node_data: Dict[str, Any]) -> None:
        if 'name' in node_data:
            node.name = node_data['name']
        if 'node_type' in node_data:
            node.node_type = canonicalize_node_type(node_data['node_type'])
        if 'bit_start' in node_data:
            node.bit_start = node_data['bit_start']
        if 'size_bits' in node_data:
            node.size_bits = node_data['size_bits']
        if 'message_type' in node_data:
            node.message_type = node_data['message_type'] or ''
        if 'data_type' in node_data:
            node.data_type = node_data['data_type']
        if 'byte_order' in node_data:
            node.byte_order = node_data['byte_order']
        if 'parent_id' in node_data:
            pid = node_data['parent_id']
            node.parent_id = str(pid) if pid is not None else None
        if 'children_ids' in node_data:
            node.children_ids = [str(child) for child in node_data['children_ids'] or []]
        if 'source' in node_data:
            node.source = node_data['source']
        if 'constraints' in node_data:
            node.constraints = node_data['constraints']
        if 'dependencies' in node_data:
            node.dependencies = node_data['dependencies']

    def _apply_validation_results_to_tree(self, cumulative_tree: Dict, validation_result: Dict) -> Dict:
        merged_tree = cumulative_tree.copy()
        existing_nodes = {str(node['node_id']): node for node in merged_tree.get('nodes', [])}
        for conflict in validation_result.get('conflicts_detected', []):
            resolution = conflict.get('resolution', {})
            merged_node = resolution.get('merged_node')
            if merged_node:
                existing_nodes[str(merged_node['node_id'])] = merged_node
        for preserved in validation_result.get('learning_preserved', []):
            new_node = preserved.get('new_node')
            if not new_node:
                continue
            new_id = str(new_node['node_id'])
            while new_id in existing_nodes:
                new_id = f'{new_id}_preserved'
            new_node['node_id'] = new_id
            existing_nodes[new_id] = new_node
        merged_tree['nodes'] = list(existing_nodes.values())
        return merged_tree

    def _merge_batch_into_cumulative_tree(self, cumulative_tree: Dict, batch_result: Dict) -> Dict:
        from position_conflict_detector import PositionConflictDetector
        detector = PositionConflictDetector()
        result = detector.merge_trees_with_position_conflict_detection(cumulative_tree, batch_result)
        logger.info('Completed merge with position conflict detection')
        return result

    def _call_api_with_retry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        api_start_time = time.time()
        model_name = payload.get('model', 'unknown')
        for attempt in range(self.max_retries):
            try:
                try:
                    approx_chars = len(json.dumps(payload))
                except Exception:
                    approx_chars = -1
                logger.info('Calling provider %s (attempt %s/%s), timeouts=(%ss connect, %ss read), payload~=%s chars', model_name, attempt + 1, self.max_retries, self.connect_timeout, self.read_timeout, approx_chars)
                response = requests.post(self.base_url, headers=self.headers, json=payload, timeout=(self.connect_timeout, self.read_timeout))
                if response.status_code == 200:
                    response_data = response.json()
                    api_duration = time.time() - api_start_time
                    self.api_call_times.append({'model': model_name, 'duration': api_duration, 'attempt': attempt + 1, 'timestamp': datetime.now().isoformat()})
                    self.total_api_time += api_duration
                    logger.info('API call succeeded: %s (%.2fs, attempt %s)', model_name, api_duration, attempt + 1)
                    return response_data
                logger.warning('API error %s: %s', response.status_code, response.text[:1000])
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
            except Exception as exc:
                api_duration = time.time() - api_start_time
                logger.warning('API call failed (attempt %s): %s (%.2fs)', attempt + 1, exc, api_duration)
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))
                else:
                    self.api_call_times.append({'model': model_name, 'duration': api_duration, 'attempt': attempt + 1, 'timestamp': datetime.now().isoformat(), 'status': 'failed', 'error': str(exc)})
                    raise
        final_duration = time.time() - api_start_time
        self.api_call_times.append({'model': model_name, 'duration': final_duration, 'attempt': self.max_retries, 'timestamp': datetime.now().isoformat(), 'status': 'failed_all_retries'})
        raise RuntimeError('API call failed after all retries')

def _strip_js_comments(text: str) -> str:
    import re
    text = re.sub('/\\*.*?\\*/', '', text, flags=re.DOTALL)
    text = re.sub('//.*$', '', text, flags=re.MULTILINE)
    return text
