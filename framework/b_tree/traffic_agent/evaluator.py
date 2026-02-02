import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
import json
try:
    from scapy.all import rdpcap, Packet
except ImportError:
    rdpcap = None
from .interpreter import DynamicTreeInterpreter
logger = logging.getLogger(__name__)
from dataclasses import dataclass, field

@dataclass
class EvaluationResult:
    total_packets: int = 0
    success_count: int = 0
    error_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    node_failures: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    sample_errors: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_packets == 0:
            return 0.0
        return self.success_count / self.total_packets

class TrafficEvaluator:

    def __init__(self, protocol_tree: Dict[str, Any]):
        self.interpreter = DynamicTreeInterpreter(protocol_tree)

    def evaluate_pcap(self, pcap_path: Path, max_packets: int=100) -> EvaluationResult:
        if rdpcap is None:
            raise ImportError('scapy is required for PCAP processing. Please install it.')
        if not pcap_path.exists():
            raise FileNotFoundError(f'PCAP file not found: {pcap_path}')
        result = EvaluationResult()
        try:
            packets = rdpcap(str(pcap_path))
        except Exception as e:
            logger.error(f'Failed to read PCAP {pcap_path}: {e}')
            return result
        count = 0
        for pkt in packets:
            if count >= max_packets:
                break
            if hasattr(pkt, 'load'):
                data = pkt.load
            else:
                data = bytes(pkt)
            if not data:
                continue
            count += 1
            result.total_packets += 1
            success, context, error = self.interpreter.parse(data)
            if success:
                result.success_count += 1
            else:
                err_msg = str(error)
                result.error_counts[err_msg] += 1
                import re
                match = re.search('node (\\d+)', err_msg)
                if match:
                    nid = int(match.group(1))
                    result.node_failures[nid] += 1
                if len(result.sample_errors) < 10:
                    result.sample_errors.append({'packet_idx': count, 'error': err_msg, 'hex_preview': data[:16].hex()})
        return result
