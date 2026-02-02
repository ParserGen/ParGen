from typing import List, Dict, Any
from ..validation_agent.syntax_validator import Issue, IssueType, Severity, TargetRef
from .evaluator import EvaluationResult

class FeedbackAdapter:

    def generate_issues(self, result: EvaluationResult) -> List[Issue]:
        issues = []
        if result.success_rate < 1.0:
            issues.append(Issue(id='traffic_success_rate', type=IssueType.SEMANTICS, severity=Severity.ERROR, description=f'Traffic validation failed: Success rate {result.success_rate:.1%} (Target: 100%). Processed {result.total_packets} packets.', target=None))
        sorted_failures = sorted(result.node_failures.items(), key=lambda x: x[1], reverse=True)
        for node_id, count in sorted_failures[:5]:
            sample_msg = 'Unknown error'
            for err in result.sample_errors:
                if f'node {node_id}' in err['error']:
                    sample_msg = err['error']
                    break
            issues.append(Issue(id=f'traffic_node_{node_id}', type=IssueType.SEMANTICS, severity=Severity.ERROR, description=f'Node {node_id} failed parsing in {count} packets. Sample error: {sample_msg}', target=TargetRef(kind='node', identifier=str(node_id))))
        for err_msg, count in result.error_counts.items():
            if count > result.total_packets * 0.1:
                if not any((str(nid) in err_msg for nid in result.node_failures)):
                    issues.append(Issue(id=f'traffic_general_{hash(err_msg)}', type=IssueType.SEMANTICS, severity=Severity.ERROR, description=f'Frequent parsing error ({count} occurrences): {err_msg}', target=None))
        return issues
