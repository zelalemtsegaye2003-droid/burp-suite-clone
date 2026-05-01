"""Vulnerability Scanner Framework"""
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import threading
import time
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('scanner')


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IssueType(Enum):
    XSS = "cross_site_scripting"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    SSRF = "server_side_request_forgery"
    IDOR = "insecure_direct_object_reference"
    XXE = "xml_external_entity"
    INFO_DISCLOSURE = "information_disclosure"
    WEAK_CRYPTO = "weak_cryptography"
    AUTH_BYPASS = "authentication_bypass"
    CSRF = "cross_site_request_forgery"
    UNKNOWN = "unknown"


class ScanMode(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    HYBRID = "hybrid"


@dataclass
class VulnerabilityIssue:
    id: Optional[int] = None
    issue_type: IssueType = IssueType.UNKNOWN
    severity: Severity = Severity.INFO
    name: str = ""
    description: str = ""
    url: str = ""
    parameter: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    confidence: str = "medium"
    timestamps: str = field(default_factory=lambda: datetime.now().isoformat())
    false_positive: bool = False
    request: Optional[bytes] = None
    response: Optional[bytes] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.issue_type.value,
            'severity': self.severity.value,
            'name': self.name,
            'description': self.description,
            'url': self.url,
            'parameter': self.parameter,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'confidence': self.confidence,
            'timestamp': self.timestamp,
            'false_positive': self.false_positive
        }


class IssueTracker:
    def __init__(self):
        self.issues: List[VulnerabilityIssue] = []
        self._lock = threading.Lock()
        self._next_id = 1

    def add_issue(self, issue: VulnerabilityIssue):
        with self._lock:
            issue.id = self._next_id
            self._next_id += 1
            self.issues.append(issue)
            logger.info(f"Issue #{issue.id}: {issue.name} ({issue.severity.value}) at {issue.url}")

    def get_issues(self, severity: Severity = None, false_positives: bool = False) -> List[VulnerabilityIssue]:
        with self._lock:
            results = self.issues
            if severity:
                results = [i for i in results if i.severity == severity]
            if not false_positives:
                results = [i for i in results if not i.false_positive]
            return results

    def get_issues_by_type(self, issue_type: IssueType) -> List[VulnerabilityIssue]:
        with self._lock:
            return [i for i in self.issues if i.issue_type == issue_type and not i.false_positive]

    def mark_false_positive(self, issue_id: int):
        with self._lock:
            for issue in self.issues:
                if issue.id == issue_id:
                    issue.false_positive = True
                    break

    def remove_issue(self, issue_id: int):
        with self._lock:
            self.issues = [i for i in self.issues if i.id != issue_id]

    def clear(self):
        with self._lock:
            self.issues.clear()

    def get_summary(self) -> Dict:
        with self._lock:
            summary = {
                'total': len(self.issues),
                'false_positives': sum(1 for i in self.issues if i.false_positive),
                'by_severity': {
                    'critical': sum(1 for i in self.issues if i.severity == Severity.CRITICAL and not i.false_positive),
                    'high': sum(1 for i in self.issues if i.severity == Severity.HIGH and not i.false_positive),
                    'medium': sum(1 for i in self.issues if i.severity == Severity.MEDIUM and not i.false_positive),
                    'low': sum(1 for i in self.issues if i.severity == Severity.LOW and not i.false_positive),
                    'info': sum(1 for i in self.issues if i.severity == Severity.INFO and not i.false_positive),
                },
                'by_type': {}
            }

            for issue in self.issues:
                if not issue.false_positive:
                    type_name = issue.issue_type.value
                    summary['by_type'][type_name] = summary['by_type'].get(type_name, 0) + 1

            return summary


class ScanResult:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.issues: List[VulnerabilityIssue] = []
        self.urls_scanned: int = 0
        self.requests_made: int = 0
        self.errors: List[str] = []


class BaseScanner:
    def __init__(self):
        self.session = requests.Session()
        self.issue_tracker = IssueTracker()
        self.mode = ScanMode.PASSIVE

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        raise NotImplementedError

    def passive_scan(self, request_data: Dict, response_data: Dict):
        pass

    def active_scan(self, target: str) -> List[VulnerabilityIssue]:
        pass


class ScannerEngine:
    def __init__(self):
        self.scanners: Dict[str, BaseScanner] = {}
        self.issue_tracker = IssueTracker()
        self.mode = ScanMode.PASSIVE
        self._lock = threading.Lock()

    def register_scanner(self, name: str, scanner: BaseScanner):
        self.scanners[name] = scanner
        logger.info(f"Registered scanner: {name}")

    def scan_target(self, target: str, mode: ScanMode = None) -> ScanResult:
        scan_id = f"scan_{int(time.time())}"
        result = ScanResult(scan_id)
        self.mode = mode or self.mode

        logger.info(f"Starting {self.mode.value} scan on {target}")

        for name, scanner in self.scanners.items():
            try:
                issues = scanner.scan(target)
                for issue in issues:
                    self.issue_tracker.add_issue(issue)
                    result.issues.append(issue)
            except Exception as e:
                logger.error(f"Scanner {name} failed: {e}")
                result.errors.append(f"{name}: {str(e)}")

        result.end_time = datetime.now()
        return result

    def passive_scan_request(self, request_data: Dict, response_data: Dict):
        for scanner in self.scanners.values():
            try:
                scanner.passive_scan(request_data, response_data)
            except Exception as e:
                logger.error(f"Passive scan error: {e}")

    def get_issues(self) -> List[VulnerabilityIssue]:
        return self.issue_tracker.get_issues()

    def get_summary(self) -> Dict:
        return self.issue_tracker.get_summary()


class PassiveScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.mode = ScanMode.PASSIVE

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        logger.info(f"Passive scan on {target}")
        return []

    def passive_scan(self, request_data: Dict, response_data: Dict):
        issues = []

        url = request_data.get('url', '')
        method = request_data.get('method', '')
        response_text = response_data.get('text', '')

        if 'X-Powered-By' in response_data.get('headers', {}):
            issues.append(VulnerabilityIssue(
                issue_type=IssueType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                name="X-Powered-By Header",
                description="Server reveals technology stack via X-Powered-By header",
                url=url,
                evidence=response_data.get('headers', {}).get('X-Powered-By', ''),
                remediation="Remove X-Powered-By header from server response"
            ))

        if 'Server' in response_data.get('headers', {}) and 'Apache' in response_data.get('headers', {}).get('Server', ''):
            issues.append(VulnerabilityIssue(
                issue_type=IssueType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                name="Verbose Server Header",
                description="Server reveals version information",
                url=url,
                evidence=response_data.get('headers', {}).get('Server', ''),
                remediation="Configure server to hide version info"
            ))

        for issue in issues:
            self.issue_tracker.add_issue(issue)


class ActiveScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.mode = ScanMode.ACTIVE

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        logger.info(f"Active scan on {target}")
        return []


if __name__ == '__main__':
    tracker = IssueTracker()
    issue = VulnerabilityIssue(
        issue_type=IssueType.XSS,
        severity=Severity.HIGH,
        name="Reflected XSS",
        description="Cross-site scripting vulnerability",
        url="http://test.com/search?q=test",
        parameter="q",
        evidence="<script>alert(1)</script>",
        remediation="Sanitize user input"
    )
    tracker.add_issue(issue)

    print("Summary:", tracker.get_summary())