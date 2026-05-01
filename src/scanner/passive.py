"""Passive Scanner - Automatically analyzes proxy traffic"""
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import re
from ..scanner.scanner import VulnerabilityIssue, IssueType, Severity
from ..scanner.checks import InfoDisclosureScanner


class PassiveScanner:
    def __init__(self):
        self.enabled = True
        self.issues: List[VulnerabilityIssue] = []
        self._next_id = 1

        self.info_scanner = InfoDisclosureScanner()

        self.passive_checks = [
            self._check_info_disclosure,
            self._check_sensitive_data,
            self._check_cookies,
            self._check_caching,
            self._check_security_headers,
            self._check_html_comments,
            self._check_error_messages,
            self._check_password_fields,
            self._check_file_paths,
            self._check_email_exposure,
        ]

    def scan_request(self, request: Dict) -> List[VulnerabilityIssue]:
        issues = []

        if not self.enabled:
            return issues

        url = request.get('url', '')
        method = request.get('method', '')
        headers = request.get('headers', {})
        body = request.get('body', b'')

        try:
            body_text = body.decode('utf-8', errors='ignore') if body else ''
        except:
            body_text = ''

        for check in self.passive_checks:
            try:
                result = check(url, method, headers, body_text, body)
                if result:
                    issues.extend(result)
            except:
                pass

        for issue in issues:
            issue.id = self._next_id
            self._next_id += 1
            self.issues.append(issue)

        return issues

    def scan_response(self, request: Dict, response: Dict) -> List[VulnerabilityIssue]:
        issues = []

        if not self.enabled:
            return issues

        url = request.get('url', '')
        status_code = response.get('status_code', 0)
        headers = response.get('headers', {})
        body = response.get('body', b'')

        try:
            body_text = body.decode('utf-8', errors='ignore') if body else ''
        except:
            body_text = ''

        response_issues = [
            self._check_response_headers(url, status_code, headers),
            self._check_sensitive_data_in_response(url, body_text),
            self._check_error_leakage(url, status_code, body_text),
            self._check_version_disclosure(url, headers),
            self._check_cache_controls(url, headers),
            self._check_xxss_protection(url, headers),
        ]

        for issue_list in response_issues:
            if issue_list:
                issues.extend(issue_list)

        for issue in issues:
            issue.id = self._next_id
            self._next_id += 1
            self.issues.append(issue)

        return issues

    def _check_info_disclosure(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        header_lower = {k.lower(): v for k, v in headers.items()}

        if 'x-powered-by' in header_lower:
            issues.append(VulnerabilityIssue(
                issue_type=IssueType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                name="X-Powered-By Header",
                description="Server reveals technology stack",
                url=url,
                evidence=header_lower['x-powered-by'],
                remediation="Remove X-Powered-By header"
            ))

        if 'server' in header_lower:
            server = header_lower['server']
            if re.search(r'\d+\.\d+', server):
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.LOW,
                    name="Verbose Server Header",
                    description="Server reveals version information",
                    url=url,
                    evidence=server,
                    remediation="Configure server to hide version"
                ))

        if 'x-aspnet-version' in header_lower:
            issues.append(VulnerabilityIssue(
                issue_type=IssueType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                name="ASP.NET Version Disclosure",
                description="ASP.NET version revealed",
                url=url,
                evidence=header_lower['x-aspnet-version'],
                remediation="Remove X-ASPNet-Version header"
            ))

        return issues

    def _check_sensitive_data(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        sensitive_patterns = {
            'API Key': r'(api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'Password': r'(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\'<>]{4,})',
            'Token': r'(token|auth[_-]?token|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            'Private Key': r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            'AWS Key': r'AKIA[0-9A-Z]{16}',
        }

        for pattern_name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, body_text, re.IGNORECASE)
            if matches:
                for match in matches[:2]:
                    evidence = match[1] if len(match) > 1 else match[0]
                    issues.append(VulnerabilityIssue(
                        issue_type=IssueType.INFO_DISCLOSURE,
                        severity=Severity.HIGH,
                        name=f"Sensitive Data: {pattern_name}",
                        description=f"Potential {pattern_name} found in request body",
                        url=url,
                        evidence=evidence[:30] + '...' if len(evidence) > 30 else evidence,
                        remediation=f"Remove {pattern_name} from request body"
                    ))

        return issues

    def _check_cookies(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        cookie_header = headers.get('Cookie', '') or headers.get('cookie', '')

        if cookie_header:
            if 'httponly' not in cookie_header.lower() and 'session' in cookie_header.lower():
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    name="Cookie Without HttpOnly Flag",
                    description="Session cookie may be accessible via JavaScript",
                    url=url,
                    evidence=cookie_header[:50],
                    remediation="Set HttpOnly flag on session cookies"
                ))

            if 'secure' not in cookie_header.lower() and url.startswith('https'):
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    name="Cookie Without Secure Flag",
                    description="Cookie may be sent over non-HTTPS connection",
                    url=url,
                    evidence=cookie_header[:50],
                    remediation="Set Secure flag on cookies"
                ))

        return issues

    def _check_caching(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        header_lower = {k.lower(): v for k, v in headers.items()}

        cache_control = header_lower.get('cache-control', '')
        if 'no-store' not in cache_control.lower() and 'no-cache' not in cache_control.lower():
            if method in ['GET', 'POST'] and any(ext in url for ext in ['.js', '.css', '.json', '.xml']):
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.LOW,
                    name="Cacheable Response",
                    description="Sensitive content may be cached by browsers",
                    url=url,
                    evidence=cache_control or 'Not set',
                    remediation="Set Cache-Control: no-store, no-cache"
                ))

        return issues

    def _check_security_headers(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        header_lower = {k.lower(): v for k, v in headers.items()}

        missing_headers = []
        if 'strict-transport-security' not in header_lower:
            missing_headers.append('Strict-Transport-Security')
        if 'x-content-type-options' not in header_lower:
            missing_headers.append('X-Content-Type-Options')
        if 'x-frame-options' not in header_lower:
            missing_headers.append('X-Frame-Options')
        if 'content-security-policy' not in header_lower:
            missing_headers.append('Content-Security-Policy')

        if missing_headers and url.startswith('https'):
            issues.append(VulnerabilityIssue(
                issue_type=IssueType.INFO_DISCLOSURE,
                severity=Severity.LOW,
                name="Missing Security Headers",
                description=f"Missing: {', '.join(missing_headers)}",
                url=url,
                evidence=', '.join(missing_headers),
                remediation="Configure web server to send security headers"
            ))

        return issues

    def _check_html_comments(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        html_comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(html_comment_pattern, body_text, re.DOTALL)

        sensitive_keywords = ['password', 'pass', 'secret', 'key', 'token', 'debug', 'todo', 'fixme', 'admin']

        for comment in comments:
            comment_lower = comment.lower()
            for keyword in sensitive_keywords:
                if keyword in comment_lower and len(comment.strip()) < 200:
                    issues.append(VulnerabilityIssue(
                        issue_type=IssueType.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        name="Sensitive Comment in HTML",
                        description=f"HTML comment contains: {keyword}",
                        url=url,
                        evidence=comment.strip()[:100],
                        remediation="Remove sensitive comments from HTML"
                    ))
                    break

        return issues

    def _check_error_messages(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        error_patterns = [
            (r'sql.*error|mysql.*error|postgresql.*error|ora-\d+', 'SQL Error', 'Database error message'),
            (r'stack\s*trace|at\s+\w+\.\w+\(|exception.*in.*line', 'Stack Trace', 'Code stack trace'),
            (r'warning.*undefined|undefined\s+variable|null\s+reference', 'JavaScript Error', 'JavaScript error'),
            (r'permission\s+denied|access\s+denied|unauthorized', 'Access Error', 'Access denied message'),
            (r'file\s+not\s+found|404|not\s+found', 'File Not Found', '404 error'),
            (r'fatal\s+error|exception|panic', 'Fatal Error', 'Fatal error message'),
        ]

        for pattern, name, description in error_patterns:
            if re.search(pattern, body_text, re.IGNORECASE):
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.LOW,
                    name=f"Information Leakage: {name}",
                    description=f"{description} may reveal system details",
                    url=url,
                    evidence=f"Error pattern found in response",
                    remediation="Customize error pages"
                ))
                break

        return issues

    def _check_password_fields(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        password_field_pattern = r'<input[^>]*type=["\']password["\']'
        if re.search(password_field_pattern, body_text, re.IGNORECASE):
            issues.append(VulnerabilityIssue(
                issue_type=IssueType.INFO_DISCLOSURE,
                severity=Severity.INFO,
                name="Password Field Detected",
                description="Password input field found in form",
                url=url,
                evidence="Password input field present",
                remediation="Ensure form uses HTTPS"
            ))

        return issues

    def _check_file_paths(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        path_patterns = [
            (r'/etc/passwd', 'Unix passwd file'),
            (r'/etc/shadow', 'Unix shadow file'),
            (r'C:\\Windows', 'Windows path'),
            (r'C:/Program Files', 'Windows program files'),
            (r'/var/log/', 'Unix log directory'),
            (r'/home/', 'Unix home directory'),
        ]

        for pattern, description in path_patterns:
            if re.search(pattern, body_text, re.IGNORECASE):
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.HIGH,
                    name="File Path Disclosure",
                    description=f"File path exposure: {description}",
                    url=url,
                    evidence=pattern,
                    remediation="Sanitize file paths in responses"
                ))

        return issues

    def _check_email_exposure(self, url: str, method: str, headers: Dict, body_text: str, body: bytes) -> List[VulnerabilityIssue]:
        issues = []

        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        emails = re.findall(email_pattern, body_text)

        if len(emails) > 0:
            unique_emails = set(emails)
            if len(unique_emails) <= 5:
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.LOW,
                    name="Email Address Exposure",
                    description=f"Email addresses found in response",
                    url=url,
                    evidence=', '.join(list(unique_emails)[:3]),
                    remediation="Remove email addresses from public pages"
                ))

        return issues

    def _check_response_headers(self, url: str, status_code: int, headers: Dict) -> List[VulnerabilityIssue]:
        return self._check_info_disclosure(url, 'GET', headers, '', b'')

    def _check_sensitive_data_in_response(self, url: str, body_text: str) -> List[VulnerabilityIssue]:
        return self._check_sensitive_data(url, 'GET', {}, body_text, b'')

    def _check_error_leakage(self, url: str, status_code: int, body_text: str) -> List[VulnerabilityIssue]:
        return self._check_error_messages(url, 'GET', {}, body_text, b'')

    def _check_version_disclosure(self, url: str, headers: Dict) -> List[VulnerabilityIssue]:
        return []

    def _check_cache_controls(self, url: str, headers: Dict) -> List[VulnerabilityIssue]:
        return self._check_caching(url, 'GET', headers, '', b'')

    def _check_xxss_protection(self, url: str, headers: Dict) -> List[VulnerabilityIssue]:
        issues = []

        header_lower = {k.lower(): v for k, v in headers.items()}

        if 'x-xss-protection' in header_lower:
            xss_prot = header_lower['x-xss-protection']
            if '0' in xss_prot:
                issues.append(VulnerabilityIssue(
                    issue_type=IssueType.INFO_DISCLOSURE,
                    severity=Severity.MEDIUM,
                    name="XSS Protection Disabled",
                    description="X-XSS-Protection header is disabled",
                    url=url,
                    evidence=xss_prot,
                    remediation="Enable XSS protection"
                ))

        return issues

    def get_issues(self) -> List[VulnerabilityIssue]:
        return self.issues

    def get_issues_by_severity(self, severity: Severity) -> List[VulnerabilityIssue]:
        return [i for i in self.issues if i.severity == severity]

    def clear_issues(self):
        self.issues.clear()

    def get_summary(self) -> Dict:
        return {
            'total': len(self.issues),
            'critical': len([i for i in self.issues if i.severity == Severity.CRITICAL]),
            'high': len([i for i in self.issues if i.severity == Severity.HIGH]),
            'medium': len([i for i in self.issues if i.severity == Severity.MEDIUM]),
            'low': len([i for i in self.issues if i.severity == Severity.LOW]),
            'info': len([i for i in self.issues if i.severity == Severity.INFO]),
        }


if __name__ == '__main__':
    scanner = PassiveScanner()

    test_request = {
        'url': 'http://example.com/login',
        'method': 'POST',
        'headers': {'Content-Type': 'application/json', 'X-Powered-By': 'Express'},
        'body': b'{"email": "test@example.com"}'
    }

    test_response = {
        'status_code': 200,
        'headers': {'Server': 'Apache/2.4.41', 'Content-Type': 'text/html'},
        'body': b'<!-- TODO: fix password handling -->'
    }

    issues = scanner.scan_request(test_request)
    print(f"Request issues: {len(issues)}")

    issues = scanner.scan_response(test_request, test_response)
    print(f"Response issues: {len(issues)}")

    print(f"Total: {scanner.get_summary()}")