"""Vulnerability Detection Checks"""
from typing import List, Dict, Optional
from dataclasses import dataclass
import re
import requests
from .scanner import (
    BaseScanner, VulnerabilityIssue, IssueType, Severity
)


class XSSScanner(BaseScanner):
    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "'\"<script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "';alert(1);'",
    ]

    REFLECTED_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"on\w+\s*=",
        r"javascript:",
        r"<svg.*?>",
    ]

    def __init__(self):
        super().__init__()
        self.name = "XSS Scanner"

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        issues = []

        try:
            response = requests.get(target, timeout=10)
            base_content = response.text

            for payload in self.PAYLOADS[:3]:
                test_url = self._inject_payload(target, "test", payload)

                if test_url:
                    test_response = requests.get(test_url, timeout=10)

                    if payload in test_response.text:
                        issues.append(VulnerabilityIssue(
                            issue_type=IssueType.XSS,
                            severity=Severity.HIGH,
                            name="Reflected Cross-Site Scripting (XSS)",
                            description="User input is reflected in the response without proper encoding",
                            url=test_url,
                            parameter="test",
                            evidence=f"Payload reflected: {payload[:50]}",
                            remediation="Sanitize and encode user input before reflecting it"
                        ))
                        break

        except Exception as e:
            pass

        for issue in issues:
            self.issue_tracker.add_issue(issue)

        return issues

    def _inject_payload(self, url: str, param: str, payload: str) -> Optional[str]:
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return None

        params[param] = payload
        new_query = urlencode(params, doseq=True)

        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


class SQLInjectionScanner(BaseScanner):
    PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "'; DROP TABLE users; --",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 OR 1=1",
        "admin'--",
        "' OR 1=1--",
    ]

    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid SQL statement",
        r"ORA-[0-9]{5}",
        r"Microsoft SQL Native Error",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Unclosed .* quote",
        r"SQLite/JDBCDriver",
    ]

    def __init__(self):
        super().__init__()
        self.name = "SQL Injection Scanner"

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        issues = []

        try:
            response = requests.get(target, timeout=10)
            base_error = self._check_errors(response.text)

            for payload in self.PAYLOADS[:3]:
                test_url = self._inject_payload(target, "id", payload)

                if test_url:
                    test_response = requests.get(test_url, timeout=10)

                    if self._check_errors(test_response.text) and not base_error:
                        issues.append(VulnerabilityIssue(
                            issue_type=IssueType.SQL_INJECTION,
                            severity=Severity.CRITICAL,
                            name="SQL Injection",
                            description="User input is used in database queries without proper sanitization",
                            url=test_url,
                            parameter="id",
                            evidence=f"Payload: {payload}",
                            remediation="Use parameterized queries or prepared statements"
                        ))
                        break

                    if test_response.status_code != response.status_code:
                        issues.append(VulnerabilityIssue(
                            issue_type=IssueType.SQL_INJECTION,
                            severity=Severity.MEDIUM,
                            name="Potential SQL Injection",
                            description="Different response with SQL payload",
                            url=test_url,
                            parameter="id",
                            evidence=f"Status: {test_response.status_code}",
                            remediation="Verify input handling"
                        ))
                        break

        except Exception as e:
            pass

        for issue in issues:
            self.issue_tracker.add_issue(issue)

        return issues

    def _inject_payload(self, url: str, param: str, payload: str) -> Optional[str]:
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return None

        params[param] = payload
        new_query = urlencode(params, doseq=True)

        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def _check_errors(self, text: str) -> bool:
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False


class CommandInjectionScanner(BaseScanner):
    PAYLOADS = [
        "; ls -la",
        "| ls -la",
        "& ls -la",
        "`ls -la`",
        "$(ls -la)",
        "; cat /etc/passwd",
        "| whoami",
        "; whoami",
    ]

    def __init__(self):
        super().__init__()
        self.name = "Command Injection Scanner"

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        issues = []

        try:
            response = requests.get(target, timeout=10)
            base_content = response.text[:500]

            for payload in self.PAYLOADS[:2]:
                test_url = self._inject_payload(target, "cmd", payload)

                if test_url:
                    test_response = requests.get(test_url, timeout=10)

                    if "root:" in test_response.text or "daemon:" in test_response.text:
                        issues.append(VulnerabilityIssue(
                            issue_type=IssueType.COMMAND_INJECTION,
                            severity=Severity.CRITICAL,
                            name="Command Injection",
                            description="User input is used in system commands without sanitization",
                            url=test_url,
                            parameter="cmd",
                            evidence="Password file contents in response",
                            remediation="Validate and sanitize user input, use strict allowlists"
                        ))
                        break

        except Exception as e:
            pass

        for issue in issues:
            self.issue_tracker.add_issue(issue)

        return issues

    def _inject_payload(self, url: str, param: str, payload: str) -> Optional[str]:
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param not in params:
            params[param] = payload
        else:
            params[param] = [payload]

        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


class SSRFScanner(BaseScanner):
    PAYLOADS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://metadata.google.internal/",
    ]

    def __init__(self):
        super().__init__()
        self.name = "SSRF Scanner"

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        issues = []

        try:
            for payload in self.PAYLOADS:
                test_url = self._inject_payload(target, "url", payload)

                if test_url:
                    test_response = requests.get(test_url, timeout=5)

                    if "localhost" in test_response.text.lower() or "127.0.0.1" in test_response.text:
                        issues.append(VulnerabilityIssue(
                            issue_type=IssueType.SSRF,
                            severity=Severity.HIGH,
                            name="Server-Side Request Forgery (SSRF)",
                            description="Server fetches user-controlled URLs",
                            url=test_url,
                            parameter="url",
                            evidence=f"Payload: {payload}",
                            remediation="Validate URLs against allowlists"
                        ))
                        break

        except Exception as e:
            pass

        for issue in issues:
            self.issue_tracker.add_issue(issue)

        return issues

    def _inject_payload(self, url: str, param: str, payload: str) -> Optional[str]:
        from urllib.parse import urlparse, parse_qs, urlencode

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if param not in params:
            params[param] = payload

        new_query = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


class InfoDisclosureScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.name = "Information Disclosure Scanner"

    def scan(self, target: str, options: Dict = None) -> List[VulnerabilityIssue]:
        issues = []

        try:
            response = requests.get(target, timeout=10)

            headers = response.headers

            disclosure_headers = {
                'X-Powered-By': 'Technology stack disclosure',
                'X-AspNet-Version': 'ASP.NET version disclosure',
                'X-AspNetMvc-Version': 'ASP.NET MVC version disclosure',
                'Server': 'Detailed server version'
            }

            for header, description in disclosure_headers.items():
                if header in headers:
                    issues.append(VulnerabilityIssue(
                        issue_type=IssueType.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        name=f"Information Disclosure: {header}",
                        description=description,
                        url=target,
                        evidence=f"{header}: {headers[header]}",
                        remediation=f"Remove or obfuscate {header} header"
                    ))

            content = response.text
            sensitive_patterns = {
                'email': r'[\w\.-]+@[\w\.-]+\.\w+',
                'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]{20,}',
                'password': r'password["\']?\s*[:=]\s*["\']?[^\s"\'<>]+',
            }

            for pattern_type, pattern in sensitive_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append(VulnerabilityIssue(
                        issue_type=IssueType.INFO_DISCLOSURE,
                        severity=Severity.MEDIUM,
                        name=f"Potential {pattern_type} in response",
                        description=f"Possibly sensitive {pattern_type} found in response",
                        url=target,
                        evidence=f"Pattern match: {pattern_type}",
                        remediation="Review and redact sensitive data"
                    ))

        except Exception as e:
            pass

        for issue in issues:
            self.issue_tracker.add_issue(issue)

        return issues


def get_all_scanners() -> List[BaseScanner]:
    return [
        XSSScanner(),
        SQLInjectionScanner(),
        CommandInjectionScanner(),
        SSRFScanner(),
        InfoDisclosureScanner()
    ]


if __name__ == '__main__':
    scanner = XSSScanner()
    issues = scanner.scan("http://example.com/test?id=1")
    print(f"Found {len(issues)} issues")
    for issue in issues:
        print(f"  - {issue.name} ({issue.severity.value})")