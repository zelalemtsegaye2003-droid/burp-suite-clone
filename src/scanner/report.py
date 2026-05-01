"""Report Generation for Vulnerability Findings"""
import os
import json
from datetime import datetime
from typing import List, Dict, Optional
from ..scanner.scanner import VulnerabilityIssue, Severity, IssueType


class ReportGenerator:
    def __init__(self):
        self.issues: List[VulnerabilityIssue] = []
        self.target_info: Dict = {}

    def set_target(self, name: str, url: str, description: str = ""):
        self.target_info = {
            'name': name,
            'url': url,
            'description': description,
            'scan_date': datetime.now().isoformat()
        }

    def add_issue(self, issue: VulnerabilityIssue):
        self.issues.append(issue)

    def add_issues(self, issues: List[VulnerabilityIssue]):
        self.issues.extend(issues)

    def generate_html(self, filename: str = "report.html") -> str:
        severity_counts = self._get_severity_counts()
        by_type = self._get_by_type()

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Burp Clone - Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #f5f5f5; color: #333; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.8; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card .count {{ font-size: 36px; font-weight: bold; }}
        .summary-card.critical {{ border-left: 4px solid #d32f2f; }}
        .summary-card.high {{ border-left: 4px solid #f57c00; }}
        .summary-card.medium {{ border-left: 4px solid #fbc02d; }}
        .summary-card.low {{ border-left: 4px solid #1976d2; }}
        .summary-card.info {{ border-left: 4px solid #388e3c; }}
        .section {{ background: white; padding: 25px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .section h2 {{ margin-bottom: 20px; color: #1a1a2e; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .issue {{ border: 1px solid #ddd; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }}
        .issue-header {{ background: #f8f9fa; padding: 15px; display: flex; justify-content: space-between; align-items: center; }}
        .issue-header .title {{ font-weight: bold; font-size: 16px; }}
        .severity-badge {{ padding: 5px 15px; border-radius: 20px; color: white; font-size: 12px; font-weight: bold; }}
        .severity-critical {{ background: #d32f2f; }}
        .severity-high {{ background: #f57c00; }}
        .severity-medium {{ background: #fbc02d; color: #333; }}
        .severity-low {{ background: #1976d2; }}
        .severity-info {{ background: #388e3c; }}
        .issue-body {{ padding: 15px; }}
        .issue-body .detail {{ margin-bottom: 10px; }}
        .issue-body .label {{ font-weight: bold; color: #666; }}
        .issue-body .evidence {{ background: #f5f5f5; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 13px; margin-top: 5px; }}
        .by-type {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .type-tag {{ background: #e3f2fd; padding: 8px 15px; border-radius: 20px; font-size: 14px; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Assessment Report</h1>
        <div class="meta">
            <p><strong>Target:</strong> {self.target_info.get('name', 'N/A')}</p>
            <p><strong>URL:</strong> {self.target_info.get('url', 'N/A')}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </div>
    </div>

    <div class="summary">
        <div class="summary-card critical">
            <div class="count">{severity_counts.get('critical', 0)}</div>
            <div>Critical</div>
        </div>
        <div class="summary-card high">
            <div class="count">{severity_counts.get('high', 0)}</div>
            <div>High</div>
        </div>
        <div class="summary-card medium">
            <div class="count">{severity_counts.get('medium', 0)}</div>
            <div>Medium</div>
        </div>
        <div class="summary-card low">
            <div class="count">{severity_counts.get('low', 0)}</div>
            <div>Low</div>
        </div>
        <div class="summary-card info">
            <div class="count">{severity_counts.get('info', 0)}</div>
            <div>Info</div>
        </div>
    </div>

    <div class="section">
        <h2>📊 Issues by Type</h2>
        <div class="by-type">
            {self._format_type_tags(by_type)}
        </div>
    </div>

    <div class="section">
        <h2>🐛 Detailed Findings</h2>
        {self._format_issues_html()}
    </div>

    <div class="section">
        <h2>📋 Recommendations</h2>
        {self._format_recommendations()}
    </div>

    <div class="footer">
        <p>Generated by Burp Clone v1.0 | Web Application Penetration Testing Toolkit</p>
    </div>
</body>
</html>"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        return filename

    def generate_json(self, filename: str = "report.json") -> str:
        report = {
            'target': self.target_info,
            'summary': self._get_severity_counts(),
            'by_type': self._get_by_type(),
            'issues': [issue.to_dict() for issue in self.issues],
            'generated': datetime.now().isoformat()
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return filename

    def generate_markdown(self, filename: str = "report.md") -> str:
        severity_counts = self._get_severity_counts()

        md = f"""# Security Assessment Report

## Target Information
- **Name:** {self.target_info.get('name', 'N/A')}
- **URL:** {self.target_info.get('url', 'N/A')}
- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M')}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {severity_counts.get('critical', 0)} |
| High | {severity_counts.get('high', 0)} |
| Medium | {severity_counts.get('medium', 0)} |
| Low | {severity_counts.get('low', 0)} |
| Info | {severity_counts.get('info', 0)} |
| **Total** | {len(self.issues)} |

## Issues

"""
        for issue in self.issues:
            md += f"""### {issue.name}

- **Severity:** {issue.severity.value.upper()}
- **Type:** {issue.issue_type.value}
- **URL:** {issue.url}
- **Parameter:** {issue.parameter or 'N/A'}

**Description:** {issue.description}

**Evidence:** {issue.evidence}

**Remediation:** {issue.remediation}

---

"""

        md += """
## Recommendations

"""
        for rec in self._get_recommendations_list():
            md += f"- {rec}\n"

        md += f"""

---
*Generated by Burp Clone v1.0*
"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(md)

        return filename

    def _get_severity_counts(self) -> Dict[str, int]:
        return {
            'critical': sum(1 for i in self.issues if i.severity == Severity.CRITICAL),
            'high': sum(1 for i in self.issues if i.severity == Severity.HIGH),
            'medium': sum(1 for i in self.issues if i.severity == Severity.MEDIUM),
            'low': sum(1 for i in self.issues if i.severity == Severity.LOW),
            'info': sum(1 for i in self.issues if i.severity == Severity.INFO),
        }

    def _get_by_type(self) -> Dict[str, int]:
        counts = {}
        for issue in self.issues:
            type_name = issue.issue_type.value
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts

    def _format_type_tags(self, by_type: Dict[str, int]) -> str:
        tags = []
        for type_name, count in by_type.items():
            tags.append(f'<span class="type-tag">{type_name}: {count}</span>')
        return ' '.join(tags)

    def _format_issues_html(self) -> str:
        if not self.issues:
            return "<p>No issues found.</p>"

        html_parts = []
        for issue in self.issues:
            severity_class = f"severity-{issue.severity.value}"
            html_parts.append(f"""
            <div class="issue">
                <div class="issue-header">
                    <span class="title">{issue.name}</span>
                    <span class="severity-badge {severity_class}">{issue.severity.value.upper()}</span>
                </div>
                <div class="issue-body">
                    <div class="detail"><span class="label">URL:</span> {issue.url}</div>
                    <div class="detail"><span class="label">Type:</span> {issue.issue_type.value}</div>
                    <div class="detail"><span class="label">Description:</span> {issue.description}</div>
                    <div class="detail"><span class="label">Evidence:</span><div class="evidence">{issue.evidence or 'N/A'}</div></div>
                    <div class="detail"><span class="label">Remediation:</span> {issue.remediation}</div>
                </div>
            </div>
            """)
        return '\n'.join(html_parts)

    def _format_recommendations(self) -> str:
        recs = self._get_recommendations_list()
        return '<ul>' + ''.join(f'<li>{r}</li>' for r in recs) + '</ul>'

    def _get_recommendations_list(self) -> List[str]:
        recommendations = []

        severity_counts = self._get_severity_counts()

        if severity_counts.get('critical', 0) > 0:
            recommendations.append("CRITICAL: Address critical vulnerabilities immediately")

        if severity_counts.get('high', 0) > 0:
            recommendations.append("HIGH: Prioritize remediation of high-severity issues")

        recommendations.append("Implement input validation and output encoding across all applications")
        recommendations.append("Use parameterized queries to prevent SQL injection")
        recommendations.append("Implement Content Security Policy (CSP) headers")
        recommendations.append("Enable HTTPS and HSTS for all endpoints")
        recommendations.append("Regular security assessments and penetration testing")
        recommendations.append("Keep dependencies and frameworks updated")

        return recommendations


def generate_report(issues: List[VulnerabilityIssue], target_name: str, target_url: str,
                   output_dir: str = ".") -> Dict[str, str]:
    generator = ReportGenerator()
    generator.set_target(target_name, target_url)
    generator.add_issues(issues)

    reports = {}

    html_file = os.path.join(output_dir, "security_report.html")
    reports['html'] = generator.generate_html(html_file)

    json_file = os.path.join(output_dir, "security_report.json")
    reports['json'] = generator.generate_json(json_file)

    md_file = os.path.join(output_dir, "security_report.md")
    reports['markdown'] = generator.generate_markdown(md_file)

    return reports


if __name__ == '__main__':
    from scanner import VulnerabilityIssue, IssueType, Severity

    issues = [
        VulnerabilityIssue(
            issue_type=IssueType.XSS,
            severity=Severity.HIGH,
            name="Reflected XSS",
            description="Cross-site scripting vulnerability in search parameter",
            url="http://example.com/search?q=test",
            parameter="q",
            evidence="<script>alert(1)</script>",
            remediation="Sanitize and escape user input"
        ),
        VulnerabilityIssue(
            issue_type=IssueType.INFO_DISCLOSURE,
            severity=Severity.LOW,
            name="X-Powered-By Header",
            description="Server reveals technology stack",
            url="http://example.com/",
            evidence="X-Powered-By: Express",
            remediation="Remove X-Powered-By header"
        )
    ]

    reports = generate_report(issues, "Test Target", "http://example.com")
    print("Reports generated:")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")