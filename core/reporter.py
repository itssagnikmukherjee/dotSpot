import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Finding:
    category: str
    severity: str
    title: str
    description: str
    url: str
    evidence: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class ScanReport:
    target_url: str
    scan_start: str
    scan_end: str
    total_urls_scanned: int
    findings: List[Finding]
    summary: Dict[str, int]


def generate_report(
    target_url: str,
    findings: List[str],
    urls_scanned: int,
    scan_start: datetime,
    output_dir: str = "reports"
) -> Dict[str, str]:
    scan_end = datetime.now()
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    timestamp = scan_start.strftime("%Y%m%d_%H%M%S")
    
    structured_findings = parse_findings(findings)
    
    summary = {
        "critical": sum(1 for f in structured_findings if f.severity == "critical"),
        "high": sum(1 for f in structured_findings if f.severity == "high"),
        "medium": sum(1 for f in structured_findings if f.severity == "medium"),
        "low": sum(1 for f in structured_findings if f.severity == "low"),
        "info": sum(1 for f in structured_findings if f.severity == "info"),
        "total": len(structured_findings)
    }
    
    report = ScanReport(
        target_url=target_url,
        scan_start=scan_start.isoformat(),
        scan_end=scan_end.isoformat(),
        total_urls_scanned=urls_scanned,
        findings=structured_findings,
        summary=summary
    )
    
    json_path = os.path.join(output_dir, f"scan_{timestamp}.json")
    save_json_report(report, json_path)
    
    html_path = os.path.join(output_dir, f"scan_{timestamp}.html")
    save_html_report(report, html_path)
    
    return {
        "json": json_path,
        "html": html_path
    }


def parse_findings(finding_strings: List[str]) -> List[Finding]:
    findings = []
    
    for finding_str in finding_strings:
        category, severity = categorize_finding(finding_str)
        
        findings.append(Finding(
            category=category,
            severity=severity,
            title=finding_str.split(':')[0] if ':' in finding_str else finding_str[:50],
            description=finding_str,
            url="",
            recommendation=get_recommendation(category)
        ))
    
    return findings


def categorize_finding(finding: str) -> tuple:
    finding_lower = finding.lower()
    
    if "sql" in finding_lower or "sqli" in finding_lower:
        return "SQL Injection", "critical"
    elif "ssti" in finding_lower or "template" in finding_lower:
        return "Template Injection", "critical"
    elif "xss" in finding_lower:
        return "Cross-Site Scripting", "high"
    elif "exposed path" in finding_lower or "admin" in finding_lower:
        return "Exposed Path", "medium"
    elif "cookie" in finding_lower:
        return "Cookie Security", "medium"
    elif "secret" in finding_lower or "api key" in finding_lower or "token" in finding_lower:
        return "Exposed Secrets", "high"
    elif "comment" in finding_lower:
        return "Information Disclosure", "low"
    else:
        return "General", "info"


def get_recommendation(category: str) -> str:
    recommendations = {
        "SQL Injection": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
        "Template Injection": "Avoid passing user input directly into template engines. Sanitize and validate all user input.",
        "Cross-Site Scripting": "Encode output data and implement Content Security Policy (CSP). Use contextual output encoding.",
        "Exposed Path": "Remove or restrict access to sensitive paths. Implement proper authentication and authorization.",
        "Cookie Security": "Set HttpOnly, Secure, and SameSite flags on all cookies containing sensitive data.",
        "Exposed Secrets": "Remove hardcoded secrets immediately. Use environment variables or secret management systems.",
        "Information Disclosure": "Remove HTML comments and debug information from production code.",
        "General": "Review and address the identified security concern."
    }
    return recommendations.get(category, recommendations["General"])


def save_json_report(report: ScanReport, path: str) -> None:
    report_dict = {
        "target_url": report.target_url,
        "scan_start": report.scan_start,
        "scan_end": report.scan_end,
        "total_urls_scanned": report.total_urls_scanned,
        "summary": report.summary,
        "findings": [asdict(f) for f in report.findings]
    }
    
    with open(path, 'w') as f:
        json.dump(report_dict, f, indent=2)


def save_html_report(report: ScanReport, path: str) -> None:
    severity_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d"
    }
    
    findings_html = ""
    for f in report.findings:
        color = severity_colors.get(f.severity, "#6c757d")
        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity" style="background-color: {color}">{f.severity.upper()}</span>
                <span class="category">{f.category}</span>
            </div>
            <h3>{f.title}</h3>
            <p>{f.description}</p>
            {f'<div class="evidence"><strong>Evidence:</strong> <code>{f.evidence}</code></div>' if f.evidence else ''}
            <div class="recommendation"><strong>Recommendation:</strong> {f.recommendation}</div>
        </div>
        """
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DotSpot Scan Report - {report.target_url}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #58a6ff; margin-bottom: 0.5rem; }}
        h2 {{ color: #8b949e; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
        h3 {{ color: #c9d1d9; margin: 0.5rem 0; }}
        .meta {{ color: #8b949e; margin-bottom: 2rem; }}
        .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }}
        .summary-item {{ background: #161b22; padding: 1rem 1.5rem; border-radius: 8px; text-align: center; min-width: 100px; }}
        .summary-item .count {{ font-size: 2rem; font-weight: bold; }}
        .summary-item .label {{ font-size: 0.875rem; color: #8b949e; }}
        .finding {{ background: #161b22; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid; }}
        .finding-header {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }}
        .severity {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: white; text-transform: uppercase; }}
        .category {{ color: #8b949e; font-size: 0.875rem; }}
        .evidence {{ background: #0d1117; padding: 0.75rem; border-radius: 4px; margin: 0.75rem 0; }}
        .evidence code {{ color: #f85149; }}
        .recommendation {{ color: #8b949e; font-size: 0.9rem; margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid #30363d; }}
        .no-findings {{ text-align: center; padding: 3rem; color: #3fb950; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 DotSpot Scan Report</h1>
        <div class="meta">
            <p><strong>Target:</strong> {report.target_url}</p>
            <p><strong>Scan Time:</strong> {report.scan_start} to {report.scan_end}</p>
            <p><strong>URLs Scanned:</strong> {report.total_urls_scanned}</p>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-item" style="border-left: 3px solid #dc3545;">
                <div class="count" style="color: #dc3545;">{report.summary['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-item" style="border-left: 3px solid #fd7e14;">
                <div class="count" style="color: #fd7e14;">{report.summary['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-item" style="border-left: 3px solid #ffc107;">
                <div class="count" style="color: #ffc107;">{report.summary['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-item" style="border-left: 3px solid #17a2b8;">
                <div class="count" style="color: #17a2b8;">{report.summary['low']}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-item" style="border-left: 3px solid #6c757d;">
                <div class="count" style="color: #6c757d;">{report.summary['info']}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <h2>Findings</h2>
        {findings_html if findings_html else '<div class="no-findings">✅ No vulnerabilities found!</div>'}
    </div>
</body>
</html>"""
    
    with open(path, 'w') as f:
        f.write(html)
