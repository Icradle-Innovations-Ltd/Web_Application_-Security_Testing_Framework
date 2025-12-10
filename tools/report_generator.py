"""
Vulnerability Report Generator for Web Application Security Tests
"""

from datetime import datetime
from typing import List, Dict, Optional, Any
from jinja2 import Template
import json
import os


class VulnerabilityReport:
    """Generate standardized vulnerability reports"""
    
    SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low", "Info"]
    OWASP_CATEGORIES = [
        "A01:2021-Broken Access Control",
        "A02:2021-Cryptographic Failures",
        "A03:2021-Injection",
        "A04:2021-Insecure Design",
        "A05:2021-Security Misconfiguration",
        "A06:2021-Vulnerable and Outdated Components",
        "A07:2021-Identification and Authentication Failures",
        "A08:2021-Software and Data Integrity Failures",
        "A09:2021-Security Logging and Monitoring Failures",
        "A10:2021-Server-Side Request Forgery (SSRF)",
    ]
    
    def __init__(self):
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)
    
    def create_report(
        self,
        title: str,
        vulnerability_type: str,
        severity: str,
        affected_url: str,
        description: str,
        reproduction_steps: List[str],
        impact: str,
        remediation: str,
        owasp_category: Optional[str] = None,
        cve_references: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a vulnerability report
        
        Args:
            title: Short descriptive title
            vulnerability_type: XSS, SQLi, CSRF, etc.
            severity: Critical, High, Medium, Low, Info
            affected_url: The vulnerable endpoint
            description: Detailed description of the vulnerability
            reproduction_steps: Step-by-step reproduction guide
            impact: Business and technical impact assessment
            remediation: Recommended fixes
            owasp_category: OWASP Top 10 classification
            cve_references: Related CVE identifiers
            evidence: Screenshots, payloads, responses
        
        Returns:
            Path to generated report file
        """
        
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Severity must be one of {self.SEVERITY_LEVELS}")
        
        report_data = {
            "title": title,
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "affected_url": affected_url,
            "description": description,
            "reproduction_steps": reproduction_steps,
            "impact": impact,
            "remediation": remediation,
            "owasp_category": owasp_category,
            "cve_references": cve_references or [],
            "evidence": evidence or {},
            "timestamp": datetime.now().isoformat(),
            "tester": os.getenv("SECURITY_TESTER", "Security Team"),
        }
        
        # Generate markdown report
        md_report = self._generate_markdown(report_data)
        
        # Generate JSON report for parsing
        json_report = json.dumps(report_data, indent=2)
        
        # Save reports
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = title.replace(" ", "_").replace("/", "_")[:50]
        
        md_filename = f"{self.report_dir}/{timestamp}_{safe_title}.md"
        json_filename = f"{self.report_dir}/{timestamp}_{safe_title}.json"
        
        with open(md_filename, "w") as f:
            f.write(md_report)
        
        with open(json_filename, "w") as f:
            f.write(json_report)
        
        print(f"✓ Report generated: {md_filename}")
        print(f"✓ JSON data saved: {json_filename}")
        
        return md_filename
    
    def _generate_markdown(self, data: Dict[str, Any]) -> str:
        """Generate markdown formatted report"""
        
        template_str = """# Vulnerability Report: {{ title }}

## Summary
- **Vulnerability Type:** {{ vulnerability_type }}
- **Severity:** {{ severity }}
- **Affected URL:** {{ affected_url }}
- **Discovery Date:** {{ timestamp.split('T')[0] }}
- **Tested By:** {{ tester }}
{% if owasp_category %}
- **OWASP Category:** {{ owasp_category }}
{% endif %}

## Description
{{ description }}

## Reproduction Steps
{% for step in reproduction_steps %}
{{ loop.index }}. {{ step }}
{% endfor %}

## Impact Assessment
{{ impact }}

## Remediation Recommendations
{{ remediation }}

{% if cve_references %}
## Related CVE References
{% for cve in cve_references %}
- {{ cve }}
{% endfor %}
{% endif %}

{% if evidence %}
## Evidence
```json
{{ evidence | tojson(indent=2) }}
```
{% endif %}

---
**Report Generated:** {{ timestamp }}
**Target:** {{ target_url | default('https://example.com', true) }}
**Authorization:** Ethical security testing with proper authorization
"""
        
        template = Template(template_str)
        return template.render(**data)


# Example usage
if __name__ == "__main__":
    reporter = VulnerabilityReport()
    
    # Example report
    reporter.create_report(
        title="Reflected XSS in Search Parameter",
        vulnerability_type="Cross-Site Scripting (XSS)",
        severity="High",
        affected_url="https://example.com/catalog/?q=<payload>",
        description="The search functionality does not properly sanitize user input, allowing attackers to inject malicious JavaScript code that executes in the victim's browser context.",
        reproduction_steps=[
            "Navigate to https://example.com/catalog/",
            "Enter the payload: <script>alert('XSS')</script> in the search box",
            "Submit the search query",
            "Observe that the script executes in the browser"
        ],
        impact="An attacker could steal session cookies, perform actions on behalf of the user, or redirect users to malicious sites. This could lead to account compromise and data theft.",
        remediation="""
1. Implement proper output encoding for all user-supplied data
2. Use Content Security Policy (CSP) headers to prevent inline script execution
3. Validate and sanitize all input on the server side
4. Consider using a web application firewall (WAF)
5. Implement the X-XSS-Protection header
        """,
        owasp_category="A03:2021-Injection",
        cve_references=["CVE-2023-XXXXX"],
        evidence={
            "payload": "<script>alert('XSS')</script>",
            "response_excerpt": "Search results for <script>alert('XSS')</script>",
            "headers": {
                "X-XSS-Protection": "Not Present",
                "Content-Security-Policy": "Not Present"
            }
        }
    )
