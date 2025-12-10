# Web Application Security Tests - Quick Start Guide

## Initial Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

## Running Tests

### Run all tests
```bash
pytest tests/ -v
```

### Run specific vulnerability tests
```bash
# XSS tests only
pytest tests/xss/ -v

# SQL injection tests only
pytest tests/sqli/ -v

# Authentication tests only
pytest tests/auth/ -v
```

### Generate HTML report
```bash
pytest tests/ --html=reports/test_report.html --self-contained-html
```

### Run with coverage
```bash
pytest tests/ --cov=tests --cov-report=html
```

## Creating Vulnerability Reports

```python
from tools.report_generator import VulnerabilityReport

reporter = VulnerabilityReport()
reporter.create_report(
    title="XSS in Search",
    vulnerability_type="XSS",
    severity="High",
    affected_url="https://example.com/search?q=test",
    description="Reflected XSS vulnerability...",
    reproduction_steps=["Step 1", "Step 2"],
    impact="User account compromise possible",
    remediation="Implement input sanitization",
    owasp_category="A03:2021-Injection"
)
```

## Project Structure
```
.
├── tests/              # All security tests
│   ├── xss/           # Cross-site scripting
│   ├── sqli/          # SQL injection
│   ├── auth/          # Authentication tests
│   ├── csrf/          # CSRF tests
│   ├── idor/          # Insecure Direct Object Reference
│   └── config/        # Security configuration tests
├── tools/             # Utility scripts
│   └── report_generator.py
├── reports/           # Generated vulnerability reports
├── exploits/          # PoC exploits (ethical use only)
└── .github/
    ├── copilot-instructions.md
    └── instructions/
        └── snyk_rules.instructions.md
```

## Important Reminders

⚠️ **ETHICAL TESTING ONLY**
- Only test with proper authorization
- Do not commit real credentials
- Follow responsible disclosure

🔒 **SECURITY**
- All new code is automatically scanned by Snyk
- Fix security issues before committing
- Never commit sensitive data or findings

📝 **DOCUMENTATION**
- Document all findings in `reports/`
- Include reproduction steps
- Reference OWASP/CVE standards
