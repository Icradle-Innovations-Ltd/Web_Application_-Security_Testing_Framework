# Web Application Security Testing Framework - AI Agent Instructions

## Project Purpose
This is a security testing framework for identifying vulnerabilities in web applications. The codebase contains security testing scripts, exploit proofs-of-concept, and vulnerability documentation.

## Security-First Development Workflow

### Code Generation & Security Scanning
1. **Always scan new code**: Run Snyk code scan on all newly generated first-party code in supported languages
2. **Fix-scan cycle**: After fixing security issues, rescan to verify fixes and check for new issues
3. **Iterate until clean**: Repeat the fix-scan process until no security issues remain

### Testing Approach
When creating security tests:
- **OWASP Top 10 2021 Coverage**:
  - A01: Broken Access Control (IDOR, privilege escalation)
  - A02: Cryptographic Failures (TLS, encryption)
  - A03: Injection (SQL, XSS, command, SSRF)
  - A04: Insecure Design (business logic flaws)
  - A05: Security Misconfiguration (CORS, headers, CSP)
  - A06: Vulnerable Components (dependency scanning)
  - A07: Authentication Failures (session, MFA)
  - A08: Data Integrity Failures (deserialization)
  - A09: Logging Failures (monitoring coverage)
  - A10: SSRF (server-side request forgery)
- **Additional Test Categories**:
  - File upload vulnerabilities (XXE, polyglot files)
  - API security (REST/GraphQL injection, mass assignment)
  - Client-side attacks (clickjacking, DOM clobbering, prototype pollution)
  - Business logic (payment bypass, race conditions, discount abuse)
- Create separate test files organized by vulnerability type
- Include both positive (exploit detection) and negative (false positive) test cases
- Document expected vs actual behavior for each test
- Use `@pytest.mark.skip()` for tests requiring authentication

## File Organization Patterns

```
.
├── .github/
│   └── instructions/          # AI agent-specific rules
│       └── snyk_rules.instructions.md  # Security scanning rules
├── tests/                     # Security test suites
│   ├── xss/                  # Cross-site scripting tests
│   ├── sqli/                 # SQL injection tests
│   ├── auth/                 # Authentication/authorization tests
│   ├── access_control/       # IDOR & access control tests
│   ├── file_upload/          # File upload vulnerability tests
│   ├── api_security/         # REST/GraphQL API security tests
│   ├── business_logic/       # Business logic & workflow tests
│   ├── injection/            # SSRF, command injection, SSTI tests
│   └── client_side/          # CORS, clickjacking, XSS tests
├── exploits/                  # PoC exploits (ethical testing only)
├── reports/                   # Vulnerability reports and findings
└── tools/                     # Custom security testing tools
```

## Key Conventions

### Test File Naming
- Use descriptive names: `test_<vulnerability_type>_<specific_case>.py`
- Example: `test_xss_reflected_search_param.py`

### Security Testing Ethics
- **CRITICAL**: All tests must be authorized and ethical
- Document test scope and authorization in each test file header
- Never commit actual credentials or sensitive data
- Use environment variables for target URLs and test credentials

### Documentation Requirements
For each vulnerability found:
1. Create a report in `reports/` with timestamp and severity
2. Include: vulnerability type, affected endpoint, reproduction steps, impact assessment
3. Provide remediation recommendations
4. Reference OWASP/CVE standards where applicable

## Common Commands

```bash
# Run all security tests
python run_tests.py all

# Run specific vulnerability categories
python run_tests.py xss           # XSS tests only
python run_tests.py sqli          # SQL injection tests
python run_tests.py auth          # Authentication tests
python run_tests.py access        # Access control & IDOR tests
python run_tests.py upload        # File upload tests
python run_tests.py api           # API security tests
python run_tests.py logic         # Business logic tests
python run_tests.py injection     # SSRF/command injection tests
python run_tests.py client        # Client-side security tests

# Run with HTML report
python run_tests.py all --html

# Generate vulnerability reports
python generate_reports.py

# View project summary
python show_summary.py

# Snyk security scan (via Copilot instructions)
# This is triggered automatically for new code
```

## Dependencies & Tools
When adding testing dependencies, prioritize:
- `pytest` for test framework
- `requests` for HTTP testing
- Security-focused libraries: `BeautifulSoup4`, `selenium`, `sqlmap` integration
- Reporting: `jinja2` for report generation

## Important Notes
- This project exists in `.github/instructions/snyk_rules.instructions.md` which enforces automatic security scanning
- All code changes trigger Snyk scans automatically
- Test against staging/authorized environments only
- Maintain responsible disclosure practices for any findings
