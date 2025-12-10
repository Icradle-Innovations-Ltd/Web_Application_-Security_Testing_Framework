# 🔒 Web Application Security Testing Framework

> **Comprehensive security vulnerability assessment toolkit for web applications**

[![Tests](https://img.shields.io/badge/tests-98%20total-blue)](tests/)
[![Coverage](https://img.shields.io/badge/OWASP%20Top%2010-100%25-green)](https://owasp.org/Top10/)
[![Python](https://img.shields.io/badge/python-3.13.5-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Ethical%20Testing-orange)](LICENSE)

---

## ⚠️ IMPORTANT LEGAL DISCLAIMER

**READ THIS BEFORE USING THIS SOFTWARE**

This security testing framework is provided **FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH PURPOSES ONLY**.

### 🚨 Legal Warnings

**UNAUTHORIZED USE IS ILLEGAL AND MAY RESULT IN:**
- **Criminal prosecution** under Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and similar laws worldwide
- **Civil liability** and monetary damages
- **Prison sentences** of up to 10+ years depending on jurisdiction
- **Permanent criminal record** affecting employment and travel

### ✅ Authorized Use Requirements

You may ONLY use this software if:
- [ ] You **OWN** the target system/website, OR
- [ ] You have **EXPLICIT WRITTEN PERMISSION** from the system owner, OR
- [ ] You are conducting **AUTHORIZED PENETRATION TESTING** with a signed contract

### ⛔ Prohibited Activities

**DO NOT:**
- ❌ Test websites or systems you do not own without written authorization
- ❌ Use discovered vulnerabilities for malicious purposes
- ❌ Access, modify, or delete data you are not authorized to access
- ❌ Perform denial-of-service attacks or disrupt services
- ❌ Share or weaponize discovered vulnerabilities before vendor notification
- ❌ Commit real credentials, API keys, or sensitive data to version control

### 🛡️ Ethical Guidelines

**ALWAYS:**
- ✅ Obtain written authorization before testing
- ✅ Define clear scope and boundaries for testing
- ✅ Use test accounts only (never real user data)
- ✅ Report vulnerabilities responsibly to vendors first
- ✅ Follow coordinated disclosure timelines (typically 90 days)
- ✅ Respect data privacy laws (GDPR, CCPA, etc.)
- ✅ Document all testing activities and findings

### 📋 Pre-Testing Checklist

Before running any tests, ensure:
- [ ] Written authorization obtained and documented
- [ ] Testing scope clearly defined in writing
- [ ] Test credentials created (NOT real user accounts)
- [ ] Legal counsel consulted if needed
- [ ] Responsible disclosure plan in place
- [ ] No intention to cause harm or disruption

### ⚖️ Liability Waiver

**BY USING THIS SOFTWARE, YOU ACKNOWLEDGE:**
1. You are solely responsible for ensuring all testing is legal and authorized
2. The authors/contributors assume NO LIABILITY for misuse
3. You will indemnify and hold harmless the authors for any damages
4. You understand the legal and ethical implications
5. You will comply with all applicable laws and regulations

### 🔒 Data Protection & Privacy

- **NEVER** extract or store real user data
- **NEVER** commit credentials, tokens, or API keys
- **ALWAYS** sanitize findings before sharing
- **ALWAYS** follow data protection regulations
- Use `.env` files for configuration (excluded from git)

---

**IF YOU DO NOT HAVE AUTHORIZATION, DO NOT USE THIS SOFTWARE.**  
**UNAUTHORIZED SECURITY TESTING IS A CRIME.**

---

## 📊 Quick Status

**Last Updated:** December 10, 2025  
**Test Status:** ✅ Fully Operational  
**Total Tests:** 98 security tests across 9 categories  
**Test Results:** 17 passed • 49 failed • 32 skipped

### 🎯 Test Coverage by Category

| Category | Tests | Status | Description |
|----------|-------|--------|-------------|
| **XSS** | 8 | ✅ All Passed | Cross-site scripting vulnerabilities |
| **SQL Injection** | 8 | ✅ All Passed | Database injection attacks |
| **Authentication** | 14 | ⚠️ 4 Passed, 10 Skipped | Session & auth security |
| **Access Control** | 12 | 🔍 Testing | IDOR & privilege escalation |
| **API Security** | 12 | 🔍 Testing | REST/GraphQL vulnerabilities |
| **Business Logic** | 15 | 🔍 Testing | Payment & workflow flaws |
| **Injection** | 14 | 🔍 Testing | SSRF, command injection, SSTI |
| **Client-Side** | 14 | 🔍 Testing | CORS, clickjacking, XSS |
| **File Upload** | 0* | 📝 Pending | *Tests created but not collected |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.13+ installed
- Virtual environment (recommended)
- Internet connection for testing against target

### Installation

```bash
# 1. Clone/navigate to project directory
cd securitytests

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Configure environment (optional)
cp .env.example .env
# Edit .env with your settings
```

### Running Tests

```bash
# Run all security tests
python run_tests.py all

# Run specific categories
python run_tests.py xss           # XSS tests
python run_tests.py sqli          # SQL injection tests
python run_tests.py auth          # Authentication tests
python run_tests.py access        # Access control & IDOR tests
python run_tests.py api           # API security tests
python run_tests.py logic         # Business logic tests
python run_tests.py injection     # SSRF/command injection tests
python run_tests.py client        # Client-side security tests

# Generate HTML report
python run_tests.py all --html

# View test summary
python test_summary.py
```

---

## 🔍 Security Test Categories

---

## 🔍 Security Test Categories

### 1️⃣ Cross-Site Scripting (XSS)

**OWASP:** A03:2021 - Injection  
**Tests:** 8  
**File:** `tests/xss/test_xss_reflected.py`

#### What We Test
- **Reflected XSS** - Malicious scripts reflected in search/URL parameters
- **Stored XSS** - Persistent XSS in user profiles and reviews
- **DOM-based XSS** - Client-side DOM manipulation attacks
- **Filter Bypass** - Attempting to bypass XSS sanitization
- **CSP Validation** - Content Security Policy header checks
- **XSS Protection Headers** - X-XSS-Protection header validation

#### Why It Matters
XSS allows attackers to:
- Steal user session cookies and credentials
- Deface websites and spread malware
- Redirect users to phishing sites
- Perform actions on behalf of victims

#### How Tests Work
```python
# Example: Testing search parameter XSS
payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')"
]

for payload in payloads:
    response = session.get(f"{target_url}/search", params={"q": payload})
    # Check if payload is reflected without sanitization
    assert payload not in response.text
```

#### When to Run
- **Before deployment** - Check all user input fields
- **After code changes** - Validate input sanitization
- **Regular audits** - Monthly security scans

---

### 2️⃣ SQL Injection

**OWASP:** A03:2021 - Injection  
**Tests:** 8  
**File:** `tests/sqli/test_sqli_basic.py`

#### What We Test
- **Error-based SQLi** - Database errors revealing structure
- **Time-based Blind SQLi** - Timing attacks to extract data
- **Union-based SQLi** - Combining queries to extract data
- **Authentication Bypass** - SQLi in login forms
- **Parameter Testing** - Search, product IDs, category filters

#### Why It Matters
SQL injection enables attackers to:
- Extract entire databases (customer data, passwords)
- Modify or delete data
- Bypass authentication
- Execute administrative operations
- Take complete control of the database server

#### How Tests Work
```python
# Example: Time-based blind SQL injection
payload = "1' AND SLEEP(5)--"
start = time.time()
response = session.get(f"{target_url}/product/{payload}")
elapsed = time.time() - start

# If response delayed, SQLi vulnerability exists
if elapsed > 5:
    print("⚠️ Time-based SQLi vulnerability found!")
```

#### When to Run
- **Critical:** Before any database-related code deployment
- **High priority:** After modifying query logic
- **Regular:** Weekly automated scans

---

### 3️⃣ Authentication & Session Security

**OWASP:** A07:2021 - Identification and Authentication Failures  
**Tests:** 14  
**File:** `tests/auth/test_auth_security.py`

#### What We Test
- **Session Cookie Security** - Secure, HttpOnly, SameSite flags
- **Session Timeout** - Automatic logout after inactivity
- **Session Fixation** - Session ID regeneration on login
- **Password Security** - Complexity requirements, encryption in transit
- **HTTPS Enforcement** - TLS/SSL configuration
- **Brute Force Protection** - Rate limiting on login attempts
- **Account Enumeration** - Username/email disclosure prevention
- **MFA Bypass** - Multi-factor authentication vulnerabilities
- **OAuth Security** - Third-party authentication providers

#### Why It Matters
Weak authentication allows:
- Account takeover and identity theft
- Unauthorized access to sensitive data
- Session hijacking attacks
- Credential stuffing attacks

#### How Tests Work
```python
# Example: Session cookie security validation
response = session.get(target_url)
for cookie in response.cookies:
    if 'session' in cookie.name.lower():
        assert cookie.secure, "Missing Secure flag"
        assert cookie.has_nonstandard_attr('HttpOnly'), "Missing HttpOnly"
        assert cookie.has_nonstandard_attr('SameSite'), "Missing SameSite"
```

#### When to Run
- **Before launch:** Validate all auth mechanisms
- **After updates:** When changing auth/session logic
- **Continuous:** Daily automated checks

---

### 4️⃣ Access Control & IDOR

**OWASP:** A01:2021 - Broken Access Control  
**Tests:** 12  
**File:** `tests/access_control/test_idor.py`

#### What We Test
- **IDOR (Insecure Direct Object References)**
  - Product ID enumeration
  - User profile access without authorization
  - Order ID manipulation
- **Privilege Escalation**
  - Horizontal (accessing other users' data)
  - Vertical (accessing admin functions)
- **Access Control Bypass**
  - Direct API access without auth
  - HTTP verb tampering (GET → POST)
  - Path traversal in URLs
  - Parameter pollution
- **Forced Browsing**
  - Hidden admin paths
  - Backup file exposure
  - Directory listing

#### Why It Matters
Access control flaws enable:
- Viewing/modifying other users' accounts
- Accessing administrative functions
- Reading sensitive business data
- Price manipulation in e-commerce

#### How Tests Work
```python
# Example: Testing IDOR on user profiles
user_ids = [1, 2, 100, 999, 1337]
for user_id in user_ids:
    response = session.get(f"{target_url}/api/user/{user_id}")
    # Should return 403 Forbidden for other users' profiles
    if response.status_code == 200:
        print(f"⚠️ IDOR vulnerability: Can access user {user_id}")
```

#### When to Run
- **Critical:** Before deploying new API endpoints
- **Important:** After changing authorization logic
- **Regular:** Bi-weekly security audits

---

### 5️⃣ API Security

**OWASP:** A01:2021 - Broken Access Control, A03:2021 - Injection  
**Tests:** 12  
**File:** `tests/api_security/test_api_security.py`

#### What We Test
- **REST API Security**
  - Endpoint discovery & documentation exposure
  - Authentication bypass
  - Rate limiting enforcement
  - HTTP method override attacks
  - Excessive data exposure
- **GraphQL Security**
  - Introspection queries (schema exposure)
  - Batching attacks (query abuse)
  - Depth limit bypass (nested queries)
- **Mass Assignment**
  - User role manipulation
  - Price manipulation via API
- **API Injection**
  - JSON injection attacks
  - NoSQL injection

#### Why It Matters
API vulnerabilities allow:
- Bypassing rate limits for scraping
- Accessing unauthorized endpoints
- Modifying prices or user roles
- Extracting sensitive data in bulk
- Overloading servers with complex queries

#### How Tests Work
```python
# Example: GraphQL introspection testing
introspection_query = """
{
  __schema {
    types { name fields { name } }
  }
}
"""
response = session.post(f"{target_url}/graphql", json={"query": introspection_query})

# Introspection should be disabled in production
if "__schema" in response.text:
    print("⚠️ GraphQL introspection enabled - schema exposed!")
```

#### When to Run
- **Essential:** Before releasing new API versions
- **Regular:** After API endpoint changes
- **Continuous:** Automated API security scanning

---

### 6️⃣ Business Logic Vulnerabilities

**OWASP:** A04:2021 - Insecure Design  
**Tests:** 15  
**File:** `tests/business_logic/test_business_logic.py`

#### What We Test
- **Payment Logic**
  - Negative price manipulation
  - Price manipulation via race conditions
  - Coupon reuse and stacking
  - Discount abuse
- **Cart Manipulation**
  - Quantity overflow (negative/excessive quantities)
  - Price manipulation in cart
  - Concurrent cart operations (race conditions)
- **Workflow Bypass**
  - Checkout step skipping
  - Payment bypass
  - Order status manipulation
- **Rate Limit Bypass**
  - Account enumeration
  - Registration spam
  - API abuse prevention
- **Session Manipulation**
  - Session fixation attacks
  - Concurrent session abuse

#### Why It Matters
Business logic flaws can:
- Allow free purchases or discounted prices
- Enable unlimited coupon usage
- Bypass payment entirely
- Create fraudulent orders
- Abuse promotional offers

#### How Tests Work
```python
# Example: Testing negative quantity in cart
cart_payload = {
    "cartItem": {
        "sku": "product-123",
        "qty": -5  # Negative quantity
    }
}
response = session.post(f"{target_url}/cart/add", json=cart_payload)

# Should reject negative quantities
assert response.status_code != 200, "Negative quantity accepted!"
```

#### When to Run
- **Critical:** Before checkout/payment feature releases
- **High priority:** After pricing logic changes
- **Regular:** Weekly business logic audits

---

### 7️⃣ Injection Attacks

**OWASP:** A03:2021 - Injection, A10:2021 - Server-Side Request Forgery  
**Tests:** 14  
**File:** `tests/injection/test_injection.py`

#### What We Test
- **SSRF (Server-Side Request Forgery)**
  - URL parameter SSRF
  - File upload SSRF
  - Webhook SSRF
  - DNS rebinding attacks
- **Command Injection**
  - Search parameter injection
  - Export function injection
- **Template Injection (SSTI)**
  - Search template injection
  - Error page template injection
- **LDAP Injection**
  - Login form LDAP injection
- **XPath Injection**
  - Search XPath injection
- **Code Injection**
  - PHP code injection
  - Expression language injection
- **Deserialization Attacks**
  - Java deserialization
  - Python pickle deserialization

#### Why It Matters
Injection attacks enable:
- Remote code execution on servers
- Internal network access (SSRF)
- Data exfiltration
- Complete server compromise
- Cloud metadata access (AWS/Azure credentials)

#### How Tests Work
```python
# Example: SSRF testing via URL parameter
ssrf_payloads = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://localhost:22",  # Internal services
    "file:///etc/passwd"  # Local file access
]

for payload in ssrf_payloads:
    response = session.get(f"{target_url}/fetch", params={"url": payload})
    if response.status_code == 200 and len(response.content) > 0:
        print(f"⚠️ SSRF vulnerability found: {payload}")
```

#### When to Run
- **Critical:** Before any URL/file handling features
- **Important:** After adding external integrations
- **Regular:** Monthly SSRF and injection scans

---

### 8️⃣ Client-Side Security

**OWASP:** A05:2021 - Security Misconfiguration  
**Tests:** 14  
**File:** `tests/client_side/test_client_side.py`

#### What We Test
- **CORS Misconfiguration**
  - Wildcard origin acceptance
  - Null origin bypass
  - Subdomain bypass
  - API endpoint CORS
- **Clickjacking Protection**
  - X-Frame-Options header
  - Frame-ancestors CSP directive
- **Open Redirect**
  - Redirect parameter manipulation
  - Bypass techniques
- **DOM Clobbering**
  - Vulnerable DOM code
- **Prototype Pollution**
  - Query parameter pollution
- **Mixed Content**
  - HTTPS page loading HTTP resources
- **Subresource Integrity (SRI)**
  - External script integrity checks
- **Referrer Policy**
  - Referrer header leakage
- **WebSocket Security**
  - Origin validation
  - Authentication requirements

#### Why It Matters
Client-side vulnerabilities allow:
- Cross-origin data theft (CORS)
- UI redressing attacks (clickjacking)
- Phishing via open redirects
- Session token leakage
- Man-in-the-middle attacks (mixed content)

#### How Tests Work
```python
# Example: CORS misconfiguration testing
headers = {"Origin": "https://evil.com"}
response = session.get(f"{target_url}/api/data", headers=headers)

# Should NOT allow arbitrary origins
cors_header = response.headers.get("Access-Control-Allow-Origin")
if cors_header == "*" or cors_header == "https://evil.com":
    print("⚠️ CORS misconfiguration: Allows arbitrary origins!")
```

#### When to Run
- **Before launch:** Validate all security headers
- **After changes:** When modifying CORS/CSP policies
- **Regular:** Weekly header audits

---

### 9️⃣ File Upload Security

**OWASP:** A03:2021 - Injection, A04:2021 - Insecure Design  
**Tests:** 14 (created, not yet collected)  
**File:** `tests/file_upload/test_file_upload.py` (pending)

#### What We Test
- **Unrestricted File Upload**
  - Executable file upload (PHP, JSP, ASP)
  - Extension validation bypass
- **File Type Validation**
  - MIME type spoofing
  - Magic byte manipulation
- **Malicious Files**
  - Polyglot files (JPG+PHP)
  - ZIP slip attacks
  - Archive bombs (zip bombs)
- **Image Upload Security**
  - SVG XSS attacks
  - EXIF data injection
- **XXE (XML External Entity)**
  - SVG XXE attacks
  - Document XXE (DOCX, XLSX)

#### Why It Matters
File upload vulnerabilities enable:
- Remote code execution (webshell upload)
- Stored XSS via SVG files
- Server-side file system access (XXE)
- Denial of service (zip bombs)
- Data exfiltration

#### When to Run
- **Critical:** Before enabling file upload features
- **Essential:** After modifying upload validation
- **Regular:** Bi-weekly file upload audits

---

## 📁 Project Structure

```
securitytests/
├── .github/
│   ├── copilot-instructions.md       # AI agent guidance
│   └── instructions/
│       └── snyk_rules.instructions.md # Auto-security scanning
│
├── tests/                             # Security test suites
│   ├── xss/
│   │   └── test_xss_reflected.py     # XSS vulnerability tests
│   ├── sqli/
│   │   └── test_sqli_basic.py        # SQL injection tests
│   ├── auth/
│   │   └── test_auth_security.py     # Authentication tests
│   ├── access_control/
│   │   └── test_idor.py              # IDOR & access control
│   ├── api_security/
│   │   └── test_api_security.py      # API security tests
│   ├── business_logic/
│   │   └── test_business_logic.py    # Business logic flaws
│   ├── injection/
│   │   └── test_injection.py         # SSRF, command injection
│   ├── client_side/
│   │   └── test_client_side.py       # CORS, clickjacking, etc.
│   ├── file_upload/
│   │   └── __init__.py               # File upload tests (pending)
│   ├── conftest.py                   # Pytest fixtures
│   └── config.py                     # Test configuration
│
├── tools/
│   ├── report_generator.py           # Vulnerability report generator
│   └── test_summary.py               # Test analysis utility
│
├── reports/                           # Generated vulnerability reports
│   └── README.md
│
├── exploits/                          # PoC exploits (ethical only)
├── logs/                              # Test execution logs
│
├── run_tests.py                       # Main test runner
├── test_summary.py                    # Quick test summary
├── generate_reports.py                # Report generation
├── show_summary.py                    # Display test results
│
├── requirements.txt                   # Python dependencies
├── pytest.ini                         # Pytest configuration
├── .env.example                       # Environment template
├── .gitignore                         # Git ignore rules
└── README.md                          # This file
```

---

## 🛠️ Configuration

### Environment Variables

Create a `.env` file from `.env.example`:

```bash
# Target Configuration
# Replace with your authorized target URL
TARGET_URL=https://example.com

# Test Credentials (NEVER use real credentials)
TEST_USERNAME=testuser@example.com
TEST_PASSWORD=TestPassword123!
TEST_EMAIL=testuser@example.com

# Proxy Configuration (optional)
HTTP_PROXY=http://127.0.0.1:8080
HTTPS_PROXY=http://127.0.0.1:8080

# Request Settings
REQUEST_TIMEOUT=30
MAX_RETRIES=3

# Test Behavior
VERBOSE_OUTPUT=true
STOP_ON_FIRST_FAILURE=false
```

### Pytest Configuration

Edit `pytest.ini` for custom test behavior:

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short --strict-markers
markers =
    skip: Skip this test
    slow: Slow running tests
    requires_auth: Tests requiring authentication
```

---

## 📊 Test Results & Reporting

### Viewing Results

```bash
# Console output (real-time)
python run_tests.py all

# HTML report (detailed)
python run_tests.py all --html
# Opens: htmlcov/index.html

# Generate vulnerability reports
python generate_reports.py

# Quick summary
python test_summary.py
```

### Report Types

1. **Console Output** - Real-time test results
2. **HTML Report** - Comprehensive test coverage
3. **Vulnerability Reports** - Professional security findings
4. **Executive Summary** - High-level overview for stakeholders

### Sample Output

```
🔍 Running All Security Tests...

✅ XSS Tests (8/8 passed)
  ✓ test_search_parameter_xss
  ✓ test_url_parameter_xss
  ✓ test_hash_fragment_xss
  ✓ test_filter_bypass_attempts
  ✓ test_content_security_policy
  ✓ test_x_xss_protection_header

✅ SQL Injection Tests (8/8 passed)
  ✓ test_search_parameter_sqli
  ✓ test_product_id_sqli
  ✓ test_time_based_sqli_search
  ✓ test_union_select_detection

⚠️ Authentication Tests (4/14 passed, 10 skipped)
  ❌ test_session_cookie_security
  ⏭️ test_session_timeout (requires auth)
  ✓ test_https_enforcement
  ✓ test_ssl_tls_configuration

📊 Results: 17 passed, 1 failed, 32 skipped in 127.98s
```

---

## 🔒 Security & Ethics

### ⚠️ CRITICAL WARNINGS

1. **Authorization Required**
   - Only test systems you own or have explicit written permission to test
   - Unauthorized security testing is ILLEGAL

2. **No Real Credentials**
   - Never use real user credentials in tests
   - Never commit credentials to version control

3. **Data Protection**
   - Do not extract or store actual user data
   - Sanitize all findings before sharing

4. **Responsible Disclosure**
   - Report vulnerabilities to the vendor first
   - Follow responsible disclosure timelines
   - Do not publicly disclose zero-days

### Ethical Testing Checklist

- [ ] Written authorization obtained
- [ ] Testing scope clearly defined
- [ ] Test accounts created (not real users)
- [ ] Results will be responsibly disclosed
- [ ] No malicious intent or damage

---

## 🚨 Known Issues & Vulnerabilities

### Current Vulnerabilities Found

1. **Session Cookie Security (HIGH)**
   - Missing `Secure` flag
   - Missing `HttpOnly` flag  
   - Missing `SameSite` attribute
   - **Impact:** Session hijacking risk
   - **Status:** Reported to vendor

2. **Missing Security Headers (MEDIUM)**
   - No Content-Security-Policy
   - No Strict-Transport-Security
   - **Impact:** XSS and MITM risk
   - **Status:** Under review

3. **File Upload Tests Not Collected**
   - Test file missing from collection
   - **Impact:** 14 tests not running
   - **Status:** In progress

---

## 🔧 Troubleshooting

### Common Issues

**Tests not collecting:**
```bash
# Verify pytest finds all tests
pytest tests/ --collect-only -q
```

**Import errors:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

**Connection timeouts:**
```bash
# Increase timeout in .env
REQUEST_TIMEOUT=60
```

**Permission errors:**
```bash
# Check file permissions
chmod +x run_tests.py
```

---

## 📚 Resources

### OWASP Top 10 2025
- **A01** - Broken Access Control
- **A02** - Cryptographic Failures
- **A03** - Injection
- **A04** - Insecure Design
- **A05** - Security Misconfiguration
- **A06** - Vulnerable and Outdated Components
- **A07** - Identification and Authentication Failures
- **A08** - Software and Data Integrity Failures
- **A09** - Security Logging and Monitoring Failures
- **A10** - Server-Side Request Forgery (SSRF)

### Learning Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacker101](https://www.hacker101.com/)

### Tools Used
- **pytest** - Testing framework
- **requests** - HTTP library
- **selenium** - Browser automation
- **BeautifulSoup** - HTML parsing
- **Snyk** - Security scanning
- **websocket-client** - WebSocket testing
- **requests-toolbelt** - Advanced HTTP testing

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new vulnerabilities
4. Run Snyk scan: All code is auto-scanned
5. Submit pull request

---

## 📄 License

**Ethical Security Testing Only**

This software is provided for authorized security testing only. Unauthorized use is strictly prohibited and may violate laws including:
- Computer Fraud and Abuse Act (CFAA)
- Computer Misuse Act
- Local cybercrime legislation

---

## 📞 Contact

For security disclosures or questions:
- **Email:** icradleinnovations@gmail.com
- **PGP Key:** [Available on request]

---

**Last Updated:** December 10, 2025  
**Version:** 2.0  
**Maintainer:** Security Testing Team
