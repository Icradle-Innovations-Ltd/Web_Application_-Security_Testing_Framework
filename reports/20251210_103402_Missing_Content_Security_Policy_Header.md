# Vulnerability Report: Missing Content Security Policy Header

## Summary
- **Vulnerability Type:** Security Misconfiguration
- **Severity:** Medium
- **Affected URL:** https://www.jumia.ug/
- **Discovery Date:** 2025-12-10
- **Tested By:** Security Team

- **OWASP Category:** A05:2021-Security Misconfiguration


## Description
The application does not implement a Content Security Policy (CSP) header, leaving it vulnerable to cross-site scripting (XSS) and data injection attacks. CSP provides an additional layer of defense against XSS by restricting sources of executable scripts.

## Reproduction Steps

1. Send HTTP request to https://www.jumia.ug/

2. Inspect response headers

3. Verify absence of Content-Security-Policy header

4. Confirm that inline scripts and external resources load without CSP restrictions


## Impact Assessment
MEDIUM: Without CSP, the application has reduced defense against XSS attacks. Attackers who find XSS vulnerabilities can more easily execute malicious scripts, load external resources, and exfiltrate data. This increases the attack surface significantly.

## Remediation Recommendations

Implement a Content Security Policy header with appropriate directives:

Recommended CSP (strict):
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

Progressive implementation:
1. Start with report-only mode to test: Content-Security-Policy-Report-Only: ...
2. Monitor CSP violation reports
3. Adjust policy based on legitimate violations
4. Switch to enforcement mode
5. Remove 'unsafe-inline' and 'unsafe-eval' where possible

Additional recommendations:
- Include nonce or hash for inline scripts instead of 'unsafe-inline'
- Use strict-dynamic for modern browsers
- Implement CSP reporting endpoint to monitor violations
    




## Evidence
```json
{
  "alternative_checked": "Content-Security-Policy-Report-Only",
  "alternative_status": "Not Present",
  "header_checked": "Content-Security-Policy",
  "status": "Not Present",
  "test_date": "2025-12-10"
}
```


---
**Report Generated:** 2025-12-10T10:34:02.946137
**Target:** https://www.jumia.ug/
**Authorization:** Ethical security testing with proper authorization