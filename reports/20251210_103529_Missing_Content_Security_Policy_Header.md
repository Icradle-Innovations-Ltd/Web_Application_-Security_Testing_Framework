# Vulnerability Report: Missing Content Security Policy Header

## Summary
- **Vulnerability Type:** Security Misconfiguration
- **Severity:** Medium
- **Affected URL:** https://www.jumia.ug/
- **Discovery Date:** 2025-12-10
- **Tested By:** Security Team

- **OWASP Category:** A05:2021-Security Misconfiguration


## Description
The application does not implement a Content Security Policy (CSP) header, leaving it vulnerable to XSS and data injection attacks.

## Reproduction Steps

1. Send HTTP request to https://www.jumia.ug/

2. Inspect response headers

3. Verify absence of Content-Security-Policy header


## Impact Assessment
MEDIUM: Without CSP, the application has reduced defense against XSS attacks. Attackers who find XSS vulnerabilities can more easily execute malicious scripts and exfiltrate data.

## Remediation Recommendations
Implement Content Security Policy header:

Recommended (strict):
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'

Progressive implementation:
1. Start with report-only mode: Content-Security-Policy-Report-Only
2. Monitor violations and adjust policy
3. Switch to enforcement mode
4. Remove 'unsafe-inline' where possible




## Evidence
```json
{
  "header": "Content-Security-Policy",
  "status": "Not Present"
}
```


---
**Report Generated:** 2025-12-10T10:35:29.339538
**Target:** https://www.jumia.ug/
**Authorization:** Ethical security testing with proper authorization