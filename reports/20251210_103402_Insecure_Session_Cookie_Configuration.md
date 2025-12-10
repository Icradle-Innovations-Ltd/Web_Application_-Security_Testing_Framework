# Vulnerability Report: Insecure Session Cookie Configuration

## Summary
- **Vulnerability Type:** Session Management
- **Severity:** High
- **Affected URL:** https://www.jumia.ug/
- **Discovery Date:** 2025-12-10
- **Tested By:** Security Team

- **OWASP Category:** A07:2021-Identification and Authentication Failures


## Description
The session cookie SOLSESSID lacks critical security flags (Secure, HttpOnly, SameSite), making it vulnerable to interception, XSS attacks, and CSRF attacks. This cookie is used for session management and authentication state.

## Reproduction Steps

1. Navigate to https://www.jumia.ug/

2. Inspect HTTP response headers and cookies

3. Observe that SOLSESSID cookie lacks Secure, HttpOnly, and SameSite attributes

4. Verify cookie can be transmitted over HTTP and accessed via JavaScript


## Impact Assessment
HIGH: An attacker could steal session cookies through XSS attacks (missing HttpOnly), intercept cookies over insecure connections (missing Secure flag), or perform CSRF attacks (missing SameSite). This could lead to account takeover, unauthorized transactions, and data theft.

## Remediation Recommendations

1. Add Secure flag: Set-Cookie: SOLSESSID=...; Secure
2. Add HttpOnly flag: Set-Cookie: SOLSESSID=...; HttpOnly
3. Add SameSite attribute: Set-Cookie: SOLSESSID=...; SameSite=Strict
4. Example secure cookie: Set-Cookie: SOLSESSID=value; Secure; HttpOnly; SameSite=Strict; Path=/

Implementation in common frameworks:
- PHP: session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict'])
- Node.js: res.cookie('SOLSESSID', value, {secure: true, httpOnly: true, sameSite: 'strict'})
- Django: SESSION_COOKIE_SECURE = True, SESSION_COOKIE_HTTPONLY = True, SESSION_COOKIE_SAMESITE = 'Strict'
    




## Evidence
```json
{
  "cookie_name": "SOLSESSID",
  "headers_analyzed": "Set-Cookie headers from https://www.jumia.ug/",
  "missing_flags": [
    "Secure",
    "HttpOnly",
    "SameSite"
  ],
  "test_date": "2025-12-10"
}
```


---
**Report Generated:** 2025-12-10T10:34:02.932534
**Target:** https://www.jumia.ug/
**Authorization:** Ethical security testing with proper authorization