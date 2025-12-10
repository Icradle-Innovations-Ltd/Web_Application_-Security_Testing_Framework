# Vulnerability Report: Missing Strict-Transport-Security Header

## Summary
- **Vulnerability Type:** Security Misconfiguration
- **Severity:** Medium
- **Affected URL:** https://www.jumia.ug/
- **Discovery Date:** 2025-12-10
- **Tested By:** Security Team

- **OWASP Category:** A05:2021-Security Misconfiguration


## Description
The application does not send the HTTP Strict-Transport-Security (HSTS) header. While HTTPS is enforced via redirects, the lack of HSTS header leaves users vulnerable to SSL stripping attacks and allows browsers to initially connect over HTTP.

## Reproduction Steps

1. Send HTTPS request to https://www.jumia.ug/

2. Inspect response headers

3. Verify absence of Strict-Transport-Security header

4. Confirm that browser can initially connect over HTTP before redirect


## Impact Assessment
MEDIUM: Users are vulnerable to SSL stripping attacks on first visit or after HSTS max-age expires. Man-in-the-middle attackers can downgrade connections to HTTP before the redirect occurs, intercepting sensitive data. The initial HTTP request is vulnerable to interception.

## Remediation Recommendations

Implement HSTS header with appropriate max-age and directives:

Recommended HSTS header:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Configuration steps:
1. Add HSTS header to all HTTPS responses
2. Start with shorter max-age (e.g., 300 seconds) for testing
3. Gradually increase max-age to 31536000 (1 year)
4. Add includeSubDomains if all subdomains support HTTPS
5. Submit to HSTS preload list: https://hstspreload.org/

Server configuration examples:
- Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
- Apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
- Node.js (helmet): app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }))

Important: Ensure all resources (images, scripts, stylesheets) are available over HTTPS before implementing HSTS
    




## Evidence
```json
{
  "cipher": "TLS_AES_256_GCM_SHA384",
  "header_checked": "Strict-Transport-Security",
  "https_redirect": "Present (but vulnerable on first request)",
  "status": "Not Present",
  "test_date": "2025-12-10",
  "tls_version": "TLSv1.3"
}
```


---
**Report Generated:** 2025-12-10T10:34:02.957916
**Target:** https://www.jumia.ug/
**Authorization:** Ethical security testing with proper authorization