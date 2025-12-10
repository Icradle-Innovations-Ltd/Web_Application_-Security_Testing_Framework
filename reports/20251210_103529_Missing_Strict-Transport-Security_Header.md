# Vulnerability Report: Missing Strict-Transport-Security Header

## Summary
- **Vulnerability Type:** Security Misconfiguration
- **Severity:** Medium
- **Affected URL:** https://www.jumia.ug/
- **Discovery Date:** 2025-12-10
- **Tested By:** Security Team

- **OWASP Category:** A05:2021-Security Misconfiguration


## Description
The application does not send the HSTS header, leaving users vulnerable to SSL stripping attacks.

## Reproduction Steps

1. Send HTTPS request to https://www.jumia.ug/

2. Inspect response headers

3. Verify absence of Strict-Transport-Security header


## Impact Assessment
MEDIUM: Users are vulnerable to SSL stripping attacks on first visit. Man-in-the-middle attackers can downgrade connections to HTTP.

## Remediation Recommendations
Implement HSTS header:

Recommended:
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

Steps:
1. Add HSTS to all HTTPS responses
2. Start with shorter max-age for testing
3. Gradually increase to 31536000 (1 year)
4. Submit to HSTS preload list: https://hstspreload.org/

Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;




## Evidence
```json
{
  "cipher": "TLS_AES_256_GCM_SHA384",
  "tls_version": "TLSv1.3"
}
```


---
**Report Generated:** 2025-12-10T10:35:29.350225
**Target:** https://www.jumia.ug/
**Authorization:** Ethical security testing with proper authorization