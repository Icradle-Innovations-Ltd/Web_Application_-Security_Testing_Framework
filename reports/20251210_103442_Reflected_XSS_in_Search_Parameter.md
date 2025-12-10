# Vulnerability Report: Reflected XSS in Search Parameter

## Summary
- **Vulnerability Type:** Cross-Site Scripting (XSS)
- **Severity:** High
- **Affected URL:** https://www.jumia.ug/catalog/?q=<payload>
- **Discovery Date:** 2025-12-10
- **Tested By:** Security Team

- **OWASP Category:** A03:2021-Injection


## Description
The search functionality does not properly sanitize user input, allowing attackers to inject malicious JavaScript code that executes in the victim's browser context.

## Reproduction Steps

1. Navigate to https://www.jumia.ug/catalog/

2. Enter the payload: <script>alert('XSS')</script> in the search box

3. Submit the search query

4. Observe that the script executes in the browser


## Impact Assessment
An attacker could steal session cookies, perform actions on behalf of the user, or redirect users to malicious sites. This could lead to account compromise and data theft.

## Remediation Recommendations

1. Implement proper output encoding for all user-supplied data
2. Use Content Security Policy (CSP) headers to prevent inline script execution
3. Validate and sanitize all input on the server side
4. Consider using a web application firewall (WAF)
5. Implement the X-XSS-Protection header
        


## Related CVE References

- CVE-2023-XXXXX




## Evidence
```json
{
  "headers": {
    "Content-Security-Policy": "Not Present",
    "X-XSS-Protection": "Not Present"
  },
  "payload": "\u003cscript\u003ealert(\u0027XSS\u0027)\u003c/script\u003e",
  "response_excerpt": "Search results for \u003cscript\u003ealert(\u0027XSS\u0027)\u003c/script\u003e"
}
```


---
**Report Generated:** 2025-12-10T10:34:42.150960
**Target:** https://www.jumia.ug/
**Authorization:** Ethical security testing with proper authorization