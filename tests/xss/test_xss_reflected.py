"""
XSS (Cross-Site Scripting) Security Tests for Web Applications

AUTHORIZATION: Ethical security testing only
SCOPE: Search functionality, product reviews, user inputs
"""

import pytest
import requests
import os
from dotenv import load_dotenv

load_dotenv()

TARGET_URL = os.getenv("TARGET_URL", "https://example.com")

# XSS Payloads - Common patterns
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src='javascript:alert(`XSS`)'>",
    "';alert('XSS');//",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
]


class TestReflectedXSS:
    """Test for reflected XSS vulnerabilities in user inputs"""
    
    def test_search_parameter_xss(self):
        """Test if search parameter reflects user input without sanitization"""
        for payload in XSS_PAYLOADS:
            response = requests.get(
                f"{TARGET_URL}/catalog/",
                params={"q": payload},
                timeout=10
            )
            
            # Check if payload is reflected in response
            if payload in response.text:
                print(f"\n⚠️  POTENTIAL XSS FOUND in search parameter")
                print(f"Payload: {payload}")
                print(f"URL: {response.url}")
                assert False, f"Unsanitized input reflected: {payload}"
    
    def test_url_parameter_xss(self):
        """Test if URL parameters are vulnerable to XSS"""
        test_params = ["redirect", "return_url", "next", "callback", "url"]
        
        for param in test_params:
            for payload in XSS_PAYLOADS[:3]:  # Test subset
                response = requests.get(
                    TARGET_URL,
                    params={param: payload},
                    timeout=10,
                    allow_redirects=False
                )
                
                if payload in response.text or payload in response.headers.get("Location", ""):
                    print(f"\n⚠️  POTENTIAL XSS in URL parameter: {param}")
                    print(f"Payload: {payload}")
                    assert False, f"XSS in {param} parameter"


class TestStoredXSS:
    """Test for stored/persistent XSS vulnerabilities"""
    
    @pytest.mark.skip(reason="Requires authentication - implement after auth tests")
    def test_product_review_xss(self):
        """Test if product reviews store and execute malicious scripts"""
        # TODO: Implement after authentication is set up
        pass
    
    @pytest.mark.skip(reason="Requires authentication")
    def test_user_profile_xss(self):
        """Test if user profile fields are vulnerable to stored XSS"""
        # TODO: Implement after authentication is set up
        pass


class TestDOMBasedXSS:
    """Test for DOM-based XSS vulnerabilities"""
    
    def test_hash_fragment_xss(self):
        """Test if URL hash fragments trigger XSS"""
        payloads_encoded = [
            "#<script>alert('XSS')</script>",
            "#<img src=x onerror=alert('XSS')>",
        ]
        
        for payload in payloads_encoded:
            test_url = f"{TARGET_URL}/{payload}"
            response = requests.get(test_url, timeout=10)
            
            # Check if JavaScript processes the hash unsafely
            if "location.hash" in response.text and "innerHTML" in response.text:
                print(f"\n⚠️  POTENTIAL DOM XSS via hash fragment")
                print(f"URL: {test_url}")
                # Note: This requires manual verification with browser


class TestXSSFilters:
    """Test the effectiveness of XSS filters and WAF"""
    
    def test_filter_bypass_attempts(self):
        """Test various XSS filter bypass techniques"""
        bypass_payloads = [
            "<ScRiPt>alert('XSS')</ScRiPt>",  # Case variation
            "<script>alert(String.fromCharCode(88,83,83))</script>",  # Encoding
            "<img src='x' onerror='alert&#40;1&#41;'>",  # HTML entities
            "<svg><script>alert('XSS')</script></svg>",  # Nested tags
            "<<script>alert('XSS')</script>",  # Double encoding
        ]
        
        for payload in bypass_payloads:
            response = requests.get(
                f"{TARGET_URL}/catalog/",
                params={"q": payload},
                timeout=10
            )
            
            if payload in response.text or payload.lower() in response.text.lower():
                print(f"\n⚠️  FILTER BYPASS POSSIBLE")
                print(f"Payload: {payload}")


def test_content_security_policy():
    """Verify Content Security Policy headers are present"""
    response = requests.get(TARGET_URL, timeout=10)
    
    csp_header = response.headers.get("Content-Security-Policy", "")
    
    if not csp_header:
        print("\n⚠️  WARNING: No Content-Security-Policy header found")
        print("Recommendation: Implement CSP to mitigate XSS attacks")
    else:
        print(f"\n✓ CSP Found: {csp_header}")
        
        # Check for unsafe directives
        if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
            print("⚠️  WARNING: CSP contains unsafe directives")


def test_x_xss_protection_header():
    """Check for X-XSS-Protection header"""
    response = requests.get(TARGET_URL, timeout=10)
    
    xss_protection = response.headers.get("X-XSS-Protection", "")
    
    if xss_protection != "1; mode=block":
        print(f"\n⚠️  X-XSS-Protection header not optimally configured")
        print(f"Current: {xss_protection}")
        print(f"Recommended: 1; mode=block")
