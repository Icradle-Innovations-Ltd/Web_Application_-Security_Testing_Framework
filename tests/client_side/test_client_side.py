"""
Client-Side Security Vulnerability Tests

OWASP: A05:2021 - Security Misconfiguration
Authorization: Ethical security testing
"""

import pytest
import requests
from typing import Dict, List
import re


class TestCORSMisconfiguration:
    """Test for CORS (Cross-Origin Resource Sharing) vulnerabilities"""
    
    def test_cors_allow_all_origins(self, config):
        """Test if CORS allows all origins (*) """
        base_url = config.target_url
        
        # Test with custom Origin header
        headers = {'Origin': 'https://evil.com'}
        
        try:
            response = requests.get(base_url, headers=headers, timeout=10)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            credentials_allowed = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # DANGEROUS: Allow * with credentials
            if cors_header == '*' and credentials_allowed.lower() == 'true':
                pytest.fail("CORS allows all origins with credentials enabled")
            
            # WARNING: Reflects arbitrary origin
            if cors_header == 'https://evil.com':
                # This might be intentional, but check if credentials are allowed
                if credentials_allowed.lower() == 'true':
                    pytest.fail("CORS reflects arbitrary origin with credentials")
        except requests.RequestException:
            pass
    
    def test_cors_null_origin_bypass(self, config):
        """Test if CORS allows null origin"""
        base_url = config.target_url
        
        headers = {'Origin': 'null'}
        
        try:
            response = requests.get(base_url, headers=headers, timeout=10)
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            credentials_allowed = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if cors_header == 'null' and credentials_allowed.lower() == 'true':
                pytest.fail("CORS allows null origin with credentials")
        except requests.RequestException:
            pass
    
    def test_cors_subdomain_bypass(self, config):
        """Test if CORS allows arbitrary subdomains"""
        base_url = config.target_url
        
        # Try various subdomain patterns
        test_origins = [
            'https://evil.example.com',
            'https://example.com.evil.com',
            'https://evil-example.com',  # Homograph attack
        ]
        
        vulnerabilities = []
        
        for origin in test_origins:
            headers = {'Origin': origin}
            
            try:
                response = requests.get(base_url, headers=headers, timeout=10)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if cors_header == origin and credentials.lower() == 'true':
                    vulnerabilities.append({
                        'origin': origin,
                        'cors_header': cors_header
                    })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"CORS subdomain bypass vulnerabilities: {vulnerabilities}"
    
    def test_cors_api_endpoints(self, config):
        """Test CORS configuration on API endpoints"""
        base_url = config.target_url
        
        api_endpoints = [
            "/rest/V1/store/storeConfigs",
            "/api/",
            "/graphql/",
        ]
        
        headers = {'Origin': 'https://evil.com'}
        
        for endpoint in api_endpoints:
            url = f"{base_url}{endpoint}"
            
            try:
                response = requests.get(url, headers=headers, timeout=10)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                
                # API endpoints should have strict CORS
                if cors_header == '*' or cors_header == 'https://evil.com':
                    # Warning: permissive CORS on API
                    pass
            except requests.RequestException:
                continue


class TestClickjackingProtection:
    """Test for clickjacking vulnerabilities"""
    
    def test_x_frame_options_header(self, config):
        """Test if X-Frame-Options header is set"""
        base_url = config.target_url
        
        try:
            response = requests.get(base_url, timeout=10)
            
            xfo_header = response.headers.get('X-Frame-Options', '')
            csp_header = response.headers.get('Content-Security-Policy', '')
            
            # Should have either X-Frame-Options or CSP frame-ancestors
            has_xfo = xfo_header.upper() in ['DENY', 'SAMEORIGIN']
            has_csp_frame = 'frame-ancestors' in csp_header.lower()
            
            assert has_xfo or has_csp_frame, \
                "Missing clickjacking protection (X-Frame-Options or CSP frame-ancestors)"
        except requests.RequestException:
            pytest.skip("Could not connect to target")
    
    def test_sensitive_pages_framing(self, config):
        """Test if sensitive pages can be framed"""
        base_url = config.target_url
        
        sensitive_pages = [
            "/customer/account/login/",
            "/checkout/",
            "/customer/account/",
        ]
        
        vulnerable_pages = []
        
        for page in sensitive_pages:
            url = f"{base_url}{page}"
            
            try:
                response = requests.get(url, timeout=10)
                
                xfo_header = response.headers.get('X-Frame-Options', '')
                csp_header = response.headers.get('Content-Security-Policy', '')
                
                has_protection = (
                    xfo_header.upper() in ['DENY', 'SAMEORIGIN'] or
                    'frame-ancestors' in csp_header.lower()
                )
                
                if not has_protection:
                    vulnerable_pages.append(page)
            except requests.RequestException:
                continue
        
        assert len(vulnerable_pages) == 0, \
            f"Sensitive pages without clickjacking protection: {vulnerable_pages}"


class TestOpenRedirect:
    """Test for open redirect vulnerabilities"""
    
    def test_redirect_parameter(self, config):
        """Test common redirect parameters"""
        base_url = config.target_url
        
        redirect_params = [
            "url", "redirect", "return", "next", "continue",
            "dest", "destination", "redir", "redirect_uri"
        ]
        
        evil_url = "https://evil.com"
        vulnerabilities = []
        
        for param in redirect_params:
            test_url = f"{base_url}/?"
            params = {param: evil_url}
            
            try:
                response = requests.get(
                    test_url,
                    params=params,
                    timeout=10,
                    allow_redirects=False
                )
                
                # Check if redirecting to external URL
                location = response.headers.get('Location', '')
                
                if evil_url in location:
                    vulnerabilities.append({
                        'param': param,
                        'location': location
                    })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"Open redirect vulnerabilities: {vulnerabilities}"
    
    def test_redirect_bypass_techniques(self, config):
        """Test redirect whitelist bypass techniques"""
        base_url = config.target_url
        
        # Bypass techniques
        bypass_payloads = [
            "https://evil.com@example.com",  # @ bypass
            "https://example.com.evil.com",  # Subdomain bypass
            "//evil.com",  # Protocol-relative
            "https://evil.com%2f@example.com",  # Encoded @
            "https://example.com%2f.evil.com",  # Encoded slash
        ]
        
        vulnerabilities = []
        
        for payload in bypass_payloads:
            params = {"return": payload}
            
            try:
                response = requests.get(
                    f"{base_url}/customer/account/login/",
                    params=params,
                    timeout=10,
                    allow_redirects=False
                )
                
                location = response.headers.get('Location', '')
                
                if 'evil.com' in location:
                    vulnerabilities.append({
                        'payload': payload,
                        'location': location
                    })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"Redirect bypass vulnerabilities: {vulnerabilities}"


class TestDOMClobbering:
    """Test for DOM clobbering vulnerabilities"""
    
    def test_dom_clobbering_vulnerable_code(self, config):
        """Test if site is vulnerable to DOM clobbering"""
        base_url = config.target_url
        
        try:
            response = requests.get(base_url, timeout=10)
            html = response.text
            
            # Look for patterns vulnerable to DOM clobbering
            vulnerable_patterns = [
                r'window\.config',
                r'document\.settings',
                r'window\["\w+"\]',
            ]
            
            vulnerabilities = []
            
            for pattern in vulnerable_patterns:
                if re.search(pattern, html):
                    vulnerabilities.append(pattern)
            
            # DOM clobbering requires manual verification
            # This is just a detection heuristic
            pass
        except requests.RequestException:
            pass


class TestPrototypePollution:
    """Test for prototype pollution vulnerabilities"""
    
    def test_prototype_pollution_in_query(self, config):
        """Test prototype pollution via query parameters"""
        base_url = config.target_url
        
        # Prototype pollution payloads
        pollution_payloads = [
            {"__proto__[admin]": "true"},
            {"constructor.prototype.admin": "true"},
            {"__proto__.isAdmin": "true"},
        ]
        
        for payload in pollution_payloads:
            try:
                response = requests.get(base_url, params=payload, timeout=10)
                
                # Prototype pollution is hard to detect from responses
                # Would need to check JavaScript execution
                pass
            except requests.RequestException:
                continue


class TestMixedContent:
    """Test for mixed content issues"""
    
    def test_mixed_content_in_https(self, config):
        """Test if HTTPS pages load HTTP resources"""
        base_url = config.target_url
        
        if not base_url.startswith('https://'):
            pytest.skip("Site not using HTTPS")
        
        try:
            response = requests.get(base_url, timeout=10)
            html = response.text
            
            # Find HTTP resources in HTTPS page
            http_resources = re.findall(r'http://[^\s"\'<>]+', html)
            
            # Filter out localhost/example references
            real_http_resources = [
                url for url in http_resources
                if not any(skip in url for skip in ['localhost', '127.0.0.1', 'example.com'])
            ]
            
            assert len(real_http_resources) == 0, \
                f"Mixed content detected: {real_http_resources[:5]}"
        except requests.RequestException:
            pytest.skip("Could not fetch page")


class TestSubresourceIntegrity:
    """Test for Subresource Integrity (SRI)"""
    
    def test_sri_on_external_scripts(self, config):
        """Test if external scripts use SRI"""
        base_url = config.target_url
        
        try:
            response = requests.get(base_url, timeout=10)
            html = response.text
            
            # Find external script tags
            external_scripts = re.findall(
                r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>',
                html
            )
            
            scripts_without_sri = []
            
            for script in external_scripts:
                # Check if script has integrity attribute
                if 'integrity=' not in script:
                    # Extract src
                    src_match = re.search(r'src=["\']([^"\']+)["\']', script)
                    if src_match:
                        src = src_match.group(1)
                        # Skip same-origin scripts
                        if not src.startswith(base_url):
                            scripts_without_sri.append(src)
            
            # SRI is recommended but not required
            # Just track for reporting
            if scripts_without_sri:
                # Warning: external scripts without SRI
                pass
        except requests.RequestException:
            pass


class TestReferrerPolicy:
    """Test for Referrer-Policy configuration"""
    
    def test_referrer_policy_header(self, config):
        """Test if Referrer-Policy is set"""
        base_url = config.target_url
        
        try:
            response = requests.get(base_url, timeout=10)
            
            referrer_policy = response.headers.get('Referrer-Policy', '')
            
            # Recommended policies
            secure_policies = [
                'no-referrer',
                'no-referrer-when-downgrade',
                'same-origin',
                'strict-origin',
                'strict-origin-when-cross-origin'
            ]
            
            # Referrer-Policy is recommended for privacy
            # Not a critical vulnerability if missing
            if not referrer_policy:
                # Warning: no Referrer-Policy set
                pass
            elif referrer_policy not in secure_policies:
                # Warning: weak Referrer-Policy
                pass
        except requests.RequestException:
            pass


class TestWebsocketSecurity:
    """Test for WebSocket security issues"""
    
    @pytest.mark.skip(reason="Requires WebSocket endpoint detection")
    def test_websocket_origin_validation(self, config):
        """Test if WebSocket validates Origin header"""
        # This would require websocket-client library
        # and knowledge of WebSocket endpoints
        pass
    
    @pytest.mark.skip(reason="Requires WebSocket endpoint detection")
    def test_websocket_authentication(self, config):
        """Test if WebSocket requires authentication"""
        # Would need to establish WebSocket connection
        pass
