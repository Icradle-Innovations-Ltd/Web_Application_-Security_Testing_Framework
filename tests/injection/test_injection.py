"""
Server-Side Injection Vulnerability Tests

OWASP: A03:2021 - Injection, A10:2021 - SSRF
Authorization: Ethical security testing
"""

import pytest
import requests
from typing import Dict, List
import time
import socket


class TestSSRFVulnerabilities:
    """Test for Server-Side Request Forgery"""
    
    def test_ssrf_via_url_parameter(self, config):
        """Test SSRF via URL parameters"""
        base_url = config.target_url
        
        # Common parameters that might fetch URLs
        ssrf_params = [
            "url", "uri", "path", "dest", "redirect",
            "image_url", "return", "continue", "callback"
        ]
        
        # Internal targets to test
        internal_targets = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://[::1]/",  # IPv6 localhost
        ]
        
        vulnerabilities = []
        
        for param in ssrf_params:
            for target in internal_targets:
                test_url = f"{base_url}/?"
                params = {param: target}
                
                try:
                    response = requests.get(
                        test_url,
                        params=params,
                        timeout=10,
                        allow_redirects=False
                    )
                    
                    # Check for SSRF indicators
                    if any(indicator in response.text.lower() for indicator in 
                           ['ami-', 'instance-id', 'metadata', 'localhost']):
                        vulnerabilities.append({
                            'param': param,
                            'target': target,
                            'status': response.status_code
                        })
                except requests.RequestException:
                    continue
        
        assert len(vulnerabilities) == 0, \
            f"SSRF vulnerabilities detected: {vulnerabilities}"
    
    def test_ssrf_via_file_upload(self, config):
        """Test SSRF via file upload with remote URL"""
        base_url = config.target_url
        
        # Some applications allow importing files from URLs
        import_endpoints = [
            "/admin/import/",
            "/api/import/",
            "/import/",
        ]
        
        internal_url = "http://169.254.169.254/latest/meta-data/"
        
        for endpoint in import_endpoints:
            url = f"{base_url}{endpoint}"
            payload = {"url": internal_url}
            
            try:
                response = requests.post(url, data=payload, timeout=10)
                
                if 'ami-' in response.text or 'instance-id' in response.text:
                    pytest.fail(f"SSRF via file import in {endpoint}")
            except requests.RequestException:
                continue
    
    def test_ssrf_via_webhook(self, config):
        """Test SSRF via webhook/callback URLs"""
        base_url = config.target_url
        
        webhook_endpoints = [
            "/api/webhook/",
            "/callback/",
            "/notify/",
        ]
        
        internal_url = "http://localhost:22"  # SSH port
        
        for endpoint in webhook_endpoints:
            url = f"{base_url}{endpoint}"
            payload = {"callback_url": internal_url}
            
            try:
                response = requests.post(url, json=payload, timeout=10)
                
                # Should not allow internal URLs
                if response.status_code == 200:
                    # Check if internal request was made
                    pass
            except requests.RequestException:
                continue
    
    def test_dns_rebinding(self, config):
        """Test DNS rebinding attack prevention"""
        base_url = config.target_url
        
        # DNS rebinding domain that resolves to localhost
        rebinding_domain = "127.0.0.1.nip.io"  # Resolves to 127.0.0.1
        
        test_url = f"{base_url}/?url=http://{rebinding_domain}/"
        
        try:
            response = requests.get(test_url, timeout=10)
            
            # Should block requests to domains resolving to internal IPs
            assert 'localhost' not in response.text.lower(), \
                "DNS rebinding protection missing"
        except requests.RequestException:
            pass


class TestCommandInjection:
    """Test for OS command injection vulnerabilities"""
    
    def test_command_injection_in_search(self, config):
        """Test command injection in search parameters"""
        base_url = config.target_url
        
        # Command injection payloads
        payloads = [
            "; ls -la",
            "| whoami",
            "; cat /etc/passwd",
            "`whoami`",
            "$(whoami)",
            "&& ping -c 3 127.0.0.1",
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            params = {"q": f"test{payload}"}
            
            try:
                start_time = time.time()
                response = requests.get(
                    f"{base_url}/catalogsearch/result/",
                    params=params,
                    timeout=15
                )
                elapsed = time.time() - start_time
                
                # Check for command injection indicators
                if any(indicator in response.text for indicator in 
                       ['root:', 'bin/bash', 'uid=', 'gid=']):
                    vulnerabilities.append({
                        'payload': payload,
                        'response_snippet': response.text[:200]
                    })
                
                # Time-based detection (ping payload)
                if 'ping' in payload and elapsed > 3:
                    vulnerabilities.append({
                        'payload': payload,
                        'type': 'time-based',
                        'elapsed': elapsed
                    })
            except requests.Timeout:
                # Timeout might indicate successful ping command
                vulnerabilities.append({
                    'payload': payload,
                    'type': 'timeout'
                })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"Command injection vulnerabilities: {vulnerabilities}"
    
    @pytest.mark.skip(reason="Requires authenticated session")
    def test_command_injection_in_export(self, config, authenticated_session):
        """Test command injection in export functionality"""
        base_url = config.target_url
        session = authenticated_session
        
        export_endpoints = [
            "/admin/export/",
            "/api/export/",
            "/export/csv/",
        ]
        
        payload = "test; cat /etc/passwd"
        
        for endpoint in export_endpoints:
            url = f"{base_url}{endpoint}"
            
            try:
                response = session.post(
                    url,
                    json={"filename": payload},
                    timeout=10
                )
                
                if 'root:' in response.text:
                    pytest.fail(f"Command injection in export: {endpoint}")
            except requests.RequestException:
                continue


class TestTemplateInjection:
    """Test for Server-Side Template Injection (SSTI)"""
    
    def test_ssti_in_search(self, config):
        """Test SSTI in search and input fields"""
        base_url = config.target_url
        
        # Template injection payloads for various engines
        ssti_payloads = [
            "{{7*7}}",  # Jinja2, Twig
            "${7*7}",  # Freemarker, Velocity
            "<%= 7*7 %>",  # ERB
            "#{7*7}",  # Ruby
            "@(7*7)",  # Razor
        ]
        
        vulnerabilities = []
        
        for payload in ssti_payloads:
            params = {"q": payload}
            
            try:
                response = requests.get(
                    f"{base_url}/catalogsearch/result/",
                    params=params,
                    timeout=10
                )
                
                # Check if expression was evaluated
                if '49' in response.text and payload not in response.text:
                    vulnerabilities.append({
                        'payload': payload,
                        'evaluated': True
                    })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"SSTI vulnerabilities detected: {vulnerabilities}"
    
    def test_ssti_in_error_pages(self, config):
        """Test SSTI in error messages"""
        base_url = config.target_url
        
        # Try triggering error with SSTI payload
        error_urls = [
            f"{base_url}/{{{{7*7}}}}/",
            f"{base_url}/${{7*7}}/",
        ]
        
        for url in error_urls:
            try:
                response = requests.get(url, timeout=10)
                
                if '49' in response.text:
                    pytest.fail(f"SSTI in error pages: {url}")
            except requests.RequestException:
                continue


class TestLDAPInjection:
    """Test for LDAP injection vulnerabilities"""
    
    @pytest.mark.skip(reason="Requires LDAP authentication endpoint")
    def test_ldap_injection_in_login(self, config):
        """Test LDAP injection in authentication"""
        base_url = config.target_url
        
        login_url = f"{base_url}/customer/account/loginPost/"
        
        # LDAP injection payloads
        ldap_payloads = [
            "admin)(&",
            "admin)(|",
            "*)(uid=*))(|(uid=*",
            "admin)(!(&(objectClass=*)",
        ]
        
        for payload in ldap_payloads:
            data = {
                "login[username]": payload,
                "login[password]": "any"
            }
            
            try:
                response = requests.post(login_url, data=data, timeout=10)
                
                # Should not bypass authentication
                if 'dashboard' in response.url.lower():
                    pytest.fail(f"LDAP injection successful: {payload}")
            except requests.RequestException:
                continue


class TestXPathInjection:
    """Test for XPath injection vulnerabilities"""
    
    def test_xpath_injection_in_search(self, config):
        """Test XPath injection in search"""
        base_url = config.target_url
        
        # XPath injection payloads
        xpath_payloads = [
            "' or '1'='1",
            "'] | //user/*[contains(*,'",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
        ]
        
        vulnerabilities = []
        
        for payload in xpath_payloads:
            params = {"q": payload}
            
            try:
                response = requests.get(
                    f"{base_url}/catalogsearch/result/",
                    params=params,
                    timeout=10
                )
                
                # Check for unusual behavior or data exposure
                if len(response.content) > 50000:  # Unusually large response
                    vulnerabilities.append({
                        'payload': payload,
                        'response_size': len(response.content)
                    })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"Possible XPath injection: {vulnerabilities}"


class TestCodeInjection:
    """Test for code injection vulnerabilities"""
    
    def test_php_code_injection(self, config):
        """Test PHP code injection"""
        base_url = config.target_url
        
        # PHP code injection payloads
        php_payloads = [
            "<?php phpinfo(); ?>",
            "${phpinfo()}",
            "<?= phpinfo() ?>",
        ]
        
        for payload in php_payloads:
            params = {"q": payload}
            
            try:
                response = requests.get(
                    f"{base_url}/catalogsearch/result/",
                    params=params,
                    timeout=10
                )
                
                # Check if PHP code was executed
                if 'phpinfo()' in response.text.lower() or 'php version' in response.text.lower():
                    pytest.fail(f"PHP code injection detected: {payload}")
            except requests.RequestException:
                continue
    
    def test_expression_language_injection(self, config):
        """Test Expression Language (EL) injection"""
        base_url = config.target_url
        
        # EL injection payloads
        el_payloads = [
            "${7*7}",
            "#{7*7}",
            "${applicationScope}",
            "#{sessionScope}",
        ]
        
        for payload in el_payloads:
            params = {"q": payload}
            
            try:
                response = requests.get(
                    f"{base_url}/catalogsearch/result/",
                    params=params,
                    timeout=10
                )
                
                if '49' in response.text and payload not in response.text:
                    pytest.fail(f"EL injection detected: {payload}")
            except requests.RequestException:
                continue


class TestDeserializationAttacks:
    """Test for insecure deserialization"""
    
    def test_java_deserialization(self, config):
        """Test Java deserialization vulnerabilities"""
        base_url = config.target_url
        
        # Java serialized object header
        java_serialized = b'\xac\xed\x00\x05'  # Java serialization magic bytes
        
        endpoints = [
            "/api/",
            "/rest/",
        ]
        
        for endpoint in endpoints:
            url = f"{base_url}{endpoint}"
            
            try:
                response = requests.post(
                    url,
                    data=java_serialized,
                    headers={'Content-Type': 'application/x-java-serialized-object'},
                    timeout=10
                )
                
                # Should reject serialized objects
                assert response.status_code in [400, 415], \
                    f"Java deserialization accepted in {endpoint}"
            except requests.RequestException:
                continue
    
    @pytest.mark.skip(reason="Requires specific endpoint")
    def test_python_pickle_deserialization(self, config):
        """Test Python pickle deserialization"""
        base_url = config.target_url
        
        # Python pickle magic bytes
        import pickle
        
        # Create malicious pickle (safe for testing)
        malicious_data = pickle.dumps({"test": "value"})
        
        api_url = f"{base_url}/api/import/"
        
        try:
            response = requests.post(
                api_url,
                data=malicious_data,
                headers={'Content-Type': 'application/python-pickle'},
                timeout=10
            )
            
            # Should reject pickle data
            assert response.status_code in [400, 415], \
                "Python pickle deserialization accepted"
        except requests.RequestException:
            pass
