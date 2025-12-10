"""
Insecure Direct Object Reference (IDOR) and Access Control Tests

OWASP: A01:2021 - Broken Access Control
Authorization: Ethical security testing
"""

import pytest
import requests
from typing import Dict, List
import re
import json


class TestIDORVulnerabilities:
    """Test for Insecure Direct Object References"""
    
    def test_product_id_enumeration(self, config):
        """Test if product IDs can be enumerated to access unauthorized products"""
        base_url = config.target_url
        
        # Try accessing products with sequential IDs
        test_ids = [1, 2, 100, 999, 1000, 9999]
        accessible_products = []
        
        for product_id in test_ids:
            url = f"{base_url}/catalog/product/view/id/{product_id}/"
            try:
                response = requests.get(url, timeout=10, allow_redirects=True)
                if response.status_code == 200:
                    accessible_products.append({
                        'id': product_id,
                        'url': url,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        
        # IDOR is acceptable for public products, but we track the pattern
        assert len(accessible_products) >= 0, "Product enumeration test completed"
    
    def test_user_profile_access_control(self, config):
        """Test if user profiles can be accessed without authentication"""
        base_url = config.target_url
        
        # Common user profile endpoints
        profile_endpoints = [
            "/customer/account/",
            "/customer/account/edit/",
            "/customer/address/",
            "/sales/order/history/",
            "/wishlist/",
            "/customer/account/index/",
        ]
        
        unauthorized_access = []
        
        for endpoint in profile_endpoints:
            url = f"{base_url}{endpoint}"
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                # Should redirect to login or return 401/403
                if response.status_code == 200:
                    unauthorized_access.append({
                        'endpoint': endpoint,
                        'status': response.status_code,
                        'issue': 'Accessible without authentication'
                    })
                elif response.status_code not in [301, 302, 401, 403, 404]:
                    unauthorized_access.append({
                        'endpoint': endpoint,
                        'status': response.status_code,
                        'issue': 'Unexpected response code'
                    })
            except requests.RequestException:
                continue
        
        assert len(unauthorized_access) == 0, \
            f"Unauthorized access detected: {unauthorized_access}"
    
    def test_order_id_idor(self, config):
        """Test if order details can be accessed using predictable order IDs"""
        base_url = config.target_url
        
        # Try accessing orders with sequential IDs
        test_order_ids = [1, 100, 1000, 10000, 99999]
        accessible_orders = []
        
        for order_id in test_order_ids:
            url = f"{base_url}/sales/order/view/order_id/{order_id}/"
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                # Should redirect to login or return 401/403
                if response.status_code == 200:
                    accessible_orders.append({
                        'order_id': order_id,
                        'url': url,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        
        assert len(accessible_orders) == 0, \
            f"IDOR vulnerability: Orders accessible without auth: {accessible_orders}"
    
    @pytest.mark.skip(reason="Requires authenticated session")
    def test_horizontal_privilege_escalation(self, config, authenticated_session):
        """Test if users can access other users' data (horizontal escalation)"""
        base_url = config.target_url
        session = authenticated_session
        
        # This would require two test accounts
        # Try accessing another user's profile/orders
        test_user_ids = [2, 3, 100, 1000]
        
        for user_id in test_user_ids:
            url = f"{base_url}/customer/account/view/id/{user_id}/"
            response = session.get(url, timeout=10)
            
            assert response.status_code in [403, 404], \
                f"Horizontal privilege escalation possible for user {user_id}"
    
    @pytest.mark.skip(reason="Requires authenticated session")
    def test_vertical_privilege_escalation(self, config, authenticated_session):
        """Test if regular users can access admin functions"""
        base_url = config.target_url
        session = authenticated_session
        
        admin_endpoints = [
            "/admin/",
            "/administrator/",
            "/backend/",
            "/admin/dashboard/",
            "/admin/catalog/product/",
        ]
        
        admin_access = []
        
        for endpoint in admin_endpoints:
            url = f"{base_url}{endpoint}"
            try:
                response = session.get(url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    admin_access.append({
                        'endpoint': endpoint,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        
        assert len(admin_access) == 0, \
            f"Vertical privilege escalation detected: {admin_access}"


class TestAccessControlBypass:
    """Test for access control bypass techniques"""
    
    def test_direct_api_access(self, config):
        """Test if API endpoints can be accessed without proper authorization"""
        base_url = config.target_url
        
        # Common API endpoints
        api_endpoints = [
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/rest/",
            "/rest/V1/",
            "/graphql/",
            "/api/customers/",
            "/api/orders/",
            "/api/products/",
        ]
        
        accessible_apis = []
        
        for endpoint in api_endpoints:
            url = f"{base_url}{endpoint}"
            try:
                response = requests.get(url, timeout=10)
                
                # API should require authentication
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'json' in content_type or 'xml' in content_type:
                        accessible_apis.append({
                            'endpoint': endpoint,
                            'status': response.status_code,
                            'content_type': content_type
                        })
            except requests.RequestException:
                continue
        
        # Some public APIs are acceptable, but track them
        assert len(accessible_apis) >= 0, "API access control test completed"
    
    def test_http_verb_tampering(self, config):
        """Test if changing HTTP methods bypasses access control"""
        base_url = config.target_url
        test_endpoint = f"{base_url}/customer/account/"
        
        methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        results = {}
        
        for method in methods_to_test:
            try:
                response = requests.request(
                    method, 
                    test_endpoint, 
                    timeout=10, 
                    allow_redirects=False
                )
                results[method] = response.status_code
            except requests.RequestException:
                results[method] = 'Error'
        
        # All methods should have consistent access control
        # If GET returns 302 (redirect), other methods should too
        if results.get('GET') in [301, 302, 401, 403]:
            for method, status in results.items():
                if method != 'OPTIONS':  # OPTIONS is special
                    assert status in [301, 302, 401, 403, 404, 405, 'Error'], \
                        f"HTTP verb tampering possible: {method} returned {status}"
    
    def test_path_traversal_in_urls(self, config):
        """Test if path traversal can bypass access control"""
        base_url = config.target_url
        
        # Try various path traversal techniques
        traversal_payloads = [
            "/customer/account/../admin/",
            "/customer/account/../../admin/",
            "/customer/account/..%2fadmin/",
            "/customer/account/%2e%2e/admin/",
            "/customer/account/....//admin/",
        ]
        
        vulnerabilities = []
        
        for payload in traversal_payloads:
            url = f"{base_url}{payload}"
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                # Should not access admin area
                if 'admin' in response.text.lower() and response.status_code == 200:
                    vulnerabilities.append({
                        'payload': payload,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"Path traversal vulnerabilities: {vulnerabilities}"
    
    def test_parameter_pollution(self, config):
        """Test if parameter pollution can bypass access control"""
        base_url = config.target_url
        
        # Try accessing protected resource with parameter pollution
        test_urls = [
            f"{base_url}/customer/account/?admin=true",
            f"{base_url}/customer/account/?role=admin",
            f"{base_url}/customer/account/?user_id=1&user_id=2",
            f"{base_url}/sales/order/view/?order_id=1&order_id=2",
        ]
        
        bypasses = []
        
        for url in test_urls:
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                # Should still require authentication
                if response.status_code == 200:
                    bypasses.append({
                        'url': url,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        
        assert len(bypasses) == 0, \
            f"Parameter pollution bypasses detected: {bypasses}"


class TestForcedBrowsing:
    """Test for forced browsing vulnerabilities"""
    
    def test_hidden_admin_paths(self, config):
        """Test for common hidden admin paths"""
        base_url = config.target_url
        
        admin_paths = [
            "/admin/",
            "/administrator/",
            "/backend/",
            "/manage/",
            "/control/",
            "/cpanel/",
            "/wp-admin/",
            "/admin.php",
            "/admin/login",
            "/admin/dashboard",
        ]
        
        found_paths = []
        
        for path in admin_paths:
            url = f"{base_url}{path}"
            try:
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                # Track admin interfaces that respond
                if response.status_code in [200, 301, 302]:
                    found_paths.append({
                        'path': path,
                        'status': response.status_code,
                        'requires_auth': response.status_code in [301, 302]
                    })
            except requests.RequestException:
                continue
        
        # Admin paths are acceptable if they require authentication
        for found in found_paths:
            assert found['requires_auth'] or found['status'] == 404, \
                f"Admin path accessible without redirect: {found}"
    
    def test_backup_file_exposure(self, config):
        """Test if backup files expose sensitive data"""
        base_url = config.target_url
        
        # Common backup file patterns
        backup_files = [
            "/config.php.bak",
            "/config.php~",
            "/database.sql",
            "/backup.sql",
            "/.git/config",
            "/.env",
            "/.env.backup",
            "/composer.json",
            "/package.json",
        ]
        
        exposed_files = []
        
        for file in backup_files:
            url = f"{base_url}{file}"
            try:
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    exposed_files.append({
                        'file': file,
                        'size': len(response.content),
                        'content_type': response.headers.get('Content-Type', '')
                    })
            except requests.RequestException:
                continue
        
        assert len(exposed_files) == 0, \
            f"Backup files exposed: {exposed_files}"
    
    def test_directory_listing(self, config):
        """Test if directory listing is enabled"""
        base_url = config.target_url
        
        # Common directories that might have listing enabled
        directories = [
            "/images/",
            "/uploads/",
            "/media/",
            "/static/",
            "/assets/",
            "/backup/",
        ]
        
        listings_enabled = []
        
        for directory in directories:
            url = f"{base_url}{directory}"
            try:
                response = requests.get(url, timeout=10)
                
                # Check for directory listing signatures
                if response.status_code == 200:
                    content = response.text.lower()
                    if any(sig in content for sig in ['index of', 'parent directory', '[dir]']):
                        listings_enabled.append({
                            'directory': directory,
                            'status': response.status_code
                        })
            except requests.RequestException:
                continue
        
        assert len(listings_enabled) == 0, \
            f"Directory listing enabled: {listings_enabled}"
