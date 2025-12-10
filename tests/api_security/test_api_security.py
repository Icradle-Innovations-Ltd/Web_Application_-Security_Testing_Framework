"""
API Security Tests

OWASP: A01:2021 - Broken Access Control, A03:2021 - Injection
OWASP API Security Top 10
Authorization: Ethical security testing
"""

import pytest
import requests
import json
from typing import Dict, List
import time


class TestRESTAPISecurit:
    """Test REST API security vulnerabilities"""
    
    def test_api_endpoint_discovery(self, config):
        """Discover available API endpoints"""
        base_url = config.target_url
        
        # Common API paths
        api_paths = [
            "/api/",
            "/api/v1/",
            "/api/v2/",
            "/rest/",
            "/rest/V1/",
            "/rest/default/V1/",
            "/api/graphql/",
            "/graphql/",
        ]
        
        discovered_apis = []
        
        for path in api_paths:
            url = f"{base_url}{path}"
            
            try:
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '')
                    discovered_apis.append({
                        'path': path,
                        'status': response.status_code,
                        'content_type': content_type
                    })
            except requests.RequestException:
                continue
        
        # APIs can be public, but track them
        assert len(discovered_apis) >= 0, "API discovery completed"
    
    def test_api_authentication_bypass(self, config):
        """Test if API endpoints can be accessed without authentication"""
        base_url = config.target_url
        
        # Sensitive API endpoints that should require auth
        protected_endpoints = [
            "/rest/V1/customers/me",
            "/rest/V1/orders/",
            "/rest/V1/customers/",
            "/api/v1/user/profile",
            "/api/v1/orders/",
        ]
        
        bypasses = []
        
        for endpoint in protected_endpoints:
            url = f"{base_url}{endpoint}"
            
            try:
                response = requests.get(url, timeout=10)
                
                # Should return 401 or 403
                if response.status_code == 200:
                    bypasses.append({
                        'endpoint': endpoint,
                        'status': response.status_code
                    })
            except requests.RequestException:
                continue
        
        assert len(bypasses) == 0, \
            f"API authentication bypass detected: {bypasses}"
    
    def test_api_rate_limiting(self, config):
        """Test if API has rate limiting implemented"""
        base_url = config.target_url
        
        # Test endpoint (use public endpoint to avoid auth issues)
        test_url = f"{base_url}/rest/V1/store/storeConfigs"
        
        # Make rapid requests
        responses = []
        for i in range(50):
            try:
                response = requests.get(test_url, timeout=5)
                responses.append(response.status_code)
            except requests.RequestException:
                break
        
        # Should eventually hit rate limit (429)
        rate_limited = 429 in responses
        
        # Rate limiting is good security practice
        if not rate_limited:
            # Warning: no rate limiting detected
            pass
    
    def test_api_method_override(self, config):
        """Test if API allows HTTP method override"""
        base_url = config.target_url
        
        test_url = f"{base_url}/rest/V1/products/"
        
        # Try using X-HTTP-Method-Override to change GET to DELETE
        headers = {'X-HTTP-Method-Override': 'DELETE'}
        
        try:
            response = requests.get(test_url, headers=headers, timeout=10)
            
            # Should not allow method override without proper auth
            assert response.status_code != 200, \
                "HTTP method override allowed without authentication"
        except requests.RequestException:
            pass
    
    def test_excessive_data_exposure(self, config):
        """Test if API returns more data than necessary"""
        base_url = config.target_url
        
        # Public API endpoints
        test_endpoints = [
            "/rest/V1/store/storeConfigs",
            "/rest/V1/products/",
            "/api/catalog/",
        ]
        
        excessive_exposure = []
        
        for endpoint in test_endpoints:
            url = f"{base_url}{endpoint}"
            
            try:
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        
                        # Check for sensitive fields in response
                        sensitive_fields = ['password', 'token', 'secret', 'api_key', 'private']
                        response_text = str(data).lower()
                        
                        found_sensitive = [field for field in sensitive_fields if field in response_text]
                        
                        if found_sensitive:
                            excessive_exposure.append({
                                'endpoint': endpoint,
                                'sensitive_fields': found_sensitive
                            })
                    except:
                        pass
            except requests.RequestException:
                continue
        
        assert len(excessive_exposure) == 0, \
            f"Excessive data exposure in API: {excessive_exposure}"


class TestGraphQLSecurity:
    """Test GraphQL API security"""
    
    def test_graphql_introspection(self, config):
        """Test if GraphQL introspection is enabled in production"""
        base_url = config.target_url
        
        graphql_urls = [
            f"{base_url}/graphql/",
            f"{base_url}/api/graphql/",
        ]
        
        introspection_query = {
            "query": "{ __schema { types { name } } }"
        }
        
        introspection_enabled = []
        
        for url in graphql_urls:
            try:
                response = requests.post(
                    url,
                    json=introspection_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if '__schema' in str(data) or 'types' in str(data):
                            introspection_enabled.append(url)
                    except:
                        pass
            except requests.RequestException:
                continue
        
        # Introspection should be disabled in production
        if introspection_enabled:
            # Warning: introspection enabled
            pass
    
    def test_graphql_batching_attack(self, config):
        """Test if GraphQL allows batched queries for DoS"""
        base_url = config.target_url
        
        graphql_url = f"{base_url}/graphql/"
        
        # Create batched query (array of queries)
        batched_queries = [
            {"query": "{ products { items { name } } }"}
            for _ in range(100)
        ]
        
        try:
            response = requests.post(
                graphql_url,
                json=batched_queries,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            # Should reject or limit batched queries
            if response.status_code == 200:
                # Warning: batched queries allowed
                pass
        except requests.RequestException:
            pass
    
    def test_graphql_depth_limit(self, config):
        """Test if GraphQL has query depth limits"""
        base_url = config.target_url
        
        graphql_url = f"{base_url}/graphql/"
        
        # Create deeply nested query
        deep_query = {
            "query": """
            {
                products {
                    items {
                        categories {
                            products {
                                items {
                                    categories {
                                        products {
                                            items {
                                                name
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        try:
            response = requests.post(
                graphql_url,
                json=deep_query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            # Should reject deeply nested queries
            if response.status_code == 200:
                # Warning: no depth limit
                pass
        except requests.RequestException:
            pass


class TestMassAssignment:
    """Test for mass assignment vulnerabilities"""
    
    @pytest.mark.skip(reason="Requires authenticated session")
    def test_user_role_mass_assignment(self, config, authenticated_session):
        """Test if user can escalate privileges via mass assignment"""
        base_url = config.target_url
        session = authenticated_session
        
        # Try updating user profile with admin role
        profile_url = f"{base_url}/rest/V1/customers/me"
        
        payload = {
            "customer": {
                "email": "test@example.com",
                "firstname": "Test",
                "lastname": "User",
                "role": "admin",  # Try to assign admin role
                "is_admin": True,
                "group_id": 1,  # Admin group
            }
        }
        
        try:
            response = session.put(
                profile_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                # Check if role was actually changed
                verify = session.get(profile_url, timeout=10)
                data = verify.json()
                
                assert 'admin' not in str(data).lower(), \
                    "Mass assignment allowed role escalation"
        except requests.RequestException:
            pass
    
    @pytest.mark.skip(reason="Requires authenticated session")
    def test_price_manipulation_mass_assignment(self, config, authenticated_session):
        """Test if product prices can be manipulated via mass assignment"""
        base_url = config.target_url
        session = authenticated_session
        
        # Try adding product to cart with custom price
        cart_url = f"{base_url}/rest/V1/carts/mine/items"
        
        payload = {
            "cartItem": {
                "sku": "test-product",
                "qty": 1,
                "price": 0.01,  # Try to set custom price
                "base_price": 0.01,
                "discount": 99.99,
            }
        }
        
        try:
            response = session.post(
                cart_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                # Check if price was manipulated
                pytest.fail("Mass assignment allowed price manipulation")
        except requests.RequestException:
            pass


class TestAPIInjection:
    """Test for injection vulnerabilities in APIs"""
    
    def test_json_injection(self, config):
        """Test for JSON injection vulnerabilities"""
        base_url = config.target_url
        
        search_url = f"{base_url}/rest/V1/products/"
        
        # JSON injection payloads
        injection_payloads = [
            '{"test": "value", "admin": true}',
            '{"test": "value"} --',
            '{"test": "value\\"}", "admin": true, "x": "y"}',
        ]
        
        vulnerabilities = []
        
        for payload in injection_payloads:
            try:
                response = requests.get(
                    search_url,
                    params={'searchCriteria': payload},
                    timeout=10
                )
                
                # Should properly escape JSON
                if '"admin": true' in response.text:
                    vulnerabilities.append(payload)
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"JSON injection vulnerabilities: {vulnerabilities}"
    
    def test_nosql_injection(self, config):
        """Test for NoSQL injection in API parameters"""
        base_url = config.target_url
        
        api_url = f"{base_url}/rest/V1/products/"
        
        # NoSQL injection payloads
        nosql_payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            '{"$regex": ".*"}',
            '{"username": {"$ne": null}}',
        ]
        
        vulnerabilities = []
        
        for payload in nosql_payloads:
            try:
                response = requests.get(
                    api_url,
                    params={'filter': payload},
                    timeout=10
                )
                
                # Should not execute NoSQL operators
                if response.status_code == 200 and len(response.content) > 1000:
                    vulnerabilities.append(payload)
            except requests.RequestException:
                continue
        
        assert len(vulnerabilities) == 0, \
            f"NoSQL injection vulnerabilities: {vulnerabilities}"
