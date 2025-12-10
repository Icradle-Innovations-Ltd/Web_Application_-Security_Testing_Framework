"""
SQL Injection Security Tests for Web Applications

AUTHORIZATION: Ethical security testing only
SCOPE: Search, filters, product IDs, category parameters
"""

import pytest
import requests
from typing import List
import os
import time
from dotenv import load_dotenv

load_dotenv()

TARGET_URL = os.getenv("TARGET_URL", "https://example.com")

# SQL Injection Payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or '1'='1--",
    "') or ('1'='1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT NULL,NULL,NULL--",
]

# Time-based SQL injection payloads
TIME_BASED_PAYLOADS = [
    "'; WAITFOR DELAY '00:00:05'--",  # MSSQL
    "' OR SLEEP(5)--",  # MySQL
    "' OR pg_sleep(5)--",  # PostgreSQL
    "1' AND SLEEP(5)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]

# Error-based detection strings
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "postgresql",
    "microsoft sql",
    "odbc",
    "jdbc",
    "oracle",
    "sqlite",
    "syntax error",
    "unexpected end of sql",
    "warning: mysql",
    "pg_query",
    "valid mysql result",
]


class TestSQLInjectionBasic:
    """Basic SQL injection tests"""
    
    def test_search_parameter_sqli(self):
        """Test if search parameter is vulnerable to SQL injection"""
        for payload in SQLI_PAYLOADS[:5]:  # Test subset
            response = requests.get(
                f"{TARGET_URL}/catalog/",
                params={"q": payload},
                timeout=10
            )
            
            # Check for SQL errors in response
            response_lower = response.text.lower()
            for error_pattern in SQL_ERROR_PATTERNS:
                if error_pattern in response_lower:
                    print(f"\n⚠️  POTENTIAL SQL INJECTION in search parameter")
                    print(f"Payload: {payload}")
                    print(f"Error pattern found: {error_pattern}")
                    print(f"URL: {response.url}")
                    assert False, f"SQL error exposed: {error_pattern}"
    
    def test_product_id_sqli(self):
        """Test if product ID parameters are vulnerable"""
        test_product_ids = ["1' OR '1'='1", "1' AND '1'='2", "1' UNION SELECT NULL--"]
        
        for payload in test_product_ids:
            # Test common product URL patterns
            test_urls = [
                f"{TARGET_URL}/product/{payload}/",
                f"{TARGET_URL}/catalog/?product_id={payload}",
            ]
            
            for url in test_urls:
                try:
                    response = requests.get(url, timeout=10)
                    response_lower = response.text.lower()
                    
                    for error_pattern in SQL_ERROR_PATTERNS:
                        if error_pattern in response_lower:
                            print(f"\n⚠️  SQL INJECTION in product ID")
                            print(f"URL: {url}")
                            print(f"Error: {error_pattern}")
                            assert False, f"SQL error in product ID: {error_pattern}"
                except requests.exceptions.RequestException:
                    continue
    
    def test_category_filter_sqli(self):
        """Test category and filter parameters for SQL injection"""
        filter_params = ["category", "price", "brand", "sort", "page"]
        
        for param in filter_params:
            payload = "1' OR '1'='1--"
            response = requests.get(
                f"{TARGET_URL}/catalog/",
                params={param: payload},
                timeout=10
            )
            
            response_lower = response.text.lower()
            for error_pattern in SQL_ERROR_PATTERNS:
                if error_pattern in response_lower:
                    print(f"\n⚠️  SQL INJECTION in {param} parameter")
                    print(f"Payload: {payload}")
                    assert False, f"SQL error in {param}"


class TestTimeBasedSQLI:
    """Time-based blind SQL injection tests"""
    
    def test_time_based_sqli_search(self):
        """Test for time-based SQL injection in search"""
        baseline_times: List[float] = []
        
        # Establish baseline response time
        for _ in range(3):
            start = time.time()
            requests.get(f"{TARGET_URL}/catalog/", params={"q": "test"}, timeout=15)
            baseline_times.append(time.time() - start)
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        
        # Test time-based payloads
        for payload in TIME_BASED_PAYLOADS[:2]:  # Test subset
            start = time.time()
            try:
                response = requests.get(
                    f"{TARGET_URL}/catalog/",
                    params={"q": payload},
                    timeout=15
                )
                elapsed = time.time() - start
                
                # If response takes significantly longer (>4 seconds more)
                if elapsed > avg_baseline + 4:
                    print(f"\n⚠️  POTENTIAL TIME-BASED SQL INJECTION")
                    print(f"Payload: {payload}")
                    print(f"Response time: {elapsed:.2f}s vs baseline: {avg_baseline:.2f}s")
                    assert False, "Time-based SQL injection detected"
            except requests.exceptions.Timeout:
                print(f"\n⚠️  REQUEST TIMEOUT - Possible time-based SQLi")
                print(f"Payload: {payload}")


class TestUnionBasedSQLI:
    """UNION-based SQL injection tests"""
    
    def test_union_select_detection(self):
        """Test for UNION SELECT vulnerabilities"""
        # Test increasing number of columns
        for col_count in range(1, 10):
            null_string = ",".join(["NULL"] * col_count)
            payload = f"1' UNION SELECT {null_string}--"
            
            response = requests.get(
                f"{TARGET_URL}/catalog/",
                params={"q": payload},
                timeout=10
            )
            
            # Check if UNION was successful (different content length or patterns)
            if "null" in response.text.lower() or len(response.text) > 50000:
                print(f"\n⚠️  POTENTIAL UNION-BASED SQL INJECTION")
                print(f"Column count: {col_count}")
                print(f"Payload: {payload}")


class TestAuthenticationBypass:
    """Test SQL injection in authentication contexts"""
    
    @pytest.mark.skip(reason="Requires login form identification")
    def test_login_sqli_bypass(self):
        """Test if login can be bypassed with SQL injection"""
        # TODO: Implement after identifying login endpoint
        pass


class TestErrorBasedSQLI:
    """Error-based SQL injection detection"""
    
    def test_deliberate_sql_errors(self):
        """Test if deliberate syntax errors reveal SQL details"""
        error_payloads = [
            "'",
            "''",
            "\"",
            "1'",
            "1\"",
            "1`",
        ]
        
        for payload in error_payloads:
            response = requests.get(
                f"{TARGET_URL}/catalog/",
                params={"q": payload},
                timeout=10
            )
            
            response_lower = response.text.lower()
            for error_pattern in SQL_ERROR_PATTERNS:
                if error_pattern in response_lower:
                    print(f"\n⚠️  SQL ERROR DISCLOSURE")
                    print(f"Payload: {payload}")
                    print(f"Error pattern: {error_pattern}")
                    print("Recommendation: Implement proper error handling")


def test_prepared_statements():
    """Verify if prepared statements/parameterized queries are used"""
    # This is a passive check - look for evidence of proper escaping
    test_chars = ["'", "\"", "--", "#", "/*"]
    
    results: List[bool] = []
    for char in test_chars:
        response = requests.get(
            f"{TARGET_URL}/catalog/",
            params={"q": char},
            timeout=10
        )
        
        # If special chars are properly escaped, they should appear in results
        # without causing errors
        if char in response.text and not any(err in response.text.lower() for err in SQL_ERROR_PATTERNS):
            results.append(True)
        else:
            results.append(False)
    
    if all(results):
        print("\n✓ Special characters appear to be properly handled")
    else:
        print("\n⚠️  Some special characters may not be properly escaped")
