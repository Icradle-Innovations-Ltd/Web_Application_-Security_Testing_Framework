"""
Common test fixtures and utilities for web application security tests
"""

import pytest
import requests
from typing import Generator
import sys
from pathlib import Path

# Add tests directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config


@pytest.fixture
def config():
    """Provide Config instance to tests"""
    return Config


@pytest.fixture
def target_url() -> str:
    """Get target URL"""
    return Config.TARGET_URL


@pytest.fixture
def session() -> Generator[requests.Session, None, None]:
    """Create a requests session with proper configuration"""
    s = requests.Session()
    # Note: timeout should be set per request, not on session object
    
    # Set proxy if configured
    proxies = Config.get_proxies()
    if proxies:
        s.proxies.update(proxies)
    
    yield s
    s.close()


@pytest.fixture
def test_credentials():
    """Get test credentials (never use real credentials)"""
    return {
        "username": Config.TEST_USERNAME,
        "password": Config.TEST_PASSWORD,
        "email": Config.TEST_EMAIL,
    }


def check_sql_error(response_text: str) -> tuple[bool, str]:
    """
    Check if response contains SQL error patterns
    
    Returns:
        (found, error_pattern)
    """
    sql_errors = [
        "sql syntax", "mysql", "postgresql", "microsoft sql",
        "odbc", "jdbc", "oracle", "sqlite", "syntax error"
    ]
    
    response_lower = response_text.lower()
    for pattern in sql_errors:
        if pattern in response_lower:
            return True, pattern
    
    return False, ""


def check_xss_reflected(response_text: str, payload: str) -> bool:
    """Check if XSS payload is reflected in response"""
    return payload in response_text
