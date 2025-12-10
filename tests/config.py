"""
Configuration loader for web application security tests
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Centralized configuration"""
    
    # Target
    TARGET_URL = os.getenv("TARGET_URL", "https://example.com")
    
    # Authentication
    TEST_USERNAME = os.getenv("TEST_USERNAME", "")
    TEST_PASSWORD = os.getenv("TEST_PASSWORD", "")
    TEST_EMAIL = os.getenv("TEST_EMAIL", "")
    
    # Test settings
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
    DELAY_BETWEEN_REQUESTS = float(os.getenv("DELAY_BETWEEN_REQUESTS", "0.5"))
    
    # Report settings
    REPORT_OUTPUT_DIR = os.getenv("REPORT_OUTPUT_DIR", "reports")
    REPORT_FORMAT = os.getenv("REPORT_FORMAT", "both")
    
    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "logs/security_tests.log")
    
    # Proxy (for intercepting tools)
    HTTP_PROXY = os.getenv("HTTP_PROXY", "")
    HTTPS_PROXY = os.getenv("HTTPS_PROXY", "")
    
    # Test scope
    ENABLE_AGGRESSIVE_TESTS = os.getenv("ENABLE_AGGRESSIVE_TESTS", "false").lower() == "true"
    ENABLE_TIME_BASED_TESTS = os.getenv("ENABLE_TIME_BASED_TESTS", "false").lower() == "true"
    ENABLE_DESTRUCTIVE_TESTS = os.getenv("ENABLE_DESTRUCTIVE_TESTS", "false").lower() == "true"
    
    # Rate limiting
    REQUESTS_PER_SECOND = int(os.getenv("REQUESTS_PER_SECOND", "2"))
    MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "5"))
    
    @classmethod
    def get_proxies(cls):
        """Get proxy configuration for requests"""
        if cls.HTTP_PROXY or cls.HTTPS_PROXY:
            return {
                "http": cls.HTTP_PROXY,
                "https": cls.HTTPS_PROXY,
            }
        return None
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        if not cls.TARGET_URL:
            raise ValueError("TARGET_URL must be set")
        
        if cls.ENABLE_DESTRUCTIVE_TESTS:
            print("⚠️  WARNING: Destructive tests enabled!")
            response = input("Are you sure? (yes/no): ")
            if response.lower() != "yes":
                raise RuntimeError("Destructive tests cancelled by user")


# Validate on import
Config.validate()
