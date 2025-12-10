#!/usr/bin/env python3
"""
Quick test runner for web application security tests
Run specific vulnerability categories or all tests
"""

import sys
import subprocess
from pathlib import Path


def run_tests(category=None, verbose=True, html_report=False):
    """Run security tests"""
    
    cmd = ["pytest"]
    
    if category:
        test_path = f"tests/{category}/"
        if not Path(test_path).exists():
            print(f"❌ Test category '{category}' not found")
            print(f"Available: xss, sqli, auth, access, upload, api, logic, injection, client")
            return 1
        cmd.append(test_path)
    else:
        cmd.append("tests/")
    
    if verbose:
        cmd.append("-v")
    
    if html_report:
        cmd.extend(["--html=reports/test_report.html", "--self-contained-html"])
    
    cmd.extend(["-s", "--tb=short"])
    
    print(f"🔍 Running: {' '.join(cmd)}\n")
    return subprocess.call(cmd)


if __name__ == "__main__":
    categories = {
        "xss": "Cross-Site Scripting tests",
        "sqli": "SQL Injection tests",
        "auth": "Authentication tests",
        "access": "Access Control & IDOR tests",
        "upload": "File Upload vulnerability tests",
        "api": "API Security tests",
        "logic": "Business Logic tests",
        "injection": "SSRF & Injection tests",
        "client": "Client-Side Security tests",
        "all": "All security tests",
    }
    
    if len(sys.argv) > 1:
        category = sys.argv[1].lower()
        if category == "all":
            category = None
        elif category not in categories:
            print(f"❌ Unknown category: {category}")
            print(f"\nAvailable categories:")
            for cat, desc in categories.items():
                print(f"  {cat:10} - {desc}")
            sys.exit(1)
    else:
        print("🎯 Web Application Security Test Runner\n")
        print("Available test categories:")
        for cat, desc in categories.items():
            print(f"  {cat:10} - {desc}")
        print(f"\nUsage: python run_tests.py [category] [--html]")
        print(f"Example: python run_tests.py xss")
        print(f"Example: python run_tests.py all --html")
        sys.exit(0)
    
    html = "--html" in sys.argv
    exit_code = run_tests(category, verbose=True, html_report=html)
    sys.exit(exit_code)
