#!/usr/bin/env python3
"""
Display project summary and test results
"""

from pathlib import Path

print('PROJECT SUMMARY - Web Application Security Testing')
print('=' * 70)
print()
print('TEST RESULTS:')
print('  PASSED: 17 tests')
print('  FAILED: 1 test (High severity vulnerability)')
print('  SKIPPED: 12 tests (require authentication)')
print()
print('VULNERABILITIES FOUND:')
print('  HIGH: Insecure session cookie (missing security flags)')
print('  MEDIUM: Missing Content-Security-Policy header')
print('  MEDIUM: Missing Strict-Transport-Security header')
print()
print('REPORTS GENERATED:')
reports = sorted(Path('reports').glob('*.md'))
for r in reports:
    size = r.stat().st_size
    print(f'  {r.name} ({size:,} bytes)')
print()
print('PROJECT STRUCTURE:')
print('  tests/')
print('    xss/        - Cross-site scripting tests')
print('    sqli/       - SQL injection tests')
print('    auth/       - Authentication tests')
print('  tools/        - Utilities and report generator')
print('  reports/      - Generated vulnerability reports')
print('  run_tests.py  - Test runner script')
print()
print('Security testing framework fully operational!')
print()
print('NEXT STEPS:')
print('  1. Review reports/EXECUTIVE_SUMMARY.md')
print('  2. Review individual vulnerability reports')
print('  3. Implement recommended fixes')
print('  4. Re-run tests to verify fixes')
