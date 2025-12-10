#!/usr/bin/env python3
"""Show compact test results"""

import subprocess
import sys

print("🔍 Running All Security Tests...\n")

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=no", "-q"],
    capture_output=True,
    text=True
)

# Parse output
lines = result.stdout.split('\n')
for line in lines:
    if any(x in line for x in ['PASSED', 'FAILED', 'SKIPPED', 'ERROR', '===', 'passed', 'failed', 'error', 'skipped']):
        print(line)

sys.exit(result.returncode)
