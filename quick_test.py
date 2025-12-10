#!/usr/bin/env python3
"""Run tests and show summary"""

import subprocess
import sys

result = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=line"],
    capture_output=False
)

sys.exit(result.returncode)
