#!/usr/bin/env python3
"""
Generate a summary of all security tests and their current status
"""

from pathlib import Path
import ast
import json


def analyze_test_file(file_path):
    """Extract test information from a Python test file"""
    with open(file_path, 'r') as f:
        content = f.read()
    
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return None
    
    tests = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith('test_'):
            # Get docstring
            docstring = ast.get_docstring(node) or "No description"
            
            # Check if test is skipped
            skipped = False
            skip_reason = ""
            for decorator in node.decorator_list:
                if isinstance(decorator, ast.Attribute):
                    if decorator.attr == 'skip':
                        skipped = True
                elif isinstance(decorator, ast.Call):
                    if hasattr(decorator.func, 'attr') and decorator.func.attr == 'skip':
                        skipped = True
                        # Try to extract reason
                        for keyword in decorator.keywords:
                            if keyword.arg == 'reason':
                                if isinstance(keyword.value, ast.Constant):
                                    skip_reason = keyword.value.value
            
            tests.append({
                'name': node.name,
                'description': docstring,
                'skipped': skipped,
                'skip_reason': skip_reason
            })
    
    return tests


def generate_summary():
    """Generate summary of all tests"""
    test_dir = Path('tests')
    
    categories = {}
    total_tests = 0
    total_skipped = 0
    
    for test_file in test_dir.rglob('test_*.py'):
        category = test_file.parent.name
        if category not in categories:
            categories[category] = []
        
        tests = analyze_test_file(test_file)
        if tests:
            total_tests += len(tests)
            total_skipped += sum(1 for t in tests if t['skipped'])
            categories[category].append({
                'file': test_file.name,
                'tests': tests
            })
    
    # Generate markdown report
    report = ["# Web Application Security Test Suite Summary\n"]
    report.append(f"**Total Tests:** {total_tests}")
    report.append(f"**Implemented:** {total_tests - total_skipped}")
    report.append(f"**Pending:** {total_skipped}\n")
    
    for category, files in sorted(categories.items()):
        report.append(f"## {category.upper()} Tests\n")
        
        for file_info in files:
            report.append(f"### {file_info['file']}\n")
            
            for test in file_info['tests']:
                status = "⏭️ SKIPPED" if test['skipped'] else "✅ ACTIVE"
                report.append(f"- **{status}** `{test['name']}`")
                report.append(f"  - {test['description']}")
                if test['skip_reason']:
                    report.append(f"  - *Reason:* {test['skip_reason']}")
                report.append("")
    
    # Write report
    with open('TEST_SUMMARY.md', 'w') as f:
        f.write('\n'.join(report))
    
    print("✓ Test summary generated: TEST_SUMMARY.md")
    
    # Also generate JSON
    with open('test_summary.json', 'w') as f:
        json.dump({
            'total_tests': total_tests,
            'implemented': total_tests - total_skipped,
            'pending': total_skipped,
            'categories': categories
        }, f, indent=2)
    
    print("✓ JSON summary generated: test_summary.json")
    print(f"\n📊 Stats: {total_tests} total tests, {total_tests - total_skipped} active, {total_skipped} pending")


if __name__ == '__main__':
    generate_summary()
