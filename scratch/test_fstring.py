import sys

code = '''
def foo(prog_name):
    return f"""
    Examples:
      {prog_name} evidence list FH-2026-001
      {prog_name} evidence show EV-2026-0001
    """
'''

try:
    compile(code, "test.py", "exec")
    print("Compiled successfully!")
except Exception as e:
    print("Error:", type(e), e)
