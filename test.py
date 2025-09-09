#!/usr/bin/env python3
print("Script starting...")
try:
    import sys
    print("Imported sys")
    import os
    print("Imported os")
    from selenium.webdriver.chrome.options import Options
    print("Imported selenium")
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    print("Added current directory to path")
    import modules.scanner as scanner
    print("Imported scanner")
    try:
        import modules.tools
        print("Imported tools")
    except ImportError:
        print("tools module not found. Please ensure tools.py exists in the project directory.")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
