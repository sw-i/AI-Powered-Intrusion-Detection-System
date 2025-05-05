#!/usr/bin/env python
"""
Run the dashboard with enhanced debuggability for UI issues
"""
import os
import sys
import webbrowser
import threading
import time
import json

# Add the parent directory to the Python path so imports work correctly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the dashboard app after fixing the path
try:
    from scripts.dashboard import app
except ImportError:
    # If running from within the scripts directory
    try:
        from dashboard import app
    except ImportError:
        print("Error: Could not import the dashboard app.")
        sys.exit(1)

def open_browser():
    """Open the browser after a short delay"""
    time.sleep(1.5)
    webbrowser.open('http://localhost:5000')

if __name__ == "__main__":
    print("Starting AI-Powered IDS Dashboard...")
    print("Debug mode enabled for UI troubleshooting")
    
    # Create data directory if it doesn't exist
    os.makedirs('data', exist_ok=True)
    
    # Ensure empty dashboard_stats.json exists
    stats_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard_stats.json")
    with open(stats_file_path, "w") as f:
        json.dump({
            'total_packets': 0,
            'normal_packets': 0,
            'attack_packets': 0,
            'recent_alerts': []
        }, f)
    
    print(f"Initialized dashboard_stats.json at {stats_file_path}")
    
    # Open browser automatically
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run the Flask app in debug mode to easily catch errors
    app.run(debug=True, host='0.0.0.0', port=5000) 