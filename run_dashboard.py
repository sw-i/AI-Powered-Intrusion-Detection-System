#!/usr/bin/env python3
"""
AI-Powered IDS Dashboard Runner

This script launches the IDS dashboard for easy access.
"""
import subprocess
import os
import sys
import webbrowser
import time
import platform

def main():
    print("Starting AI-Powered IDS Dashboard...")
    
    # Use our new app.py script instead of scripts/dashboard.py
    app_path = "app.py"
    
    # Launch the dashboard in a new process
    if platform.system() == "Windows":
        proc = subprocess.Popen([sys.executable, app_path], 
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        proc = subprocess.Popen([sys.executable, app_path])
    
    # Wait a moment for the server to start
    print("Dashboard starting up, please wait...")
    time.sleep(3)
    
    # Open the browser
    try:
        webbrowser.open("http://localhost:5000")
        print("Dashboard opened in your web browser.")
        print("If the page did not open, navigate to: http://localhost:5000")
    except Exception as e:
        print(f"Could not open browser automatically: {e}")
        print("Please navigate to: http://localhost:5000")

    print("\nPress Ctrl+C to stop the dashboard when finished.")
    
    try:
        # Keep the script running until the user interrupts
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Terminate the dashboard process
        proc.terminate()
        print("\nDashboard stopped. Thank you for using AI-Powered IDS!")

if __name__ == "__main__":
    main() 