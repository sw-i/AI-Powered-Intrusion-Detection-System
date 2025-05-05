#!/usr/bin/env python3
"""
AI-Powered IDS Dashboard - Flask App
"""
import os
import sys
import json
import uuid
import random
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash

# Remove scripts directory from sys.path and all scripts.dashboard imports
# All backend logic is now self-contained in this file or imported as needed

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Global variables for monitoring state
monitoring_active = False
refresh_interval = None

# Global traffic stats
traffic_stats = {
    'total_packets': 0,
    'safe_packets': 0,
    'threat_packets': 0,
    'suspicious_packets': 0,
    'traffic_labels': ['00:00', '00:05', '00:10', '00:15', '00:20', '00:25'],
    'traffic_data': [0, 0, 0, 0, 0, 0],
    'attack_types': {'DoS': 3, 'Port Scan': 2, 'Brute Force': 1, 'SQL Injection': 0},
    'sources': {'192.168.1.100': 2, '10.0.0.15': 3, '172.16.0.8': 1},
    'timeline_labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    'timeline_data': [2, 5, 3, 0, 1, 4, 2],
    'alerts': []
}

#
# Route handlers
#

@app.route('/')
def index():
    """Render the main dashboard page"""
    return render_template('dashboard.html', 
                          active_page="dashboard",
                          monitoring_active=monitoring_active,
                          stats=traffic_stats)

@app.route('/analytics')
def analytics():
    """Render the analytics page"""
    # Get hourly traffic data
    hourly_data = {
        'labels': [f"{i}:00" for i in range(24)],
        'values': [random.randint(50, 200) for _ in range(24)]
    }
    
    # Get attack distribution data 
    attack_distribution = {
        'dos': random.randint(5, 15),
        'port_scan': random.randint(8, 20),
        'brute_force': random.randint(3, 10),
        'sql_injection': random.randint(1, 5),
        'xss': random.randint(1, 3),
        'other': random.randint(2, 8)
    }
    
    # Get traffic sources data
    traffic_sources = {
        'internal': random.randint(40, 80),
        'external': random.randint(20, 50),
        'unknown': random.randint(5, 15)
    }
    
    # Get weekly attack timeline
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    attack_timeline = [random.randint(3, 20) for _ in range(7)]
    
    return render_template('analytics.html',
                          active_page="analytics",
                          hourly_traffic=hourly_data,
                          attack_distribution=attack_distribution,
                          traffic_sources=traffic_sources,
                          days=days,
                          attack_timeline=attack_timeline)

@app.route('/threats')
def threats():
    """Render the threats page"""
    # Get sample threats data
    threats_data = generate_sample_threats()
    
    return render_template('threats.html',
                          active_page="threats",
                          threats=threats_data)

@app.route('/settings')
def settings():
    """Render the settings page"""
    # Load system settings
    system_settings = load_settings()
    
    return render_template('settings.html',
                          active_page="settings",
                          settings=system_settings)

@app.route('/api-docs')
def api_docs():
    """Render the API documentation/help page"""
    return render_template('api_docs.html', active_page="api_docs")

#
# API endpoints for AJAX calls
#

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start the monitoring process"""
    global monitoring_active
    
    try:
        # Start the detector process
        start_detector()
        monitoring_active = True
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop the monitoring process"""
    global monitoring_active
    
    try:
        # Stop the detector process
        stop_detector()
        monitoring_active = False
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/clear_data', methods=['POST'])
def clear_data():
    """Clear all collected data"""
    global traffic_stats
    
    try:
        # Clear statistics
        clear_statistics()
        
        # Reset traffic stats
        traffic_stats = {
            'total_packets': 0,
            'safe_packets': 0,
            'threat_packets': 0,
            'suspicious_packets': 0,
            'traffic_labels': ['00:00', '00:05', '00:10', '00:15', '00:20', '00:25'],
            'traffic_data': [0, 0, 0, 0, 0, 0],
            'attack_types': {'DoS': 0, 'Port Scan': 0, 'Brute Force': 0, 'SQL Injection': 0},
            'sources': {},
            'timeline_labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            'timeline_data': [0, 0, 0, 0, 0, 0, 0],
            'alerts': []
        }
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/reset_system', methods=['POST'])
def reset_system():
    """Reset the entire system"""
    global monitoring_active, traffic_stats
    
    try:
        # Stop monitoring if active
        if monitoring_active:
            stop_detector()
            monitoring_active = False
        
        # Clear all data
        clear_statistics()
        
        # Reset traffic stats
        traffic_stats = {
            'total_packets': 0,
            'safe_packets': 0,
            'threat_packets': 0,
            'suspicious_packets': 0,
            'traffic_labels': ['00:00', '00:05', '00:10', '00:15', '00:20', '00:25'],
            'traffic_data': [0, 0, 0, 0, 0, 0],
            'attack_types': {'DoS': 0, 'Port Scan': 0, 'Brute Force': 0, 'SQL Injection': 0},
            'sources': {},
            'timeline_labels': ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            'timeline_data': [0, 0, 0, 0, 0, 0, 0],
            'alerts': []
        }
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/stats')
def get_stats():
    """Get current system stats"""
    global traffic_stats, monitoring_active
    
    # Update stats with some random data for demo purposes
    if monitoring_active:
        now = datetime.now().strftime('%H:%M')
        # Update traffic data
        traffic_stats['traffic_labels'].append(now)
        traffic_stats['traffic_labels'] = traffic_stats['traffic_labels'][-6:]
        traffic_stats['traffic_data'].append(traffic_stats['traffic_data'][-1] + random.randint(1, 5))
        traffic_stats['traffic_data'] = traffic_stats['traffic_data'][-6:]
        
        # Update packet counts
        traffic_stats['total_packets'] += random.randint(1, 5)
        traffic_stats['safe_packets'] += random.randint(1, 3)
        traffic_stats['threat_packets'] += random.randint(0, 1)
        traffic_stats['suspicious_packets'] += random.randint(0, 1)
        
        # Randomly add an alert
        if random.random() < 0.3:  # 30% chance of new alert
            alert_types = ['DoS', 'Port Scan', 'Brute Force', 'SQL Injection']
            alert_type = random.choice(alert_types)
            source_ip = f"192.168.1.{random.randint(1, 255)}"
            dest_ip = f"10.0.0.{random.randint(1, 255)}"
            protocols = ['TCP', 'UDP', 'ICMP', 'HTTP']
            
            alert = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'type': alert_type,
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'protocol': random.choice(protocols),
                'status': 'Blocked' if random.random() < 0.7 else 'Alert'
            }
            
            traffic_stats['alerts'].append(alert)
            traffic_stats['alerts'] = traffic_stats['alerts'][-5:]  # Keep only 5 latest alerts
            
            # Update attack types
            traffic_stats['attack_types'][alert_type] += 1
            
            # Update sources
            if source_ip in traffic_stats['sources']:
                traffic_stats['sources'][source_ip] += 1
            else:
                traffic_stats['sources'][source_ip] = 1
        
        # Generate packet details data for display
        packet_details = generate_packet_details(5)  # Generate 5 new packets
        if 'packets' not in traffic_stats:
            traffic_stats['packets'] = []
        
        # Add new packets to the beginning of the list
        traffic_stats['packets'] = packet_details + traffic_stats['packets']
        # Keep only the latest 50 packets
        traffic_stats['packets'] = traffic_stats['packets'][:50]
    
    # Add monitoring state to the response
    response = traffic_stats.copy()
    response['monitoring_active'] = monitoring_active
    
    return jsonify(response)

def generate_packet_details(count=1):
    """Generate synthetic packet details for display"""
    packet_types = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SMTP']
    statuses = ['Safe', 'Threat', 'Suspicious']
    weighted_statuses = ['Safe', 'Safe', 'Safe', 'Safe', 'Threat', 'Suspicious']  # Weighted for more safe packets
    packets = []
    
    for _ in range(count):
        now = datetime.now()
        timestamp = now.strftime('%H:%M:%S')
        source_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dest_ip = f"10.0.0.{random.randint(1, 255)}"
        protocol = random.choice(packet_types)
        size = random.randint(64, 1500)  # Typical packet sizes
        port = random.randint(1, 65535)
        status = random.choice(weighted_statuses)
        
        packets.append({
            'timestamp': timestamp,
            'sourceIp': source_ip,
            'destIp': dest_ip,
            'protocol': protocol,
            'size': size,
            'port': port,
            'status': status
        })
    
    return packets

@app.route('/api/analytics/data')
def get_analytics_data():
    """Get data for analytics charts"""
    # Generate hourly traffic data
    hourly_traffic = {
        'labels': [f"{i}:00" for i in range(24)],
        'values': [random.randint(50, 200) for _ in range(24)]
    }
    
    # Generate attack distribution
    attack_distribution = {
        'dos': random.randint(5, 15),
        'port_scan': random.randint(8, 20),
        'brute_force': random.randint(3, 10),
        'sql_injection': random.randint(1, 5),
        'xss': random.randint(1, 3),
        'other': random.randint(2, 8)
    }
    
    # Generate traffic sources
    traffic_sources = {
        'internal': random.randint(40, 80),
        'external': random.randint(20, 50),
        'unknown': random.randint(5, 15)
    }
    
    # Generate attack timeline
    attack_timeline = [random.randint(3, 20) for _ in range(7)]
    
    return jsonify({
        'hourly_traffic': hourly_traffic,
        'attack_distribution': attack_distribution,
        'traffic_sources': traffic_sources,
        'attack_timeline': attack_timeline
    })

@app.route('/api/threats/block', methods=['POST'])
def block_threat():
    """Block a threatening IP address"""
    data = request.json
    ip = data.get('ip')
    
    if not ip:
        return jsonify({'success': False, 'error': 'No IP address provided'})
    
    # Simulate blocking the IP
    time.sleep(0.5)  # Simulate processing time
    
    return jsonify({
        'success': True,
        'message': f'IP {ip} has been blocked',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/api/system/settings', methods=['GET', 'POST'])
def system_settings():
    """Get or update system settings"""
    if request.method == 'POST':
        # Update settings
        settings = request.json
        
        # Validate settings
        if 'auto_reset' not in settings or 'detection_sensitivity' not in settings or 'log_level' not in settings or 'refresh_rate' not in settings:
            return jsonify({'success': False, 'error': 'Missing required settings'})
        
        # Save settings (in a real app this would write to a file or database)
        current_settings = load_settings()
        current_settings.update(settings)
        
        # In a real app, save to file/database here
        
        return jsonify({'success': True})
    else:
        # Get current settings
        settings = load_settings()
        return jsonify({'settings': settings})

@app.route('/api/threats')
def get_threats():
    """Get list of detected threats"""
    threats = generate_sample_threats()
    return jsonify({'threats': threats})

@app.route('/api/simulate/dos', methods=['POST'])
def simulate_dos_attack():
    """Simulate a DoS attack for demonstration purposes"""
    try:
        # Get target IP if provided or use default
        data = request.json or {}
        target_ip = data.get('target_ip', '10.0.0.1')
        packets = data.get('packets', 100)
        
        # Call simulate_dos function
        result = simulate_dos(target_ip, packets)
        
        return jsonify({
            'success': True,
            'message': f'DoS attack simulation initiated against {target_ip}',
            'details': result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/simulate/port_scan', methods=['POST'])
def simulate_port_scan_attack():
    """Simulate a Port Scan attack for demonstration purposes"""
    try:
        # Get target IP if provided or use default
        data = request.json or {}
        target_ip = data.get('target_ip', '10.0.0.1')
        ports = data.get('ports', 20)
        
        # Call simulate_port_scan function
        result = simulate_port_scan(target_ip, ports)
        
        return jsonify({
            'success': True,
            'message': f'Port Scan simulation initiated against {target_ip}',
            'details': result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/simulate/brute_force', methods=['POST'])
def simulate_brute_force_attack():
    """Simulate a Brute Force attack for demonstration purposes"""
    try:
        # Get target IP if provided or use default
        data = request.json or {}
        target_ip = data.get('target_ip', '10.0.0.1')
        attempts = data.get('attempts', 10)
        
        # Call simulate_brute_force function
        result = simulate_brute_force(target_ip, attempts)
        
        return jsonify({
            'success': True,
            'message': f'Brute Force attack simulation initiated against {target_ip}',
            'details': result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def generate_sample_threats():
    """Generate sample threat data for demo purposes"""
    threats = [
        {
            'id': 'threat-001',
            'timestamp': (datetime.now() - timedelta(minutes=15)).strftime("%H:%M:%S"),
            'ip': '192.168.1.105',
            'type': 'Port Scan',
            'severity': 'Low',
            'status': 'Investigating'
        },
        {
            'id': 'threat-002',
            'timestamp': (datetime.now() - timedelta(minutes=25)).strftime("%H:%M:%S"),
            'ip': '45.33.49.78',
            'type': 'SQL Injection',
            'severity': 'High',
            'status': 'Active'
        },
        {
            'id': 'threat-003',
            'timestamp': (datetime.now() - timedelta(hours=2)).strftime("%H:%M:%S"),
            'ip': '172.16.23.45',
            'type': 'Port Scan',
            'severity': 'Medium',
            'status': 'Mitigated'
        },
        {
            'id': 'threat-004',
            'timestamp': (datetime.now() - timedelta(minutes=5)).strftime("%H:%M:%S"),
            'ip': '10.45.12.85',
            'type': 'XSS',
            'severity': 'Medium',
            'status': 'Active'
        },
        {
            'id': 'threat-005',
            'timestamp': (datetime.now() - timedelta(minutes=1)).strftime("%H:%M:%S"),
            'ip': '192.168.1.87',
            'type': 'Port Scan',
            'severity': 'Low',
            'status': 'Active'
        }
    ]
    
    return threats

def load_settings():
    # Example: load settings from a JSON file
    import json
    try:
        with open('data/system_settings.json') as f:
            return json.load(f)
    except Exception:
        # Return default settings if file is missing or invalid
        return {
            "detection_sensitivity": "medium",
            "refresh_rate": 2000,
            "auto_reset": False,
            "log_level": "info"
        }

def simulate_dos(target_ip, packets):
    # Simulate a DoS attack (stub)
    return {"target_ip": target_ip, "packets": packets, "result": "Simulated DoS"}

def simulate_port_scan(target_ip, ports):
    # Simulate a port scan (stub)
    return {"target_ip": target_ip, "ports": ports, "result": "Simulated Port Scan"}

def simulate_brute_force(target_ip, attempts):
    # Simulate a brute force attack (stub)
    return {"target_ip": target_ip, "attempts": attempts, "result": "Simulated Brute Force"}

def start_detector():
    # Start the IDS detector (stub)
    pass

def stop_detector():
    # Stop the IDS detector (stub)
    pass

def clear_statistics():
    # Clear statistics (stub)
    pass

# Main application entry point
if __name__ == '__main__':
    # Ensure data directory exists
    if not os.path.exists('data'):
        os.makedirs('data')
    
    # Start the Flask app
    app.run(debug=True, host='127.0.0.1', port=5000) 