import pyshark
import joblib
import numpy as np
import pandas as pd
import csv
from datetime import datetime
from socket import inet_aton
import struct
from collections import defaultdict, deque
import time
import json
import os
import random

# Create data directory if it doesn't exist
os.makedirs('data', exist_ok=True)

# Load model and scaler
model = joblib.load("models/rf_ids_model.pkl")
scaler = joblib.load("models/scaler.pkl")
label_encoders = joblib.load("models/label_encoders.pkl")

# Print available classes to see format
print("Protocol classes:", label_encoders['protocol_type'].classes_)
print("Service classes:", label_encoders['service'].classes_)
print("Flag classes:", label_encoders['flag'].classes_)

# Map network services to KDD dataset services
# The first few common ones
SERVICE_MAP = {
    'http': 'http',
    'https': 'http_443',
    'ftp': 'ftp',
    'ssh': 'ssh',
    'telnet': 'telnet',
    'smtp': 'smtp',
    'dns': 'domain'
}

# All features from training
feature_names = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# In-memory tracking of recent activity per IP
ip_activity = defaultdict(lambda: {
    "timestamps": deque(maxlen=60),  # Last minute
    "ports": set(),
    "syn_count": 0,
    "packets": deque(maxlen=100)  # Last 100 packets
})

RECENT_PACKETS_FILE = 'data/recent_packets.json'
MAX_RECENT_PACKETS = 200

AI_TIMELINE_FILE = 'data/ai_timeline.json'
MAX_AI_EVENTS = 200

def append_recent_packet(packet_info):
    try:
        if os.path.exists(RECENT_PACKETS_FILE):
            with open(RECENT_PACKETS_FILE, 'r') as f:
                packets = json.load(f)
        else:
            packets = []
        packets.append(packet_info)
        if len(packets) > MAX_RECENT_PACKETS:
            packets = packets[-MAX_RECENT_PACKETS:]
        with open(RECENT_PACKETS_FILE, 'w') as f:
            json.dump(packets, f)
    except Exception as e:
        print(f"Error appending recent packet: {e}")

def update_ip_stats(pkt, src_ip, dst_port, tcp_flags):
    now = time.time()
    record = ip_activity[src_ip]
    record["timestamps"].append(now)
    record["ports"].add(dst_port)
    if tcp_flags is not None and tcp_flags & 0x02:  # SYN flag
        record["syn_count"] += 1
    record["packets"].append(pkt)
    
    # Calculate rates and statistics
    duration = max(now - min(record["timestamps"]), 1) if record["timestamps"] else 1
    packet_rate = len(record["timestamps"]) / duration
    error_rate = sum(1 for p in record["packets"] if hasattr(p, 'tcp') and p.tcp.flags == '0x02') / len(record["packets"]) if record["packets"] else 0
    
    return {
        'count': len(record["timestamps"]),
        'srv_count': len(record["ports"]),
        'serror_rate': error_rate,
        'srv_serror_rate': error_rate,
        'rerror_rate': 0,
        'srv_rerror_rate': 0,
        'same_srv_rate': 1 if len(record["ports"]) == 1 else 0,
        'diff_srv_rate': 1 if len(record["ports"]) > 1 else 0,
        'srv_diff_host_rate': 0,
        'dst_host_count': len(record["timestamps"]),
        'dst_host_srv_count': len(record["ports"]),
        'dst_host_same_srv_rate': 1 if len(record["ports"]) == 1 else 0,
        'dst_host_diff_srv_rate': 1 if len(record["ports"]) > 1 else 0,
        'dst_host_same_src_port_rate': 1,
        'dst_host_srv_diff_host_rate': 0,
        'dst_host_serror_rate': error_rate,
        'dst_host_srv_serror_rate': error_rate,
        'dst_host_rerror_rate': 0,
        'dst_host_srv_rerror_rate': 0
    }

def extract_features(pkt):
    try:
        duration = 0
        src_bytes = dst_bytes = int(pkt.length)
        land = 0
        wrong_fragment = 0
        urgent = 0
        hot = 0
        num_failed_logins = 0
        logged_in = 0
        num_compromised = 0
        root_shell = 0
        su_attempted = 0
        num_root = 0
        num_file_creations = 0
        num_shells = 0
        num_access_files = 0
        num_outbound_cmds = 0
        is_host_login = 0
        is_guest_login = 0

        if hasattr(pkt, 'ip'):
            src_ip = pkt.ip.src
            src_port = 0
            dst_port = 0
            protocol_name = 'tcp'
            service_name = 'other'
            flag_name = 'OTH'
            tcp_flags = None

            if hasattr(pkt, 'tcp'):
                protocol_name = 'tcp'
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
                tcp_flags = int(pkt.tcp.flags, 16) if hasattr(pkt, 'tcp.flags') else 0
                # Service mapping
                if dst_port == 80:
                    service_name = 'http'
                elif dst_port == 443:
                    service_name = 'http_443'
                elif dst_port == 22:
                    service_name = 'ssh'
                elif dst_port == 21:
                    service_name = 'ftp'
                elif dst_port == 23:
                    service_name = 'telnet'
                elif dst_port == 25:
                    service_name = 'smtp'
                elif dst_port == 53:
                    service_name = 'domain'
                else:
                    service_name = 'other'
                # Flag mapping
                if tcp_flags is not None:
                    if tcp_flags & 0x02 and not (tcp_flags & 0x10):
                        flag_name = 'S0'
                    elif tcp_flags & 0x10:
                        flag_name = 'SF'
                    elif tcp_flags & 0x01:
                        flag_name = 'REJ'
                    elif tcp_flags & 0x04:
                        flag_name = 'RSTO'
                    else:
                        flag_name = 'OTH'
            elif hasattr(pkt, 'udp'):
                protocol_name = 'udp'
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)
                if dst_port == 53:
                    service_name = 'domain_u'
                else:
                    service_name = 'other'
                flag_name = 'SF'
            elif hasattr(pkt, 'icmp'):
                protocol_name = 'icmp'
                service_name = 'eco_i'
                flag_name = 'SF'
            else:
                protocol_name = 'other'
                service_name = 'other'
                flag_name = 'OTH'

            # Encode protocol_type, service, flag
            try:
                protocol_idx = label_encoders['protocol_type'].transform([protocol_name])[0]
            except:
                protocol_idx = 0
            try:
                service_idx = label_encoders['service'].transform([service_name])[0]
            except:
                service_idx = 0
            try:
                flag_idx = label_encoders['flag'].transform([flag_name])[0]
            except:
                flag_idx = 0

            stats = update_ip_stats(pkt, src_ip, dst_port, tcp_flags)
            features = [
                duration, protocol_idx, service_idx, flag_idx, src_bytes, dst_bytes,
                land, wrong_fragment, urgent, hot, num_failed_logins,
                logged_in, num_compromised, root_shell, su_attempted, num_root,
                num_file_creations, num_shells, num_access_files, num_outbound_cmds,
                is_host_login, is_guest_login
            ]
            features.extend([
                stats['count'], stats['srv_count'], stats['serror_rate'],
                stats['srv_serror_rate'], stats['rerror_rate'], stats['srv_rerror_rate'],
                stats['same_srv_rate'], stats['diff_srv_rate'], stats['srv_diff_host_rate'],
                stats['dst_host_count'], stats['dst_host_srv_count'],
                stats['dst_host_same_srv_rate'], stats['dst_host_diff_srv_rate'],
                stats['dst_host_same_src_port_rate'], stats['dst_host_srv_diff_host_rate'],
                stats['dst_host_serror_rate'], stats['dst_host_srv_serror_rate'],
                stats['dst_host_rerror_rate'], stats['dst_host_srv_rerror_rate']
            ])
            # Return all details for dashboard
            return features, src_ip, pkt.ip.dst, src_port, dst_port, protocol_name.upper(), src_bytes, service_name, flag_name, pkt.sniff_time.strftime('%Y-%m-%d %H:%M:%S')
    except AttributeError as e:
        print(f"Error extracting features: {e}")
        return None, None, None, None, None, None, None, None, None, None

# Attack type classification based on features
def classify_attack_type(features, stats, protocol=None):
    # protocol: 'TCP', 'UDP', 'ICMP', etc.
    if protocol is not None and protocol.upper() == 'TCP':
        if stats['serror_rate'] > 0.8:
            return 'SYN Flood'
        elif stats['diff_srv_rate'] > 0.5:
            return 'Port Scan'
        if features[4] > 1000:  # src_bytes
            return 'DoS'
        return 'Suspicious Activity'
    elif protocol is not None and protocol.upper() in ['UDP', 'ICMP']:
        if features[4] > 2000:
            return 'DoS'
        return 'Normal'
    else:
        return 'Normal'

# Log flagged attack to CSV and update dashboard stats
def log_attack(pkt_info, pred, attack_type):
    try:
        # Log to CSV
        with open("data/flagged_attacks.csv", "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                pkt_info[1],  # src_ip
                pkt_info[2],  # dst_ip
                pkt_info[5],  # protocol
                pkt_info[6],  # length
                pred,
                attack_type
            ])

        # Update dashboard stats
        with open("dashboard_stats.json", "w") as f:
            stats = {
                'total_packets': 0,  # Will be updated by dashboard
                'normal_packets': 0,  # Will be updated by dashboard
                'attack_packets': 0,  # Will be updated by dashboard
                'recent_alerts': [{
                    'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'type': attack_type,
                    'source': f"{pkt_info[1]}:{pkt_info[3]}",
                    'destination': f"{pkt_info[2]}:{pkt_info[4]}"
                }]
            }
            json.dump(stats, f)

    except Exception as e:
        print(f"Logging error: {e}")

def log_ai_event(event_type, message, extra=None):
    try:
        if os.path.exists(AI_TIMELINE_FILE):
            with open(AI_TIMELINE_FILE, 'r') as f:
                events = json.load(f)
        else:
            events = []
        event = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'type': event_type,
            'message': message,
        }
        if extra:
            event.update(extra)
        events.append(event)
        if len(events) > MAX_AI_EVENTS:
            events = events[-MAX_AI_EVENTS:]
        with open(AI_TIMELINE_FILE, 'w') as f:
            json.dump(events, f)
    except Exception as e:
        print(f"Error logging AI event: {e}")

# Log model load
log_ai_event('Model', 'AI model loaded', {'version': getattr(model, 'version', 'N/A')})

# In classify(), after each prediction, log:
def classify(pkt):
    result = extract_features(pkt)
    if result is None:
        return  # Skip non-IP packets
        
    features, src_ip, dst_ip, src_port, dst_port, proto, length, service, flag, timestamp = result
    
    df = pd.DataFrame([features], columns=feature_names)
    scaled = scaler.transform(df)
    pred = model.predict(scaled)[0]

    if pred == 'attack':
        # Get statistics for attack classification
        stats = update_ip_stats(pkt, src_ip, dst_port, None)
        attack_type = classify_attack_type(features, stats, proto)
        
        print(f"[{attack_type}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
              f"| Protocol: {proto} | Size: {length} bytes | Service: {service} | Flag: {flag}")

        log_attack((None, src_ip, dst_ip, src_port, dst_port, proto, length, service, flag, timestamp), pred, attack_type)

        packet_details = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'protocol': proto,
            'size': length,
            'service': service,
            'flag': flag,
            'classification': attack_type if pred == 'attack' else 'Normal',
        }
        append_recent_packet(packet_details)

        log_ai_event('Detection', f"{proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} classified as {attack_type if pred == 'attack' else 'Normal'}", {
            'classification': attack_type if pred == 'attack' else 'Normal',
            'protocol': proto,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port
        })
    else:
        print(f"[NORMAL] {src_ip}:{src_port} -> {dst_ip}:{dst_port} "
              f"| Protocol: {proto} | Size: {length} bytes | Service: {service} | Flag: {flag}")

# Start capture
if __name__ == "__main__":
    print(" Starting real-time IDS with smart features...")
    interface = "Ethernet"  # Changed from "Wi-Fi" to "Ethernet"
    cap = pyshark.LiveCapture(interface=interface)
    cap.apply_on_packets(classify)
