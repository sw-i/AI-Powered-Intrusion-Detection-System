#!/usr/bin/env python3
import csv
import os
import time
import numpy as np
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import pickle
from sklearn.preprocessing import StandardScaler
import joblib

# Protocol mapping
PROTO_MAP = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
SERVICE_MAP = {'http': 80, 'https': 443, 'ftp': 21, 'ssh': 22, 'dns': 53, 'unknown': 0}
FLAG_MAP = {'S': 1, 'A': 2, 'F': 4, 'R': 8, 'P': 16, 'U': 32, 'E': 64, 'C': 128, 'unknown': 0}

# Output files
OUTPUT_DIR = 'data'
MODERN_DATASET = os.path.join(OUTPUT_DIR, 'modern_ids_dataset.csv')
FLAGGED_ATTACKS = os.path.join(OUTPUT_DIR, 'flagged_attacks.csv')
PREPROCESSED_DATA = os.path.join(OUTPUT_DIR, 'modern_preprocessed_data.npz')

# Feature headers (match enhanced model)
FEATURE_HEADERS = [
    'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'time_since_last', 'packet_rate', 'burst_count',
    'unique_ports', 'port_entropy', 'ip_entropy', 'tcp_syn_count', 'tcp_ack_count',
    'flow_duration', 'flow_packets', 'flow_bytes', 'avg_packet_size',
    'label'
]

class ModernDatasetBuilder:
    def __init__(self):
        self.dataset = []
        self.running = False
        self.last_packet_time = time.time()
        self.packet_count = 0
        self.packets_per_second = 0
        
        # Flow tracking for advanced features
        self.flows = defaultdict(lambda: {
            'start_time': time.time(),
            'packets': 0,
            'bytes': 0,
            'ports': set(),
            'ips': set(),
            'tcp_syn': 0,
            'tcp_ack': 0,
            'last_seen': time.time()
        })
        
        # Ensure output directory exists
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    def start_capture(self, duration=60):
        """Start capturing live traffic for a specified duration (seconds)"""
        print(f">>> Starting live traffic capture for {duration} seconds...")
        self.running = True
        
        # Start a thread to update packet rate
        rate_thread = threading.Thread(target=self._update_packet_rate)
        rate_thread.daemon = True
        rate_thread.start()
        
        # Start sniffing packets
        try:
            sniff(prn=self._process_packet, store=False, timeout=duration)
        except Exception as e:
            print(f"!!! Error during packet capture: {e}")
        finally:
            self.running = False
            print(f">>> Capture completed. Collected {len(self.dataset)} packets.")
    
    def _update_packet_rate(self):
        """Update packets per second calculation periodically"""
        last_count = 0
        while self.running:
            time.sleep(1)
            current_count = self.packet_count
            self.packets_per_second = current_count - last_count
            last_count = current_count
            if self.packets_per_second > 0:
                print(f">>> Capturing at {self.packets_per_second} packets/second")
    
    def _process_packet(self, packet):
        """Process a captured packet and extract features"""
        if not self.running:
            return
        
        self.packet_count += 1
        current_time = time.time()
        
        # Skip non-IP packets
        if IP not in packet:
            return
        
        # Basic packet info
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Convert numeric protocol to string name for mapping
        if protocol == 6:
            proto_str = 'TCP'
        elif protocol == 17:
            proto_str = 'UDP'
        elif protocol == 1:
            proto_str = 'ICMP'
        else:
            proto_str = 'OTHER'
        
        # Get ports and flags
        src_port = 0
        dst_port = 0
        flags = 0
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            # Extract TCP flags
            if tcp_flags & 0x02:  # SYN flag
                flags = FLAG_MAP['S']
            elif tcp_flags & 0x10:  # ACK flag
                flags = FLAG_MAP['A']
            elif tcp_flags & 0x01:  # FIN flag
                flags = FLAG_MAP['F']
            elif tcp_flags & 0x04:  # RST flag
                flags = FLAG_MAP['R']
            else:
                flags = FLAG_MAP['unknown']
                
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = FLAG_MAP['unknown']
            
        # Determine service by port
        service = 0
        if dst_port == 80 or dst_port == 8080:
            service = SERVICE_MAP['http']
        elif dst_port == 443:
            service = SERVICE_MAP['https']
        elif dst_port == 22:
            service = SERVICE_MAP['ssh']
        elif dst_port == 21:
            service = SERVICE_MAP['ftp']
        elif dst_port == 53:
            service = SERVICE_MAP['dns']
        else:
            service = SERVICE_MAP['unknown']
        
        # Packet sizes
        src_bytes = len(packet)
        dst_bytes = 0  # Will be updated in bidirectional flow tracking
        
        # Land attack detection (src ip = dst ip, src port = dst port)
        land = 1 if src_ip == dst_ip and src_port == dst_port else 0
        
        # Wrong fragment (not implemented in basic capture)
        wrong_fragment = 0
        
        # Urgent pointer (TCP only)
        urgent = packet[TCP].urgptr if TCP in packet else 0
        
        # Calculate time-based features
        time_since_last = current_time - self.last_packet_time
        self.last_packet_time = current_time
        
        # Update flow statistics
        flow_key = (src_ip, dst_ip, protocol)
        flow = self.flows[flow_key]
        flow['packets'] += 1
        flow['bytes'] += len(packet)
        flow['ports'].add(dst_port)
        flow['ips'].add(dst_ip)
        flow['last_seen'] = current_time
        
        if TCP in packet:
            if packet[TCP].flags & 0x02:  # SYN flag
                flow['tcp_syn'] += 1
            if packet[TCP].flags & 0x10:  # ACK flag
                flow['tcp_ack'] += 1
        
        # Calculate flow-based features
        flow_duration = current_time - flow['start_time']
        flow_packets = flow['packets']
        flow_bytes = flow['bytes']
        unique_ports = len(flow['ports'])
        
        # Port and IP entropy
        port_entropy = self._calculate_entropy(flow['ports'])
        ip_entropy = self._calculate_entropy(flow['ips'])
        
        # TCP counters
        tcp_syn_count = flow['tcp_syn']
        tcp_ack_count = flow['tcp_ack']
        
        # Average packet size
        avg_packet_size = flow_bytes / flow_packets if flow_packets > 0 else 0
        
        # Bursts (not implemented in basic capture)
        burst_count = 0
        
        # Simple attack detection heuristics for labeling
        # These are rudimentary rules - your enhanced model will do better detection
        label = "normal"
        
        # Port scan detection: high unique_ports or high port_entropy
        if unique_ports > 5 or port_entropy > 2.0:
            label = "attack"  # Port Scan
        
        # SYN flood detection: high tcp_syn_count with low tcp_ack_count
        elif tcp_syn_count > 10 and tcp_ack_count < tcp_syn_count / 2:
            label = "attack"  # SYN Flood
        
        # Volume-based DoS: high packet rate or high bytes
        elif self.packets_per_second > 100 or flow_bytes > 100000:
            label = "attack"  # DoS
        
        # Create feature vector
        packet_features = {
            'protocol_type': PROTO_MAP.get(proto_str, 0),
            'service': service,
            'flag': flags,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent,
            'time_since_last': time_since_last,
            'packet_rate': self.packets_per_second,
            'burst_count': burst_count,
            'unique_ports': unique_ports,
            'port_entropy': port_entropy,
            'ip_entropy': ip_entropy,
            'tcp_syn_count': tcp_syn_count,
            'tcp_ack_count': tcp_ack_count,
            'flow_duration': flow_duration,
            'flow_packets': flow_packets,
            'flow_bytes': flow_bytes,
            'avg_packet_size': avg_packet_size,
            'label': label,
            # Additional metadata for reference (not used in model)
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': proto_str
        }
        
        # Add to dataset
        self.dataset.append(packet_features)
        
        # Log if it's an attack
        if label == "attack":
            print(f">>> Potential attack detected: {proto_str} from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
            
        # Periodic cleanup of old flows
        if self.packet_count % 100 == 0:
            self._cleanup_old_flows()
    
    def _calculate_entropy(self, items):
        """Calculate Shannon entropy of a set of items"""
        if not items:
            return 0
        
        # Count occurrences of each item
        counts = defaultdict(int)
        for item in items:
            counts[item] += 1
        
        # Calculate probabilities and entropy
        total = len(items)
        probabilities = [count/total for count in counts.values()]
        entropy = -sum(p * np.log2(p) for p in probabilities)
        
        return entropy
    
    def _cleanup_old_flows(self, max_age=300):
        """Remove flows older than max_age seconds"""
        current_time = time.time()
        to_remove = []
        
        for flow_key, flow in self.flows.items():
            if current_time - flow['last_seen'] > max_age:
                to_remove.append(flow_key)
        
        for key in to_remove:
            del self.flows[key]
    
    def import_flagged_attacks(self):
        """Import flagged attacks from flagged_attacks.csv"""
        if not os.path.exists(FLAGGED_ATTACKS):
            print(f"!!! No flagged attacks file found at {FLAGGED_ATTACKS}")
            return
        
        try:
            # Check if file is actually CSV or Python code
            with open(FLAGGED_ATTACKS, 'r') as f:
                first_line = f.readline().strip()
                if first_line.startswith('import '):
                    print(f"!!! The flagged_attacks.csv file contains Python code, not CSV data.")
                    print("Creating a new empty CSV file...")
                    # Backup the Python file
                    os.rename(FLAGGED_ATTACKS, f"{FLAGGED_ATTACKS}.bak")
                    # Create empty CSV
                    with open(FLAGGED_ATTACKS, 'w', newline='') as f_new:
                        writer = csv.writer(f_new)
                        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'label'])
                    return
            
            # Process the CSV file
            count = 0
            with open(FLAGGED_ATTACKS, 'r') as f:
                reader = csv.reader(f)
                # Skip header if present
                try:
                    header = next(reader)
                except StopIteration:
                    print("Empty CSV file")
                    return
                
                for row in reader:
                    # Handle file with different number of columns
                    if len(row) < 5:
                        print(f"!!! Skipping invalid row (too few columns): {row}")
                        continue
                    
                    # Extract fields based on position
                    timestamp = row[0]
                    src_ip = row[1]
                    dst_ip = row[2]
                    protocol = row[3]
                    
                    # Handle length field
                    try:
                        length = int(row[4])
                    except (ValueError, IndexError):
                        length = 0
                    
                    # Handle label field - merge additional columns if needed
                    if len(row) >= 6:
                        label = row[5]
                        # If there's a 7th column with specific attack type, use it
                        if len(row) >= 7 and row[6] and row[6] != 'Normal':
                            label = f"attack-{row[6].lower()}"
                    else:
                        label = "unknown"
                    
                    # Create features
                    packet_features = {
                        'protocol_type': PROTO_MAP.get(protocol, 0),
                        'service': 0,  # Unknown
                        'flag': 0,  # Unknown
                        'src_bytes': length,
                        'dst_bytes': 0,
                        'land': 0,  # Unknown
                        'wrong_fragment': 0,  # Unknown
                        'urgent': 0,  # Unknown
                        'time_since_last': 0,  # Unknown
                        'packet_rate': 0,  # Unknown
                        'burst_count': 0,  # Unknown
                        'unique_ports': 0,  # Unknown
                        'port_entropy': 0,  # Unknown
                        'ip_entropy': 0,  # Unknown
                        'tcp_syn_count': 0,  # Unknown
                        'tcp_ack_count': 0,  # Unknown
                        'flow_duration': 0,  # Unknown
                        'flow_packets': 1,
                        'flow_bytes': length,
                        'avg_packet_size': length,
                        'label': 'attack' if 'attack' in label.lower() else 'normal',
                        # Additional metadata
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol
                    }
                    
                    self.dataset.append(packet_features)
                    count += 1
            
            print(f">>> Imported {count} flagged attacks from {FLAGGED_ATTACKS}")
        
        except Exception as e:
            print(f"!!! Error importing flagged attacks: {e}")
    
    def import_kdd_dataset(self, kdd_file='data/kdd99.csv', sample_size=10000):
        """Import and convert KDD99 dataset for modern features"""
        if not os.path.exists(kdd_file):
            print(f"!!! KDD dataset not found at {kdd_file}")
            return
        
        try:
            print(f">>> Importing KDD dataset from {kdd_file} (sampling {sample_size} records)...")
            
            # KDD99 columns (simplified)
            kdd_cols = [
                'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
                'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
                'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
                'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
                'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
                'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
                'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
                'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
                'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
            ]
            
            # Read the KDD dataset (first N rows for sample)
            df = pd.read_csv(kdd_file, names=kdd_cols, nrows=sample_size)
            
            # Convert protocol_type to numeric
            df['protocol_type'] = df['protocol_type'].map(lambda x: PROTO_MAP.get(x.upper(), 0) if isinstance(x, str) else 0)
            
            # Convert label to binary (normal or attack)
            df['label'] = df['label'].apply(lambda x: 'normal' if x == 'normal.' else 'attack')
            
            # Map KDD features to our modern features
            count = 0
            for _, row in df.iterrows():
                # Create features with KDD values where possible and defaults for new features
                packet_features = {
                    'protocol_type': row['protocol_type'],
                    'service': hash(str(row['service'])) % 100,  # Hash service to numeric value
                    'flag': hash(str(row['flag'])) % 100,  # Hash flag to numeric value
                    'src_bytes': row['src_bytes'],
                    'dst_bytes': row['dst_bytes'],
                    'land': row['land'],
                    'wrong_fragment': row['wrong_fragment'],
                    'urgent': row['urgent'],
                    'time_since_last': 0,  # Not in KDD
                    'packet_rate': row['count'] / row['duration'] if row['duration'] > 0 else 0,
                    'burst_count': row['count'],
                    'unique_ports': row['srv_count'],
                    'port_entropy': row['diff_srv_rate'] * 5,  # Approximation
                    'ip_entropy': row['dst_host_diff_srv_rate'] * 5,  # Approximation
                    'tcp_syn_count': row['serror_rate'] * 100 if row['protocol_type'] == PROTO_MAP['TCP'] else 0,
                    'tcp_ack_count': row['rerror_rate'] * 100 if row['protocol_type'] == PROTO_MAP['TCP'] else 0,
                    'flow_duration': row['duration'],
                    'flow_packets': row['count'],
                    'flow_bytes': row['src_bytes'] + row['dst_bytes'],
                    'avg_packet_size': (row['src_bytes'] + row['dst_bytes']) / row['count'] if row['count'] > 0 else 0,
                    'label': row['label']
                }
                
                self.dataset.append(packet_features)
                count += 1
            
            print(f">>> Imported {count} records from KDD dataset")
        
        except Exception as e:
            print(f"!!! Error importing KDD dataset: {e}")
    
    def save_dataset(self):
        """Save the dataset to CSV"""
        if not self.dataset:
            print("!!! No data to save")
            return
        
        try:
            # Save to CSV
            with open(MODERN_DATASET, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=FEATURE_HEADERS)
                writer.writeheader()
                for packet in self.dataset:
                    # Only write the features needed for the model
                    row = {k: packet[k] for k in FEATURE_HEADERS if k in packet}
                    writer.writerow(row)
            
            print(f">>> Saved {len(self.dataset)} records to {MODERN_DATASET}")
            
            # Also save a preprocessed version for model training
            self._save_preprocessed()
            
        except Exception as e:
            print(f"!!! Error saving dataset: {e}")
    
    def _save_preprocessed(self):
        """Save preprocessed data for model training"""
        # Extract features and labels
        X = []
        y = []
        
        for packet in self.dataset:
            # Extract all features except label
            features = [packet[k] for k in FEATURE_HEADERS if k != 'label']
            if len(features) != len(FEATURE_HEADERS) - 1:
                # Skip incomplete records
                continue
                
            X.append(features)
            y.append(packet['label'])
        
        if not X:
            print("!!! No valid data for preprocessing")
            return
            
        X = np.array(X)
        y = np.array(y)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Save preprocessed data
        np.savez(PREPROCESSED_DATA, X=X_scaled, y=y)
        
        # Save scaler
        joblib.dump(scaler, os.path.join(OUTPUT_DIR, 'modern_scaler.pkl'))
        
        print(f">>> Saved preprocessed data to {PREPROCESSED_DATA}")
        print(f"  - Features shape: {X.shape}")
        print(f"  - Labels shape: {y.shape}")
        print(f"  - Attack ratio: {np.mean(y == 'attack') * 100:.2f}%")


def main():
    print(">>> Modern IDS Dataset Builder <<<")
    print("=" * 60)
    
    builder = ModernDatasetBuilder()
    
    # 1. Import existing flagged attacks
    print("\n>>> Importing flagged attacks...")
    builder.import_flagged_attacks()
    
    # 2. Import KDD dataset (if available, for additional training samples)
    print("\n>>> Importing KDD dataset for baseline...")
    builder.import_kdd_dataset()
    
    # 3. Capture live traffic
    capture_duration = 60  # seconds
    print(f"\n>>> Capturing live traffic for {capture_duration} seconds...")
    builder.start_capture(duration=capture_duration)
    
    # 4. Save the modern dataset
    print("\n>>> Saving modern dataset...")
    builder.save_dataset()
    
    print("\n*** Dataset building complete! ***")
    print(f"You can now use the modern dataset to train your enhanced IDS model.")
    print("Run: python scripts/train_enhanced_model.py")


if __name__ == "__main__":
    main() 