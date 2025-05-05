import time
from scapy.all import sniff, IP, TCP, UDP
from enhanced_model import EnhancedIDSModel
import threading
from collections import defaultdict
import numpy as np
from datetime import datetime

class EnhancedRealtimeDetector:
    def __init__(self):
        self.model = EnhancedIDSModel()
        self.model.load_or_initialize()
        self.running = False
        self.packet_count = 0
        self.attack_count = 0
        self.normal_count = 0
        self.last_packet_time = time.time()
        self.flow_stats = defaultdict(lambda: {
            'start_time': time.time(),
            'packet_count': 0,
            'byte_count': 0,
            'ports': set(),
            'ips': set(),
            'tcp_syn': 0,
            'tcp_ack': 0
        })
        
    def start(self):
        """Start the real-time detection"""
        self.running = True
        self.detection_thread = threading.Thread(target=self._run_detection)
        self.detection_thread.start()
        print("🚀 Started enhanced real-time detection")
        
    def stop(self):
        """Stop the real-time detection"""
        self.running = False
        if hasattr(self, 'detection_thread'):
            self.detection_thread.join()
        print("🛑 Stopped enhanced real-time detection")
        
    def _run_detection(self):
        """Main detection loop"""
        sniff(prn=self._process_packet, store=0, stop_filter=lambda _: not self.running)
        
    def _process_packet(self, packet):
        """Process each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        current_time = time.time()
        
        # Extract basic packet information
        packet_data = {
            'timestamp': current_time,
            'src_ip': packet[IP].src if IP in packet else None,
            'dst_ip': packet[IP].dst if IP in packet else None,
            'protocol_type': packet[IP].proto if IP in packet else 0,
            'src_port': packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0),
            'dst_port': packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
            'src_bytes': len(packet),
            'dst_bytes': 0,  # Will be updated in bidirectional flows
            'land': 1 if packet[IP].src == packet[IP].dst else 0 if IP in packet else 0,
            'wrong_fragment': 0,  # Would need more detailed packet inspection
            'urgent': packet[TCP].urgptr if TCP in packet else 0,
            'last_packet_time': self.last_packet_time,
            'packet_rate': self.packet_count / (current_time - self.last_packet_time) if self.last_packet_time else 0
        }
        
        # Update flow statistics
        flow_key = (packet_data['src_ip'], packet_data['dst_ip'], packet_data['protocol_type'])
        flow_stats = self.flow_stats[flow_key]
        
        flow_stats['packet_count'] += 1
        flow_stats['byte_count'] += len(packet)
        flow_stats['ports'].add(packet_data['dst_port'])
        flow_stats['ips'].add(packet_data['dst_ip'])
        
        if TCP in packet:
            if packet[TCP].flags & 0x02:  # SYN flag
                flow_stats['tcp_syn'] += 1
            if packet[TCP].flags & 0x10:  # ACK flag
                flow_stats['tcp_ack'] += 1
                
        # Add flow-based features
        packet_data.update({
            'flow_duration': current_time - flow_stats['start_time'],
            'flow_packets': flow_stats['packet_count'],
            'flow_bytes': flow_stats['byte_count'],
            'unique_ports': len(flow_stats['ports']),
            'port_entropy': self._calculate_entropy(flow_stats['ports']),
            'ip_entropy': self._calculate_entropy(flow_stats['ips']),
            'tcp_syn_count': flow_stats['tcp_syn'],
            'tcp_ack_count': flow_stats['tcp_ack'],
            'avg_packet_size': flow_stats['byte_count'] / flow_stats['packet_count'] if flow_stats['packet_count'] > 0 else 0
        })
        
        # Make prediction
        prediction, confidence, anomaly_score = self.model.predict(packet_data)
        
        # Update counts
        if prediction == 'attack':
            self.attack_count += 1
        else:
            self.normal_count += 1
            
        # Update model with new data
        self.model.update(packet_data, prediction)
        
        # Update last packet time
        self.last_packet_time = current_time
        
        # Return detection result
        return {
            'timestamp': datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': packet_data['src_ip'],
            'dst_ip': packet_data['dst_ip'],
            'protocol': packet_data['protocol_type'],
            'src_port': packet_data['src_port'],
            'dst_port': packet_data['dst_port'],
            'prediction': prediction,
            'confidence': confidence,
            'anomaly_score': anomaly_score,
            'flow_id': flow_key
        }
        
    def _calculate_entropy(self, items):
        """Calculate entropy of a set of items"""
        if not items:
            return 0
        counts = defaultdict(int)
        total = len(items)
        for item in items:
            counts[item] += 1
        probs = [count/total for count in counts.values()]
        return -sum(p * np.log2(p) for p in probs)
        
    def get_stats(self):
        """Get current detection statistics"""
        return {
            'total_packets': self.packet_count,
            'attack_packets': self.attack_count,
            'normal_packets': self.normal_count,
            'detection_rate': self.attack_count / self.packet_count if self.packet_count > 0 else 0,
            'model_info': self.model.get_model_info()
        }
        
    def provide_feedback(self, flow_id, correct_label):
        """Provide feedback for a specific flow"""
        if flow_id in self.flow_stats:
            flow_data = self.flow_stats[flow_id]
            self.model.update(flow_data, correct_label, feedback=True)
            return True
        return False 