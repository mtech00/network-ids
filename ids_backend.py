#!/usr/bin/env python3

import time
import signal
from scapy.all import sniff

from config import INTERFACE, TIME_WINDOW, MIN_PACKETS, STATS_UPDATE
from flow_manager import FlowManager
from packet_processor import PacketProcessor
from feature_extractor import FeatureExtractor
from model_predictor import ModelPredictor
from alert_manager import AlertManager

class IDSBackend:
    def __init__(self):
        self.running = False
        self.packet_count = 0
        
        self.flow_mgr = FlowManager()
        self.packet_proc = PacketProcessor()
        self.feature_ext = FeatureExtractor()
        self.predictor = ModelPredictor()
        self.alert_mgr = AlertManager()
        
        print("IDS Backend started")
    
    def process_packet(self, packet):
        packet_info = self.packet_proc.process_packet(packet)
        if packet_info is None:
            return
        
        self.packet_count += 1
        current_time = time.time()
        
        self.packet_proc.update_stats(packet_info['protocol'])
        
        # Get flow
        fwd_key, bwd_key = self.flow_mgr.get_flow_key(
            packet_info['ip_src'], packet_info['src_port'],
            packet_info['ip_dst'], packet_info['dst_port'],
            packet_info['protocol']
        )
        # Doesn't matter which is "forward": For statistical analysis, 
        # what matters is tracking two directions consistently, 
        # not which one is "truly" forward
        flow_key, is_forward = self.flow_mgr.get_flow(fwd_key, bwd_key) 
        flow = self.flow_mgr.init_flow(flow_key, current_time)
        
        # Update flow
        self.flow_mgr.update_timing(flow, current_time)
        
        if is_forward:
            self.flow_mgr.update_forward(
                flow, packet_info['packet_size'], packet_info['header_length'],
                packet_info['window_size'], current_time
            )
        else:
            self.flow_mgr.update_backward(
                flow, packet_info['packet_size'], packet_info['header_length'],
                packet_info['window_size'], current_time
            )
        
        if packet_info['protocol'] == 'TCP':
            self.flow_mgr.update_tcp(
                flow, packet_info['flags'], packet_info['mss'],
                packet_info['payload_length'], is_forward
            )
        
        # Check for prediction
        if self.should_predict(flow, current_time):
            self.predict_flow(flow_key)
        
        # Update stats
        if self.packet_count % STATS_UPDATE == 0:
            self.update_stats()
        
        # Cleanup
        self.flow_mgr.cleanup_old(current_time)
    
    def should_predict(self, flow, current_time):
        packet_count = flow['fwd_packets'] + flow['bwd_packets']
        
        if packet_count < MIN_PACKETS:
            return False
        
        if (flow['last_extraction_time'] is None and 
            current_time - flow['start_time'] >= TIME_WINDOW):
            return True
        
        if (flow['last_extraction_time'] is not None and 
            current_time - flow['last_extraction_time'] >= TIME_WINDOW):
            return True
        
        return False
    
    def predict_flow(self, flow_key):
        flow = self.flow_mgr.flows[flow_key]
        
        features = self.feature_ext.extract_features(flow_key, flow)
        if features is None:
            return
        
        prob, prediction = self.predictor.predict(features)
        if prob is None:
            return
        
        if prediction == 1:
            alert = self.alert_mgr.create_alert(flow_key, prob)
            self.alert_mgr.send_alert(alert)
        
        flow['last_extraction_time'] = time.time()
        self.flow_mgr.reset_flow(flow_key)
    
    def update_stats(self):
        self.alert_mgr.update_stats(
            self.packet_count,
            self.flow_mgr.get_count(),
            self.packet_proc.get_stats()
        )
    
    def run(self):
        print(f"Starting on interface: {INTERFACE}")
        print("Press Ctrl+C to stop")
        
        self.running = True
        try:
            sniff(
                iface=INTERFACE,
                prn=self.process_packet,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            print("\nStopping...")
        except Exception as e:
            print(f"Error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        self.running = False
        self.update_stats()
        
        print(f"\nStats:")
        print(f"Packets: {self.packet_count}")
        print(f"Flows: {self.flow_mgr.get_count()}")
        print(f"Anomalies: {self.alert_mgr.get_anomaly_count()}")
        print("Stopped")

def main():
    backend = IDSBackend()
    
    def signal_handler(sig, frame): 
        backend.running = False
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    backend.run()

if __name__ == "__main__":
    main()
