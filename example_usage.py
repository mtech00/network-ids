#!/usr/bin/env python3

import time
from packet_processor import PacketProcessor
from flow_manager import FlowManager
from feature_extractor import FeatureExtractor
from alert_manager import AlertManager

def test_components():
    print("Testing IDS components...")
    
    # Test packet processor
    print("\n1. Packet Processor")
    processor = PacketProcessor()
    print("✓ Packet processor created")
    
    # Test flow manager
    print("\n2. Flow Manager")
    flow_mgr = FlowManager()
    fwd_key, bwd_key = flow_mgr.get_flow_key("192.168.1.100", 54321, "10.0.0.50", 80, "TCP")
    print(f"✓ Flow keys: {fwd_key}")
    
    # Test feature extractor
    print("\n3. Feature Extractor")
    extractor = FeatureExtractor()
    
    # Mock flow data
    mock_flow = {
        'start_time': time.time() - 10,
        'end_time': time.time(),
        'fwd_packets': 5,
        'bwd_packets': 3,
        'fwd_bytes': 1500,
        'bwd_bytes': 800,
        'fwd_packet_sizes': [300, 300, 300, 300, 300],
        'bwd_packet_sizes': [200, 300, 300],
        'packet_sizes': [300, 200, 300, 300, 300, 300, 300, 300],
        'fwd_iat': [0.1, 0.1, 0.1, 0.1],
        'bwd_iat': [0.2, 0.2],
        'flow_iat': [0.1, 0.05, 0.1, 0.05, 0.1, 0.05, 0.1],
        'fwd_header_bytes': 100,
        'bwd_header_bytes': 60,
        'fwd_win_bytes': 65535,
        'bwd_win_bytes': 32768,
        'psh_flags': 2,
        'fin_flags': 1,
        'ack_flags': 8,
        'active_times': [1.5, 2.0],
        'idle_times': [0.5],
        'min_seg_size_forward': 1460,
        'fwd_data_packets': 5
    }
    
    features = extractor.extract_features("192.168.1.100:54321-10.0.0.50:80-TCP", mock_flow)
    if features:
        print(f"✓ Extracted {len(features)} features")
    else:
        print("✗ Feature extraction failed")
    
    # Test alert manager
    print("\n4. Alert Manager")
    try:
        alert_mgr = AlertManager()
        alert = alert_mgr.create_alert("192.168.1.100:54321-10.0.0.50:80-TCP", 0.85)
        if alert:
            print("✓ Alert created")
        print("✓ Alert manager works")
    except Exception as e:
        print(f"✗ Alert manager failed: {e}")
        print("Make sure Redis is running") # wtf what is the point of this?     
    print("\nTest completed!")

if __name__ == "__main__":
    test_components()
