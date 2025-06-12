import numpy as np

class FeatureExtractor:
    def extract_features(self, flow_key, flow):
        if flow['fwd_packets'] + flow['bwd_packets'] < 2:
            return None
        
        duration = flow['end_time'] - flow['start_time']
        if duration <= 0:
            duration = 0.001
        
        features = {}
        
        # Basic stuff
        try:
            parts = flow_key.split('-')
            dst_part = parts[0].split(':')[1] if ':' in parts[0] else parts[1].split(':')[1]
            features['Destination Port'] = int(dst_part)
        except:
            features['Destination Port'] = 0
        
        total_bytes = flow['fwd_bytes'] + flow['bwd_bytes']
        total_packets = flow['fwd_packets'] + flow['bwd_packets']
        
        features['Flow Duration'] = duration * 1000 # in milliseconds
        features['Flow Bytes/s'] = total_bytes / duration
        features['Flow Packets/s'] = total_packets / duration
        
        # Forward stats
        features['Total Fwd Packets'] = flow['fwd_packets']
        features['Total Length of Fwd Packets'] = flow['fwd_bytes']
        features['Fwd Packets/s'] = flow['fwd_packets'] / duration
        features['Fwd Header Length'] = flow['fwd_header_bytes']
        
        if flow['fwd_packet_sizes']:
            features['Fwd Packet Length Min'] = min(flow['fwd_packet_sizes'])
            features['Fwd Packet Length Max'] = max(flow['fwd_packet_sizes'])
            features['Fwd Packet Length Mean'] = np.mean(flow['fwd_packet_sizes'])
            features['Fwd Packet Length Std'] = np.std(flow['fwd_packet_sizes']) if len(flow['fwd_packet_sizes']) > 1 else 0
        else:
            features['Fwd Packet Length Min'] = 0
            features['Fwd Packet Length Max'] = 0
            features['Fwd Packet Length Mean'] = 0
            features['Fwd Packet Length Std'] = 0
        
        # Backward stats
        features['Bwd Packets/s'] = flow['bwd_packets'] / duration
        features['Bwd Header Length'] = flow['bwd_header_bytes']
        
        if flow['bwd_packet_sizes']:
            features['Bwd Packet Length Min'] = min(flow['bwd_packet_sizes'])
            features['Bwd Packet Length Max'] = max(flow['bwd_packet_sizes'])
            features['Bwd Packet Length Mean'] = np.mean(flow['bwd_packet_sizes'])
            features['Bwd Packet Length Std'] = np.std(flow['bwd_packet_sizes']) if len(flow['bwd_packet_sizes']) > 1 else 0
        else:
            features['Bwd Packet Length Min'] = 0
            features['Bwd Packet Length Max'] = 0
            features['Bwd Packet Length Mean'] = 0
            features['Bwd Packet Length Std'] = 0
        
        # Packet length stats
        if flow['packet_sizes']:
            features['Min Packet Length'] = min(flow['packet_sizes'])
            features['Max Packet Length'] = max(flow['packet_sizes'])
            features['Packet Length Mean'] = np.mean(flow['packet_sizes'])
            features['Packet Length Std'] = np.std(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
            features['Packet Length Variance'] = np.var(flow['packet_sizes']) if len(flow['packet_sizes']) > 1 else 0
            features['Average Packet Size'] = total_bytes / total_packets if total_packets > 0 else 0
        else:
            features['Min Packet Length'] = 0
            features['Max Packet Length'] = 0
            features['Packet Length Mean'] = 0
            features['Packet Length Std'] = 0
            features['Packet Length Variance'] = 0
            features['Average Packet Size'] = 0
        
        # IAT features
        if flow['flow_iat']:
            features['Flow IAT Mean'] = np.mean(flow['flow_iat'])
            features['Flow IAT Std'] = np.std(flow['flow_iat']) if len(flow['flow_iat']) > 1 else 0
            features['Flow IAT Max'] = max(flow['flow_iat'])
            features['Flow IAT Min'] = min(flow['flow_iat'])
        else:
            features['Flow IAT Mean'] = 0
            features['Flow IAT Std'] = 0
            features['Flow IAT Max'] = 0
            features['Flow IAT Min'] = 0
        
        if flow['fwd_iat']:
            features['Fwd IAT Total'] = sum(flow['fwd_iat'])
            features['Fwd IAT Mean'] = np.mean(flow['fwd_iat'])
            features['Fwd IAT Std'] = np.std(flow['fwd_iat']) if len(flow['fwd_iat']) > 1 else 0
            features['Fwd IAT Max'] = max(flow['fwd_iat'])
            features['Fwd IAT Min'] = min(flow['fwd_iat'])
        else:
            features['Fwd IAT Total'] = 0
            features['Fwd IAT Mean'] = 0
            features['Fwd IAT Std'] = 0
            features['Fwd IAT Max'] = 0
            features['Fwd IAT Min'] = 0
        
        if flow['bwd_iat']:
            features['Bwd IAT Total'] = sum(flow['bwd_iat'])
            features['Bwd IAT Mean'] = np.mean(flow['bwd_iat'])
            features['Bwd IAT Std'] = np.std(flow['bwd_iat']) if len(flow['bwd_iat']) > 1 else 0
            features['Bwd IAT Max'] = max(flow['bwd_iat'])
            features['Bwd IAT Min'] = min(flow['bwd_iat'])
        else:
            features['Bwd IAT Total'] = 0
            features['Bwd IAT Mean'] = 0
            features['Bwd IAT Std'] = 0
            features['Bwd IAT Max'] = 0
            features['Bwd IAT Min'] = 0
        
        # Flag counts
        features['PSH Flag Count'] = flow['psh_flags']
        features['FIN Flag Count'] = flow['fin_flags']
        features['ACK Flag Count'] = flow['ack_flags']
        
        # Window stuff
        features['Init_Win_bytes_forward'] = flow['fwd_win_bytes'] if flow['fwd_win_bytes'] is not None else 0
        features['Init_Win_bytes_backward'] = flow['bwd_win_bytes'] if flow['bwd_win_bytes'] is not None else 0
        
        # Active/idle times
        if flow['active_times']:
            features['Active Mean'] = np.mean(flow['active_times'])
            features['Active Max'] = max(flow['active_times'])
            features['Active Min'] = min(flow['active_times'])
        else:
            features['Active Mean'] = 0
            features['Active Max'] = 0
            features['Active Min'] = 0
        
        if flow['idle_times']:
            features['Idle Mean'] = np.mean(flow['idle_times'])
            features['Idle Max'] = max(flow['idle_times'])
            features['Idle Min'] = min(flow['idle_times'])
        else:
            features['Idle Mean'] = 0
            features['Idle Max'] = 0
            features['Idle Min'] = 0
        
        # Other stuff
        features['min_seg_size_forward'] = flow['min_seg_size_forward'] if flow['min_seg_size_forward'] != float('inf') else 0
        features['act_data_pkt_fwd'] = flow['fwd_data_packets']
        features['Subflow Fwd Bytes'] = flow['fwd_bytes']
        
        return features
