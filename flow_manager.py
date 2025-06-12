import time
from collections import defaultdict, deque
from config import MAX_HISTORY, CLEANUP_INTERVAL, ACTIVITY_TIMEOUT

class FlowManager:
    def __init__(self):
        self.flows = defaultdict(self.new_flow)
        self.last_cleanup = time.time()
        
    def new_flow(self):
        return {
            'start_time': None,
            'end_time': None,
            'last_extraction_time': None,
            'fwd_packets': 0,
            'bwd_packets': 0,
            'fwd_bytes': 0,
            'bwd_bytes': 0,
            'fwd_packet_sizes': deque(maxlen=MAX_HISTORY),
            'bwd_packet_sizes': deque(maxlen=MAX_HISTORY),
            'packet_sizes': deque(maxlen=MAX_HISTORY),
            'fwd_iat': deque(maxlen=MAX_HISTORY),
            'bwd_iat': deque(maxlen=MAX_HISTORY),
            'flow_iat': deque(maxlen=MAX_HISTORY),
            'fwd_header_bytes': 0,
            'bwd_header_bytes': 0,
            'fwd_win_bytes': None,
            'bwd_win_bytes': None,
            'last_packet_time': None,
            'last_fwd_packet_time': None,
            'last_bwd_packet_time': None,
            'psh_flags': 0,
            'fin_flags': 0,
            'ack_flags': 0,
            'fwd_psh_flags': 0,
            'fwd_urg_flags': 0,
            'syn_flags': 0,
            'rst_flags': 0,
            'urg_flags': 0,
            'ece_flags': 0,
            'active_times': deque(maxlen=MAX_HISTORY),
            'idle_times': deque(maxlen=MAX_HISTORY),
            'last_active_time': None,
            'last_idle_time': None,
            'active_start': None,
            'idle_start': None,
            'active': False,
            'min_seg_size_forward': float('inf'),
            'fwd_data_packets': 0,
        }
    
    def get_flow_key(self, ip_src, src_port, ip_dst, dst_port, protocol):
        forward_key = f"{ip_src}:{src_port}-{ip_dst}:{dst_port}-{protocol}"
        backward_key = f"{ip_dst}:{dst_port}-{ip_src}:{src_port}-{protocol}"
        return forward_key, backward_key
    
    def get_flow(self, forward_key, backward_key):
        if forward_key in self.flows:
            return forward_key, True
        elif backward_key in self.flows:
            return backward_key, False
        else:
            return forward_key, True
    
    def init_flow(self, flow_key, current_time):
        flow = self.flows[flow_key]
        if flow['start_time'] is None:
            flow['start_time'] = current_time
            flow['active_start'] = current_time
            flow['active'] = True
        return flow
    
    def update_timing(self, flow, current_time):
        flow['end_time'] = current_time
        
        if flow['last_packet_time'] is not None:
            iat = current_time - flow['last_packet_time']
            flow['flow_iat'].append(iat)
            
            if iat > ACTIVITY_TIMEOUT:
                if flow['active_start'] is not None:
                    active_time = flow['last_packet_time'] - flow['active_start']
                    flow['active_times'].append(active_time)
                    flow['active_start'] = None
                    flow['idle_start'] = flow['last_packet_time']
                
                if flow['idle_start'] is not None:
                    idle_time = current_time - flow['idle_start']
                    flow['idle_times'].append(idle_time)
                    flow['idle_start'] = None
                
                flow['active_start'] = current_time
                flow['active'] = True
        
        flow['last_packet_time'] = current_time
    
    def update_forward(self, flow, packet_size, header_len, window_size, current_time):
        flow['fwd_packets'] += 1
        flow['fwd_bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        flow['fwd_packet_sizes'].append(packet_size)
        flow['fwd_header_bytes'] += header_len
        
        if flow['fwd_win_bytes'] is None and window_size > 0:
            flow['fwd_win_bytes'] = window_size
        
        if flow['last_fwd_packet_time'] is not None:
            flow['fwd_iat'].append(current_time - flow['last_fwd_packet_time'])
        flow['last_fwd_packet_time'] = current_time
    
    def update_backward(self, flow, packet_size, header_len, window_size, current_time):
        flow['bwd_packets'] += 1
        flow['bwd_bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        flow['bwd_packet_sizes'].append(packet_size)
        flow['bwd_header_bytes'] += header_len
        
        if flow['bwd_win_bytes'] is None and window_size > 0:
            flow['bwd_win_bytes'] = window_size
        
        if flow['last_bwd_packet_time'] is not None:
            flow['bwd_iat'].append(current_time - flow['last_bwd_packet_time'])
        flow['last_bwd_packet_time'] = current_time
    
    def update_tcp(self, flow, flags, mss, payload_len, is_forward):
        flow['psh_flags'] += 1 if flags.get('psh', False) else 0
        flow['fin_flags'] += 1 if flags.get('fin', False) else 0
        flow['ack_flags'] += 1 if flags.get('ack', False) else 0
        flow['syn_flags'] += 1 if flags.get('syn', False) else 0
        flow['rst_flags'] += 1 if flags.get('rst', False) else 0
        flow['urg_flags'] += 1 if flags.get('urg', False) else 0
        flow['ece_flags'] += 1 if flags.get('ece', False) else 0
        
        if is_forward:
            if flags.get('psh', False):
                flow['fwd_psh_flags'] += 1
            if flags.get('urg', False):
                flow['fwd_urg_flags'] += 1
            
            if mss is not None and mss < flow['min_seg_size_forward']:
                flow['min_seg_size_forward'] = mss
            
            if payload_len > 0:
                flow['fwd_data_packets'] += 1
            # TCP packet types:
            # SYN packet: payload_len = 0 (just establishing connection)
            # ACK packet: payload_len = 0 (just acknowledging)  
            # HTTP request: payload_len > 0 (contains actual data)
    
    def reset_flow(self, flow_key):
        flow = self.flows[flow_key]
        
        flow['fwd_packets'] = 0
        flow['bwd_packets'] = 0
        flow['fwd_bytes'] = 0 
        flow['bwd_bytes'] = 0
        flow['fwd_header_bytes'] = 0    
        flow['bwd_header_bytes'] = 0    
        flow['fwd_win_bytes'] = None 
        flow['bwd_win_bytes'] = None    
        
        flow['fwd_packet_sizes'].clear()
        flow['bwd_packet_sizes'].clear() 
        flow['packet_sizes'].clear()
        flow['fwd_iat'].clear()
        flow['bwd_iat'].clear()
        flow['flow_iat'].clear()
        
        flow['psh_flags'] = 0
        flow['fin_flags'] = 0
        flow['ack_flags'] = 0
        flow['fwd_psh_flags'] = 0
        flow['fwd_urg_flags'] = 0
        flow['syn_flags'] = 0
        flow['rst_flags'] = 0
        flow['urg_flags'] = 0
        flow['ece_flags'] = 0
        
        flow['min_seg_size_forward'] = float('inf')
        flow['fwd_data_packets'] = 0
        
        flow['active_times'].clear()
        flow['idle_times'].clear()
    
    def cleanup_old(self, current_time):
        if current_time - self.last_cleanup > CLEANUP_INTERVAL:
            to_remove = []
            for flow_key, flow in self.flows.items():
                if (flow['last_packet_time'] is not None and 
                    current_time - flow['last_packet_time'] > CLEANUP_INTERVAL):
                    to_remove.append(flow_key)
            
            for flow_key in to_remove:
                del self.flows[flow_key]
            
            self.last_cleanup = current_time
    
    def get_count(self):
        return len(self.flows)
