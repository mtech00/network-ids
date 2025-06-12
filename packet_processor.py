from scapy.all import IP, TCP, UDP

class PacketProcessor:
    def __init__(self):
        self.protocol_stats = {}
    
    def process_packet(self, packet):
        if IP not in packet:
            return None
        
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        packet_info = {
            'ip_src': ip_src,
            'ip_dst': ip_dst,
            'packet_size': len(packet),
            'protocol': None,
            'src_port': None,
            'dst_port': None,
            'header_length': 0,
            'window_size': 0,
            'flags': {},
            'mss': None,
            'payload_length': 0
        }
        
        if TCP in packet:
            packet_info.update(self.process_tcp(packet))
        elif UDP in packet:
            packet_info.update(self.process_udp(packet))
        else:
            return None
        
        return packet_info
    
    def process_tcp(self, packet):
        tcp = packet[TCP]
        
        flags = {
            'psh': bool(tcp.flags & 0x08),
            'fin': bool(tcp.flags & 0x01),
            'ack': bool(tcp.flags & 0x10),
            'syn': bool(tcp.flags & 0x02),
            'rst': bool(tcp.flags & 0x04),
            'urg': bool(tcp.flags & 0x20),
            'ece': bool(tcp.flags & 0x40)
        }
        
        mss = None
        if hasattr(tcp, 'options'):
            mss = next((x[1] for x in tcp.options if x[0] == 'MSS'), None)
        
        payload_len = len(tcp.payload) if tcp.payload else 0
        
        return {
            'protocol': 'TCP',
            'src_port': tcp.sport,
            'dst_port': tcp.dport,
            'header_length': len(tcp),
            'window_size': tcp.window if hasattr(tcp, 'window') else 0,
            'flags': flags,
            'mss': mss,
            'payload_length': payload_len
        }
    
    def process_udp(self, packet):
        udp = packet[UDP]
        
        return {
            'protocol': 'UDP',
            'src_port': udp.sport,
            'dst_port': udp.dport,
            'header_length': len(udp),
            'window_size': 0,
            'flags': {
                'psh': False, 'fin': False, 'ack': False,
                'syn': False, 'rst': False, 'urg': False, 'ece': False
            },
            'mss': None,
            'payload_length': 0 #### WHY !!! ZERO 
        }
    
    def update_stats(self, protocol):
        if protocol not in self.protocol_stats:
            self.protocol_stats[protocol] = 0
        self.protocol_stats[protocol] += 1
    
    def get_stats(self):
        return dict(self.protocol_stats)
