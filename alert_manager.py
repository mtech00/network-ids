import json
import time
import datetime
import redis
from config import REDIS_HOST, REDIS_PORT, REDIS_DB, MAX_ALERTS, WHITELIST_PATTERNS

class AlertManager:
    def __init__(self):
        self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        self.anomaly_count = 0
        self.redis.flushdb()
    
    def is_whitelisted(self, flow_key):
        for pattern in WHITELIST_PATTERNS:
            if pattern.match(flow_key):
                return True
        return False
    
    def create_alert(self, flow_key, prob):
        if self.is_whitelisted(flow_key):
            return None
        
        timestamp = datetime.datetime.now()
        parts = flow_key.split('-')
        src = parts[0] if len(parts) > 0 else 'Unknown'
        dst = parts[1] if len(parts) > 1 else 'Unknown'
        protocol = parts[2] if len(parts) > 2 else 'Unknown'
        
        alert = {
            'timestamp': timestamp.isoformat(),
            'src': src,
            'dst': dst,
            'protocol': protocol,
            'confidence': float(prob),
            'flow_key': flow_key
        }
        
        return alert
    
    def send_alert(self, alert):
        if alert is None:
            return
        
        try:
            self.redis.lpush('ids_alerts', json.dumps(alert))
            self.redis.ltrim('ids_alerts', 0, MAX_ALERTS - 1) #### why ??? delete not log
            self.anomaly_count += 1
            
            print(f"\033[91m[ANOMALY] {alert['timestamp']} | {alert['src']} -> {alert['dst']} ({alert['protocol']}) | Confidence: {alert['confidence']:.3f}\033[0m")
            
        except Exception as e:
            print(f"Redis error: {e}")
    
    def update_stats(self, total_packets, active_flows, protocol_stats):
        stats = {
            'total_packets': total_packets,
            'active_flows': active_flows,
            'anomalies_detected': self.anomaly_count,
            'protocol_stats': protocol_stats,
            'timestamp': time.time()
        }
        
        try:
            self.redis.set('ids_stats', json.dumps(stats))
        except Exception as e:
            print(f"Stats update error: {e}")
    
    def get_anomaly_count(self):
        return self.anomaly_count
