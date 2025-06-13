
import json
import time
import datetime
import redis
from collections import defaultdict, deque
from config import REDIS_HOST, REDIS_PORT, REDIS_DB, MAX_ALERTS, WHITELIST_PATTERNS

class AlertManager:
    def __init__(self):
        self.redis = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)
        self.anomaly_count = 0
        self.attack_patterns = defaultdict(int)
        self.source_tracking = defaultdict(list)
        self.port_scanning_detection = defaultdict(set)
        self.time_window_attacks = deque(maxlen=1000)
        #self.redis.flushdb()
    
    def is_whitelisted(self, flow_key):
        for pattern in WHITELIST_PATTERNS:
            if pattern.match(flow_key):
                return True
        return False
    
    def detect_attack_patterns(self, flow_key, prob):
        """Detect specific attack patterns for visualization"""
        parts = flow_key.split('-')
        src = parts[0] if len(parts) > 0 else 'Unknown'
        dst = parts[1] if len(parts) > 1 else 'Unknown'
        protocol = parts[2] if len(parts) > 2 else 'Unknown'
        
        current_time = time.time()
        
        # Extract IPs and ports
        try:
            src_ip = src.split(':')[0]
            dst_ip = dst.split(':')[0]
            dst_port = dst.split(':')[1] if ':' in dst else '0'
        except:
            src_ip = dst_ip = dst_port = 'Unknown'
        
        attack_type = 'Unknown'
        
        # Port scanning detection
        self.port_scanning_detection[src_ip].add(dst_port)
        if len(self.port_scanning_detection[src_ip]) > 2:  # Scanning multiple ports
            attack_type = 'Port_Scan'
        
        # High confidence attacks
        if prob > 0.9:
            attack_type = 'High_Confidence_Attack'
        elif prob > 0.8:
            attack_type = 'Medium_Confidence_Attack'
        
        # Rapid fire attacks (DDoS-like)
        self.time_window_attacks.append(current_time)
        recent_attacks = [t for t in self.time_window_attacks if current_time - t < 60]  # Last 30 seconds
        if len(recent_attacks) > 3:  # More than 3 attacks per 30 seconds
            attack_type = 'DDoS_Like'
        
        # Track attack frequency per source
        self.source_tracking[src_ip].append(current_time)
        recent_from_source = [t for t in self.source_tracking[src_ip] if current_time - t < 300]  # Last 5 minutes
        if len(recent_from_source) > 20:  # More than 20 attacks from same source in 5 min
            attack_type = 'Persistent_Attacker'
        
        return attack_type
    
    def create_alert(self, flow_key, prob):
        if self.is_whitelisted(flow_key):
            return None
        
        timestamp = datetime.datetime.now()
        parts = flow_key.split('-')
        src = parts[0] if len(parts) > 0 else 'Unknown'
        dst = parts[1] if len(parts) > 1 else 'Unknown'
        protocol = parts[2] if len(parts) > 2 else 'Unknown'
        
        # Detect attack patterns
        attack_type = self.detect_attack_patterns(flow_key, prob)
        
        # Severity classification
        if prob > 0.2:
            severity = 'Critical'
        elif prob > 0.15:
            severity = 'High'
        elif prob > 0.10:
            severity = 'Medium'
        else:
            severity = 'Low'
        
        alert = {
            'timestamp': timestamp.isoformat(),
            'src': src,
            'dst': dst,
            'protocol': protocol,
            'confidence': float(prob),
            'flow_key': flow_key,
            'attack_type': attack_type,
            'severity': severity,
            'src_ip': src.split(':')[0] if ':' in src else src,
            'dst_ip': dst.split(':')[0] if ':' in dst else dst,
            'src_port': src.split(':')[1] if ':' in src else '0',
            'dst_port': dst.split(':')[1] if ':' in dst else '0'
        }
        
        return alert
    
    def send_alert(self, alert):
        if alert is None:
            return
        
        try:
            # Store individual alert
            self.redis.lpush('ids_alerts', json.dumps(alert))
            self.redis.ltrim('ids_alerts', 0, MAX_ALERTS - 1)
            self.anomaly_count += 1
            
            # Store pattern data for visualization
            self.store_pattern_data(alert)
            
            # Enhanced console output with color coding
            severity_colors = {
                'Critical': '\033[91m',  # Red
                'High': '\033[93m',      # Yellow
                'Medium': '\033[94m',    # Blue
                'Low': '\033[92m'        # Green
            }
            color = severity_colors.get(alert['severity'], '\033[0m')
            
            print(f"{color}[{alert['severity']} {alert['attack_type']}] {alert['timestamp']} | "
                  f"{alert['src']} -> {alert['dst']} ({alert['protocol']}) | "
                  f"Confidence: {alert['confidence']:.3f}\033[0m")
            
        except Exception as e:
            print(f"Redis error: {e}")
    
    def store_pattern_data(self, alert):
        """Store aggregated pattern data for visualization"""
        current_hour = datetime.datetime.now().hour
        current_minute = datetime.datetime.now().minute
        
        # Hourly attack patterns
        hourly_key = f"hourly_attacks:{current_hour}"
        self.redis.hincrby(hourly_key, alert['attack_type'], 1)
        self.redis.expire(hourly_key, 86400)  # Expire after 24 hours
        
        # Source IP tracking
        src_key = f"source_attacks:{alert['src_ip']}"
        self.redis.hincrby(src_key, 'count', 1)
        self.redis.hset(src_key, 'last_seen', alert['timestamp'])
        self.redis.expire(src_key, 86400)
        
        # Protocol patterns
        proto_key = f"protocol_attacks:{alert['protocol']}"
        self.redis.hincrby(proto_key, 'count', 1)
        self.redis.expire(proto_key, 86400)
        
        # Port targeting
        port_key = f"port_attacks:{alert['dst_port']}"
        self.redis.hincrby(port_key, 'count', 1)
        self.redis.expire(port_key, 86400)
        
        # Time-based patterns (minute-level for real-time visualization)
        minute_key = f"minute_attacks:{current_hour}:{current_minute}"
        self.redis.incr(minute_key)
        self.redis.expire(minute_key, 3600)  # Expire after 1 hour
    
    def get_pattern_statistics(self):
        """Get aggregated pattern statistics for visualization"""
        try:
            # Get top attacking sources
            source_keys = self.redis.keys("source_attacks:*")
            top_sources = []
            for key in source_keys[:20]:  # Limit for performance
                src_ip = key.decode().split(':')[1]
                count = self.redis.hget(key, 'count')
                last_seen = self.redis.hget(key, 'last_seen')
                if count:
                    top_sources.append({
                        'ip': src_ip,
                        'count': int(count.decode()),
                        'last_seen': last_seen.decode() if last_seen else None
                    })
            
            # Get port statistics
            port_keys = self.redis.keys("port_attacks:*")
            port_stats = []
            for key in port_keys[:20]:
                port = key.decode().split(':')[1]
                count = self.redis.hget(key, 'count')
                if count:
                    port_stats.append({
                        'port': port,
                        'count': int(count.decode())
                    })
            
            # Get recent minute-by-minute data
            current_hour = datetime.datetime.now().hour
            minute_stats = []
            for minute in range(60):
                minute_key = f"minute_attacks:{current_hour}:{minute}"
                count = self.redis.get(minute_key)
                minute_stats.append({
                    'minute': minute,
                    'count': int(count.decode()) if count else 0
                })
            
            return {
                'top_sources': sorted(top_sources, key=lambda x: x['count'], reverse=True),
                'port_stats': sorted(port_stats, key=lambda x: x['count'], reverse=True),
                'minute_stats': minute_stats
            }
            
        except Exception as e:
            print(f"Error getting pattern statistics: {e}")
            return {}
    
    def update_stats(self, total_packets, active_flows, protocol_stats):
        stats = {
            'total_packets': total_packets,
            'active_flows': active_flows,
            'anomalies_detected': self.anomaly_count,
            'protocol_stats': protocol_stats,
            'timestamp': time.time(),
            'pattern_stats': self.get_pattern_statistics()  # Add pattern data
        }
        
        try:
            self.redis.set('ids_stats', json.dumps(stats))
        except Exception as e:
            print(f"Stats update error: {e}")
    
    def get_anomaly_count(self):
        return self.anomaly_count
    
    def cleanup_old_patterns(self):
        """Clean up old pattern data to prevent memory issues"""
        try:
            # Clean up minute-level data older than 2 hours
            cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=2)
            old_keys = []
            
            for key in self.redis.keys("minute_attacks:*"):
                key_str = key.decode()
                try:
                    hour_minute = key_str.split(':')[1:]
                    if len(hour_minute) == 2:
                        hour, minute = int(hour_minute[0]), int(hour_minute[1])
                        key_time = datetime.datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
                        if key_time < cutoff_time:
                            old_keys.append(key)
                except:
                    continue
            
            if old_keys:
                self.redis.delete(*old_keys)
                
        except Exception as e:
            print(f"Cleanup error: {e}")