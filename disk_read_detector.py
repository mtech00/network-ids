import psutil
import time
import statistics
from collections import deque

class DiskReadDetector:
    def __init__(self, window_size=50, threshold_multiplier=2.5, high_volume_threshold=50*1024*1024):  # 50MB/s
        self.read_bytes_history = deque(maxlen=window_size)
        self.read_count_history = deque(maxlen=window_size)
        self.threshold_multiplier = threshold_multiplier
        self.high_volume_threshold = high_volume_threshold
        self.last_stats = None
        
    def detect_spike(self):
        current_stats = psutil.disk_io_counters()
        
        if self.last_stats is None:
            self.last_stats = current_stats
            return False, False
        
        read_bytes_rate = current_stats.read_bytes - self.last_stats.read_bytes
        read_count_rate = current_stats.read_count - self.last_stats.read_count
        
        self.last_stats = current_stats
        
        # High volume network-based read detection
        high_volume_detected = read_bytes_rate > self.high_volume_threshold
        
        if len(self.read_bytes_history) < 10:
            self.read_bytes_history.append(read_bytes_rate)
            self.read_count_history.append(read_count_rate)
            return False, high_volume_detected
        
        bytes_mean = statistics.mean(self.read_bytes_history)
        bytes_std = statistics.stdev(self.read_bytes_history)
        bytes_threshold = bytes_mean + (bytes_std * self.threshold_multiplier)
        
        count_mean = statistics.mean(self.read_count_history)
        count_std = statistics.stdev(self.read_count_history)
        count_threshold = count_mean + (count_std * self.threshold_multiplier)
        
        self.read_bytes_history.append(read_bytes_rate)
        self.read_count_history.append(read_count_rate)
        
        spike_detected = read_bytes_rate > bytes_threshold or read_count_rate > count_threshold
        
        return spike_detected, high_volume_detected