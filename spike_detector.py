import psutil
import time
import statistics
from collections import deque

class SpikeDetector:
    def __init__(self, window_size=50, threshold_multiplier=2.5):
        self.cpu_history = deque(maxlen=window_size)
        self.mem_history = deque(maxlen=window_size)
        self.threshold_multiplier = threshold_multiplier
        self.baseline_collected = False
        
    def collect_baseline(self, duration=30, interval=1):

        for _ in range(duration):
            self.cpu_history.append(psutil.cpu_percent(interval=0.1))
            self.mem_history.append(psutil.virtual_memory().percent)
            time.sleep(interval)
        self.baseline_collected = True
    
    def detect_spike(self):
        current_cpu = psutil.cpu_percent(interval=0.1)
        current_mem = psutil.virtual_memory().percent
        
        if len(self.cpu_history) < 10:
            self.cpu_history.append(current_cpu)
            self.mem_history.append(current_mem)
            return False
        
        cpu_mean = statistics.mean(self.cpu_history)
        cpu_std = statistics.stdev(self.cpu_history)
        cpu_threshold = cpu_mean + (cpu_std * self.threshold_multiplier)
        
        mem_mean = statistics.mean(self.mem_history)
        mem_std = statistics.stdev(self.mem_history)
        mem_threshold = mem_mean + (mem_std * self.threshold_multiplier)
        
        self.cpu_history.append(current_cpu)
        self.mem_history.append(current_mem)
        
        return current_cpu > cpu_threshold or current_mem > mem_threshold