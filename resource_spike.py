import psutil
import time
import statistics
from collections import deque, defaultdict

class SmartSystemMonitor:
    def __init__(self, window_size=50, spike_threshold=2.5, rate_threshold=20):
        self.cpu_history = deque(maxlen=window_size)
        self.mem_history = deque(maxlen=window_size)
        self.spike_threshold = spike_threshold
        self.rate_threshold = rate_threshold  # % change per second
        self.process_baseline = defaultdict(lambda: {'cpu': 0, 'mem': 0})
        
    def get_top_processes(self, n=5):
        """Get top CPU/memory consuming processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:n]
    
    def is_legitimate_spike(self, current_cpu, current_mem):
        """Check if spike is from known legitimate processes"""
        top_procs = self.get_top_processes(3)
        
        # Check for new high-usage processes (likely user-initiated)
        for proc in top_procs:
            if proc['cpu_percent'] and proc['cpu_percent'] > 30:
                baseline = self.process_baseline[proc['name']]
                if proc['cpu_percent'] > baseline['cpu'] * 3:  # 3x increase
                    return True, f"New high usage: {proc['name']} ({proc['cpu_percent']:.1f}%)"
        
        return False, None
    
    def detect_anomaly(self):
        current_cpu = psutil.cpu_percent(interval=0.1)
        current_mem = psutil.virtual_memory().percent
        
        if len(self.cpu_history) < 10:
            self.cpu_history.append(current_cpu)
            self.mem_history.append(current_mem)
            return False, current_cpu, current_mem, None
        
        # Rate of change detection (sudden vs gradual)
        prev_cpu = self.cpu_history[-1]
        cpu_rate = abs(current_cpu - prev_cpu)
        
        # Statistical spike detection
        cpu_mean = statistics.mean(self.cpu_history)
        cpu_std = statistics.stdev(self.cpu_history)
        cpu_threshold = cpu_mean + (cpu_std * self.spike_threshold)
        
        # Update process baselines periodically
        if len(self.cpu_history) % 30 == 0:  # Every 30 measurements
            for proc in self.get_top_processes(10):
                name = proc['name']
                self.process_baseline[name]['cpu'] = max(
                    self.process_baseline[name]['cpu'] * 0.9,  # Decay
                    proc['cpu_percent'] or 0
                )
        
        self.cpu_history.append(current_cpu)
        self.mem_history.append(current_mem)
        
        # Check for spikes
        statistical_spike = current_cpu > cpu_threshold
        sudden_spike = cpu_rate > self.rate_threshold
        
        if statistical_spike or sudden_spike:
            is_legit, reason = self.is_legitimate_spike(current_cpu, current_mem)
            if not is_legit:
                return True, current_cpu, current_mem, "Unknown cause"
            else:
                return False, current_cpu, current_mem, reason
        
        return False, current_cpu, current_mem, None

# Usage
monitor = SmartSystemMonitor()

while True:
    anomaly, cpu, mem, reason = monitor.detect_anomaly()
    if anomaly:
        print(f"ANOMALY: CPU {cpu:.1f}% | MEM {mem:.1f}% | {reason}")
    elif reason:
        print(f"Legitimate: {reason}")
    time.sleep(1)