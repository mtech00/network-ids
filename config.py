import re
import netifaces

# Network setup
gateways = netifaces.gateways()  
default_gateway = gateways.get('default', {})

try:
    INTERFACE = default_gateway[netifaces.AF_INET][1]
except:
    raise Exception("Could not determine the default interface.")

# Basic settings
TIME_WINDOW = 1
ACTIVITY_TIMEOUT = 5
CLEANUP_INTERVAL = 120

# Model files
MODEL_FILE = "cic_ids_binary_model.txt"
FEATURE_NAMES_FILE = "feature_names.pkl"
MODEL_INFO_FILE = "model_info.pkl"

# Redis stuff
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 0
MAX_ALERTS = 100

# Detection settings
THRESHOLD = 0.5
MIN_PACKETS = 3
MAX_HISTORY = 100

# Whitelist for normal traffic
WHITELIST_PATTERNS = [
    re.compile(r"^0\.0\.0\.0:68->255\.255\.255\.255:67-UDP$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}:\d+->255\.255\.255\.255:68-UDP$"),
    re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}:\d+->224\.0\.0\.251:5353-UDP$"),
]

STATS_UPDATE = 1
