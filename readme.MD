
# Advanced Network Anomaly Detection System

Real-time machine learning-based intrusion detection system with packet-level analysis, flow , and visualization dashboard.

## Features

-   **Real-time packet capture** using Scapy with configurable network interfaces
-   **ML-based anomaly detection** using LightGBM trained on CIC-IDS-2017 dataset
-   **Flow-based analysis** with 35+ network flow features
-   **Interactive web dashboard** built with Streamlit and Plotly
-   **Automated alerting** via email notifications for high-confidence threats
-   **Pattern visualization** including attack timelines, network topology, and threat intelligence
-   **Redis backend** for real-time data storage and retrieval
-   **System resource monitoring** with CPU/memory spike detection

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Packet        │    │   Flow           │    │   Feature       │
│   Capture       │───▶│   Management     │───▶│   Extraction    │
│   (Scapy)       │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web           │    │   Alert          │    │   ML            │
│   Dashboard     │◀───│   Management     │◀───│   Prediction    │
│   (Streamlit)   │    │   (Redis)        │    │   (LightGBM)    │
└─────────────────┘    └──────────────────┘    └─────────────────┘

```

## Installation

### Prerequisites

```bash
# System dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install python3-pip python3-venv redis-server libpcap-dev

# Install Redis
sudo systemctl start redis
sudo systemctl enable redis
```

### Setup

```bash
# Clone repository
git clone https://github.com/mtech00/network-ids
cd network-ids

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download CIC-IDS-2017 dataset (for training)
mkdir cic-ids-17
# Place CSV files in cic-ids-17/ directory

```

### Requirements.txt

```txt
# Core libraries
pandas==2.3.0
numpy==1.26.4
scikit-learn==1.6.1
lightgbm==4.6.0
joblib==1.5.1

# Network and system libraries
scapy==2.6.1
psutil==7.0.0
netifaces==0.11.0
redis==6.2.0

# UI and plotting
streamlit==1.45.1
plotly==6.1.2
networkx==3.4.2
```

## Configuration

Edit `config.py`:

```python
# Network interface (auto-detected by default)
INTERFACE = "eth0"  # Override if needed

# Detection thresholds
THRESHOLD = 0.4
MIN_PACKETS = 5
TIME_WINDOW = 10

# Email notifications
SMTP_SERVER = "your-smtp-server.com"
SMTP_USERNAME = "your-username"
SMTP_PASSWORD = "your-password"
FROM_EMAIL = "ids@yourdomain.com"
TO_EMAIL = "admin@yourdomain.com"

# Redis configuration
REDIS_HOST = 'localhost'
REDIS_PORT = 6379

```

## Usage

### 1. Train Model (First Run)

```bash
# Train on CIC-IDS-2017 dataset
python train.py
```

Expected output:

-   `cic_ids_binary_model.txt` - LightGBM model
-   `feature_names.pkl` - Feature list
-   `model_info.pkl` - Model metadata

### 2. Start IDS Backend

```bash
# Run with appropriate permissions
 sudo "path_to_your_venv" ids_backend.py     
```

### 3. Launch Web Dashboard

```bash
# In separate terminal
streamlit run ids_ui.py
```

Access dashboard at `http://localhost:8501`



## Dashboard Features

### Overview Tab

-   Real-time packet/flow statistics
-   Protocol distribution
-   Recent anomaly alerts

### Time Patterns Tab

-   Attack timeline visualization
-   Hourly attack patterns
-   Confidence score trends

### Network Topology Tab

-   Suspicious IP analysis
-   Port targeting statistics
-   Network flow visualization

### Attack Patterns Tab

-   Attack intensity heatmaps
-   Protocol-based analysis
-   Confidence clustering

### Threat Intelligence Tab

-   Threat severity metrics
-   Top attacker identification
-   Risk assessment tables

## Technical Details

### Feature Extraction

Extracts 35+ flow-based features including:

-   Packet size statistics (min/max/mean/std)
-   Inter-arrival time analysis
-   Protocol-specific flags
-   Flow duration and byte rates
-   Window size analysis

### ML Model

-   **Algorithm**: LightGBM with binary classification
-   **Training**: CIC-IDS-2017 dataset (8 CSV files)
-   **Features**: 35 numerical features
-   **Regularization**: Strong L1/L2 with early stopping
-   **Performance**: >95% accuracy on test set

### Real-time Processing

-   Packet capture at network interface level
-   Flow reconstruction with bidirectional tracking
-   Sliding window analysis (1-second intervals)
-   Redis-based alert storage and retrieval





## File Structure

```
├── ids_backend.py          # Main IDS engine
├── ids_ui.py              # Streamlit dashboard
├── train.py               # Model training script
├── config.py              # Configuration settings
├── packet_processor.py    # Packet parsing
├── flow_manager.py        # Flow tracking
├── feature_extractor.py   # Feature computation
├── model_predictor.py     # ML inference
├── alert_manager.py       # Alert handling
├── email_notifier.py      # Email alerts
├── spike_detector.py      # System monitoring
├── disk_read_detector.py  # Disk anomaly detection
├── example_usage.py       # Test script
└── cic-ids-17/           # Training dataset
```




