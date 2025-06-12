# ids_ui.py - Run this without sudo
import streamlit as st
import pandas as pd
import redis
import json
import time
import datetime
import plotly.graph_objects as go
import plotly.express as px

# Redis connection
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

st.set_page_config(page_title="Network IDS Monitor", layout="wide")

st.title(" Real-Time Network Intrusion Detection System")

# Check if backend is running
try:
    stats_json = r.get('ids_stats')
    if stats_json:
        backend_running = True
    else:
        backend_running = False
except:
    backend_running = False

if not backend_running:
    st.error(" IDS Backend not running! `")
    st.stop()

# Main dashboard
stats = json.loads(r.get('ids_stats'))

# Metrics row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Packets", f"{stats['total_packets']:,}")

with col2:
    st.metric("Active Flows", stats['active_flows'])

with col3:
    st.metric("Anomalies Detected", stats['anomalies_detected'])

with col4:
    detection_rate = stats['anomalies_detected'] / max(1, stats['total_packets']) * 100
    st.metric("Detection Rate", f"{detection_rate:.2f}%")

# Charts
col1, = st.columns(1)

with col1:
    st.subheader("Protocol Distribution")
    if stats['protocol_stats']:
        fig = px.pie(
            values=list(stats['protocol_stats'].values()),
            names=list(stats['protocol_stats'].keys()),
            title="Network Protocol Usage"
        )
        st.plotly_chart(fig, use_container_width=True)

# with col2:
#     st.subheader("Traffic Timeline")
#     # You could store timeline data in Redis for this
#     st.info("Traffic timeline visualization here")

# Alerts section
st.subheader(" Recent Anomalies")

alerts = []
alert_count = r.llen('ids_alerts')
if alert_count > 0:
    for i in range(min(20, alert_count)):  # Show last 20 alerts
        alert_json = r.lindex('ids_alerts', i)
        if alert_json:
            alerts.append(json.loads(alert_json))

if alerts:
    alerts_df = pd.DataFrame(alerts)
    alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
    alerts_df = alerts_df.sort_values('timestamp', ascending=False)
    
    # Format display
    display_df = alerts_df[['timestamp', 'src', 'dst', 'protocol', 'confidence']].copy()
    display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.3f}")
    display_df['timestamp'] = display_df['timestamp'].apply(lambda x: x.strftime("%H:%M:%S"))
    
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": "Time",
            "src": "Source",
            "dst": "Destination",
            "protocol": "Protocol",
            "confidence": "Confidence"
        }
    )
else:
    st.info("No anomalies detected yet")

# Auto-refresh
time.sleep(1)
st.rerun() # Forces the Streamlit script to rerun from the top.
