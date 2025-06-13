
import streamlit as st
import pandas as pd
import redis
import json
import time
import datetime
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
from collections import defaultdict, Counter
import networkx as nx

# Redis connection
r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

st.set_page_config(page_title="Network IDS Monitor", layout="wide")

st.title(" Real-Time Network Anomaly Detection System")

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
    st.error(" IDS Backend not running!")
    st.stop()

# Load data
stats = json.loads(r.get('ids_stats'))

# Load alerts for pattern analysis
alerts = []
alert_count = r.llen('ids_alerts')
if alert_count > 0:
    for i in range(min(100, alert_count)):  # Load more alerts for pattern analysis
        alert_json = r.lindex('ids_alerts', i)
        if alert_json:
            alerts.append(json.loads(alert_json))

# Convert to DataFrame for analysis
alerts_df = pd.DataFrame(alerts) if alerts else pd.DataFrame()

# Main metrics
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

# Tabs for different visualizations
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    " Overview", 
    " Time Patterns", 
    " Network Topology", 
    " Attack Patterns",
    " Threat Intelligence"
])

with tab1:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Protocol Distribution")
        if stats['protocol_stats']:
            fig = px.pie(
                values=list(stats['protocol_stats'].values()),
                names=list(stats['protocol_stats'].keys()),
                title="Network Protocol Usage"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Recent Anomalies")
        if not alerts_df.empty:
            alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
            recent_alerts = alerts_df.head(10)
            
            display_df = recent_alerts[['timestamp', 'src', 'dst', 'protocol', 'confidence']].copy()
            display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.3f}")
            display_df['timestamp'] = display_df['timestamp'].apply(lambda x: x.strftime("%H:%M:%S"))
            
            st.dataframe(display_df, use_container_width=True, hide_index=True)
        else:
            st.info("No anomalies detected yet")

with tab2:
    st.subheader(" Temporal Attack Patterns")
    
    if not alerts_df.empty:
        alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
        alerts_df['hour'] = alerts_df['timestamp'].dt.hour
        alerts_df['minute'] = alerts_df['timestamp'].dt.minute
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Anomaly timeline
            alerts_timeline = alerts_df.set_index('timestamp').resample('1Min').size()
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=alerts_timeline.index,
                y=alerts_timeline.values,
                mode='lines+markers',
                name='Anomalies per Minute',
                line=dict(color='red', width=2),
                marker=dict(size=4)
            ))
            
            fig.update_layout(
                title="Anomaly Detection Timeline",
                xaxis_title="Time",
                yaxis_title="Anomalies Count",
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Hourly pattern
            hourly_pattern = alerts_df['hour'].value_counts().sort_index()
            
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=hourly_pattern.index,
                y=hourly_pattern.values,
                marker_color='red',
                opacity=0.7
            ))
            
            fig.update_layout(
                title="Attack Pattern by Hour",
                xaxis_title="Hour of Day",
                yaxis_title="Number of Anomalies",
                xaxis=dict(tickmode='linear', tick0=0, dtick=2)
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Confidence score distribution over time
        st.subheader("Confidence Score Patterns")
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=alerts_df['timestamp'],
            y=alerts_df['confidence'],
            mode='markers',
            marker=dict(
                size=8,
                color=alerts_df['confidence'],
                colorscale='Reds',
                showscale=True,
                colorbar=dict(title="Confidence")
            ),
            text=alerts_df['src'] + ' -> ' + alerts_df['dst'],
            hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Confidence: %{y:.3f}<extra></extra>'
        ))
        
        fig.update_layout(
            title="Anomaly Confidence Scores Over Time",
            xaxis_title="Time",
            yaxis_title="Confidence Score"
        )
        st.plotly_chart(fig, use_container_width=True)

with tab3:
    st.subheader("Suspicious Network Topology")
    
    if not alerts_df.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            # Top suspicious IPs
            src_counts = alerts_df['src'].value_counts().head(10)
            dst_counts = alerts_df['dst'].value_counts().head(10)
            
            fig = make_subplots(
                rows=1, cols=2,
                subplot_titles=("Top Suspicious Sources", "Top Targeted Destinations"),
                specs=[[{"type": "bar"}, {"type": "bar"}]]
            )
            
            fig.add_trace(
                go.Bar(x=src_counts.values, y=src_counts.index, orientation='h', 
                      marker_color='red', name='Source IPs'),
                row=1, col=1
            )
            
            fig.add_trace(
                go.Bar(x=dst_counts.values, y=dst_counts.index, orientation='h',
                      marker_color='orange', name='Destination IPs'),
                row=1, col=2
            )
            
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Port distribution
            st.subheader("Suspicious Port Activity")
            
            # Extract ports from flow keys
            ports = []
            for _, alert in alerts_df.iterrows():
                try:
                    src_port = alert['src'].split(':')[1] if ':' in alert['src'] else 'Unknown'
                    dst_port = alert['dst'].split(':')[1] if ':' in alert['dst'] else 'Unknown'
                    ports.extend([src_port, dst_port])
                except:
                    continue
            
            if ports:
                port_counts = Counter(ports).most_common(10)
                port_df = pd.DataFrame(port_counts, columns=['Port', 'Count'])
                
                fig = px.bar(port_df, x='Port', y='Count', 
                           title="Most Targeted Ports",
                           color='Count', color_continuous_scale='Reds')
                st.plotly_chart(fig, use_container_width=True)
        
        # Network flow visualization
        st.subheader("Attack Flow Network")
        
        # Create network graph data
        if len(alerts_df) > 5:  # Only if we have enough data
            # Sample for performance
            sample_alerts = alerts_df.head(20)
            
            nodes = set()
            edges = []
            edge_weights = defaultdict(int)
            
            for _, alert in sample_alerts.iterrows():
                src = alert['src'].split(':')[0]  # Remove port
                dst = alert['dst'].split(':')[0]  # Remove port
                nodes.add(src)
                nodes.add(dst)
                edge_key = (src, dst)
                edge_weights[edge_key] += 1
            
            # Create network graph
            node_trace = go.Scatter(
                x=[], y=[], mode='markers+text',
                marker=dict(size=10, color='red'),
                text=[], textposition="middle center",
                hoverinfo='text', name='Network Nodes'
            )
            
            edge_trace = []
            
            # Simple circular layout
            import math
            nodes_list = list(nodes)
            n = len(nodes_list)
            
            for i, node in enumerate(nodes_list):
                angle = 2 * math.pi * i / n
                x = math.cos(angle)
                y = math.sin(angle)
                node_trace['x'] += tuple([x])
                node_trace['y'] += tuple([y])
                node_trace['text'] += tuple([node])
            
            # Add edges
            for (src, dst), weight in edge_weights.items():
                if src in nodes_list and dst in nodes_list:
                    src_idx = nodes_list.index(src)
                    dst_idx = nodes_list.index(dst)
                    
                    src_x = math.cos(2 * math.pi * src_idx / n)
                    src_y = math.sin(2 * math.pi * src_idx / n)
                    dst_x = math.cos(2 * math.pi * dst_idx / n)
                    dst_y = math.sin(2 * math.pi * dst_idx / n)
                    
                    edge_trace.append(go.Scatter(
                        x=[src_x, dst_x, None],
                        y=[src_y, dst_y, None],
                        mode='lines',
                        line=dict(width=weight, color='red'),
                        hoverinfo='none', showlegend=False
                    ))
            
            fig = go.Figure(data=[node_trace] + edge_trace)
            fig.update_layout(
                title="Suspicious Network Connections",
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[ dict(
                    text="Red lines show attack flows",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor="left", yanchor="bottom",
                    font=dict(color="red", size=12)
                )],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
            
            st.plotly_chart(fig, use_container_width=True)

with tab4:
    st.subheader(" Attack Pattern Analysis")
    
    if not alerts_df.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack intensity heatmap
            st.subheader("Attack Intensity Heatmap")
            
            alerts_df['hour'] = alerts_df['timestamp'].dt.hour
            alerts_df['day'] = alerts_df['timestamp'].dt.day_name()
            
            # Create pivot table for heatmap
            heatmap_data = alerts_df.groupby(['day', 'hour']).size().unstack(fill_value=0)
            
            fig = go.Figure(data=go.Heatmap(
                z=heatmap_data.values,
                x=heatmap_data.columns,
                y=heatmap_data.index,
                colorscale='Reds',
                hoverongaps=False
            ))
            
            fig.update_layout(
                title="Attack Intensity by Day and Hour",
                xaxis_title="Hour of Day",
                yaxis_title="Day of Week"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Protocol-based attack patterns
            st.subheader("Attack Patterns by Protocol")
            
            protocol_pattern = alerts_df['protocol'].value_counts()
            
            fig = go.Figure(data=[
                go.Bar(x=protocol_pattern.index, y=protocol_pattern.values,
                      marker_color=['red', 'orange', 'yellow'][:len(protocol_pattern)])
            ])
            
            fig.update_layout(
                title="Attacks by Protocol Type",
                xaxis_title="Protocol",
                yaxis_title="Number of Attacks"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Confidence vs Time scatter with attack clusters
        st.subheader("Attack Clustering Analysis")
        
        fig = go.Figure()
        
        # Group by confidence ranges for better visualization
        alerts_df['confidence_range'] = pd.cut(alerts_df['confidence'], 
                                             bins=[0, 0.10, 0.15, 0.2], 
                                             labels=['Low', 'Medium', 'High'])
        
        colors = {'Low': 'yellow', 'Medium': 'orange', 'High': 'red'}
        
        for conf_range in alerts_df['confidence_range'].unique():
            if pd.notna(conf_range):
                subset = alerts_df[alerts_df['confidence_range'] == conf_range]
                fig.add_trace(go.Scatter(
                    x=subset['timestamp'],
                    y=subset['confidence'],
                    mode='markers',
                    marker=dict(
                        size=10,
                        color=colors.get(conf_range, 'gray'),
                        opacity=0.7
                    ),
                    name=f'{conf_range} Confidence',
                    text=subset['src'] + ' -> ' + subset['dst'],
                    hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Confidence: %{y:.3f}<extra></extra>'
                ))
        
        fig.update_layout(
            title="Attack Confidence Clustering",
            xaxis_title="Time",
            yaxis_title="Confidence Score",
            hovermode='closest'
        )
        st.plotly_chart(fig, use_container_width=True)

with tab5:
    st.subheader(" Threat Intelligence Dashboard")
    
    if not alerts_df.empty:
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Unique Attackers", 
                len(alerts_df['src'].unique()),
                delta=f"+{len(alerts_df['src'].unique()) - len(alerts_df['src'].unique()[:-1])}" if len(alerts_df) > 1 else None
            )
        
        with col2:
            avg_confidence = alerts_df['confidence'].mean()
            st.metric(
                "Avg Threat Level", 
                f"{avg_confidence:.3f}",
                delta=f"{'High' if avg_confidence > 0.8 else 'Medium' if avg_confidence > 0.6 else 'Low'}"
            )
        
        with col3:
            recent_attacks = len(alerts_df[alerts_df['timestamp'] > (pd.Timestamp.now() - pd.Timedelta(minutes=5))])
            st.metric("Recent Attacks (5min)", recent_attacks)
        
        # Threat severity distribution
        st.subheader("Threat Severity Distribution")
        
        severity_bins = pd.cut(alerts_df['confidence'], 
                             bins=[0, 0.10, 0.15, 0.20, 0.25], 
                             labels=['Low', 'Medium', 'High', 'Critical'])
        severity_counts = severity_bins.value_counts()
        
        fig = go.Figure(data=[
            go.Bar(x=severity_counts.index, y=severity_counts.values,
                  marker_color=['green', 'yellow', 'orange', 'red'])
        ])
        
        fig.update_layout(
            title="Threat Severity Distribution",
            xaxis_title="Severity Level",
            yaxis_title="Number of Threats"
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Top threats table
        st.subheader("Top Threat Sources")
        
        threat_summary = alerts_df.groupby('src').agg({
            'confidence': ['count', 'mean', 'max'],
            'dst': 'nunique'
        }).round(3)
        
        threat_summary.columns = ['Attack_Count', 'Avg_Confidence', 'Max_Confidence', 'Targets']
        threat_summary = threat_summary.sort_values('Attack_Count', ascending=False).head(10)
        
        st.dataframe(threat_summary, use_container_width=True)

# # Auto-refresh controls
# st.sidebar.header(" Refresh Settings")
# auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
# refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 1, 30, 5)

while(1)  :

    time.sleep(1)
    st.rerun()