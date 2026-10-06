import sys
from pathlib import Path

# `streamlit run dashboard/dashboard.py` puts dashboard/ on sys.path, not the
# project root, so sibling packages (storage, utils) are not importable without this.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import streamlit as st
import plotly.express as px
from storage.database import init_db, fetch_packets, fetch_alerts

st.set_page_config(page_title="Network Traffic Analyzer", layout="wide")
st.title("Network Traffic Analyzer")
st.caption("Packet metadata monitoring with basic anomaly detection")

init_db()
packets = fetch_packets(500)
alerts = fetch_alerts(200)

packet_df = pd.DataFrame(packets)
alert_df = pd.DataFrame(alerts)

c1, c2, c3 = st.columns(3)
c1.metric("Packets loaded", len(packet_df))
c2.metric("Alerts", len(alert_df))
c3.metric("Total bytes", int(packet_df["length"].sum()) if not packet_df.empty else 0)

st.subheader("Recent packets")
st.dataframe(packet_df, use_container_width=True)

if not packet_df.empty:
    st.subheader("Protocol distribution")
    counts = packet_df["protocol"].value_counts().reset_index()
    counts.columns = ["protocol", "count"]
    fig = px.pie(counts, names="protocol", values="count")
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top source IPs")
    top = packet_df["src_ip"].dropna().value_counts().head(10).reset_index()
    top.columns = ["src_ip", "count"]
    fig2 = px.bar(top, x="src_ip", y="count")
    st.plotly_chart(fig2, use_container_width=True)

st.subheader("Anomaly alerts")
if alert_df.empty:
    st.info("No alerts recorded yet.")
else:
    st.dataframe(alert_df, use_container_width=True)
