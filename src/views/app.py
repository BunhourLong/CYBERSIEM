import os

import pandas as pd
import plotly.express as px
import streamlit as st
from pymongo import MongoClient
from streamlit_autorefresh import st_autorefresh

# -----------------------------
# Mongo Connection
# -----------------------------
st_autorefresh(interval=5000, key="refresh")

MONGO_URI = os.getenv("MONGO_URI", "mongodb://sentinel:sentinelpass@localhost:27017")

client = MongoClient(MONGO_URI)
db = client["sentinel_ids"]
events_collection = db["events"]


# -----------------------------
# Page Config
# -----------------------------

st.set_page_config(page_title="Sentinel IDS", layout="wide")

st.title("🛡️ Sentinel IDS - Live Monitoring")

# Auto-refresh every 5 seconds
st_autorefresh = st.empty()


# -----------------------------
# Fetch Data
# -----------------------------


def get_recent_events(limit=200):
    events = list(events_collection.find().sort("timestamp", -1).limit(limit))
    return events


events = get_recent_events()

if not events:
    st.warning("No events captured yet...")
    st.stop()

df = pd.DataFrame(events)

# Remove Mongo _id column
if "_id" in df.columns:
    df = df.drop(columns=["_id"])


# -----------------------------
# Severity Metrics
# -----------------------------

col1, col2, col3, col4 = st.columns(4)

total_events = len(df)
high_count = len(df[df["severity"] == "high"])
medium_count = len(df[df["severity"] == "medium"])
normal_count = len(df[df["classification"] == "normal"])

col1.metric("Total Events", total_events)
col2.metric("High Severity 🔴", high_count)
col3.metric("Medium Severity 🟡", medium_count)
col4.metric("Normal Traffic 🟢", normal_count)


st.divider()


def show_map(df):
    geo_df = df.dropna(subset=["latitude", "longitude"])

    if geo_df.empty:
        st.info("No geolocation data yet.")
        return

    color_map = {"normal": "green", "port_scan": "orange", "brute_force": "red"}

    geo_df["color"] = geo_df["classification"].map(color_map)

    fig = px.scatter_geo(
        geo_df,
        lat="latitude",
        lon="longitude",
        hover_name="src_ip",
        hover_data=["country", "classification", "severity"],
        color="classification",
        color_discrete_map={"normal": "green", "port_scan": "orange", "brute_force": "red"},
    )

    fig.update_layout(title="Global Traffic Map", height=600)

    st.plotly_chart(fig, use_container_width=True)


st.divider()
st.subheader("🌍 Global Traffic Overview")
show_map(df)

# -----------------------------
# Styled Event Table
# -----------------------------


def highlight_severity(row):
    if row["severity"] == "high":
        return ["background-color: #ffcccc"] * len(row)
    elif row["severity"] == "medium":
        return ["background-color: #fff3cd"] * len(row)
    elif row["classification"] == "normal":
        return ["background-color: #d4edda"] * len(row)
    else:
        return [""] * len(row)


styled_df = df.style.apply(highlight_severity, axis=1)

st.subheader("Recent Network Events")
st.dataframe(styled_df, use_container_width=True)


# -----------------------------
# Auto Refresh Loop
# -----------------------------
