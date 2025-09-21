import os
import psutil
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import plotly.express as px
from dotenv import load_dotenv
from datetime import datetime
from computation_stuff import total_risk

load_dotenv()
Your_Name = os.getenv("USER_NAME", "DEF_NAME")

# DATABASE SETUP AND SAVE
# This would be useful for the chart later
def save_to_db(rows):
    conn = sqlite3.connect("network_logs.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            ts TEXT,
            process TEXT,
            local TEXT,
            remote TEXT,
            country TEXT,
            domain TEXT,
            isp TEXT,
            reports INTEGER,
            last_reported TEXT,
            status TEXT,
            risk TEXT,
            risk_score INTEGER
        )
    """)

    for row in rows:
        c.execute("""
            INSERT INTO logs (
                ts, process, local, remote, country, domain, isp,
                reports, last_reported, status, risk, risk_score
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            datetime.now().isoformat(),
            row["Process"],
            row["Local Address"],
            row["Remote Address"],
            row["Country Code"],
            row["Domain"],
            row["ISP"],
            row["Total Reports"],
            row["Last Reported At"],
            row["Status"],
            row["Risk"],
            row["Risk Score"]
        ))

    conn.commit()
    conn.close()

def load_history():
    conn = sqlite3.connect("network_logs.db")
    dff = pd.read_sql_query("SELECT * FROM logs", conn)
    conn.close()
    return dff

def get_connections():
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.raddr:
            pid = conn.pid
            try:
                proc = psutil.Process(pid).name() if pid else "Unknown"
            except Exception:
                proc = "Unknown"

            local = f"{conn.laddr.ip}:{conn.laddr.port}"
            remote_ip = conn.raddr.ip
            remote = f"{conn.raddr.ip}:{conn.raddr.port}"
            status = conn.status
            risk_score, risk_label, extra = total_risk(remote_ip)

            rows.append({
                "Process": proc,
                "Local Address": local,
                "Remote Address": remote,
                "Country Code": extra.get("country", ""),
                "Domain": extra.get("domain", ""),
                "ISP": extra.get("isp", ""),
                "Total Reports": extra.get("reports", 0),
                "Last Reported At": extra.get("lastReported", ""),
                "Status": status,
                "Risk": risk_label,
                "Risk Score": risk_score
            })

    df = pd.DataFrame(rows)
    if not df.empty:
        save_to_db(df.to_dict(orient="records"))
    return df





# THE STREAMLIT INTERFACE
st.set_page_config(page_title="Network Monitor", page_icon="🛡️", layout="wide")
st.title("Welcome "+ Your_Name + "!")
now = datetime.now()
st.subheader("Here's a snapshot of your network activity, taken at exactly " + now.strftime("%Y-%m-%d %H:%M:%S"))

df = get_connections()

if df.empty:
    st.info("No active network connections found. Try something else, maybe the API is messing up")

else:
    col1, col2 = st.columns(2)
