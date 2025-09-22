import os
import psutil
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import plotly.express as px
from dotenv import load_dotenv
from datetime import datetime
from computation_stuff import total_risk, DEMO_MODE, generate_demo_data

load_dotenv()
Your_Name = os.getenv("USER_NAME", "DEF_NAME")

# DATABASE SETUP AND SAVE AND LOAD
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

# DATA RETRIVAL STUFF
def get_connections():
    if DEMO_MODE:
        rows = generate_demo_data(100)
        return pd.DataFrame(rows)
    else:
        rows = []
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr:
                pid = conn.pid
                try:
                    proc_name = psutil.Process(pid).name() if pid else "Unknown"
                    proc_loc = psutil.Process(pid).exe() if pid else "Unknown"
                except Exception:
                    proc_name = "Unknown"
                    proc_loc = "Unknown Location"

                local = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_ip = conn.raddr.ip
                remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                status = conn.status
                risk_score, risk_label, extra = total_risk(remote_ip)

                rows.append({
                    "Process": proc_name,
                    "Local Address": local,
                    "Remote Address": remote,
                    "Path Location": proc_loc,
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

# INTRO
st.set_page_config(page_title="Securea Network Monitor", layout="wide")
st.title("Welcome "+ Your_Name + "!")
now = datetime.now()
st.subheader("Here's a snapshot of your network activity, taken at exactly " + now.strftime("%Y-%m-%d %H:%M:%S"))
df = get_connections()

# MAIN DASHBOARD STUFF
if df.empty:
    st.info("No active network connections found. Try something else, maybe the API is messing up")

else:
    col1, col2 = st.columns(2)

    # Helper vars
    safe_count = (df["Risk"] == "Usual Systems").sum()
    suspicious_count = (df["Risk"] == "Approach with Caution").sum()
    malicious_count = (df["Risk"] == "Likely Malicious").sum()

    risk_data = pd.DataFrame({
        "Category" : ["Usual Systems", "Approach with Caution", "Likely Malicious"],
        "Count" : [safe_count, suspicious_count, malicious_count]
    })

    # CHARTS: PIE FIRST THEN BAR
    pie_chart = px.pie(
        risk_data,
        values="Count",
        names="Category",
        title="Risk Distribution",
        color="Category",
        color_discrete_map={
            "Usual Systems": "green",
            "Approach with Caution": "orange",
            "Likely Malicious": "red"
        }
    )

    # THEN BAR
    df_counts = df["Process"].value_counts().reset_index()
    df_counts.columns = ["Process", "Connections"]
    bar_chart = px.bar(df_counts, x="Process", y="Connections", title="Connections by Process")


    with col1:
        st.plotly_chart(pie_chart, use_container_width=True)

    with col2:
        st.plotly_chart(bar_chart, use_container_width=True)


    # OVERVIEW
    # More stats, but also state most rec remote address, like who's the comp talking to the most
    st.header("Risk Overview")
    # A fun little greeting header
    if malicious_count >= 1:
        message = "Uh oh, seems to be trouble a brew, check it out ASAP!"
    elif suspicious_count >= 1:
        message = "Seems to be business as usual, just a few things to be cautious about."
    else:
        message = "All good here! Wow!"
    st.subheader(message)


    # 1.Metric slide
    col1, col2, col3, col4 = st.columns(4)
    top_remote = df["Remote Address"].value_counts().idxmax()
    count = df["Remote Address"].value_counts().max()

    col1.metric("Usual Systems", safe_count)
    col2.metric("Approach with Caution", suspicious_count)
    col3.metric("Likely Malicious", malicious_count)
    col4.metric("Most Recurring Remote", top_remote, f"{count} connections")

    # Markdown colors. Can't decide which look better, but I'll go with the above for now
    # col1.markdown(f"""
    #     <div style='text-align:center;'>
    #         <span style='font-weight:bold;'>Usual Systems</span><br>
    #         <span style='color:green; font-size:36px;'>{safe_count}</span>
    #     </div>
    # """, unsafe_allow_html=True)
    #
    # col2.markdown(f"""
    #     <div style='text-align:center;'>
    #         <span style='font-weight:bold;'>Approach with Caution</span><br>
    #         <span style='color:orange; font-size:36px;'>{suspicious_count}</span>
    #     </div>
    # """, unsafe_allow_html=True)
    #
    # col3.markdown(f"""
    #     <div style='text-align:center;'>
    #         <span style='font-weight:bold;'>Likely Malicious</span><br>
    #         <span style='color:red; font-size:36px;'>{malicious_count}</span>
    #     </div>
    # """, unsafe_allow_html=True)
    #
    # col4.markdown(f"""
    #     <div style='text-align:center;'>
    #         <span style='font-weight:bold;'>Most Recurring Remote</span><br>
    #         <span style='color:#87CEEB; font-size:36px;'>{top_remote} </span>
    #         <span style='color:#87CEEB; font-size:12px;'>({count} connections)</span>
    #     </div>
    # """, unsafe_allow_html=True)

    # 2.Table
    # The Table Color settings, then the table
    # TODO: More expo for ports
    st.header("Processes Captured")
    st.write(" This all the process connections that were happening at that time stamp. Note they happen fast and some disappear as quick as they came. So snapshots tend to not be the same.")
    def highlight_risk(val):
        if "Usual Systems" in val: return "color: green; font-weight: bold;"
        if "Approach with Caution" in val: return "color: orange; font-weight: bold;"
        if "Likely Malicious" in val: return "color: red; font-weight: bold;"
        return ""

    st.dataframe(
        df.style.applymap(highlight_risk, subset=["Risk"]),
        use_container_width=True
    )

    # 3. TimeLine Trend
    st.subheader("Timeline Trends")
    st.write(" This chart shows your connections overtime PER category. That is, 'how many connections of that risk level occurred in that time bucket.' If at 2025-09-21 01:05 you had 12 Safe, "
             "2 Suspicious, 1 Malicious, then count = 12, 2, 1 for each risk category. Although this means the more you keep spamming this program, the more screenshots "
             "you get and of course, the bigger the database. Count is, well, count, and ts is the timestamp. A small observation I made is that the 2 lines below (thankfully everything but NOT Likely Malicious) indicate that there are invisible, unknown processes the usual ones may talk to, as they follow a similar trend line, just with a different number of connections." )

    # if not DEMO_MODE:
    #     hist_df = load_history()
    # else:
    #     hist_df = pd.DataFrame()
    hist_df = load_history()
    if hist_df.empty:
        st.info("No history logged yet. Try again??")
    else:

        hist_df["ts"] = pd.to_datetime(hist_df["ts"])

        hist_summary = (
            hist_df.groupby([pd.Grouper(key="ts", freq="1min"), "risk"])
            .size()
            .reset_index(name="count")
        )

        fig_hist = px.line(
            hist_summary,
            x="ts",
            y="count",
            color="risk",
            title="Risk Levels Over Time",
            color_discrete_map={
                "Usual Systems": "green",
                "Approach with Caution": "orange",
                "Likely Malicious": "red"
            }
        )
        st.plotly_chart(fig_hist, use_container_width=True)
