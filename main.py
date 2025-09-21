import os
import psutil
import streamlit as st
import pandas as pd
import sqlite3
from datetime import datetime
import plotly.express as px
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
Your_Name = os.getenv("USER_NAME", "DEF_NAME")


# THE STREAMLIT INTERFACE
st.set_page_config(page_title="Network Monitor", page_icon="🛡️", layout="wide")
st.title("Welcome "+ Your_Name + "!")
now = datetime.now()
st.write("Here's a snapshot of your network activity, taken at exactly " + now.strftime("%Y-%m-%d %H:%M:%S"))