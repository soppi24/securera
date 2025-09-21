import os
import ipaddress
import requests
from dotenv import load_dotenv
from functools import lru_cache
import random

# Setup Stuff
DEMO_MODE = False
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY", "")


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

# Essentially, anything that is not local is like a 50. Not dangerous but not innocent
def basic_risk(ip: str) -> int:
    if not ip or ip.startswith("127."):
        return 0
    if is_private_ip(ip):
        return 0
    return 50

