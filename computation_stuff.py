# For Future Me: Always make comments for the code, really helps down the road

import os
import ipaddress
from datetime import datetime
import requests
from dotenv import load_dotenv
from functools import lru_cache
import random

# Setup Stuff
DEMO_MODE = True
load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY", "")


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

# Essentially, anything is not local is like a 50. Not dangerous but not innocent either
# It's editable but making 50 the cutoff here. It means it's talking to something outside the computer
# but the danger is uncertain
def basic_risk(ip: str) -> int:
    if not ip or ip.startswith("127."):
        return 0
    if is_private(ip):
        return 0
    return 50

# Cache for super recent lookups to save my api usages
@lru_cache(maxsize=500)
def abuseipdb_lookup(ip: str) -> dict:
    if DEMO_MODE:
        if not API_KEY or is_private(ip) or ip.startswith("127."):
            return {"abuseConfidenceScore": 0}
        return {}
    else:
        if not API_KEY or is_private(ip) or ip.startswith("127."):
            return {"abuseConfidenceScore": 0}

        # try:
        #     resp = requests.get(
        #         "https://api.abuseipdb.com/api/v2/check",
        #         params={"ipAddress": ip, "maxAgeInDays": 90},
        #         headers={"Key": API_KEY, "Accept": "application/json"},
        #         timeout=3,
        #     )
        #     data = resp.json().get("data", {})
        #     return {
        #         "score": data.get("abuseConfidenceScore", 0),
        #         "country": data.get("countryCode", "Unknown"),
        #         "domain": data.get("domain", "Unknown"),
        #         "isp": data.get("isp", "Unknown"),
        #         "reports": data.get("totalReports", 0),
        #         "lastReported": data.get("lastReportedAt", "Never")
        #     }
        # except Exception as e:
        #     return {"error": str(e)}
        return None


# Here it combines the basic/predicted risk and adds to the risk Abuse
# IPDB gives back, but capped at 100 so it's not over it
def total_risk(ip: str):
    base = basic_risk(ip)
    report = abuseipdb_lookup(ip)

    score = min(100, base + report.get("score", 0))

    if score >= 75:
        label = "Likely Malicious"
    elif score >= 50:
        label = "Approach with Caution"
    else:
        label = "Usual Systems"

    return score, label, report

# For demo stuff. Really just random data
def generate_demo_data(n=50):
    fake_processes = ["chrome.exe", "python.exe", "discord.exe", "svchost.exe", "spotify.exe",
                      "teams.exe", "zoom.exe", "slack.exe", "explorer.exe",
                      "outlook.exe", "word.exe","supersketchy.exe", "dontworryaboutit.exe", "imnotminingbitcoiniswear.exe"]
    fake_bad_processes = ["supersketchy.exe", "dontworryaboutit.exe", "imnotminingbitcoiniswear.exe",]
    fake_ips = ["8.8.8.8", "1.1.1.1", "142.250.72.14", "185.220.101.1", "192.168.1.10"]
    fake_status = ["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"]
    fake_domains = ["example.com", "secure-login.net","fastvpn.org", "evenfastervpnipromise.org"
        "mailservice.co", "cloudsync.app", "update-server.net", "willmineyourdata.org",
                    "dataexchange.io","freegames247.org","darkmarket.biz" ]
    fake_isps = ["Comcast Cable Communications", "AT&T Internet Services","Deutsche Telekom AG", "Bell Alient.",
        "EastLink Group", "China Telecom", "Gimme your money Communications","Legit ISP Services","FakeNet ISP"]
    fake_country= ["US", "CA", "GB", "DE", "FR","RU", "CN", "BR", "IN", "AU"]

    rows = []
    for _ in range(n):
        proc = random.choice(fake_processes)
        ip = random.choice(fake_ips)
        port = random.randint(1024, 65535)
        local = f"192.168.1.{random.randint(2,200)}:{random.randint(1000,9999)}"
        remote = f"{ip}:{port}"

        score, label, rep = total_risk(ip)

        if proc in fake_bad_processes:
            score = random.randint(75, 100)
            label = "Likely Malicious"

        rows.append({
            "Process": proc,
            "Local Address": local,
            "Remote Address": remote,
            "Path Location": f"C:/Program Files/{proc}",
            "Country Code": random.choice(fake_country),
            "Domain": random.choice(fake_domains),
            "ISP": random.choice(fake_isps),
            "Total Reports": rep.get("reports", random.randint(0, 10)),
            "Last Reported At": datetime.now().isoformat(),
            "Status": random.choice(fake_status),
            "Risk": label,
            "Risk Score": score
        })


    return rows