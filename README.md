# Secura Network Analyzer Platform (SNAP)
_'Catch connections before they catch you!'_


Meet **Secura Network Analyzer Platform (SNAP)** (Like a picture!) a mini SIEM (Security Information and event management)  dashboard for your pc built with Python and Streamlit!

## What's All This?

Curiosity got the better of me, and I find myself now presenting a lightweight network activity monitoring application that shows which processes, on your machine, are talking to the internet, how risky those connections look, and gives you clear visual dashboards of what’s going on.
Built with Streamlit to display, **psutil** to inspect the machine's running process and **Plotly** to generate interactive visuals of the data, you can:
- Check out the process names, paths, remote addresses, domain, ISP and more for each connection
- Monitor the risk scores and associated risks levels of each connection
- Analyze the charts and data to see what connections that are happening under your nose, both the safe and the not so safe
- Store each connection in an SQLite database to form a timeline of all the connections you've snapped so far

"Isn't it just kinda like Task Manager?" Well yes, but now you get to feel like your own SOC (Security operations center) Analyst with this, which I think is a lot cooler.

[**Here, try the Demo**](https://securera-network.streamlit.app/)! Of course, it's random data, but you get to see how it works visually! But still, it's a cool way to check it out without needing to run it locally or burn through API quotas (yet, at least).
## Setup & Run

**Important:** 
- You need your own API key for this to functionally work, or it just defaults of basic data.
- You must also turn DEMO_MODE to false you WILL get a complete mess of data that is not true. I promise you're not getting hacked, you're probably just on demo mode
- Being a project, it is NO WAY a 100% reliable source to tell if you have compromised executable talking to another machine over internet, although if you do find an actual one, I'm glad it's doing its job somehow.
- Very important to run as administrator, but this code in no shape or form write code TO your system; it just checks the processes that are going and reports back to you, but you're free to modify the code and check


### Steps
1. **Clone the repo**  
   ```bash
   git clone https://github.com/soppi24/securera
   cd securera
    ```

2. **Create a virtual environment**

   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Mac/Linux
   .venv\Scripts\activate      # Windows (That's me!)
   ```

3. **Install requirements**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up your `.env` file.**
   - Don't touch DEF_NAME, it's like the default name if you don't put your name

   ```ini
   ABUSEIPDB_KEY=your_api_key_here
   USER_NAME=your_own_name_here
   DEF_NAME=Stranger 
   ```

5. **Run the app**

   ```bash
   streamlit run main.py
   ```

## Files

- `main.py` - Main Streamlit place with charts 
- `computation_stuff.py` - Place that figures out important data for each connection, like it's risk score
- `netwrok_logs.db` - (auto generated) Keeps track of every connection you've hit per time stamp

## Tech Stack (Or if you can even call it that)

- Python 3.10+ 
- LangChain 
- Streamlit for UI 
- Python Libraries
  - psutil 
  - plotly
  - amongst other ones of course
-AbuseIPDB (API for IP reputation) 