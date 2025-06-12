import streamlit as st
import pandas as pd
from pushbullet import Pushbullet

# --------------- PUSHBULLET CONFIG -------------------
PUSHBULLET_TOKEN = "o.aXiYN8UVCcVKTcaklBTJ1YlIMrVhyibS"  # Your Pushbullet API token
pb = Pushbullet(PUSHBULLET_TOKEN)

def send_pushbullet_alert(title, message):
    try:
        pb.push_note(title, message)
        print("✅ Pushbullet alert sent.")
    except Exception as e:
        print("❌ Failed to send Pushbullet alert:", e)

# --------------- PAGE SETUP -------------------
st.set_page_config(
    page_title="USB Threat Monitor",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 USB Threat Monitoring Dashboard")
st.markdown("Monitor real-time logs of USB activity and detect any suspicious or malware-like behavior on USB devices.")

# --------------- SIDEBAR -------------------
with st.sidebar:
    st.image("https://img.icons8.com/external-flat-juicy-fish/344/external-usb-technology-flat-flat-juicy-fish.png", width=100)
    st.header("USB Tool Control Panel")
    st.info("Check logs and detect threats on USB-connected devices in real-time.")

# --------------- LOAD DATA -------------------
sheet_id = "1mBuhti3Z9cukL3lhTs0kx63qcJ3Zqh0nGS_McB28OXI"
sheet_name = "Sheet1"
csv_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&sheet={sheet_name}"

try:
    df = pd.read_csv(csv_url)
    st.success("USB logs successfully loaded.")
except Exception as e:
    st.error("Failed to load USB logs. Please check the sheet link or your internet connection.")
    st.stop()

# Ensure required columns are present
required_cols = ['Timestamp', 'Device Name', 'Message']
if not all(col in df.columns for col in required_cols):
    st.error("The data is missing required columns: Timestamp, Device Name, or Message.")
    st.stop()

# Sort by timestamp
df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
df = df.sort_values(by='Timestamp', ascending=False)

# --------------- DISPLAY ALL LOGS -------------------
st.subheader("🧾 USB Device Activity Log")
st.dataframe(df, use_container_width=True)

# --------------- MALWARE DETECTION -------------------
malware_keywords = [
    '.exe', '.vbs', '.scr', 'autorun.inf', 'malware', 'exploit',
    'payload', 'vulnerability', 'ransomware', 'keylogger', 'worm',
    'trojan', 'spyware'
]

# Add Suspicious column
df['Suspicious'] = df['Message'].str.contains('|'.join(malware_keywords), case=False, na=False)
suspicious_df = df[df['Suspicious']]

# 🧪 Debugging section to test detection
st.write("🔍 Suspicious Keyword Detection Debug")
st.dataframe(df[['Message', 'Suspicious']], use_container_width=True)

if not suspicious_df.empty:
    st.error("🚨 ALERT: Suspicious USB Activity Detected!")
    st.dataframe(suspicious_df, use_container_width=True)

    # 🔔 Send Pushbullet alert
    latest_alert = suspicious_df.iloc[0]
    title = "🚨 USB Threat Detected"
    message = f"Suspicious file detected: {latest_alert['Message']} on {latest_alert['Device Name']}"
    send_pushbullet_alert(title, message)

    # 🔊 Browser beep
    st.markdown("""
    <script>
        var ctx = new (window.AudioContext || window.webkitAudioContext)();
        var oscillator = ctx.createOscillator();
        oscillator.type = "sine";
        oscillator.frequency.setValueAtTime(1000, ctx.currentTime);
        oscillator.connect(ctx.destination);
        oscillator.start();
        oscillator.stop(ctx.currentTime + 0.4);
    </script>
    """, unsafe_allow_html=True)
else:
    st.success("✅ No suspicious USB activity detected.")
    st.info("Debug: No suspicious activity found in suspicious_df.")

# --------------- MANUAL ALERT TEST BUTTON -------------------
if st.button("🚨 Send Manual Test Alert"):
    st.warning("🚨 TEST ALERT TRIGGERED MANUALLY")
    send_pushbullet_alert("🚨 Test Alert", "Manual test alert sent from Streamlit.")

# --------------- SEARCH / FILTER -------------------
with st.expander("🔍 Filter logs by keyword"):
    keyword = st.text_input("Enter a keyword (e.g., '.exe', 'autorun') to filter logs:")
    if keyword:
        filtered_df = df[df['Message'].str.contains(keyword, case=False, na=False)]
        if not filtered_df.empty:
            st.write(f"Showing results for: **{keyword}**")
            st.dataframe(filtered_df, use_container_width=True)
        else:
            st.warning("No matching logs found for that keyword.")

# --------------- END -------------------
st.caption("Project by Krupal Sudra — USB Threat Monitor v1.0")
