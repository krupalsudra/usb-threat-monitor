import streamlit as st
import gspread
from google.oauth2.service_account import Credentials
import pandas as pd

# Google Sheets Setup
SERVICE_ACCOUNT_FILE = 'credentials.json'  # 🔧 FIXED path for cloud
SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
credentials = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
gc = gspread.authorize(credentials)

# Load sheet
sheet = gc.open("USB Threat Logs").sheet1  # Make sure this name is correct
data = sheet.get_all_records()
df = pd.DataFrame(data)

# Streamlit App
st.set_page_config(page_title="USB Threat Monitor", layout="wide")
st.title("🔐 USB Threat Monitoring Dashboard")

st.markdown("This dashboard displays real-time logs of USB devices and potential threats detected on local machines.")

# Display log data
st.dataframe(df)

# Optional filter
with st.expander("🔍 Filter by keyword"):
    keyword = st.text_input("Enter keyword to search (e.g., '.exe', 'D:\\', etc.)")
    if keyword:
        st.dataframe(df[df['Message'].str.contains(keyword, case=False)])

st.success("Dashboard Loaded Successfully ✅")
