import streamlit as st
import pandas as pd

# 🔗 Public Google Sheet as CSV
sheet_id = "1mBuhti3Z9cukL3lhTs0kx63qcJ3Zqh0nGS_McB28OXI"
sheet_name = "Sheet1"  # Update if your sheet has a different name
csv_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/gviz/tq?tqx=out:csv&sheet={sheet_name}"

# Load data
df = pd.read_csv(csv_url)

# Streamlit UI
st.set_page_config(page_title="USB Threat Monitor", layout="wide")
st.title("🔐 USB Threat Monitoring Dashboard")
st.markdown("This dashboard displays real-time logs of USB devices and potential threats detected on local machines.")

# Show data
st.dataframe(df)

# Filter option
with st.expander("🔍 Filter by keyword"):
    keyword = st.text_input("Enter keyword to search (e.g., '.exe', 'D:\\', etc.)")
    if keyword:
        st.dataframe(df[df['Message'].str.contains(keyword, case=False, na=False)])

st.success("Dashboard Loaded Successfully ✅")
