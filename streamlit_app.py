
import streamlit as st
import app as sentinelai

st.set_page_config(
    page_title="SentinelAI 2.0",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ SENTINELAI 2.0")

st.subheader(
    "An Explainable and Intelligent "
    "Multi-Layer Phishing URL Detection System"
)

st.write(
    "Analyze website URLs using Machine Learning, "
    "suspicious pattern analysis and brand impersonation detection."
)

url = st.text_input(
    "Enter Website URL",
    placeholder="https://example.com"
)

if st.button("🔍 Analyze Website", type="primary"):

    if url.strip():

        with st.spinner("Analyzing website..."):
            result = sentinelai.analyze_sentinelai_2(url)

        if "Error" in result:
            st.error(result["Error"])

        else:
            st.success("Analysis completed!")

            col1, col2 = st.columns(2)

            with col1:
                st.metric("ML Prediction", result["ML Prediction"])

            with col2:
                st.metric("Smart Detection", result["Smart Detection"])

            st.metric("Risk Score", str(result["Risk Score"]) + "/100")

            if result["Risk Level"] == "HIGH":
                st.error("🔴 HIGH RISK")
            elif result["Risk Level"] == "MEDIUM":
                st.warning("🟠 MEDIUM RISK")
            else:
                st.success("🟢 LOW RISK")

            st.write(
                "ML Malicious Probability:",
                result["ML Malicious Probability"]
            )

            st.subheader("URL Warnings")
            st.write(result["URL Warnings"])

            st.subheader("Brand Impersonation Warnings")
            st.write(result["Brand Warnings"])

            st.subheader("Explainable Analysis Report")
            st.text(result["Explanation"])

    else:
        st.warning("Please enter a website URL.")

st.divider()

st.caption(
    "Academic research prototype. Predictions are estimates "
    "and do not guarantee that a website is safe."
)
