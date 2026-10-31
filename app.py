
import os
import re
import json
import ipaddress
import joblib
import pandas as pd

from urllib.parse import urlparse
from rapidfuzz import fuzz


# ==========================================
# 1. LOAD TRAINED MODEL
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(
    BASE_DIR, "sentinelai_2_compressed.pkl"
)

FEATURE_PATH = os.path.join(
    BASE_DIR, "feature_names.json"
)

loaded_model = joblib.load(MODEL_PATH)

with open(FEATURE_PATH, "r") as f:
    loaded_features = json.load(f)


# ==========================================
# 2. EXTRACT 22 URL FEATURES
# ==========================================

def extract_url_features(url):

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    domain = parsed.netloc.split("@")[-1].split(":")[0]

    if not domain:
        domain = re.split(r"[/?:#]", url)[0]

    lower_url = url.lower()

    suspicious_words = [
        "login", "verify", "account", "password",
        "payment", "free", "secure", "update",
        "bank", "signin", "confirm", "wallet"
    ]

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_question_marks": url.count("?"),
        "num_equal": url.count("="),
        "num_at": url.count("@"),
        "num_ampersand": url.count("&"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_https": int(lower_url.startswith("https://")),
        "has_ip": 0,
        "has_percent": int("%" in url),
        "domain_length": len(domain),
        "num_subdomains": max(0, domain.count(".") - 1),
        "num_suspicious_keywords": sum(
            word in lower_url for word in suspicious_words
        ),
        "has_login_word": int("login" in lower_url),
        "has_verify_word": int("verify" in lower_url),
        "has_account_word": int("account" in lower_url),
        "has_password_word": int("password" in lower_url),
        "has_payment_word": int("payment" in lower_url),
        "has_free_word": int("free" in lower_url)
    }

    try:
        ipaddress.ip_address(domain)
        features["has_ip"] = 1
    except ValueError:
        features["has_ip"] = 0

    return features


# ==========================================
# 3. URL PATTERN ANALYSIS
# ==========================================

def analyze_url_patterns(url):

    findings = []

    try:
        explicit_scheme = (
            urlparse(url).scheme.lower()
            if "://" in url else ""
        )

        parsed = urlparse(
            url if explicit_scheme else "http://" + url
        )

        domain = parsed.hostname or ""

    except ValueError:

        domain = ""
        explicit_scheme = ""

        findings.append("Malformed URL structure")

    full_url = url.lower()

    try:
        ipaddress.ip_address(domain)
        findings.append("IP address used instead of domain")
    except ValueError:
        pass

    suspicious_words = [
        "login", "verify", "account",
        "password", "secure", "update",
        "payment", "confirm"
    ]

    detected_words = [
        word for word in suspicious_words
        if word in full_url
    ]

    if detected_words:
        findings.append(
            "Suspicious keywords detected: "
            + ", ".join(detected_words)
        )

    if explicit_scheme == "http":
        findings.append("Uses HTTP instead of HTTPS")

    if "@" in url:
        findings.append("Contains @ symbol")

    if domain.count("-") >= 3:
        findings.append("Multiple hyphens in domain")

    return findings


# ==========================================
# 4. BRAND IMPERSONATION DETECTION
# ==========================================

brand_database = {
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "google": ["google.com"],
    "facebook": ["facebook.com"],
    "microsoft": ["microsoft.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"]
}


def detect_brand_impersonation(url):

    findings = []

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    domain = (parsed.hostname or "").lower()

    if not domain:
        return findings

    main_domain = domain.split(".")[0]

    parts = re.split(r"[-_]", main_domain)

    substitutions = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t"
    })

    for brand in brand_database:

        for part in parts:

            normalized = part.translate(substitutions)

            if part == brand:
                continue

            similarity = fuzz.ratio(
                normalized, brand
            )

            if similarity >= 75:

                findings.append({
                    "brand": brand,
                    "suspicious_part": part,
                    "similarity": round(similarity, 2)
                })

                break

    return findings


# ==========================================
# 5. RISK SCORE
# ==========================================

def calculate_risk_score(
    ml_prediction, url_findings, brand_findings
):

    risk_score = 0

    if ml_prediction == 1:
        risk_score += 40

    risk_score += min(len(url_findings) * 8, 32)

    if brand_findings:
        risk_score += 28

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level
    }


# ==========================================
# 6. EXPLANATION GENERATION
# ==========================================

def generate_explanation(
    url, url_findings, brand_findings, risk_result
):

    report = [
        "SENTINELAI 2.0 ANALYSIS REPORT",
        "",
        f"Website: {url}",
        "",
        "URL PATTERN ANALYSIS:"
    ]

    if url_findings:
        report.extend(
            ["- " + finding for finding in url_findings]
        )
    else:
        report.append("No suspicious URL patterns detected.")

    report.extend(["", "BRAND IMPERSONATION ANALYSIS:"])

    if brand_findings:

        for item in brand_findings:
            report.append(
                f"- Possible {item['brand']} impersonation: "
                f"{item['suspicious_part']} "
                f"(similarity: {item['similarity']}%)"
            )

    else:
        report.append("No possible brand impersonation detected.")

    report.extend([
        "",
        f"Risk Score: {risk_result['risk_score']}/100",
        f"Risk Level: {risk_result['risk_level']}",
        ""
    ])

    if risk_result["risk_level"] == "HIGH":
        report.append(
            "Recommendation: Avoid visiting this website "
            "or entering personal information."
        )

    elif risk_result["risk_level"] == "MEDIUM":
        report.append(
            "Recommendation: Be careful and verify the "
            "website before sharing information."
        )

    else:
        report.append(
            "Recommendation: No major warning was detected. "
            "Still verify the website before trusting it."
        )

    return "\n".join(report)


# ==========================================
# 7. MAIN SENTINELAI DETECTION
# ==========================================

def analyze_sentinelai_2(url):

    if not url or not url.strip():
        return {"Error": "Please enter a website URL."}

    url = url.strip()

    try:

        features = extract_url_features(url)

        input_df = pd.DataFrame([features])

        input_df = input_df[loaded_features]

        prediction = int(
            loaded_model.predict(input_df)[0]
        )

        probabilities = loaded_model.predict_proba(
            input_df
        )[0]

        malicious_index = list(
            loaded_model.classes_
        ).index(1)

        ml_probability = round(
            probabilities[malicious_index] * 100, 2
        )

        url_findings = analyze_url_patterns(url)

        brand_findings = detect_brand_impersonation(url)

        smart_prediction = int(
            prediction == 1
            or len(brand_findings) > 0
            or len(url_findings) >= 2
        )

        risk_result = calculate_risk_score(
            smart_prediction,
            url_findings,
            brand_findings
        )

        explanation = generate_explanation(
            url,
            url_findings,
            brand_findings,
            risk_result
        )

        return {
            "Website URL": url,

            "ML Prediction":
                "Malicious" if prediction == 1 else "Good",

            "ML Malicious Probability":
                f"{ml_probability}%",

            "Smart Detection":
                "Malicious" if smart_prediction == 1 else "Good",

            "URL Warnings": url_findings,

            "Brand Warnings": brand_findings,

            "Risk Score":
                risk_result["risk_score"],

            "Risk Level":
                risk_result["risk_level"],

            "Explanation": explanation
        }

    except Exception as e:

        return {
            "Error": str(e)
        }


