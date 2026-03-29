
import requests
import joblib
import pandas as pd
import numpy as np
import urllib.parse
import socket
import ssl
import whois
import time
import csv
import os
import warnings
warnings.filterwarnings("ignore")

# Load model and feature names
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH    = os.path.join(BASE_DIR, "../models/gradient_boosting_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "../models/feature_names.pkl")
PHISHTANK_DB  = os.path.join(BASE_DIR, "../data/raw/phishtank_db.csv")

gb_model      = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)


def is_valid_short_url(url):
    result = {"is_valid": False, "error_message": None, "url_length": len(url)}
    if not url.startswith(("http://", "https://")):
        result["error_message"] = "URL must start with http:// or https://"
        return result
    result["is_valid"] = True
    return result


def unshorten_url(short_url, timeout=10):
    result = {"original_url": short_url, "expanded_url": None,
              "redirect_count": 0, "success": False, "error": None}
    try:
        headers  = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(short_url, allow_redirects=True,
                                timeout=timeout, headers=headers, stream=True)
        result["expanded_url"]   = response.url
        result["redirect_count"] = len(response.history)
        result["success"]        = True
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_phishtank(url, db_path=PHISHTANK_DB):
    result = {"checked": False, "is_phishing": False, "error": None}
    if not db_path or not os.path.exists(db_path):
        result["error"] = "PhishTank DB not available"
        return result
    try:
        parsed     = urllib.parse.urlparse(url)
        url_domain = parsed.netloc.lower().replace("www.", "")
        with open(db_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                phish_url    = row.get("url", "").lower()
                phish_parsed = urllib.parse.urlparse(phish_url)
                phish_domain = phish_parsed.netloc.lower().replace("www.", "")
                if url_domain and url_domain in phish_domain:
                    result["is_phishing"] = True
                    break
        result["checked"] = True
    except Exception as e:
        result["error"] = str(e)
    return result


def extract_features(url):
    features = {}
    try:
        parsed   = urllib.parse.urlparse(url)
        domain   = parsed.netloc.lower().replace("www.", "")
        full_url = url.lower()
        try:
            socket.inet_aton(domain.split(":")[0])
            features["having_IP_Address"] = 1
        except:
            features["having_IP_Address"] = -1
        url_len = len(url)
        features["URL_Length"] = -1 if url_len < 54 else (0 if url_len <= 75 else 1)
        shorteners = ["bit.ly","tinyurl","goo.gl","ow.ly","cutt.ly","t.co","short.io","rb.gy"]
        features["Shortining_Service"]         = 1 if any(s in full_url for s in shorteners) else -1
        features["having_At_Symbol"]           = 1 if "@" in url else -1
        features["double_slash_redirecting"]   = 1 if "//" in url[7:] else -1
        features["Prefix_Suffix"]              = 1 if "-" in domain else -1
        dot_count = domain.count(".")
        features["having_Sub_Domain"] = -1 if dot_count == 1 else (0 if dot_count == 2 else 1)
        features["SSLfinal_State"]             = 1 if url.startswith("https://") else -1
        features["Domain_registeration_length"] = 0
        features["Favicon"]                    = 0
        features["port"]                       = -1 if not parsed.port else 1
        features["HTTPS_token"]                = 1 if "https" in domain else -1
        features["Request_URL"]                = 0
        features["URL_of_Anchor"]              = 0
        features["Links_in_tags"]              = 0
        features["SFH"]                        = 0
        features["Submitting_to_email"]        = 1 if "mailto:" in full_url else -1
        features["Abnormal_URL"]               = -1 if domain in full_url else 1
        features["Redirect"]                   = 0
        features["on_mouseover"]               = 0
        features["RightClick"]                 = 0
        features["popUpWidnow"]                = 0
        features["Iframe"]                     = 0
        features["age_of_domain"]              = 0
        try:
            socket.gethostbyname(domain.split(":")[0])
            features["DNSRecord"] = -1
        except:
            features["DNSRecord"] = 1
        features["web_traffic"]            = 0
        features["Page_Rank"]              = 0
        features["Google_Index"]           = 0
        features["Links_pointing_to_page"] = 0
        features["Statistical_report"]     = 0
    except Exception:
        pass
    return {fname: features.get(fname, 0) for fname in feature_names}


def predict_url(features_dict):
    features_df   = pd.DataFrame([features_dict])[feature_names]
    prediction    = gb_model.predict(features_df)[0]
    probabilities = gb_model.predict_proba(features_df)[0]
    classes       = gb_model.classes_.tolist()
    phishing_prob = probabilities[classes.index(1)]
    return {
        "prediction"     : prediction,
        "is_phishing"    : prediction == 1,
        "phishing_prob"  : round(phishing_prob * 100, 1),
        "legitimate_prob": round((1 - phishing_prob) * 100, 1),
        "confidence"     : round(max(phishing_prob, 1 - phishing_prob) * 100, 1)
    }


def check_url(short_url, db_path=PHISHTANK_DB, verbose=True):
    report = {"input_url": short_url, "expanded_url": None,
              "phishtank_result": None, "ml_result": None,
              "final_verdict": None, "error": None}
    validation = is_valid_short_url(short_url)
    if not validation["is_valid"]:
        report["error"]         = validation["error_message"]
        report["final_verdict"] = "INVALID URL"
        return report
    unshorten_result      = unshorten_url(short_url)
    expanded              = unshorten_result["expanded_url"] if unshorten_result["success"] else short_url
    report["expanded_url"] = expanded
    pt_result             = check_phishtank(expanded, db_path)
    report["phishtank_result"] = "PHISHING" if pt_result["is_phishing"] else (
                                 "UNAVAILABLE" if pt_result["error"] else "SAFE")
    features              = extract_features(expanded)
    ml_result             = predict_url(features)
    report["ml_result"]   = ml_result
    pt_phishing           = report["phishtank_result"] == "PHISHING"
    ml_phishing           = ml_result["is_phishing"]
    report["final_verdict"] = "PHISHING" if (pt_phishing or ml_phishing) else "SAFE"
    return report
