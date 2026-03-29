# ============================================================
# src/url_pipeline.py
# PSUDPS — Phishing Short URL Detection & Prevention System
# Complete pipeline with all fixes applied
# ============================================================

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

# ── Paths ─────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH    = os.path.join(BASE_DIR, "../models/gradient_boosting_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "../models/feature_names.pkl")
PHISHTANK_DB  = os.path.join(BASE_DIR, "../data/raw/phishtank_db.csv")

# ── Load model once at import time ────────────────────────
gb_model      = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)

# ── Redirect abuse patterns ───────────────────────────────
REDIRECT_PATTERNS = [
    '/url?', '/amp/', '/amp/s/', '/amp/a/',
    '/redirect', '/l?', '/link?', '//amp',
    '?url=', '&url=', '?q=', 'shortlink='
]

# ── Known shortener services ──────────────────────────────
SHORTENERS = [
    'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly',
    'cutt.ly', 't.co', 'short.io', 'rb.gy',
    'is.gd', 'buff.ly', 'tiny.cc', 'tr.im'
]


# ============================================================
# STEP 1 — URL VALIDATOR
# ============================================================

def is_valid_short_url(url):
    """
    Validates the input URL format.
    Returns dict with is_valid flag and error message.
    """
    result = {
        'is_valid'     : False,
        'error_message': None,
        'url_length'   : len(url)
    }

    if not isinstance(url, str) or not url.strip():
        result['error_message'] = "Empty or invalid input"
        return result

    if not url.startswith(('http://', 'https://')):
        result['error_message'] = "URL must start with http:// or https://"
        return result

    if len(url) < 10:
        result['error_message'] = "URL too short to be valid"
        return result

    result['is_valid'] = True
    return result


# ============================================================
# STEP 2 — URL UNSHORTENER
# ============================================================

def unshorten_url(short_url, timeout=10):
    """
    Follows all redirects to find the true destination URL.
    Handles timeouts and connection errors gracefully.
    """
    result = {
        'original_url'  : short_url,
        'expanded_url'  : None,
        'redirect_count': 0,
        'success'       : False,
        'error'         : None
    }

    try:
        headers  = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(
            short_url,
            allow_redirects=True,
            timeout=timeout,
            headers=headers,
            stream=True
        )
        result['expanded_url']   = response.url
        result['redirect_count'] = len(response.history)
        result['success']        = True

    except requests.exceptions.Timeout:
        result['error'] = "Timeout — URL took too long to respond"
    except requests.exceptions.ConnectionError:
        result['error'] = "Connection error — could not reach URL"
    except requests.exceptions.InvalidURL:
        result['error'] = "Invalid URL format"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"

    return result


# ============================================================
# STEP 3 — PHISHTANK BLACKLIST CHECKER
# ============================================================

def check_phishtank(url, db_path=PHISHTANK_DB):
    """
    Checks URL against PhishTank blacklist.
    Uses smart redirect-abuse detection to avoid false positives
    on legitimate domains like google.com being abused as redirects.
    """
    result = {
        'checked'    : False,
        'is_phishing': False,
        'error'      : None
    }

    if db_path is None or not os.path.exists(db_path):
        result['error'] = "PhishTank DB not available"
        return result

    try:
        parsed     = urllib.parse.urlparse(url)
        url_domain = parsed.netloc.lower().replace('www.', '').strip()
        url_raw    = url.lower()

        with open(db_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                phish_url    = row.get('url', '').lower()
                phish_parsed = urllib.parse.urlparse(phish_url)
                phish_domain = phish_parsed.netloc.lower().replace('www.', '').strip()

                # Domains must match exactly
                if url_domain != phish_domain:
                    continue

                # Check if PhishTank entry is redirect abuse
                phish_is_redirect = any(
                    p in phish_url for p in REDIRECT_PATTERNS
                )

                if phish_is_redirect:
                    # Only flag if our URL also uses redirect
                    our_is_redirect = any(
                        p in url_raw for p in REDIRECT_PATTERNS
                    )
                    if our_is_redirect:
                        result['is_phishing'] = True
                        break
                else:
                    # Normal phishing domain
                    result['is_phishing'] = True
                    break

        result['checked'] = True

    except Exception as e:
        result['error'] = str(e)

    return result


# ============================================================
# STEP 4 — FEATURE EXTRACTOR
# ============================================================

def extract_features(url):
    """
    Extracts 30 features from a URL matching the UCI dataset format.
    Values: 1=phishing indicator, -1=legitimate, 0=neutral/unknown
    """
    features = {}

    try:
        parsed   = urllib.parse.urlparse(url)
        domain   = parsed.netloc.lower().replace('www.', '')
        full_url = url.lower()

        # 1. IP Address in URL
        try:
            socket.inet_aton(domain.split(':')[0])
            features['having_IP_Address'] = 1
        except:
            features['having_IP_Address'] = -1

        # 2. URL Length
        url_len = len(url)
        features['URL_Length'] = -1 if url_len < 54 else (0 if url_len <= 75 else 1)

        # 3. Shortening Service
        features['Shortining_Service'] = 1 if any(
            s in full_url for s in SHORTENERS) else -1

        # 4. @ Symbol
        features['having_At_Symbol'] = 1 if '@' in url else -1

        # 5. Double Slash Redirect
        features['double_slash_redirecting'] = 1 if '//' in url[7:] else -1

        # 6. Prefix/Suffix (hyphen in domain)
        features['Prefix_Suffix'] = 1 if '-' in domain else -1

        # 7. Subdomains
        dot_count = domain.count('.')
        features['having_Sub_Domain'] = (
            -1 if dot_count == 1 else (0 if dot_count == 2 else 1)
        )

        # 8. SSL State
        features['SSLfinal_State'] = 1 if url.startswith('https://') else -1

        # 9. Domain Registration Length (WHOIS)
        try:
            w        = whois.whois(domain)
            expiry   = w.expiration_date
            creation = w.creation_date
            if isinstance(expiry, list):   expiry   = expiry[0]
            if isinstance(creation, list): creation = creation[0]
            if expiry and creation:
                reg_len = (expiry - creation).days
                features['Domain_registeration_length'] = -1 if reg_len > 365 else 1
            else:
                features['Domain_registeration_length'] = 0
        except:
            features['Domain_registeration_length'] = 0

        # 10-16. Page content features (need browser — use neutral)
        features['Favicon']           = 0
        features['port']              = -1 if not parsed.port else 1
        features['HTTPS_token']       = 1 if 'https' in domain else -1
        features['Request_URL']       = 0
        features['URL_of_Anchor']     = 0
        features['Links_in_tags']     = 0
        features['SFH']               = 0

        # 17. Email submission
        features['Submitting_to_email'] = 1 if 'mailto:' in full_url else -1

        # 18. Abnormal URL
        features['Abnormal_URL'] = -1 if domain in full_url else 1

        # 19-23. JavaScript features (need browser — use neutral)
        features['Redirect']      = 0
        features['on_mouseover']  = 0
        features['RightClick']    = 0
        features['popUpWidnow']   = 0
        features['Iframe']        = 0

        # 24. Domain Age
        try:
            w        = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list): creation = creation[0]
            if creation:
                from datetime import datetime
                age_days = (datetime.now() - creation).days
                features['age_of_domain'] = -1 if age_days > 180 else 1
            else:
                features['age_of_domain'] = 0
        except:
            features['age_of_domain'] = 0

        # 25. DNS Record
        try:
            socket.gethostbyname(domain.split(':')[0])
            features['DNSRecord'] = -1
        except:
            features['DNSRecord'] = 1

        # 26-30. External service features (need APIs — use neutral)
        features['web_traffic']            = 0
        features['Page_Rank']              = 0
        features['Google_Index']           = 0
        features['Links_pointing_to_page'] = 0
        features['Statistical_report']     = 0

    except Exception as e:
        pass

    # Return in exact feature order model expects
    return {fname: features.get(fname, 0) for fname in feature_names}


# ============================================================
# STEP 5 — ML PREDICTOR
# ============================================================

def predict_url(features_dict):
    """
    Runs the saved Gradient Boosting model on extracted features.
    Returns prediction, probabilities and confidence score.
    """
    features_df   = pd.DataFrame([features_dict])[feature_names]
    prediction    = gb_model.predict(features_df)[0]
    probabilities = gb_model.predict_proba(features_df)[0]
    classes       = gb_model.classes_.tolist()
    phishing_prob = probabilities[classes.index(1)]
    legit_prob    = probabilities[classes.index(-1)]

    return {
        'prediction'     : prediction,
        'is_phishing'    : prediction == 1,
        'phishing_prob'  : round(phishing_prob * 100, 1),
        'legitimate_prob': round(legit_prob * 100, 1),
        'confidence'     : round(max(phishing_prob, legit_prob) * 100, 1)
    }


# ============================================================
# STEP 6 — COMPLETE PIPELINE
# ============================================================

def check_url(short_url, db_path=PHISHTANK_DB, verbose=True):
    """
    Master function — runs the complete PSUDPS pipeline:
      1. Validate URL
      2. Unshorten URL
      3. Check PhishTank blacklist
      4. Extract 30 features
      5. Run GB model
      6. Return final verdict

    Confidence threshold: 70%
    Verdicts: SAFE / SUSPICIOUS / PHISHING / INVALID URL
    """
    CONFIDENCE_THRESHOLD = 70.0

    if verbose:
        print("\n" + "=" * 60)
        print("PSUDPS — Phishing Short URL Detection System")
        print("=" * 60)
        print(f"Input : {short_url}")
        print("-" * 60)

    report = {
        'input_url'       : short_url,
        'expanded_url'    : None,
        'phishtank_result': None,
        'ml_result'       : None,
        'final_verdict'   : None,
        'verdict_reason'  : None,
        'error'           : None
    }

    # ── Step 1: Validate ──────────────────────────────────
    validation = is_valid_short_url(short_url)
    if not validation['is_valid']:
        report['error']         = validation['error_message']
        report['final_verdict'] = 'INVALID URL'
        if verbose:
            print(f"INVALID: {validation['error_message']}")
        return report

    # ── Step 2: Unshorten ─────────────────────────────────
    if verbose: print("\nStep 1: Unshortening URL...")
    unshorten_result = unshorten_url(short_url)

    if unshorten_result['success']:
        expanded = unshorten_result['expanded_url']
        if verbose:
            print(f"  Original : {short_url}")
            print(f"  Expanded : {expanded}")
            print(f"  Redirects: {unshorten_result['redirect_count']}")
    else:
        expanded = short_url
        if verbose:
            print(f"  Could not expand: {unshorten_result['error']}")
            print(f"  Using original URL for analysis")

    report['expanded_url'] = expanded

    # ── Step 3: PhishTank ─────────────────────────────────
    if verbose: print("\nStep 2: Checking PhishTank blacklist...")
    pt_result = check_phishtank(expanded, db_path)

    if pt_result.get('error'):
        report['phishtank_result'] = 'UNAVAILABLE'
        if verbose: print(f"  PhishTank unavailable — using ML only")
    elif pt_result['is_phishing']:
        report['phishtank_result'] = 'PHISHING'
        if verbose: print(f"  FOUND IN BLACKLIST")
    else:
        report['phishtank_result'] = 'SAFE'
        if verbose: print(f"  Not in blacklist")

    # ── Step 4+5: Features + ML ───────────────────────────
    if verbose: print("\nStep 3: Running ML model...")
    features  = extract_features(expanded)
    ml_result = predict_url(features)
    report['ml_result'] = ml_result

    if verbose:
        print(f"  Phishing probability : {ml_result['phishing_prob']}%")
        print(f"  Legitimate probability: {ml_result['legitimate_prob']}%")
        print(f"  Confidence           : {ml_result['confidence']}%")

    # ── Step 6: Final Verdict ─────────────────────────────
    pt_phishing  = report['phishtank_result'] == 'PHISHING'
    ml_phishing  = (ml_result['is_phishing'] and
                    ml_result['phishing_prob'] >= CONFIDENCE_THRESHOLD)
    ml_suspicious = (ml_result['is_phishing'] and
                     50 <= ml_result['phishing_prob'] < CONFIDENCE_THRESHOLD)

    if pt_phishing and ml_phishing:
        report['final_verdict']  = 'PHISHING'
        report['verdict_reason'] = 'Flagged by BOTH PhishTank and ML model'
    elif pt_phishing:
        report['final_verdict']  = 'PHISHING'
        report['verdict_reason'] = 'Found in PhishTank blacklist'
    elif ml_phishing:
        report['final_verdict']  = 'PHISHING'
        report['verdict_reason'] = f'ML confidence {ml_result["phishing_prob"]}% above 70% threshold'
    elif ml_suspicious:
        report['final_verdict']  = 'SUSPICIOUS'
        report['verdict_reason'] = f'ML flagged but low confidence ({ml_result["phishing_prob"]}%) — monitor'
    else:
        report['final_verdict']  = 'SAFE'
        report['verdict_reason'] = 'Passed all checks'

    if verbose:
        print("\n" + "=" * 60)
        verdict = report['final_verdict']
        if verdict == 'PHISHING':
            print(f"VERDICT: PHISHING — BLOCKED")
        elif verdict == 'SUSPICIOUS':
            print(f"VERDICT: SUSPICIOUS — Proceed with caution")
        else:
            print(f"VERDICT: SAFE")
        print(f"Reason : {report['verdict_reason']}")
        print("=" * 60)

    return report