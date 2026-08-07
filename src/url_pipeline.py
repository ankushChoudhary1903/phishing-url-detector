# ============================================================
# src/url_pipeline.py
# Phishing URL Detection System — Phishing Short URL Detection & Prevention System
# Complete pipeline — with WHOIS cache + timeout fix
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
import threading
import warnings
from datetime import datetime
warnings.filterwarnings("ignore")

# ── Paths ─────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH    = os.path.join(BASE_DIR, "../models/gradient_boosting_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "../models/feature_names.pkl")
PHISHTANK_DB  = os.path.join(BASE_DIR, "../data/raw/phishtank_db.csv")

# ── Load model once at import time ────────────────────────
gb_model      = joblib.load(MODEL_PATH)
feature_names = joblib.load(FEATURES_PATH)

# ── Constants ─────────────────────────────────────────────
REDIRECT_PATTERNS = [
    '/url?', '/amp/', '/amp/s/', '/amp/a/',
    '/redirect', '/l?', '/link?', '//amp',
    '?url=', '&url=', '?q=', 'shortlink='
]

SHORTENERS = [
    'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly',
    'cutt.ly', 't.co', 'short.io', 'rb.gy',
    'is.gd', 'buff.ly', 'tiny.cc', 'tr.im'
]

CONFIDENCE_THRESHOLD  = 70.0   # above this = PHISHING
SUSPICIOUS_THRESHOLD  = 60.0   # above this = SUSPICIOUS
WHOIS_TIMEOUT_SECONDS = 5      # max wait for WHOIS


# ============================================================
# WHOIS CACHE SYSTEM
# ============================================================

# Global cache dictionary — persists for entire session
# Key   = domain name (string)
# Value = whois result object OR None (if lookup failed)
_whois_cache = {}

def whois_lookup_cached(domain):
    """
    Smart WHOIS lookup with two improvements:
    
    1. CACHE: If we already looked up this domain this session,
       return stored result instantly — no network call.
    
    2. TIMEOUT: If WHOIS server is slow, give up after 5 seconds
       instead of hanging forever.
    
    Returns whois object if successful, None if failed/timeout.
    """

    # ── Check cache first ─────────────────────────────────
    if domain in _whois_cache:
        # We've seen this domain before — return instantly
        cached = _whois_cache[domain]
        return cached  # could be data OR None (failed before)

    # ── Not in cache — do live lookup with timeout ─────────
    result    = [None]   # list so thread can modify it
    completed = [False]

    def do_lookup():
        try:
            result[0]    = whois.whois(domain)
            completed[0] = True
        except Exception:
            result[0] = None
            completed[0] = True  # failed but completed

    # Run WHOIS in separate thread
    thread        = threading.Thread(target=do_lookup)
    thread.daemon = True   # thread dies if main program exits
    thread.start()
    thread.join(timeout=WHOIS_TIMEOUT_SECONDS)

    if not completed[0]:
        # Thread is still running = timeout occurred
        return None

    # ── Cache and return the result ────────────────────────
    if result[0] is not None:
        _whois_cache[domain] = result[0]
    
    return result[0]


def get_cache_stats():
    """
    Utility function — shows what's in the cache.
    Useful for debugging and demos.
    """
    total    = len(_whois_cache)
    hits     = sum(1 for v in _whois_cache.values() if v is not None)
    failures = total - hits

    return {
        'total_domains_cached': total,
        'successful_lookups'  : hits,
        'failed_lookups'      : failures,
        'cached_domains'      : list(_whois_cache.keys())
    }


# ============================================================
# STEP 1 — URL VALIDATOR
# ============================================================

def is_valid_short_url(url):
    """
    Validates basic URL format.
    Returns dict with is_valid flag and error message.
    """
    result = {
        'is_valid'     : False,
        'error_message': None,
        'url_length'   : len(url) if url else 0
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
    Follows all redirects to reveal the true destination URL.
    Handles timeouts and errors gracefully.
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
# STEP 3 — PHISHTANK CHECKER
# ============================================================

def check_phishtank(url, db_path=PHISHTANK_DB):
    """
    Checks URL against PhishTank blacklist.
    Uses redirect-abuse pattern detection to prevent
    false positives on legitimate domains.
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
                phish_domain = (phish_parsed.netloc.lower()
                                .replace('www.', '').strip())

                if url_domain != phish_domain:
                    continue

                phish_is_redirect = any(
                    p in phish_url for p in REDIRECT_PATTERNS
                )

                if phish_is_redirect:
                    our_is_redirect = any(
                        p in url_raw for p in REDIRECT_PATTERNS
                    )
                    if our_is_redirect:
                        result['is_phishing'] = True
                        break
                else:
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
    Extracts all 30 features from a URL.
    Matches UCI phishing dataset feature format exactly.
    Values: 1=phishing, -1=legitimate, 0=neutral/unknown

    WHOIS features use cache+timeout system for reliability.
    """
    features = {}

    try:
        parsed   = urllib.parse.urlparse(url)
        domain   = parsed.netloc.lower().replace('www.', '')
        full_url = url.lower()

        # ── Feature 1: IP Address in URL ──────────────────
        try:
            socket.inet_aton(domain.split(':')[0])
            features['having_IP_Address'] = 1
        except:
            features['having_IP_Address'] = -1

        # ── Feature 2: URL Length ──────────────────────────
        url_len = len(url)
        features['URL_Length'] = (
            -1 if url_len < 54 else (0 if url_len <= 75 else 1)
        )

        # ── Feature 3: Shortening Service ─────────────────
        features['Shortining_Service'] = (
            1 if any(s in full_url for s in SHORTENERS) else -1
        )

        # ── Feature 4: @ Symbol ───────────────────────────
        features['having_At_Symbol'] = 1 if '@' in url else -1

        # ── Feature 5: Double Slash Redirect ──────────────
        features['double_slash_redirecting'] = (
            1 if '//' in url[7:] else -1
        )

        # ── Feature 6: Hyphen in Domain ───────────────────
        features['Prefix_Suffix'] = 1 if '-' in domain else -1

        # ── Feature 7: Subdomain Count ────────────────────
        dot_count = domain.count('.')
        features['having_Sub_Domain'] = (
            -1 if dot_count == 1 else (0 if dot_count == 2 else 1)
        )

        # ── Feature 8: SSL Certificate ────────────────────
        features['SSLfinal_State'] = (
            1 if url.startswith('https://') else -1
        )

        # ── Feature 9: Domain Registration Length ─────────
        # Uses WHOIS cache — fast after first lookup
        w = whois_lookup_cached(domain)
        if w:
            try:
                expiry   = w.expiration_date
                creation = w.creation_date
                if isinstance(expiry, list):   expiry   = expiry[0]
                if isinstance(creation, list): creation = creation[0]
                if expiry and creation:
                    reg_len = (expiry - creation).days
                    features['Domain_registeration_length'] = (
                        -1 if reg_len > 365 else 1
                    )
                else:
                    features['Domain_registeration_length'] = (
                        -1 if len(domain) < 15 else 0
                    )
            except:
                features['Domain_registeration_length'] = (
                    -1 if len(domain) < 15 else 0
                )
        else:
            # WHOIS failed — use domain length as proxy signal
            # Short domains (< 15 chars) tend to be legitimate
            features['Domain_registeration_length'] = (
                -1 if len(domain) < 15 else 0
            )

        # ── Features 10-16: Page content (need browser) ───
        features['Favicon']       = 0
        features['port']          = -1 if not parsed.port else 1
        features['HTTPS_token']   = 1 if 'https' in domain else -1
        features['Request_URL']   = 0
        features['URL_of_Anchor'] = 0
        features['Links_in_tags'] = 0
        features['SFH']           = 0

        # ── Feature 17: Email Submission ──────────────────
        features['Submitting_to_email'] = (
            1 if 'mailto:' in full_url else -1
        )

        # ── Feature 18: Abnormal URL ──────────────────────
        features['Abnormal_URL'] = -1 if domain in full_url else 1

        # ── Features 19-23: JS behavior (need browser) ────
        features['Redirect']     = 0
        features['on_mouseover'] = 0
        features['RightClick']   = 0
        features['popUpWidnow']  = 0
        features['Iframe']       = 0

        # ── Feature 24: Domain Age ─────────────────────────
        # Reuses same cached WHOIS result — no second lookup!
        if w:
            try:
                creation = w.creation_date
                if isinstance(creation, list): creation = creation[0]
                if creation:
                    age_days = (datetime.now() - creation).days
                    features['age_of_domain'] = (
                        -1 if age_days > 180 else 1
                    )
                else:
                    features['age_of_domain'] = (
                        -1 if domain.count('-') == 0
                        and len(domain) < 15 else 0
                    )
            except:
                features['age_of_domain'] = (
                    -1 if domain.count('-') == 0
                    and len(domain) < 15 else 0
                )
        else:
            # WHOIS failed — use domain signals as proxy
            # Legitimate domains: short, no hyphens, common TLD
            legit_signals = sum([
                len(domain) < 15,
                domain.count('-') == 0,
                domain.endswith(('.com', '.org', '.edu', '.gov'))
            ])
            features['age_of_domain'] = (
                -1 if legit_signals >= 2 else
                (0  if legit_signals == 1 else 1)
            )

        # ── Feature 25: DNS Record ─────────────────────────
        try:
            socket.gethostbyname(domain.split(':')[0])
            features['DNSRecord'] = -1
        except:
            features['DNSRecord'] = 1

        # ── Features 26-30: External APIs (unavailable) ───
        features['web_traffic']            = 0
        features['Page_Rank']              = 0
        features['Google_Index']           = 0
        features['Links_pointing_to_page'] = 0
        features['Statistical_report']     = 0

    except Exception as e:
        pass

    return {fname: features.get(fname, 0) for fname in feature_names}


# ============================================================
# STEP 5 — ML PREDICTOR
# ============================================================

def predict_url(features_dict):
    """
    Runs Gradient Boosting model on extracted features.
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
    Master pipeline function.
    Runs all steps and returns complete report.

    Verdicts:
      SAFE       — passed all checks
      SUSPICIOUS — ML flagged 60-70% confidence
      PHISHING   — blacklist hit OR ML >= 70%
      INVALID    — bad URL format
    """
    if verbose:
        print("\n" + "=" * 60)
        print("Phishing URL Detection System — Phishing Short URL Detection System")
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

    # Step 1: Validate
    validation = is_valid_short_url(short_url)
    if not validation['is_valid']:
        report['error']         = validation['error_message']
        report['final_verdict'] = 'INVALID URL'
        if verbose:
            print(f"INVALID: {validation['error_message']}")
        return report

    # Step 2: Unshorten
    if verbose: print("\nStep 1: Unshortening URL...")
    unshorten_result = unshorten_url(short_url)
    redirect_count = 0
    is_shortened = 1 if any(s in short_url for s in SHORTENERS) else -1

    if unshorten_result['success']:
        expanded = unshorten_result['expanded_url']
        redirect_count = unshorten_result['redirect_count']
        is_shortened = 1 if any(s in short_url for s in SHORTENERS) else -1        
        if verbose:
            print(f"  Original : {short_url}")
            print(f"  Expanded : {expanded}")
            print(f"  Redirects: {unshorten_result['redirect_count']}")
    else:
        expanded = short_url
        if verbose:
            print(f"  Could not expand: {unshorten_result['error']}")
            print(f"  Using original URL")

    report['expanded_url'] = expanded

    # Step 3: PhishTank
    if verbose: print("\nStep 2: Checking PhishTank blacklist...")
    pt_result = check_phishtank(expanded, db_path)

    if pt_result.get('error'):
        report['phishtank_result'] = 'UNAVAILABLE'
        if verbose: print(f"  PhishTank unavailable")
    elif pt_result['is_phishing']:
        report['phishtank_result'] = 'PHISHING'
        if verbose: print(f"  FOUND IN BLACKLIST")
    else:
        report['phishtank_result'] = 'SAFE'
        if verbose: print(f"  Not in blacklist")

    # Step 4+5: Features + ML
    if verbose: print("\nStep 3: Running ML model...")
    features  = extract_features(expanded)
    
    report['features'] = features

    if verbose:
        print("\nFeature Snapshot:")
        for k, v in features.items():
            print(f"  {k}: {v}")

    ml_result = predict_url(features)
    report['ml_result'] = ml_result

    if verbose:
        print(f"  Phishing prob  : {ml_result['phishing_prob']}%")
        print(f"  Legitimate prob: {ml_result['legitimate_prob']}%")

    # Step 6: Final Verdict
    pt_phishing   = report['phishtank_result'] == 'PHISHING'
    ml_phishing   = (ml_result['is_phishing'] and
                     ml_result['phishing_prob'] >= CONFIDENCE_THRESHOLD)
    ml_suspicious = (ml_result['is_phishing'] and
                     SUSPICIOUS_THRESHOLD <= ml_result['phishing_prob']
                     < CONFIDENCE_THRESHOLD)

    if pt_phishing and ml_phishing:
        report['final_verdict']  = 'PHISHING'
        report['verdict_reason'] = 'Flagged by BOTH PhishTank and ML'
    elif pt_phishing:
        report['final_verdict']  = 'PHISHING'
        report['verdict_reason'] = 'Found in PhishTank blacklist'
    elif ml_phishing:
        report['final_verdict']  = 'PHISHING'
        report['verdict_reason'] = (f'ML confidence '
                                    f'{ml_result["phishing_prob"]}% '
                                    f'above 70% threshold')
    elif ml_suspicious:
        report['final_verdict']  = 'SUSPICIOUS'
        report['verdict_reason'] = (f'ML flagged at '
                                    f'{ml_result["phishing_prob"]}% '
                                    f'— proceed with caution')
    else:
        report['final_verdict']  = 'SAFE'
        report['verdict_reason'] = 'Passed all checks'

    if verbose:
        print("\n" + "=" * 60)
        v = report['final_verdict']
        icon = '' if v == 'PHISHING' else ('' if v == 'SUSPICIOUS'
                                              else '')
        print(f"{icon} VERDICT: {v}")
        print(f"Reason : {report['verdict_reason']}")
        print("=" * 60)

    return report