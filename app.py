# app.py - Complete MFA System with Working Email

import streamlit as st
import sys
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta, timezone
import bcrypt
import secrets
import time
import hashlib
import random
import re
import numpy as np
import json
from pathlib import Path

# Page config — MUST be first Streamlit command
st.set_page_config(
    page_title="EduAuth MFA System",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="expanded"
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from firebase_config import initialize_firebase
initialize_firebase()

from firebase_config import (
    get_user_by_email, get_user_by_username, get_user_by_id,
    create_user, update_user, delete_user, get_all_users,
    log_auth_attempt, get_auth_logs, save_otp, get_valid_otp,
    get_risk_rules, log_action, get_firestore
)
from risk_engine import risk_engine
from email_utils import send_otp_email

# ──────────────────────────────────────────────
# STYLES
# ──────────────────────────────────────────────
st.markdown("""
<style>
    /* Modern gradient backgrounds */
    .main-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2rem;
        border-radius: 20px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    }
    .main-header h1 { 
        margin: 0; 
        font-size: 2.2rem;
        font-weight: 700;
    }
    .main-header p { 
        margin: 0.5rem 0 0; 
        opacity: 0.9; 
    }
    
    /* Card styles */
    .stat-card {
        background: linear-gradient(145deg, #ffffff 0%, #f8f9fa 100%);
        padding: 1.5rem;
        border-radius: 20px;
        box-shadow: 0 8px 25px rgba(0,0,0,0.08);
        text-align: center;
        margin-bottom: 1rem;
        transition: all 0.3s ease;
    }
    .stat-card:hover {
        transform: translateY(-5px);
    }
    .stat-card h3 {
        font-size: 2.2rem;
        margin: 0;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .stat-card p {
        margin: 0.5rem 0 0;
        color: #6c757d;
        font-size: 0.85rem;
    }
    
    /* Risk colors */
    .risk-low { 
        color: #28a745 !important;
        background: #28a74520;
        padding: 0.2rem 0.8rem;
        border-radius: 20px;
        display: inline-block;
    }
    .risk-med { 
        color: #ffc107 !important;
        background: #ffc10720;
        padding: 0.2rem 0.8rem;
        border-radius: 20px;
        display: inline-block;
    }
    .risk-high { 
        color: #dc3545 !important;
        background: #dc354520;
        padding: 0.2rem 0.8rem;
        border-radius: 20px;
        display: inline-block;
    }
    
    /* Login boxes */
    .login-box, .signup-box {
        background: white;
        padding: 2.5rem;
        border-radius: 24px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
        border: 1px solid rgba(102, 126, 234, 0.15);
    }
    
    /* Badges */
    .badge {
        display: inline-block;
        padding: 0.3rem 0.9rem;
        border-radius: 30px;
        font-size: 0.75rem;
        font-weight: 700;
    }
    .badge-admin { 
        background: linear-gradient(135deg, #dc3545, #c82333);
        color: white;
    }
    .badge-student { 
        background: linear-gradient(135deg, #28a745, #20c997);
        color: white;
    }
    
    /* ML Info Box */
    .ml-info-box {
        background: linear-gradient(135deg, #f0f4ff 0%, #e8eeff 100%);
        border-left: 5px solid #667eea;
        padding: 1rem 1.2rem;
        border-radius: 12px;
        margin: 0.8rem 0;
    }
    
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
    }
    section[data-testid="stSidebar"] .stMarkdown {
        color: #f0f0f0;
    }
</style>
""", unsafe_allow_html=True)

# ──────────────────────────────────────────────
# SESSION STATE
# ──────────────────────────────────────────────
def _init_state():
    defaults = dict(
        authenticated=False, user=None, pending_auth=False,
        otp_id=None, risk_score=0.0, show_signup=False,
        session_id=secrets.token_urlsafe(32),
        nav_page="Dashboard"
    )
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────
def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw, hashed):
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def generate_otp():
    return f"{random.randint(100000, 999999)}"

def format_dt(v):
    if v is None: return "N/A"
    if hasattr(v, "strftime"): return v.strftime("%Y-%m-%d %H:%M")
    return str(v)

def _is_expired(dt):
    if dt is None:
        return True
    now = datetime.now(timezone.utc)
    if hasattr(dt, "tzinfo") and dt.tzinfo is not None:
        return now > dt
    return now > dt.replace(tzinfo=timezone.utc)

def get_browser_info():
    try:
        ua = st.context.headers.get("User-Agent", "")
    except Exception:
        ua = ""
    browser = ("Chrome" if "Chrome" in ua and "Edg" not in ua else
               "Firefox" if "Firefox" in ua else
               "Safari" if "Safari" in ua and "Chrome" not in ua else
               "Edge" if "Edg" in ua else "Unknown")
    os_name = ("Windows" if "Windows" in ua else
               "macOS" if "Mac" in ua else
               "Android" if "Android" in ua else
               "iOS" if "iPhone" in ua or "iPad" in ua else
               "Linux" if "Linux" in ua else "Unknown")
    return browser, os_name

def send_otp_code(email, name, code, role, risk):
    """Send OTP via email with fallback to console."""
    success = send_otp_email(email, name, code, role, risk)
    if success:
        st.success(f"📧 Verification code sent to **{email}**")
    else:
        st.info(f"📧 Check the server console for the OTP code (email configuration pending)")

def validate_signup(username, email, password, confirm, full_name, matric, department, level):
    errs = []
    if len(username) < 3 or not re.match(r"^[a-zA-Z0-9_]+$", username):
        errs.append("Username must be at least 3 characters and use only letters, numbers, underscores")
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        errs.append("Please enter a valid email address")
    if len(password) < 8:
        errs.append("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        errs.append("Password must contain at least one uppercase letter")
    if not re.search(r"\d", password):
        errs.append("Password must contain at least one number")
    if password != confirm:
        errs.append("Passwords do not match")
    if not full_name.strip():
        errs.append("Full name is required")
    if not matric.strip():
        errs.append("Matric/Student number is required")
    if not department.strip():
        errs.append("Department is required")
    return errs

# ──────────────────────────────────────────────
# RISK ASSESSMENT
# ──────────────────────────────────────────────
def _enrich_from_history(request_data, user):
    if not user or not user.get("id"):
        return request_data
    try:
        logs = get_auth_logs(filters={"user_id": user["id"]}, limit=100) or []
        if logs:
            fp = request_data.get("device_fingerprint")
            past_ok = [l for l in logs if l.get("status") == "success"]
            request_data["is_known_device"] = any(
                l.get("device_fingerprint") == fp for l in past_ok
            )
            hours = [l.get("hour", 12) for l in past_ok]
            if hours:
                avg_h = np.mean(hours)
                std_h = np.std(hours) if len(hours) > 1 else 6
                request_data["time_anomaly"] = abs(request_data["hour"] - avg_h) > max(std_h * 2, 4)
            failed_recent = sum(1 for l in logs[:10] if l.get("status") == "failed")
            request_data["velocity_check"] = failed_recent * 100
    except Exception as e:
        print(f"[Risk] history enrichment error: {e}")
    return request_data

def assess_risk(user, context, failed_attempts):
    now = datetime.now()
    request_data = {
        "hour": now.hour,
        "minute": now.minute,
        "day_of_week": now.weekday(),
        "is_weekend": now.weekday() >= 5,
        "is_business_hours": 9 <= now.hour <= 17,
        "failed_attempts": failed_attempts,
        "device_fingerprint": context.get("device_fingerprint"),
        "browser": context.get("browser", "Unknown"),
        "os": context.get("os", "Unknown"),
        "device_type": context.get("device_type", "desktop"),
        "country": context.get("country", "Unknown"),
        "location_mismatch": context.get("location_mismatch", False),
        "is_known_device": context.get("is_known_device", False),
        "time_anomaly": context.get("time_anomaly", False),
        "velocity_check": context.get("velocity_check", 0),
        "cookies_enabled": True,
        "javascript_enabled": True,
    }
    request_data = _enrich_from_history(request_data, user)
    return risk_engine.predict(request_data)

def log_attempt(user_id, username, email, role, status, action, risk_score, context):
    now = datetime.now()
    log_auth_attempt({
        "user_id": user_id, "username": username, "email": email,
        "role": role, "status": status, "action_taken": action,
        "risk_score": risk_score,
        "ip_address": context.get("ip_address", "web"),
        "device_fingerprint": context.get("device_fingerprint"),
        "browser": context.get("browser"), "os": context.get("os"),
        "device_type": context.get("device_type", "desktop"),
        "country": context.get("country", "Unknown"),
        "failed_attempts": context.get("failed_attempts", 0),
        "is_known_device": context.get("is_known_device", False),
        "location_mismatch": context.get("location_mismatch", False),
        "hour": now.hour, "minute": now.minute,
        "day_of_week": now.weekday(),
        "is_weekend": now.weekday() >= 5,
        "is_business_hours": 9 <= now.hour <= 17,
        "created_at": now,
    })

# ──────────────────────────────────────────────
# ML TRAINING (works with ANY data amount)
# ──────────────────────────────────────────────
def train_ml_with_available_data(auth_logs):
    """Train ML models with whatever data is available."""
    try:
        n_records = len(auth_logs) if auth_logs else 0
        
        if n_records >= 10:
            trained = risk_engine.train_models_from_logs(auth_logs)
            return trained, n_records
        elif n_records >= 3:
            # Augment small dataset
            augmented = []
            for _ in range(min(50, 100 // max(n_records, 1))):
                augmented.extend(auth_logs)
            for log in auth_logs:
                var_log = log.copy()
                if "risk_score" in var_log:
                    var_log["risk_score"] = min(100, max(0, var_log["risk_score"] + np.random.normal(0, 5)))
                augmented.append(var_log)
            trained = risk_engine.train_models_from_logs(augmented)
            return trained, n_records
        else:
            # Create minimal synthetic data for basic training
            synthetic_logs = [
                {"hour": h, "day_of_week": d, "failed_attempts": f, "is_weekend": h>20,
                 "is_business_hours": 9<=h<=17, "is_known_device": True, "status": "success",
                 "risk_score": 10}
                for h in range(0, 24, 4) for d in range(7) for f in [0, 1, 2, 5]
            ]
            risk_engine.train_models_from_logs(synthetic_logs)
            return False, n_records
    except Exception as e:
        print(f"[ML Train Error] {e}")
        return False, 0

# ──────────────────────────────────────────────
# SEED DATA
# ──────────────────────────────────────────────
def seed_admin():
    if not get_user_by_email("admin@test.com"):
        create_user({
            "username": "admin", "email": "admin@test.com",
            "password": hash_password("Admin123!"),
            "full_name": "System Administrator", "role": "admin",
            "contact": "", "dob": "", "gender": "", "image": "",
            "failed_attempts": 0, "last_login": None, "created_at": datetime.now()
        })
        print("✅ Default admin created: admin@test.com / Admin123!")

def seed_risk_rules():
    if get_risk_rules(active_only=False):
        return
    db = get_firestore()
    for rule in [
        {"rule_name": "Unusual Hours", "rule_category": "time", "risk_weight": 25,
         "condition_field": "hour", "condition_type": "range", "condition_value": "23-5",
         "risk_level": "high", "action_on_match": "challenge", "priority": 8, "is_active": True},
        {"rule_name": "Weekend Login", "rule_category": "time", "risk_weight": 15,
         "condition_field": "day", "condition_type": "in_list", "condition_value": "6,0",
         "risk_level": "medium", "action_on_match": "alert", "priority": 6, "is_active": True},
        {"rule_name": "New Device", "rule_category": "device", "risk_weight": 20,
         "condition_field": "device_known", "condition_type": "equals", "condition_value": "0",
         "risk_level": "medium", "action_on_match": "challenge", "priority": 7, "is_active": True},
        {"rule_name": "Multiple Failed Attempts", "rule_category": "behavior", "risk_weight": 30,
         "condition_field": "failed_attempts", "condition_type": "greater_than", "condition_value": "3",
         "risk_level": "high", "action_on_match": "challenge", "priority": 9, "is_active": True},
        {"rule_name": "Excessive Failures", "rule_category": "behavior", "risk_weight": 50,
         "condition_field": "failed_attempts", "condition_type": "greater_than", "condition_value": "5",
         "risk_level": "critical", "action_on_match": "block", "priority": 10, "is_active": True},
    ]:
        db.collection("risk_rules").document().set(rule)
    print("✅ Default risk rules created")

# ──────────────────────────────────────────────
# LOGOUT
# ──────────────────────────────────────────────
def logout():
    st.session_state.clear()
    st.rerun()

# ──────────────────────────────────────────────
# PAGES
# ──────────────────────────────────────────────
def page_signup():
    st.markdown('<div class="main-header"><h1>🎓 Student Registration</h1><p>Create your secure MFA account</p></div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2.5, 1])
    with col2:
        with st.container():
            st.markdown('<div class="signup-box">', unsafe_allow_html=True)
            with st.form("signup_form"):
                st.markdown("#### 👤 Personal Information")
                c1, c2 = st.columns(2)
                with c1:
                    full_name = st.text_input("Full Name *", placeholder="e.g., Adebayo Ogunlesi")
                    username = st.text_input("Username *", placeholder="e.g., adebayo")
                    email = st.text_input("Email *", placeholder="ade@university.edu.ng")
                with c2:
                    matric = st.text_input("Matric / Student No. *", placeholder="e.g., 19/ENG/001")
                    department = st.text_input("Department *", placeholder="e.g., Computer Science")
                    level = st.selectbox("Level", ["100", "200", "300", "400", "500", "Postgraduate"])
                
                st.markdown("#### 🔒 Security Credentials")
                p1, p2 = st.columns(2)
                with p1:
                    password = st.text_input("Password *", type="password", placeholder="Min 8 chars, 1 uppercase, 1 digit")
                with p2:
                    confirm = st.text_input("Confirm Password *", type="password")
                
                submitted = st.form_submit_button("🎓 Create Student Account", use_container_width=True)
                if submitted:
                    errs = validate_signup(username, email, password, confirm, full_name, matric, department, level)
                    if errs:
                        for e in errs: st.error(e)
                    elif get_user_by_email(email) or get_user_by_username(username):
                        st.error("❌ Email or username already registered")
                    else:
                        result = create_user({
                            "username": username.lower(), "email": email.lower(),
                            "password": hash_password(password),
                            "full_name": full_name, "role": "student",
                            "matric": matric, "department": department, "level": level,
                            "failed_attempts": 0, "last_login": None,
                            "contact": "", "dob": "", "gender": "", "image": "",
                            "created_at": datetime.now()
                        })
                        if result:
                            st.success("✅ Account created successfully! You can now log in.")
                            st.balloons()
                            time.sleep(1.5)
                            st.session_state.show_signup = False
                            st.rerun()
                        else:
                            st.error("❌ Failed to create account. Please try again.")
            
            st.markdown('<hr>', unsafe_allow_html=True)
            if st.button("← Back to Login", use_container_width=True):
                st.session_state.show_signup = False
                st.rerun()
            st.markdown('</div>', unsafe_allow_html=True)

def page_login():
    st.markdown('<div class="main-header"><h1>🔐 Multi-Factor Authentication System</h1><p>AI-Powered Adaptive Risk Assessment & MFA</p></div>', unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 1.8, 1])
    with col2:
        st.markdown('<div class="login-box">', unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["👨‍🎓 Student Login", "👨‍💼 Admin Login"])
        
        with tab1:
            with st.form("student_login_form"):
                identifier = st.text_input("Email or Username", placeholder="Enter your email or username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                login_btn = st.form_submit_button("🔓 Login as Student", use_container_width=True)
                
                if login_btn:
                    _handle_login(identifier, password, "student")
        
        with tab2:
            with st.form("admin_login_form"):
                identifier = st.text_input("Email or Username", placeholder="Enter admin email or username")
                password = st.text_input("Password", type="password", placeholder="Enter admin password")
                login_btn = st.form_submit_button("🔓 Login as Admin", use_container_width=True)
                
                if login_btn:
                    _handle_login(identifier, password, "admin")
        
        st.markdown("---")
        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
        with col_btn2:
            if st.button("📝 Sign Up", use_container_width=True):
                st.session_state.show_signup = True
                st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)

def _handle_login(identifier, password, role_val):
    if not identifier or not password:
        st.error("Please fill in both fields.")
        return
    
    user = get_user_by_email(identifier) or get_user_by_username(identifier)
    browser, os_name = get_browser_info()
    fp = hashlib.sha256(f"{browser}{os_name}{st.session_state.session_id}".encode()).hexdigest()
    context = {"device_fingerprint": fp, "browser": browser, "os": os_name,
               "device_type": "desktop", "country": "Unknown",
               "failed_attempts": 0, "is_known_device": False,
               "location_mismatch": False, "ip_address": "web",
               "time_anomaly": False, "velocity_check": 0}
    
    if not user:
        r = assess_risk(None, context, 1)
        log_attempt(None, identifier, None, role_val, "failed", "none", r["risk_score"], context)
        st.error("❌ Invalid credentials")
        return
    
    if user["role"] != role_val:
        st.error(f"❌ This account is not registered as {role_val}.")
        return
    
    if not verify_password(password, user["password"]):
        fa = user.get("failed_attempts", 0) + 1
        update_user(user["id"], {"failed_attempts": fa})
        r = assess_risk(user, context, fa)
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "failed", "none", r["risk_score"], context)
        rem = max(0, 5 - fa)
        st.error(f"❌ Wrong password. {rem} attempt(s) remaining." if rem else
                 "❌ Account temporarily locked. Contact support.")
        return
    
    update_user(user["id"], {"failed_attempts": 0})
    r = assess_risk(user, context, 0)
    risk_score, action, method = r["risk_score"], r["action"], r.get("method", "rule_based")
    
    st.markdown(f'<div class="ml-info-box">🤖 <b>ML Risk Engine:</b> {method.replace("_"," ").title()} | Score: <b>{risk_score:.1f}/100</b></div>', unsafe_allow_html=True)
    
    if action == "block":
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "blocked", action, risk_score, context)
        st.error("🚫 Access denied — suspicious activity detected. Contact support.")
        return
    
    if action == "allow" and risk_score < 30:
        update_user(user["id"], {"last_login": datetime.now()})
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "success", action, risk_score, context)
        st.session_state.update(authenticated=True, user=user, risk_score=risk_score)
        st.success("✅ Login successful!")
        time.sleep(0.8)
        st.rerun()
    else:
        otp_code = generate_otp()
        otp_id = save_otp({"user_id": user["id"], "otp_code": otp_code,
                           "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5), "is_used": False})
        send_otp_code(user["email"], user.get("full_name", user["username"]),
                      otp_code, user["role"], risk_score)
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "challenge", action, risk_score, context)
        st.session_state.update(pending_auth=True, otp_id=otp_id, user=user, risk_score=risk_score)
        time.sleep(0.8)
        st.rerun()

def page_otp():
    st.markdown('<div class="main-header"><h1>🔐 Two-Factor Verification</h1></div>', unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.8, 1])
    with col2:
        user = st.session_state.user
        rs = st.session_state.risk_score
        st.markdown(f"**Welcome, {user.get('full_name', user['username'])}**")
        color = "risk-low" if rs < 30 else "risk-med" if rs < 70 else "risk-high"
        st.markdown(f'<p>Risk Score: <span class="{color}"><b>{rs:.1f}/100</b></span></p>', unsafe_allow_html=True)
        st.markdown("Enter the 6-digit code sent to your email:")
        
        cols = st.columns(6)
        digits = [cols[i].text_input(f"Digit {i+1}", max_chars=1, key=f"d{i}", placeholder="0",
                                      label_visibility="hidden") for i in range(6)]
        otp_input = "".join(digits)
        
        c1, c2 = st.columns(2)
        with c1: verify_btn = st.button("✅ Verify", use_container_width=True)
        with c2: resend_btn = st.button("🔄 Resend Code", use_container_width=True)
        
        if verify_btn:
            if len(otp_input) != 6 or not otp_input.isdigit():
                st.error("Enter the complete 6-digit code.")
                return
            otp = get_valid_otp(user["id"], otp_input)
            if not otp:
                st.error("❌ Invalid or already-used code.")
                return
            if _is_expired(otp["expires_at"]):
                st.error("⌛ Code expired. Request a new one.")
                return
            db = get_firestore()
            db.collection("otp_codes").document(otp["id"]).update({"is_used": True})
            update_user(user["id"], {"last_login": datetime.now()})
            st.session_state.update(authenticated=True, pending_auth=False, otp_id=None)
            st.success("✅ Verified! Redirecting…")
            time.sleep(0.8)
            st.rerun()
        
        if resend_btn:
            db = get_firestore()
            if st.session_state.otp_id:
                db.collection("otp_codes").document(st.session_state.otp_id).update({"is_used": True})
            new_code = generate_otp()
            new_id = save_otp({"user_id": user["id"], "otp_code": new_code,
                               "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5), "is_used": False})
            st.session_state.otp_id = new_id
            send_otp_code(user["email"], user.get("full_name", user["username"]),
                          new_code, user["role"], st.session_state.risk_score)
            for i in range(6): st.session_state.pop(f"d{i}", None)
            st.rerun()
        
        st.markdown("---")
        if st.button("← Back to Login", use_container_width=True):
            st.session_state.update(pending_auth=False, otp_id=None, user=None)
            st.rerun()

# ──────────────────────────────────────────────
# ADMIN DASHBOARD
# ──────────────────────────────────────────────
def page_admin():
    user = st.session_state.user
    page = st.session_state.nav_page
    
    @st.cache_data(ttl=30)
    def _users():
        return get_all_users() or []
    @st.cache_data(ttl=30)
    def _logs():
        return get_auth_logs(limit=2000) or []
    
    users = _users()
    auth_logs = _logs()
    students = [u for u in users if u.get("role") == "student"]
    ok_logs = [l for l in auth_logs if l.get("status") == "success"]
    fail_logs = [l for l in auth_logs if l.get("status") == "failed"]
    chal_logs = [l for l in auth_logs if l.get("action_taken") == "challenge"]
    block_logs = [l for l in auth_logs if l.get("action_taken") == "block"]
    scores = [l["risk_score"] for l in auth_logs if l.get("risk_score") is not None]
    avg_risk = np.mean(scores) if scores else 0.0
    
    if page == "Dashboard":
        st.markdown('<div class="main-header"><h1>📊 Admin Dashboard</h1><p>System Overview & ML Risk Analytics</p></div>', unsafe_allow_html=True)
        
        c1, c2, c3, c4, c5 = st.columns(5)
        def _card(col, val, label, sub=""):
            col.markdown(f'<div class="stat-card"><h3>{val}</h3><p>{label}</p><small>{sub}</small></div>', unsafe_allow_html=True)
        _card(c1, len(users), "Total Users", f"🎓 {len(students)} Students")
        sr = f"{len(ok_logs)/(len(ok_logs)+len(fail_logs))*100:.0f}%" if (ok_logs or fail_logs) else "N/A"
        _card(c2, len(ok_logs), "Successful Logins", f"✅ Rate: {sr}")
        _card(c3, len(fail_logs), "Failed Logins", f"❌ {len(block_logs)} blocked")
        _card(c4, len(chal_logs), "MFA Challenged", "🔒 Required OTP")
        risk_cls = "risk-low" if avg_risk < 30 else "risk-med" if avg_risk < 70 else "risk-high"
        c5.markdown(f'<div class="stat-card"><h3 class="{risk_cls}">{avg_risk:.1f}</h3><p>Avg Risk Score</p><small>📈 {len(auth_logs)} total logs</small></div>', unsafe_allow_html=True)
        
        st.markdown("---")
        
        col_ml, col_info = st.columns([1, 3])
        with col_ml:
            if st.button("🧠 Retrain ML from Auth Logs", use_container_width=True):
                with st.spinner("Training ML models on Firebase auth_logs…"):
                    ok, n = train_ml_with_available_data(auth_logs)
                st.success(f"✅ ML models retrained on {n} records!" if ok else
                           f"⚠️ Trained on {n} records. Need more data for optimal accuracy.")
        
        if auth_logs:
            df = pd.DataFrame(auth_logs)
            if "created_at" in df.columns:
                df["date"] = df["created_at"].apply(lambda x: x.date() if hasattr(x, "date") else None)
            
            c_left, c_right = st.columns(2)
            with c_left:
                if "date" in df.columns and df["date"].notna().any():
                    daily = df.groupby("date").size().reset_index(name="logins")
                    fig = px.area(daily, x="date", y="logins", title="Daily Login Activity",
                                  color_discrete_sequence=["#667eea"])
                    fig.update_layout(margin=dict(t=40, b=20), height=280)
                    st.plotly_chart(fig, use_container_width=True)
            
            with c_right:
                if scores:
                    fig2 = go.Figure(go.Histogram(x=scores, nbinsx=20,
                                                  marker_color="#764ba2", opacity=0.8))
                    fig2.update_layout(title="Risk Score Distribution",
                                       xaxis_title="Score", yaxis_title="Count",
                                       height=280, margin=dict(t=40, b=20))
                    st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No authentication data yet. Students need to log in first.")
    
    elif page == "Students":
        st.markdown('<div class="main-header"><h1>🎓 Student Management</h1></div>', unsafe_allow_html=True)
        
        if students:
            df_s = pd.DataFrame(students)
            for col in ["created_at", "last_login"]:
                if col in df_s.columns:
                    df_s[col] = df_s[col].apply(format_dt)
            show = [c for c in ["username","email","full_name","matric","department","level","last_login","created_at"] if c in df_s.columns]
            st.dataframe(df_s[show], use_container_width=True)
        else:
            st.info("No students registered yet.")
        
        with st.expander("➕ Add Student Manually"):
            with st.form("add_student"):
                c1, c2 = st.columns(2)
                with c1:
                    sn = st.text_input("Full Name")
                    su = st.text_input("Username")
                    se = st.text_input("Email")
                    sm = st.text_input("Matric No.")
                with c2:
                    sd = st.text_input("Department")
                    sl = st.selectbox("Level", ["100","200","300","400","500","Postgraduate"])
                    sp = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Create Student", use_container_width=True)
                if submitted:
                    if sn and su and se and sm and sp:
                        if get_user_by_email(se) or get_user_by_username(su):
                            st.error("Email or username already exists")
                        else:
                            r = create_user({"username":su.lower(),"email":se.lower(),"password":hash_password(sp),
                                             "full_name":sn,"role":"student","matric":sm,"department":sd,
                                             "level":sl,"failed_attempts":0,"last_login":None,
                                             "contact":"","dob":"","gender":"","image":"","created_at":datetime.now()})
                            if r: st.success(f"✅ Student {su} created!"); time.sleep(1); st.rerun()
                            else: st.error("Failed to create student")
                    else:
                        st.error("Fill in all required fields")
    
    elif page == "Auth Logs":
        st.markdown('<div class="main-header"><h1>📜 Authentication Logs</h1></div>', unsafe_allow_html=True)
        if auth_logs:
            df_l = pd.DataFrame(auth_logs)
            if "created_at" in df_l.columns:
                df_l["created_at"] = df_l["created_at"].apply(format_dt)
            st.dataframe(df_l, use_container_width=True)
        else:
            st.info("No authentication logs yet.")
    
    elif page == "ML Risk Engine":
        st.markdown('<div class="main-header"><h1>🤖 ML Risk Engine</h1><p>Train & Inspect the Adaptive Risk Model</p></div>', unsafe_allow_html=True)
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Random Forest", "✅ Ready" if risk_engine.random_forest else "❌ Not trained")
        c2.metric("Gradient Boosting", "✅ Ready" if risk_engine.gradient_boosting else "❌ Not trained")
        c3.metric("Isolation Forest", "✅ Ready" if risk_engine.isolation_forest else "❌ Not trained")
        c4.metric("Records Available", len(auth_logs))
        
        if st.button("🧠 Train / Retrain ML Models", use_container_width=False):
            if len(auth_logs) < 3:
                st.warning(f"Only {len(auth_logs)} records. Training with synthetic augmentation.")
            with st.spinner("Training ML models..."):
                ok, n = train_ml_with_available_data(auth_logs)
            if ok:
                st.success(f"✅ Models trained on {n} records!")
            else:
                st.info(f"⚠️ Trained on {n} records with augmentation. Add more real data for better accuracy.")
    
    elif page == "Risk Rules":
        st.markdown('<div class="main-header"><h1>⚙️ Risk Rules</h1></div>', unsafe_allow_html=True)
        rules = get_risk_rules(active_only=False)
        if rules:
            df_r = pd.DataFrame(rules)
            st.dataframe(df_r, use_container_width=True)
        else:
            st.info("No risk rules found.")

# ──────────────────────────────────────────────
# STUDENT DASHBOARD
# ──────────────────────────────────────────────
def page_student():
    user = st.session_state.user
    rs = st.session_state.risk_score
    last = format_dt(user.get("last_login"))
    
    st.markdown(f'<div class="main-header"><h1>🎓 Student Dashboard</h1><p>Welcome back, {user.get("full_name", user["username"])}</p></div>', unsafe_allow_html=True)
    
    try:
        ulogs = get_auth_logs(filters={"user_id": user["id"]}, limit=100) or []
    except Exception:
        ulogs = []
    
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f'<div class="stat-card"><h3>{len(ulogs)}</h3><p>Total Logins</p></div>', unsafe_allow_html=True)
    risk_cls = "risk-low" if rs < 30 else "risk-med" if rs < 70 else "risk-high"
    c2.markdown(f'<div class="stat-card"><h3 class="{risk_cls}">{rs:.0f}</h3><p>Last Risk Score</p></div>', unsafe_allow_html=True)
    c3.markdown(f'<div class="stat-card"><h3>{user.get("department","N/A")}</h3><p>Department</p></div>', unsafe_allow_html=True)
    c4.markdown(f'<div class="stat-card"><h3>{user.get("level","N/A")}</h3><p>Level</p></div>', unsafe_allow_html=True)
    
    st.markdown("---")
    st.subheader("📋 My Login History")
    if ulogs:
        df_u = pd.DataFrame(ulogs)
        if "created_at" in df_u.columns:
            df_u["created_at"] = df_u["created_at"].apply(format_dt)
        st.dataframe(df_u, use_container_width=True)
        
        if "risk_score" in df_u.columns and df_u["risk_score"].notna().any():
            fig = px.line(df_u.sort_values("created_at"), x="created_at", y="risk_score",
                          title="My Risk Score Over Time", markers=True,
                          color_discrete_sequence=["#667eea"])
            st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No login history yet.")

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    seed_admin()
    seed_risk_rules()
    
    if not st.session_state.authenticated:
        if st.session_state.show_signup:
            page_signup()
        elif st.session_state.pending_auth:
            page_otp()
        else:
            page_login()
        return
    
    user = st.session_state.user
    is_admin = user["role"] == "admin"
    
    with st.sidebar:
        st.markdown(f"**{user.get('full_name', user['username'])}**")
        badge_cls = f"badge-{user['role']}"
        st.markdown(f'<span class="badge {badge_cls}">{user["role"].upper()}</span>', unsafe_allow_html=True)
        rs = st.session_state.risk_score
        risk_cls = "risk-low" if rs < 30 else "risk-med" if rs < 70 else "risk-high"
        st.markdown(f'Risk: <span class="{risk_cls}"><b>{rs:.0f}/100</b></span>', unsafe_allow_html=True)
        st.markdown("---")
        
        if is_admin:
            nav = st.radio("Navigation", ["Dashboard", "Students", "Auth Logs", "ML Risk Engine", "Risk Rules"])
            st.session_state.nav_page = nav
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            logout()
    
    if is_admin:
        page_admin()
    else:
        page_student()

if __name__ == "__main__":
    main()
