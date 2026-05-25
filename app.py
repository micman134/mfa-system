# app.py - MFA System v3 — Session persistence, improved UI, flexible ML training

import streamlit as st
import sys, os, re, time, hashlib, random, secrets
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import bcrypt
from datetime import datetime, timedelta, timezone

# ── Page config (must be first) ──────────────────────────────────────────────
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
    create_user, update_user, get_all_users,
    log_auth_attempt, get_auth_logs, get_user_logs, save_otp, get_valid_otp,
    get_risk_rules, get_firestore
)
from risk_engine import risk_engine

# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL CSS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ── fonts & base ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

/* ── hide default streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }

/* ── hero header ── */
.hero {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 40%, #0f3460 100%);
    border-radius: 16px; padding: 2.5rem 2rem; text-align: center;
    margin-bottom: 2rem; position: relative; overflow: hidden;
}
.hero::before {
    content: ""; position: absolute; top: -50%; left: -50%;
    width: 200%; height: 200%;
    background: radial-gradient(circle, rgba(102,126,234,.15) 0%, transparent 60%);
    animation: pulse 4s ease-in-out infinite;
}
@keyframes pulse { 0%,100%{transform:scale(1)} 50%{transform:scale(1.05)} }
.hero h1 { color: #fff; font-size: 2.2rem; font-weight: 700; margin: 0; letter-spacing: -.5px; }
.hero p  { color: rgba(255,255,255,.7); margin: .6rem 0 0; font-size: 1rem; }
.hero-badge {
    display: inline-block; margin-top: 1rem;
    background: rgba(102,126,234,.3); border: 1px solid rgba(102,126,234,.5);
    color: #a0aec0; padding: .3rem 1rem; border-radius: 20px; font-size: .8rem;
}

/* ── auth cards ── */
.auth-card {
    background: #fff; border-radius: 16px; padding: 2.2rem;
    box-shadow: 0 4px 6px -1px rgba(0,0,0,.07), 0 20px 60px -10px rgba(0,0,0,.12);
    border: 1px solid #f0f0f0;
}
.auth-card h2 { font-size: 1.4rem; font-weight: 700; color: #1a1a2e; margin: 0 0 .3rem; }
.auth-card .sub { color: #718096; font-size: .9rem; margin: 0 0 1.5rem; }

/* ── tab pills (login page) ── */
.tab-pills { display: flex; gap: .5rem; margin-bottom: 1.5rem; }
.tab-pill {
    flex: 1; padding: .6rem; border-radius: 8px; text-align: center;
    font-weight: 600; font-size: .9rem; cursor: pointer; border: 2px solid #e2e8f0;
    color: #718096; background: #f8fafc; transition: all .2s;
}
.tab-pill.active { background: #1a1a2e; color: #fff; border-color: #1a1a2e; }

/* ── stat cards ── */
.stat-card {
    background: #fff; border-radius: 12px; padding: 1.3rem 1.1rem;
    box-shadow: 0 1px 3px rgba(0,0,0,.08), 0 4px 16px rgba(0,0,0,.06);
    border: 1px solid #f0f4ff; margin-bottom: 1rem; text-align: center;
    transition: transform .2s, box-shadow .2s;
}
.stat-card:hover { transform: translateY(-3px); box-shadow: 0 8px 30px rgba(0,0,0,.1); }
.stat-card .val  { font-size: 2rem; font-weight: 700; color: #1a1a2e; margin: 0; }
.stat-card .lbl  { color: #718096; font-size: .82rem; margin: .3rem 0 0; font-weight: 500; }
.stat-card .sub  { color: #a0aec0; font-size: .75rem; margin-top: .2rem; }

/* ── risk colours ── */
.risk-low  { color: #22c55e !important; }
.risk-med  { color: #f59e0b !important; }
.risk-high { color: #ef4444 !important; }

/* ── role badges ── */
.badge {
    display: inline-block; padding: .2rem .75rem; border-radius: 20px;
    font-size: .75rem; font-weight: 700; letter-spacing: .3px;
}
.badge-admin   { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.badge-student { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }

/* ── sidebar ── */
section[data-testid="stSidebar"] > div:first-child {
    background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
    padding-top: 1.5rem;
}
section[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
section[data-testid="stSidebar"] hr { border-color: rgba(255,255,255,.1) !important; }
section[data-testid="stSidebar"] .stRadio label { 
    padding: .4rem .6rem; border-radius: 8px; transition: background .15s;
}
section[data-testid="stSidebar"] .stRadio label:hover { background: rgba(255,255,255,.08); }
.sidebar-user { text-align: center; padding: 1rem .5rem; }
.sidebar-avatar {
    width: 56px; height: 56px; border-radius: 50%;
    background: linear-gradient(135deg, #667eea, #764ba2);
    display: flex; align-items: center; justify-content: center;
    font-size: 1.4rem; margin: 0 auto .6rem; font-weight: 700; color: white;
}
.sidebar-name { font-weight: 600; font-size: 1rem; color: #fff !important; }
.sidebar-role { font-size: .75rem; color: #a0aec0 !important; margin-top: .2rem; }
.sidebar-risk { 
    font-size: .78rem; margin-top: .5rem; padding: .3rem .8rem;
    background: rgba(255,255,255,.08); border-radius: 20px; display: inline-block;
}

/* ── logout button ── */
.stButton button[kind="secondary"], 
div[data-testid="stSidebar"] .stButton button {
    background: rgba(239,68,68,.12) !important;
    border: 1px solid rgba(239,68,68,.3) !important;
    color: #fca5a5 !important; border-radius: 8px !important;
    font-weight: 600 !important; transition: all .2s !important;
}
div[data-testid="stSidebar"] .stButton button:hover {
    background: rgba(239,68,68,.25) !important;
    border-color: #ef4444 !important; color: #fff !important;
}

/* ── primary buttons ── */
.stButton > button[data-baseweb="button"] {
    border-radius: 8px !important; font-weight: 600 !important;
}

/* ── OTP boxes ── */
.otp-row input {
    text-align: center !important; font-size: 1.6rem !important;
    font-weight: 700 !important; letter-spacing: .2rem !important;
}

/* ── ml info box ── */
.ml-box {
    background: linear-gradient(135deg, #f0f4ff, #faf5ff);
    border-left: 4px solid #667eea; border-radius: 0 8px 8px 0;
    padding: .8rem 1rem; font-size: .85rem; margin: .8rem 0;
    color: #4a5568;
}

/* ── section headers ── */
.section-title {
    font-size: 1.1rem; font-weight: 700; color: #1a1a2e;
    margin: 1.5rem 0 .8rem; padding-bottom: .4rem;
    border-bottom: 2px solid #f0f4ff;
}

/* ── risk meter ── */
.risk-meter-wrap { text-align: center; padding: .5rem; }
.risk-meter-val { font-size: 3rem; font-weight: 800; margin: 0; }
.risk-meter-lbl { font-size: .9rem; color: #718096; margin-top: -.2rem; }

/* ── info alert ── */
.info-alert {
    background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px;
    padding: .8rem 1rem; color: #1e40af; font-size: .88rem;
}

/* hide streamlit's own expander arrow styling issues */
div[data-testid="stExpander"] { border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION STATE  (persistent across reruns via st.session_state)
# ═══════════════════════════════════════════════════════════════════════════════
_DEFAULTS = dict(
    authenticated=False,
    user=None,
    pending_auth=False,
    otp_id=None,
    otp_display_code=None,      # persists OTP code across reruns
    otp_email_sent=False,       # whether email was delivered
    risk_score=0.0,
    risk_method="",
    show_signup=False,
    login_mode="student",        # "student" | "admin"
    session_id=secrets.token_urlsafe(32),
    nav_page="Dashboard",
    failed_login_count=0,
    last_failed_ts=None,
)
for _k, _v in _DEFAULTS.items():
    if _k not in st.session_state:
        st.session_state[_k] = _v

# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def hash_password(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
def verify_password(pw, hashed): return bcrypt.checkpw(pw.encode(), hashed.encode())
def generate_otp(): return f"{random.randint(100000, 999999)}"

def format_dt(v):
    if v is None: return "—"
    if hasattr(v, "strftime"): return v.strftime("%d %b %Y, %H:%M")
    return str(v)

def now_utc(): return datetime.now(timezone.utc)

def _is_expired(dt):
    if dt is None: return True
    now = now_utc()
    if hasattr(dt, "tzinfo") and dt.tzinfo is not None: return now > dt
    return now > dt.replace(tzinfo=timezone.utc)

def get_browser_info():
    try: ua = st.context.headers.get("User-Agent", "")
    except: ua = ""
    browser = ("Chrome" if "Chrome" in ua and "Edg" not in ua else
               "Firefox" if "Firefox" in ua else
               "Safari" if "Safari" in ua and "Chrome" not in ua else
               "Edge" if "Edg" in ua else "Unknown")
    os_name = ("Windows" if "Windows" in ua else "macOS" if "Mac" in ua else
               "Android" if "Android" in ua else
               "iOS" if "iPhone" in ua or "iPad" in ua else
               "Linux" if "Linux" in ua else "Unknown")
    return browser, os_name

def send_otp_display(email, name, code, role, risk):
    """Send OTP email, print to console, and SAVE to session_state for persistent display."""
    # Always print to console
    print(f"\n{'='*60}")
    print(f"  *** OTP CODE ***")
    print(f"  User  : {name} <{email}>  [{role.upper()}]")
    print(f"  Code  : {code}")
    print(f"  Risk  : {risk:.1f}/100")
    print(f"{'='*60}\n")

    # Try email
    email_sent = False
    try:
        from email_utils import send_otp_email as _send
        email_sent = _send(email, name, code, role, risk)
    except Exception as e:
        print(f"[OTP email error] {e}")

    # Store in session_state — survives reruns
    st.session_state.otp_display_code = code
    st.session_state.otp_email_sent   = email_sent


def _render_otp_code_box():
    """Render the persistent OTP code box from session_state. Call inside page_otp()."""
    code       = st.session_state.get("otp_display_code")
    email_sent = st.session_state.get("otp_email_sent", False)
    if not code:
        return
    if email_sent:
        st.success("📧 Verification code sent to your email — also shown below:")
    else:
        st.warning("📧 Email unavailable — use the code below to verify:")
    st.markdown(f"""
    <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);border-radius:14px;
                padding:28px;text-align:center;margin:12px 0;
                border:1px solid rgba(102,126,234,.4);">
        <div style="color:#a0aec0;font-size:.82rem;letter-spacing:2px;
                    text-transform:uppercase;margin-bottom:10px;">
            Your Verification Code
        </div>
        <div style="color:#fff;font-size:3rem;font-weight:900;
                    letter-spacing:20px;font-family:monospace;
                    text-shadow:0 0 20px rgba(102,126,234,.8);">
            {code}
        </div>
        <div style="color:#f59e0b;font-size:.82rem;margin-top:12px;">
            ⏱ Expires in 5 minutes &nbsp;|&nbsp; Do not share this code
        </div>
    </div>
    """, unsafe_allow_html=True)

def validate_signup(username, email, password, confirm, full_name, matric, dept):
    errs = []
    if len(username) < 3 or not re.match(r"^[a-zA-Z0-9_]+$", username):
        errs.append("Username must be ≥ 3 characters (letters, numbers, underscores)")
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        errs.append("Please enter a valid email address")
    if len(password) < 8: errs.append("Password must be at least 8 characters")
    if not re.search(r"[A-Z]", password): errs.append("Password needs at least one uppercase letter")
    if not re.search(r"\d", password): errs.append("Password needs at least one number")
    if password != confirm: errs.append("Passwords do not match")
    if not full_name.strip(): errs.append("Full name is required")
    if not matric.strip(): errs.append("Matric/Student number is required")
    if not dept.strip(): errs.append("Department is required")
    return errs

# ═══════════════════════════════════════════════════════════════════════════════
# RISK / ML
# ═══════════════════════════════════════════════════════════════════════════════
def _enrich_context(req, user):
    """Pull user's login history from Firebase to improve ML features."""
    if not user or not user.get("id"): return req
    try:
        logs = get_user_logs(user["id"], limit=200) or []
        if logs:
            fp = req.get("device_fingerprint")
            ok = [l for l in logs if l.get("status") == "success"]
            req["is_known_device"] = any(l.get("device_fingerprint") == fp for l in ok)
            hrs = [l.get("hour", 12) for l in ok]
            if hrs:
                avg_h, std_h = np.mean(hrs), max(np.std(hrs) if len(hrs)>1 else 6, 3)
                req["time_anomaly"] = abs(req["hour"] - avg_h) > std_h * 2
            recent_fails = sum(1 for l in logs[:15] if l.get("status") == "failed")
            req["velocity_check"] = recent_fails * 100
    except Exception as e:
        print(f"[enrich_context] {e}")
    return req

def assess_risk(user, context, failed_attempts):
    now = datetime.now()
    req = {
        "hour": now.hour, "minute": now.minute, "day_of_week": now.weekday(),
        "is_weekend": now.weekday() >= 5, "is_business_hours": 9 <= now.hour <= 17,
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
        "cookies_enabled": True, "javascript_enabled": True,
    }
    req = _enrich_context(req, user)
    return risk_engine.predict(req)

def log_attempt(uid, username, email, role, status, action, risk_score, ctx):
    now = datetime.now()
    log_auth_attempt({
        "user_id": uid, "username": username, "email": email, "role": role,
        "status": status, "action_taken": action, "risk_score": risk_score,
        "ip_address": ctx.get("ip_address", "web"),
        "device_fingerprint": ctx.get("device_fingerprint"),
        "browser": ctx.get("browser"), "os": ctx.get("os"),
        "device_type": ctx.get("device_type", "desktop"),
        "country": ctx.get("country", "Unknown"),
        "failed_attempts": ctx.get("failed_attempts", 0),
        "is_known_device": ctx.get("is_known_device", False),
        "location_mismatch": ctx.get("location_mismatch", False),
        "hour": now.hour, "minute": now.minute, "day_of_week": now.weekday(),
        "is_weekend": now.weekday() >= 5, "is_business_hours": 9 <= now.hour <= 17,
        "created_at": now,
    })

def train_ml(logs):
    """Train ML with any number of records — no minimum enforced."""
    if not logs:
        return False, "No logs available in database."
    try:
        # Monkey-patch minimum check to allow any size
        import risk_engine as _re_mod
        orig = _re_mod.RiskEngine.train_models_from_logs
        def _patched(self, auth_logs):
            if not auth_logs: return False
            from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor, IsolationForest
            from sklearn.preprocessing import StandardScaler
            import joblib, os
            X, y = [], []
            for log in auth_logs:
                features = self.extract_features_from_log(log)
                if features is not None:
                    X.append(features)
                    rs = log.get("risk_score")
                    if rs is None: rs = self.calculate_rule_based_score(log)
                    y.append(float(rs) / 100.0)
            if len(X) < 2:
                return False
            import numpy as np
            X, y = np.array(X), np.array(y)
            n = len(X)
            self.scaler = StandardScaler()
            Xs = self.scaler.fit_transform(X)
            ne = max(10, min(100, n * 2))  # scale estimators with data size
            self.random_forest = RandomForestRegressor(n_estimators=ne, max_depth=min(8, max(2, n//3)), random_state=42)
            self.random_forest.fit(Xs, y)
            self.gradient_boosting = GradientBoostingRegressor(n_estimators=ne, learning_rate=0.1, max_depth=min(4, max(2, n//5)), random_state=42)
            self.gradient_boosting.fit(Xs, y)
            cont = min(0.3, max(0.05, 1/n)) if n >= 10 else 0.1
            self.isolation_forest = IsolationForest(contamination=cont, random_state=42)
            self.isolation_forest.fit(Xs)
            os.makedirs(self.model_path, exist_ok=True)
            joblib.dump(self.random_forest, os.path.join(self.model_path, "risk_model_rf.pkl"))
            joblib.dump(self.gradient_boosting, os.path.join(self.model_path, "risk_model_gb.pkl"))
            joblib.dump(self.scaler, os.path.join(self.model_path, "scaler.pkl"))
            joblib.dump(self.isolation_forest, os.path.join(self.model_path, "isolation_forest.pkl"))
            return True
        _re_mod.RiskEngine.train_models_from_logs = _patched
        ok = risk_engine.train_models_from_logs(logs)
        _re_mod.RiskEngine.train_models_from_logs = orig
        if ok:
            return True, f"✅ Trained on {len(logs)} records."
        else:
            return False, f"Need ≥ 2 valid feature records (have {len(logs)})."
    except Exception as e:
        return False, f"Training error: {e}"

# ═══════════════════════════════════════════════════════════════════════════════
# SEED DATA
# ═══════════════════════════════════════════════════════════════════════════════
@st.cache_data(ttl=3600)
def _seeded(): return False  # placeholder

def seed_admin():
    if not get_user_by_email("admin@eduauth.ng"):
        create_user({"username":"admin","email":"admin@eduauth.ng",
                     "password":hash_password("Admin123!"),
                     "full_name":"System Administrator","role":"admin",
                     "contact":"","dob":"","gender":"","image":"",
                     "failed_attempts":0,"last_login":None,"created_at":datetime.now()})
        print("✅ Default admin: admin@eduauth.ng / Admin123!")

def seed_rules():
    if get_risk_rules(active_only=False): return
    db = get_firestore()
    for r in [
        {"rule_name":"Unusual Hours","rule_category":"time","risk_weight":25,"condition_field":"hour","condition_type":"range","condition_value":"23-5","risk_level":"high","action_on_match":"challenge","priority":8,"is_active":True},
        {"rule_name":"Weekend Login","rule_category":"time","risk_weight":15,"condition_field":"day","condition_type":"in_list","condition_value":"6,0","risk_level":"medium","action_on_match":"alert","priority":6,"is_active":True},
        {"rule_name":"New Device","rule_category":"device","risk_weight":20,"condition_field":"device_known","condition_type":"equals","condition_value":"0","risk_level":"medium","action_on_match":"challenge","priority":7,"is_active":True},
        {"rule_name":"Multiple Failures","rule_category":"behavior","risk_weight":30,"condition_field":"failed_attempts","condition_type":"greater_than","condition_value":"3","risk_level":"high","action_on_match":"challenge","priority":9,"is_active":True},
        {"rule_name":"Excessive Failures","rule_category":"behavior","risk_weight":50,"condition_field":"failed_attempts","condition_type":"greater_than","condition_value":"5","risk_level":"critical","action_on_match":"block","priority":10,"is_active":True},
    ]: db.collection("risk_rules").document().set(r)

# ═══════════════════════════════════════════════════════════════════════════════
# UI COMPONENTS
# ═══════════════════════════════════════════════════════════════════════════════
def stat_card(col, value, label, sub="", color=None):
    val_class = f' style="color:{color}"' if color else ""
    col.markdown(f"""
    <div class="stat-card">
        <div class="val"{val_class}>{value}</div>
        <div class="lbl">{label}</div>
        {"" if not sub else f'<div class="sub">{sub}</div>'}
    </div>""", unsafe_allow_html=True)

def risk_badge(score):
    if score < 30: return "🟢", "#22c55e", "Low Risk"
    if score < 70: return "🟡", "#f59e0b", "Medium Risk"
    return "🔴", "#ef4444", "High Risk"

def logout():
    # Preserve session_id so the browser tab stays connected
    sid = st.session_state.session_id
    for k in list(st.session_state.keys()):
        del st.session_state[k]
    for _k, _v in _DEFAULTS.items():
        st.session_state[_k] = _v
    st.session_state.session_id = sid
    st.rerun()

def sidebar_user_panel():
    user = st.session_state.user
    rs   = st.session_state.risk_score
    initials = "".join(p[0].upper() for p in user.get("full_name","?").split()[:2])
    emoji, color, label = risk_badge(rs)
    with st.sidebar:
        st.markdown(f"""
        <div class="sidebar-user">
            <div class="sidebar-avatar">{initials}</div>
            <div class="sidebar-name">{user.get("full_name","User")}</div>
            <div class="sidebar-role">{user.get("department","") or user["role"].upper()}</div>
            <div class="sidebar-risk" style="color:{color}">{emoji} Risk: {rs:.0f}/100 — {label}</div>
        </div>""", unsafe_allow_html=True)
        st.markdown("---")

        if user["role"] == "admin":
            nav = st.radio("Navigation", ["Dashboard","Students","Auth Logs","ML Engine","Risk Rules"],
                format_func=lambda x: {
                    "Dashboard": "📊  Dashboard",
                    "Students":  "🎓  Students",
                    "Auth Logs": "📋  Auth Logs",
                    "ML Engine": "🤖  ML Engine",
                    "Risk Rules":"⚙️   Risk Rules",
                }.get(x, x), label_visibility="collapsed")
            st.session_state.nav_page = nav
        else:
            nav_s = st.radio("Menu", ["My Dashboard","Login History","Security"],
                format_func=lambda x: {
                    "My Dashboard":  "🏠  My Dashboard",
                    "Login History": "📋  Login History",
                    "Security":      "🔒  Security",
                }.get(x, x), label_visibility="collapsed")
            st.session_state.nav_page = nav_s

        st.markdown("---")
        if st.button("🚪  Logout", use_container_width=True, key="logout_btn"):
            logout()

# ═══════════════════════════════════════════════════════════════════════════════
# AUTH PAGES
# ═══════════════════════════════════════════════════════════════════════════════
def page_login():
    # Hero
    st.markdown("""
    <div class="hero">
        <h1>🎓 EduAuth MFA System</h1>
        <p>AI-Powered Adaptive Risk Authentication for Universities</p>
        <span class="hero-badge">🔒 Secured with Machine Learning Risk Assessment</span>
    </div>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.6, 1])
    with col2:
        # Tab selector
        mode = st.session_state.login_mode
        c_s, c_a = st.columns(2)
        if c_s.button("🎓 Student Login", use_container_width=True,
                      type="primary" if mode=="student" else "secondary"):
            st.session_state.login_mode = "student"; st.rerun()
        if c_a.button("🔐 Admin Login", use_container_width=True,
                      type="primary" if mode=="admin" else "secondary"):
            st.session_state.login_mode = "admin"; st.rerun()

        st.markdown('<div class="auth-card">', unsafe_allow_html=True)

        if mode == "student":
            st.markdown('<h2>Student Portal</h2><p class="sub">Login with your university credentials</p>', unsafe_allow_html=True)
        else:
            st.markdown('<h2>Admin Portal</h2><p class="sub">Restricted — authorised personnel only</p>', unsafe_allow_html=True)

        identifier = st.text_input("📧 Email or Username", placeholder="Enter your email or username", key="li_ident")
        password   = st.text_input("🔑 Password", type="password", placeholder="Enter your password", key="li_pw")

        login_btn = st.button("🔓 Login", use_container_width=True, type="primary", key="li_btn")

        if mode == "student":
            st.markdown('<div style="text-align:center;margin-top:.8rem;color:#718096;font-size:.88rem">Don\'t have an account?</div>', unsafe_allow_html=True)
            if st.button("📝 Create Student Account", use_container_width=True, key="goto_signup"):
                st.session_state.show_signup = True; st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

        if login_btn:
            _do_login(identifier, password, mode)


def _do_login(identifier, password, role_val):
    if not identifier or not password:
        st.error("Please fill in both fields.")
        return

    user = get_user_by_email(identifier) or get_user_by_username(identifier)
    browser, os_name = get_browser_info()
    fp = hashlib.sha256(f"{browser}{os_name}{st.session_state.session_id}".encode()).hexdigest()
    ctx = {"device_fingerprint": fp, "browser": browser, "os": os_name,
           "device_type": "desktop", "country": "Unknown",
           "failed_attempts": st.session_state.failed_login_count,
           "is_known_device": False, "location_mismatch": False,
           "ip_address": "web", "time_anomaly": False, "velocity_check": 0}

    if not user:
        st.session_state.failed_login_count += 1
        r = assess_risk(None, ctx, st.session_state.failed_login_count)
        log_attempt(None, identifier, None, role_val, "failed", "none", r["risk_score"], ctx)
        st.error("❌ No account found with those credentials.")
        return

    if not verify_password(password, user.get("password", "")):
        fa = user.get("failed_attempts", 0) + 1
        update_user(user["id"], {"failed_attempts": fa})
        st.session_state.failed_login_count = fa
        r = assess_risk(user, ctx, fa)
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "failed", "none", r["risk_score"], ctx)
        rem = max(0, 5 - fa)
        msg = f"❌ Incorrect password. {rem} attempt(s) remaining." if rem else "❌ Account locked after too many failures. Contact support."
        st.error(msg)
        return

    if user["role"] != role_val:
        st.error(f"❌ This account is not registered as **{role_val}**.")
        return

    # Reset failures on successful password match
    update_user(user["id"], {"failed_attempts": 0})
    st.session_state.failed_login_count = 0

    ctx["failed_attempts"] = 0
    r = assess_risk(user, ctx, 0)
    risk_score, action, method = r["risk_score"], r["action"], r.get("method","rule_based")
    emoji, color, label = risk_badge(risk_score)

    st.markdown(f'<div class="ml-box">🤖 <b>ML Risk Engine</b> ({method.replace("_"," ").title()}) — Score: <b style="color:{color}">{risk_score:.1f}/100</b> {emoji} {label}</div>', unsafe_allow_html=True)

    if action == "block":
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "blocked", action, risk_score, ctx)
        st.error("🚫 Access denied — high-risk activity detected. Contact the administrator.")
        return

    if action == "allow" and risk_score < 30:
        update_user(user["id"], {"last_login": datetime.now()})
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "success", action, risk_score, ctx)
        st.session_state.update(authenticated=True, user=user, risk_score=risk_score, risk_method=method)
        st.success("✅ Login successful! Welcome back.")
        time.sleep(0.6); st.rerun()
    else:
        otp = generate_otp()
        oid = save_otp({"user_id": user["id"], "otp_code": otp,
                        "expires_at": now_utc() + timedelta(minutes=5), "is_used": False})
        send_otp_display(user["email"], user.get("full_name", user["username"]), otp, user["role"], risk_score)
        log_attempt(user["id"], user["username"], user["email"], user["role"],
                    "challenge", action, risk_score, ctx)
        st.session_state.update(pending_auth=True, otp_id=oid, user=user,
                                risk_score=risk_score, risk_method=method)
        time.sleep(0.6); st.rerun()


def page_signup():
    st.markdown("""
    <div class="hero">
        <h1>📝 Student Registration</h1>
        <p>Create your university MFA account</p>
    </div>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2.2, 1])
    with col2:
        st.markdown('<div class="auth-card">', unsafe_allow_html=True)
        st.markdown('<h2>Create Account</h2><p class="sub">All fields marked * are required</p>', unsafe_allow_html=True)

        with st.form("signup_form", clear_on_submit=False):
            st.markdown('<div class="section-title">👤 Personal Information</div>', unsafe_allow_html=True)
            c1, c2 = st.columns(2)
            with c1:
                full_name  = st.text_input("Full Name *", placeholder="Ada Okafor")
                email      = st.text_input("Email Address *", placeholder="ada@university.edu.ng")
                department = st.text_input("Department *", placeholder="Computer Science")
            with c2:
                username   = st.text_input("Username *", placeholder="adaokafor")
                matric     = st.text_input("Matric / Student No. *", placeholder="19/ENG/CS/001")
                level      = st.selectbox("Academic Level *", ["100","200","300","400","500","Postgraduate"])

            st.markdown('<div class="section-title">🔐 Security Credentials</div>', unsafe_allow_html=True)
            p1, p2 = st.columns(2)
            with p1: password = st.text_input("Password *", type="password", placeholder="Min 8 chars, 1 uppercase, 1 number")
            with p2: confirm  = st.text_input("Confirm Password *", type="password", placeholder="Repeat password")

            st.markdown('<div class="info-alert">🔒 Your account will default to <b>Student</b> role. Admins are created by the system administrator.</div>', unsafe_allow_html=True)

            submitted = st.form_submit_button("🎓 Create My Account", use_container_width=True, type="primary")
            if submitted:
                errs = validate_signup(username, email, password, confirm, full_name, matric, department)
                if errs:
                    for e in errs: st.error(f"❌ {e}")
                elif get_user_by_email(email) or get_user_by_username(username):
                    st.error("❌ An account with this email or username already exists.")
                else:
                    result = create_user({
                        "username": username.lower(), "email": email.lower(),
                        "password": hash_password(password), "full_name": full_name,
                        "role": "student", "matric": matric, "department": department,
                        "level": level, "failed_attempts": 0, "last_login": None,
                        "contact": "", "dob": "", "gender": "", "image": "",
                        "created_at": datetime.now()
                    })
                    if result:
                        st.success("✅ Account created successfully!")
                        st.balloons()
                        time.sleep(2)
                        st.session_state.show_signup = False; st.rerun()
                    else:
                        st.error("❌ Could not create account. Please try again.")

        st.markdown("---")
        if st.button("← Back to Login", use_container_width=True, key="back_login"):
            st.session_state.show_signup = False; st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


def page_otp():
    st.markdown("""
    <div class="hero">
        <h1>🔐 Two-Factor Verification</h1>
        <p>Additional security step required for your login</p>
    </div>""", unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.6, 1])
    with col2:
        user = st.session_state.user
        rs   = st.session_state.risk_score
        emoji, color, label = risk_badge(rs)

        st.markdown('<div class="auth-card">', unsafe_allow_html=True)
        st.markdown(f"**Welcome, {user.get('full_name', user['username'])}**")
        st.markdown(f'<div class="ml-box">{emoji} Risk Score: <b style="color:{color}">{rs:.1f}/100</b> — {label}<br><small>Method: {st.session_state.risk_method.replace("_"," ").title()}</small></div>', unsafe_allow_html=True)
        st.markdown("Enter the **6-digit code** sent to your email address. Code expires in 5 minutes.")
        st.markdown("---")

        # Always show OTP code box (persists across reruns via session_state)
        _render_otp_code_box()

        # OTP digits
        cols = st.columns(6)
        digits = [cols[i].text_input(f"Digit {i+1}", max_chars=1, key=f"otp_d{i}",
                                      placeholder="•", label_visibility="hidden") for i in range(6)]
        otp_input = "".join(digits)

        c1, c2 = st.columns(2)
        with c1: verify_btn = st.button("✅ Verify Code", use_container_width=True, type="primary")
        with c2: resend_btn = st.button("🔄 Resend Code", use_container_width=True)

        if verify_btn:
            if len(otp_input) != 6 or not otp_input.isdigit():
                st.error("Please enter the full 6-digit code.")
            else:
                otp = get_valid_otp(user["id"], otp_input)
                if not otp:
                    st.error("❌ Invalid or already-used code. Request a new one.")
                elif _is_expired(otp.get("expires_at")):
                    st.error("⌛ This code has expired. Please request a new one.")
                else:
                    db = get_firestore()
                    db.collection("otp_codes").document(otp["id"]).update({"is_used": True})
                    update_user(user["id"], {"last_login": datetime.now()})
                    log_attempt(user["id"], user["username"], user["email"], user["role"],
                                "success", "otp_verified", rs, {})
                    st.session_state.update(authenticated=True, pending_auth=False,
                                            otp_id=None, otp_display_code=None, otp_email_sent=False)
                    st.success("✅ Verified! Logging you in…")
                    time.sleep(0.6); st.rerun()

        if resend_btn:
            db = get_firestore()
            if st.session_state.otp_id:
                db.collection("otp_codes").document(st.session_state.otp_id).update({"is_used": True})
            new_code = generate_otp()
            new_id = save_otp({"user_id": user["id"], "otp_code": new_code,
                               "expires_at": now_utc() + timedelta(minutes=5), "is_used": False})
            st.session_state.otp_id = new_id
            send_otp_display(user["email"], user.get("full_name", user["username"]),
                             new_code, user["role"], rs)
            for i in range(6): st.session_state.pop(f"otp_d{i}", None)
            st.rerun()  # rerun — code persists via session_state

        st.markdown("---")
        if st.button("← Cancel & Return to Login", use_container_width=True):
            st.session_state.update(pending_auth=False, otp_id=None, user=None,
                                    otp_display_code=None, otp_email_sent=False)
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
@st.cache_data(ttl=20)
def _fetch_users(): return get_all_users() or []

@st.cache_data(ttl=20)
def _fetch_logs(): return get_auth_logs(limit=2000) or []

def page_admin():
    page = st.session_state.nav_page

    users     = _fetch_users()
    auth_logs = _fetch_logs()
    students  = [u for u in users if u.get("role") == "student"]
    ok_l      = [l for l in auth_logs if l.get("status") == "success"]
    fail_l    = [l for l in auth_logs if l.get("status") == "failed"]
    chal_l    = [l for l in auth_logs if l.get("action_taken") == "challenge"]
    block_l   = [l for l in auth_logs if l.get("action_taken") == "block"]
    scores    = [l["risk_score"] for l in auth_logs if l.get("risk_score") is not None]
    avg_risk  = np.mean(scores) if scores else 0.0

    # ── Dashboard ────────────────────────────────────────────────────────────
    if page == "Dashboard":
        st.markdown('<div class="hero"><h1>📊 Admin Dashboard</h1><p>System Overview & Security Analytics</p></div>', unsafe_allow_html=True)

        c1,c2,c3,c4,c5 = st.columns(5)
        stat_card(c1, len(users),     "Total Users",       f"🎓 {len(students)} students")
        sr = f"{len(ok_l)/(len(ok_l)+len(fail_l))*100:.0f}%" if (ok_l or fail_l) else "N/A"
        stat_card(c2, len(ok_l),      "Successful Logins", f"✅ Rate: {sr}")
        stat_card(c3, len(fail_l),    "Failed Logins",     f"🚫 {len(block_l)} blocked")
        stat_card(c4, len(chal_l),    "MFA Challenged",    "🔒 OTP required")
        _, color, _ = risk_badge(avg_risk)
        stat_card(c5, f"{avg_risk:.1f}", "Avg Risk Score", f"📊 {len(auth_logs)} total events", color=color)

        st.markdown("---")

        # ML retrain row
        ml_c1, ml_c2 = st.columns([1, 3])
        with ml_c1:
            if st.button("🧠 Retrain ML Model", use_container_width=True, type="primary"):
                _fetch_logs.clear()
                fresh_logs = get_auth_logs(limit=2000) or []
                with st.spinner(f"Training on {len(fresh_logs)} records…"):
                    ok, msg = train_ml(fresh_logs)
                (st.success if ok else st.warning)(msg)
        with ml_c2:
            rf = "✅" if risk_engine.random_forest else "❌"
            gb = "✅" if risk_engine.gradient_boosting else "❌"
            iso = "✅" if risk_engine.isolation_forest else "❌"
            st.markdown(f'<div class="ml-box">🤖 <b>ML Models:</b> Random Forest {rf} | Gradient Boosting {gb} | Isolation Forest {iso}<br>Training works with <b>any</b> number of records in the auth_logs collection.</div>', unsafe_allow_html=True)

        if not auth_logs:
            st.info("No authentication events yet. Users need to log in to generate data.")
            return

        df = pd.DataFrame(auth_logs)
        if "created_at" in df.columns:
            df["date"] = df["created_at"].apply(lambda x: x.date() if hasattr(x,"date") else None)

        ca, cb = st.columns(2)
        with ca:
            if "date" in df.columns and df["date"].notna().any():
                daily = df.groupby("date").agg(
                    logins=("status","count"),
                    success=("status", lambda x: (x=="success").sum()),
                ).reset_index()
                fig = px.area(daily, x="date", y=["logins","success"],
                              title="Daily Login Activity", labels={"value":"Count","date":"Date"},
                              color_discrete_sequence=["#667eea","#22c55e"])
                fig.update_layout(height=280, margin=dict(t=40,b=10), legend_title="")
                st.plotly_chart(fig, use_container_width=True)
        with cb:
            if scores:
                fig2 = go.Figure(go.Histogram(x=scores, nbinsx=20,
                    marker=dict(color="#764ba2", line=dict(color="#fff",width=.5)),opacity=.85))
                fig2.update_layout(title="Risk Score Distribution", xaxis_title="Score",
                                   yaxis_title="Count", height=280, margin=dict(t=40,b=10))
                st.plotly_chart(fig2, use_container_width=True)

        cc, cd = st.columns(2)
        with cc:
            if "status" in df.columns:
                sv = df["status"].value_counts().reset_index()
                sv.columns = ["Status","Count"]
                fig3 = px.pie(sv, values="Count", names="Status", title="Login Outcomes",
                              color_discrete_sequence=["#22c55e","#ef4444","#f59e0b","#667eea"])
                fig3.update_layout(height=270, margin=dict(t=40))
                st.plotly_chart(fig3, use_container_width=True)
        with cd:
            if "action_taken" in df.columns and df["action_taken"].notna().any():
                av = df["action_taken"].value_counts().reset_index()
                av.columns = ["Action","Count"]
                fig4 = px.bar(av, x="Action", y="Count", title="Actions Taken",
                              color="Action", color_discrete_sequence=["#667eea","#22c55e","#ef4444","#f59e0b"])
                fig4.update_layout(height=270, margin=dict(t=40), showlegend=False)
                st.plotly_chart(fig4, use_container_width=True)

    # ── Students ─────────────────────────────────────────────────────────────
    elif page == "Students":
        st.markdown('<div class="hero"><h1>🎓 Student Management</h1></div>', unsafe_allow_html=True)

        st.metric("Total Students", len(students))

        if students:
            df_s = pd.DataFrame(students)
            for col in ["created_at","last_login"]:
                if col in df_s.columns: df_s[col] = df_s[col].apply(format_dt)
            show = [c for c in ["username","email","full_name","matric","department","level","last_login","created_at"] if c in df_s.columns]
            st.dataframe(df_s[show], use_container_width=True,
                column_config={"username":"Username","email":"Email","full_name":"Full Name",
                               "matric":"Matric No.","department":"Dept","level":"Level",
                               "last_login":"Last Login","created_at":"Joined"})
        else:
            st.info("No students registered yet.")

        with st.expander("➕ Add Student Manually"):
            with st.form("add_student_form"):
                c1,c2 = st.columns(2)
                with c1:
                    sn = st.text_input("Full Name *")
                    su = st.text_input("Username *")
                    se = st.text_input("Email *")
                    sm = st.text_input("Matric No. *")
                with c2:
                    sd = st.text_input("Department *")
                    sl = st.selectbox("Level", ["100","200","300","400","500","Postgraduate"])
                    sp = st.text_input("Password *", type="password")
                if st.form_submit_button("Create Student", use_container_width=True, type="primary"):
                    if all([sn,su,se,sm,sp]):
                        if get_user_by_email(se) or get_user_by_username(su):
                            st.error("Email or username already exists")
                        else:
                            r = create_user({"username":su.lower(),"email":se.lower(),
                                "password":hash_password(sp),"full_name":sn,"role":"student",
                                "matric":sm,"department":sd,"level":sl,"failed_attempts":0,
                                "last_login":None,"contact":"","dob":"","gender":"","image":"",
                                "created_at":datetime.now()})
                            if r:
                                _fetch_users.clear()
                                st.success(f"✅ Student '{su}' created!"); time.sleep(1); st.rerun()
                            else: st.error("Failed to create student")
                    else: st.error("Please fill all required fields")

    # ── Auth Logs ─────────────────────────────────────────────────────────────
    elif page == "Auth Logs":
        st.markdown('<div class="hero"><h1>📋 Authentication Logs</h1></div>', unsafe_allow_html=True)

        if not auth_logs:
            st.info("No logs yet."); return

        df_l = pd.DataFrame(auth_logs)
        if "created_at" in df_l.columns: df_l["created_at"] = df_l["created_at"].apply(format_dt)

        f1,f2,f3 = st.columns(3)
        opts = lambda col: ["All"] + sorted(df_l[col].dropna().unique().tolist()) if col in df_l.columns else ["All"]
        with f1: sf = st.selectbox("Status",  opts("status"))
        with f2: rf = st.selectbox("Role",    opts("role"))
        with f3: af = st.selectbox("Action",  opts("action_taken"))
        filt = df_l.copy()
        if sf != "All" and "status" in filt.columns:       filt = filt[filt["status"]==sf]
        if rf != "All" and "role" in filt.columns:         filt = filt[filt["role"]==rf]
        if af != "All" and "action_taken" in filt.columns: filt = filt[filt["action_taken"]==af]
        show = [c for c in ["created_at","username","email","role","status","risk_score","browser","action_taken"] if c in filt.columns]
        st.dataframe(filt[show], use_container_width=True,
            column_config={"created_at":"Time","risk_score":st.column_config.NumberColumn("Risk Score",format="%.1f")})

    # ── ML Engine ─────────────────────────────────────────────────────────────
    elif page == "ML Engine":
        st.markdown('<div class="hero"><h1>🤖 ML Risk Engine</h1><p>Train & inspect the adaptive risk model</p></div>', unsafe_allow_html=True)

        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Random Forest",     "✅ Ready" if risk_engine.random_forest      else "❌ Untrained")
        c2.metric("Gradient Boosting", "✅ Ready" if risk_engine.gradient_boosting  else "❌ Untrained")
        c3.metric("Isolation Forest",  "✅ Ready" if risk_engine.isolation_forest   else "❌ Untrained")
        c4.metric("Records Available", len(auth_logs))

        st.markdown("---")
        st.markdown("""
        <div class="ml-box">
        🔔 <b>Flexible Training:</b> The ML engine will train on <b>any number</b> of records
        available in your Firebase <code>auth_logs</code> collection — even just 2 records.
        More data = better accuracy. Records: <b>{}</b>
        </div>""".format(len(auth_logs)), unsafe_allow_html=True)

        col_btn, col_info = st.columns([1,2])
        with col_btn:
            if st.button("🧠 Train / Retrain Now", use_container_width=True, type="primary"):
                _fetch_logs.clear()
                fresh = get_auth_logs(limit=2000) or []
                with st.spinner(f"Training on {len(fresh)} records…"):
                    ok, msg = train_ml(fresh)
                (st.success if ok else st.warning)(msg)
        with col_info:
            if len(auth_logs) < 10:
                st.warning("⚠️ Fewer than 10 records — model will train but accuracy will be low. More logins = better model.")
            else:
                st.success(f"✅ {len(auth_logs)} records available — good training set.")

        if auth_logs:
            df_m = pd.DataFrame(auth_logs)
            st.markdown("### Feature Distributions")
            feats = [f for f in ["hour","day_of_week","failed_attempts","risk_score","is_weekend","is_known_device"] if f in df_m.columns]
            fc = st.columns(3)
            for i, feat in enumerate(feats[:6]):
                with fc[i%3]:
                    vals = df_m[feat].dropna()
                    if set(vals.astype(str).unique()) <= {"True","False","0","1","0.0","1.0"}:
                        vc = vals.astype(int).value_counts().rename({0:"No",1:"Yes"})
                        st.bar_chart(vc); st.caption(feat.replace("_"," ").title())
                    else:
                        fig = px.histogram(df_m, x=feat, nbins=15, title=feat.replace("_"," ").title(),
                                           color_discrete_sequence=["#667eea"])
                        fig.update_layout(height=210, margin=dict(t=30,b=5,l=5,r=5), showlegend=False)
                        st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        st.markdown("### 🎯 Live Prediction Sandbox")
        with st.form("sandbox_form"):
            s1,s2,s3 = st.columns(3)
            with s1:
                s_hour  = st.slider("Hour of Day", 0, 23, 14)
                s_fails = st.number_input("Failed Attempts", 0, 10, 0)
            with s2:
                s_known   = st.checkbox("Known Device", value=True)
                s_weekend = st.checkbox("Weekend",      value=False)
                s_loc     = st.checkbox("Location Mismatch", value=False)
            with s3:
                s_browser = st.selectbox("Browser", ["Chrome","Firefox","Safari","Edge","Unknown"])
                s_os      = st.selectbox("OS", ["Windows","macOS","Linux","Android","iOS","Unknown"])
            if st.form_submit_button("▶ Predict Risk", use_container_width=True, type="primary"):
                pred = risk_engine.predict({
                    "hour":s_hour,"minute":0,"day_of_week":5 if s_weekend else 2,
                    "is_weekend":s_weekend,"is_business_hours":9<=s_hour<=17,
                    "failed_attempts":s_fails,"device_fingerprint":"sandbox",
                    "browser":s_browser,"os":s_os,"device_type":"desktop",
                    "country":"Unknown","location_mismatch":s_loc,"is_known_device":s_known,
                    "time_anomaly":False,"velocity_check":s_fails*100,
                    "cookies_enabled":True,"javascript_enabled":True
                })
                rs = pred["risk_score"]
                em, col, lbl = risk_badge(rs)
                pa,pb,pc = st.columns(3)
                pa.metric("Risk Score", f"{rs:.1f}/100")
                pb.metric("Action", pred["action"].upper())
                pc.metric("Method", pred.get("method","rule_based").replace("_"," ").title())
                st.progress(int(rs)/100)
                st.markdown(f'<p style="color:{col};font-weight:700;font-size:1.1rem">{em} {lbl} — {"Direct login allowed" if rs<30 else "OTP challenge required" if rs<70 else "Access will be blocked"}</p>', unsafe_allow_html=True)

    # ── Risk Rules ────────────────────────────────────────────────────────────
    elif page == "Risk Rules":
        st.markdown('<div class="hero"><h1>⚙️ Risk Rules</h1></div>', unsafe_allow_html=True)
        rules = get_risk_rules(active_only=False)
        if rules:
            df_r = pd.DataFrame(rules)
            show = [c for c in ["rule_name","rule_category","risk_weight","condition_field",
                                 "condition_type","condition_value","action_on_match","is_active","priority"] if c in df_r.columns]
            st.dataframe(df_r[show], use_container_width=True)
        else:
            st.info("No risk rules configured.")

# ═══════════════════════════════════════════════════════════════════════════════
# STUDENT DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
def page_student():
    user = st.session_state.user
    rs   = st.session_state.risk_score
    page = st.session_state.nav_page
    emoji, color, label = risk_badge(rs)

    try:
        ulogs = get_user_logs(user["id"], limit=200) or []
    except Exception as e:
        print(f"[student logs error] {e}")
        ulogs = []

    ok_u   = [l for l in ulogs if l.get("status") == "success"]
    fail_u = [l for l in ulogs if l.get("status") == "failed"]
    chal_u = [l for l in ulogs if l.get("action_taken") == "challenge"]
    scores_u = [l["risk_score"] for l in ulogs if l.get("risk_score") is not None]
    avg_rs = np.mean(scores_u) if scores_u else 0.0

    # ── prepare dataframe ─────────────────────────────────────────────────────
    df_u = pd.DataFrame(ulogs) if ulogs else pd.DataFrame()
    if not df_u.empty and "created_at" in df_u.columns:
        df_u["date"] = df_u["created_at"].apply(lambda x: x.date() if hasattr(x, "date") else None)
        df_u["hour"] = df_u["created_at"].apply(lambda x: x.hour if hasattr(x, "hour") else None)

    # ══════════════════════════════════════════════════════════════════════════
    if page in ("My Dashboard", "Dashboard"):
        st.markdown(f'''<div class="hero">
            <h1>🏠 Student Dashboard</h1>
            <p>Welcome back, {user.get("full_name", "Student")} &bull; {user.get("department","")}</p>
        </div>''', unsafe_allow_html=True)

        # ── stat cards ────────────────────────────────────────────────────────
        c1,c2,c3,c4,c5 = st.columns(5)
        stat_card(c1, len(ulogs),        "Total Logins",    "All time")
        stat_card(c2, len(ok_u),         "Successful",      f"✅ {round(len(ok_u)/max(len(ulogs),1)*100)}%")
        stat_card(c3, len(fail_u),       "Failed Attempts", "❌ Incorrect password")
        stat_card(c4, len(chal_u),       "MFA Challenges",  "🔒 OTP required")
        _, ac, al = risk_badge(avg_rs)
        stat_card(c5, f"{avg_rs:.1f}",   "Avg Risk Score",  al, color=ac)

        st.markdown("---")

        if df_u.empty:
            st.info("No login activity yet. Stats will appear after your first login.")
            return

        # ── row 1: risk over time + login outcomes ────────────────────────────
        ca, cb = st.columns(2)
        with ca:
            if "risk_score" in df_u.columns and df_u["risk_score"].notna().any():
                dfs = df_u.dropna(subset=["date","risk_score"]).sort_values("date")
                fig = px.line(dfs, x="date", y="risk_score",
                              title="📈 Risk Score Over Time",
                              markers=True, color_discrete_sequence=["#667eea"])
                fig.add_hrect(y0=0,  y1=30,  fillcolor="#22c55e", opacity=.07, line_width=0)
                fig.add_hrect(y0=30, y1=70,  fillcolor="#f59e0b", opacity=.07, line_width=0)
                fig.add_hrect(y0=70, y1=100, fillcolor="#ef4444", opacity=.07, line_width=0)
                fig.update_layout(height=300, margin=dict(t=40,b=10),
                                  yaxis=dict(range=[0,100]),
                                  xaxis_title="Date", yaxis_title="Risk Score")
                st.plotly_chart(fig, use_container_width=True)
        with cb:
            if "status" in df_u.columns:
                sv = df_u["status"].value_counts().reset_index()
                sv.columns = ["Status","Count"]
                fig2 = px.pie(sv, values="Count", names="Status",
                              title="🔐 Login Outcomes",
                              color_discrete_sequence=["#22c55e","#ef4444","#f59e0b","#667eea"],
                              hole=0.4)
                fig2.update_layout(height=300, margin=dict(t=40,b=10))
                st.plotly_chart(fig2, use_container_width=True)

        # ── row 2: logins by hour + day of week ───────────────────────────────
        cc, cd = st.columns(2)
        with cc:
            if "hour" in df_u.columns and df_u["hour"].notna().any():
                hc = df_u["hour"].value_counts().sort_index().reset_index()
                hc.columns = ["Hour","Logins"]
                fig3 = px.bar(hc, x="Hour", y="Logins",
                              title="⏰ Logins by Hour of Day",
                              color="Logins",
                              color_continuous_scale=["#667eea","#764ba2"])
                fig3.update_layout(height=280, margin=dict(t=40,b=10),
                                   showlegend=False, coloraxis_showscale=False)
                st.plotly_chart(fig3, use_container_width=True)
        with cd:
            if "day_of_week" in df_u.columns and df_u["day_of_week"].notna().any():
                day_map = {0:"Mon",1:"Tue",2:"Wed",3:"Thu",4:"Fri",5:"Sat",6:"Sun"}
                df_u["day_name"] = df_u["day_of_week"].map(day_map)
                dc = df_u["day_name"].value_counts().reset_index()
                dc.columns = ["Day","Count"]
                day_order = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
                dc["Day"] = pd.Categorical(dc["Day"], categories=day_order, ordered=True)
                dc = dc.sort_values("Day")
                fig4 = px.bar(dc, x="Day", y="Count",
                              title="📅 Logins by Day of Week",
                              color="Count",
                              color_continuous_scale=["#22c55e","#667eea"])
                fig4.update_layout(height=280, margin=dict(t=40,b=10),
                                   showlegend=False, coloraxis_showscale=False)
                st.plotly_chart(fig4, use_container_width=True)

        # ── row 3: risk distribution + browser ───────────────────────────────
        ce, cf = st.columns(2)
        with ce:
            if scores_u:
                fig5 = go.Figure(go.Histogram(
                    x=scores_u, nbinsx=15,
                    marker=dict(color="#764ba2", line=dict(color="#fff", width=0.5)),
                    opacity=0.85))
                fig5.update_layout(title="📊 My Risk Score Distribution",
                                   xaxis_title="Score", yaxis_title="Count",
                                   height=270, margin=dict(t=40,b=10))
                st.plotly_chart(fig5, use_container_width=True)
        with cf:
            if "browser" in df_u.columns and df_u["browser"].notna().any():
                bc = df_u["browser"].value_counts().reset_index()
                bc.columns = ["Browser","Count"]
                fig6 = px.pie(bc, values="Count", names="Browser",
                              title="🌐 Browsers Used",
                              color_discrete_sequence=["#667eea","#764ba2","#22c55e","#f59e0b"])
                fig6.update_layout(height=270, margin=dict(t=40,b=10))
                st.plotly_chart(fig6, use_container_width=True)

        # ── recent activity table ─────────────────────────────────────────────
        st.markdown("### 🕐 Recent Activity")
        recent = df_u.head(10).copy()
        if "created_at" in recent.columns:
            recent["created_at"] = recent["created_at"].apply(format_dt)
        show = [c for c in ["created_at","status","risk_score","browser","action_taken"] if c in recent.columns]
        st.dataframe(recent[show], use_container_width=True,
            column_config={"created_at":"Time","status":"Status",
                           "risk_score":st.column_config.NumberColumn("Risk Score",format="%.1f"),
                           "browser":"Browser","action_taken":"Action"})

    # ══════════════════════════════════════════════════════════════════════════
    elif page == "Login History":
        st.markdown('<div class="hero"><h1>📋 My Login History</h1></div>', unsafe_allow_html=True)
        if not df_u.empty:
            df_show = df_u.copy()
            if "created_at" in df_show.columns:
                df_show["created_at"] = df_show["created_at"].apply(format_dt)
            show = [c for c in ["created_at","status","risk_score","browser","os","action_taken"] if c in df_show.columns]
            st.dataframe(df_show[show], use_container_width=True,
                column_config={"created_at":"Time","status":"Status",
                               "risk_score":st.column_config.NumberColumn("Risk Score",format="%.1f"),
                               "browser":"Browser","os":"OS","action_taken":"Action"})

            # download button
            csv = df_show[show].to_csv(index=False)
            st.download_button("⬇️ Download History CSV", csv,
                               file_name="my_login_history.csv", mime="text/csv")
        else:
            st.info("No login history found.")

    # ══════════════════════════════════════════════════════════════════════════
    elif page == "Security":
        st.markdown('<div class="hero"><h1>🔒 Security Overview</h1></div>', unsafe_allow_html=True)

        c1,c2,c3,c4 = st.columns(4)
        stat_card(c1, len(ok_u),   "Successful Logins", "")
        stat_card(c2, len(fail_u), "Failed Attempts",   "")
        stat_card(c3, len(chal_u), "MFA Challenges",    "")
        _, ac, al = risk_badge(avg_rs)
        stat_card(c4, f"{avg_rs:.1f}", "Avg Risk Score", al, color=ac)

        st.markdown("---")

        # Risk trend with moving average
        if not df_u.empty and "risk_score" in df_u.columns and df_u["risk_score"].notna().any():
            dfs = df_u.dropna(subset=["date","risk_score"]).sort_values("date").copy()
            dfs["moving_avg"] = dfs["risk_score"].rolling(window=3, min_periods=1).mean()
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=dfs["date"], y=dfs["risk_score"],
                                     mode="markers", name="Risk Score",
                                     marker=dict(color="#667eea", size=8)))
            fig.add_trace(go.Scatter(x=dfs["date"], y=dfs["moving_avg"],
                                     mode="lines", name="3-Login Average",
                                     line=dict(color="#f59e0b", width=2, dash="dot")))
            fig.add_hrect(y0=0,  y1=30,  fillcolor="#22c55e", opacity=.06, line_width=0, annotation_text="Safe")
            fig.add_hrect(y0=30, y1=70,  fillcolor="#f59e0b", opacity=.06, line_width=0, annotation_text="Medium")
            fig.add_hrect(y0=70, y1=100, fillcolor="#ef4444", opacity=.06, line_width=0, annotation_text="High Risk")
            fig.update_layout(title="📈 Risk Score Trend with Moving Average",
                              height=320, margin=dict(t=40,b=10),
                              yaxis=dict(range=[0,100]))
            st.plotly_chart(fig, use_container_width=True)

        st.markdown("---")
        st.subheader("🔒 Security Recommendations")
        t1,t2,t3 = st.columns(3)
        t1.info("💡 **Use Known Devices**\nLog in from the same device consistently to lower your risk score.")
        t2.warning("📍 **Business Hours**\nLogins between 9am–5pm on weekdays get the lowest risk scores.")
        t3.success("🔐 **Protect Your OTP**\nYour 6-digit code expires in 5 minutes. Never share it with anyone.")

        if fail_u:
            st.markdown("---")
            st.error(f"⚠️ You have **{len(fail_u)} failed login attempt(s)** on record. "
                     "If you don't recognise these, contact the administrator immediately.")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    seed_admin()
    seed_rules()

    # ── Unauthenticated ───────────────────────
    if not st.session_state.authenticated:
        if st.session_state.show_signup:
            page_signup()
        elif st.session_state.pending_auth:
            page_otp()
        else:
            page_login()
        return

    # ── Authenticated ─────────────────────────
    sidebar_user_panel()

    if st.session_state.user["role"] == "admin":
        page_admin()
    else:
        page_student()

if __name__ == "__main__":
    main()
