# firebase_config.py — firebase-admin only (no pyrebase4, works on Python 3.14)

import firebase_admin
from firebase_admin import credentials, firestore, storage
import os
import json
from datetime import datetime

# Load .env for local development
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ── Secret resolver: st.secrets (Streamlit Cloud) → os.environ (local) ───────
def _secret(key, default=""):
    try:
        import streamlit as st
        val = st.secrets.get(key)
        if val: return val
    except Exception:
        pass
    return os.getenv(key, default)

# ── Globals ───────────────────────────────────────────────────────────────────
_db     = None
_bucket = None


def initialize_firebase():
    global _db, _bucket
    try:
        if not firebase_admin._apps:
            # Priority 1: JSON string from Streamlit secrets or env var
            sa_json = _secret("FIREBASE_SERVICE_ACCOUNT")
            if sa_json:
                try:
                    cred = credentials.Certificate(json.loads(sa_json))
                    print("✅ Firebase credentials loaded from secrets")
                except Exception as e:
                    print(f"❌ Failed to parse FIREBASE_SERVICE_ACCOUNT: {e}")
                    return
            else:
                # Priority 2: local JSON file (dev only)
                sa_file = "mfasystem-61756-firebase-adminsdk-fbsvc-1a5d8b4456.json"
                if os.path.exists(sa_file):
                    cred = credentials.Certificate(sa_file)
                    print("✅ Firebase credentials loaded from local file")
                else:
                    print("❌ No Firebase credentials found!")
                    return

            firebase_admin.initialize_app(cred, {
                "storageBucket": "mfasystem-61756.firebasestorage.app"
            })
            print("✅ Firebase Admin SDK initialized")
        else:
            print("✅ Firebase already initialized")

        _db     = firestore.client()
        _bucket = storage.bucket()
        print("✅ Firestore + Storage ready")

    except Exception as e:
        print(f"FIREBASE ERROR: {e}")


def get_firestore():
    if _db is None:
        initialize_firebase()
    return _db

def get_storage():
    if _bucket is None:
        initialize_firebase()
    return _bucket


# ── Collection helpers ────────────────────────────────────────────────────────
def get_users_collection():       return get_firestore().collection('users')
def get_auth_logs_collection():   return get_firestore().collection('auth_logs')
def get_otp_codes_collection():   return get_firestore().collection('otp_codes')
def get_risk_rules_collection():  return get_firestore().collection('risk_rules')
def get_action_logs_collection(): return get_firestore().collection('action_logs')
def get_sessions_collection():    return get_firestore().collection('sessions')


# ── Users ─────────────────────────────────────────────────────────────────────
def get_user_by_email(email):
    if not email: return None
    try:
        r = list(get_users_collection().where('email', '==', email.lower()).limit(1).get())
        if r:
            d = r[0].to_dict(); d['id'] = r[0].id; return d
    except Exception as e: print(f"get_user_by_email: {e}")
    return None

def get_user_by_username(username):
    if not username: return None
    try:
        r = list(get_users_collection().where('username', '==', username.lower()).limit(1).get())
        if r:
            d = r[0].to_dict(); d['id'] = r[0].id; return d
    except Exception as e: print(f"get_user_by_username: {e}")
    return None

def get_user_by_id(user_id):
    if not user_id: return None
    try:
        doc = get_users_collection().document(user_id).get()
        if doc.exists:
            d = doc.to_dict(); d['id'] = doc.id; return d
    except Exception as e: print(f"get_user_by_id: {e}")
    return None

def create_user(user_data):
    try:
        ref = get_users_collection().document()
        user_data.pop('id', None)
        user_data.setdefault('created_at', datetime.now())
        ref.set(user_data)
        user_data['id'] = ref.id
        return user_data
    except Exception as e: print(f"create_user: {e}"); return None

def update_user(user_id, data):
    try:
        get_users_collection().document(user_id).update(data); return True
    except Exception as e: print(f"update_user: {e}"); return False

def delete_user(user_id):
    try:
        get_users_collection().document(user_id).delete(); return True
    except Exception as e: print(f"delete_user: {e}"); return False

def get_all_users():
    try:
        return [{**d.to_dict(), 'id': d.id} for d in get_users_collection().get()]
    except Exception as e: print(f"get_all_users: {e}"); return []


# ── Auth Logs ─────────────────────────────────────────────────────────────────
def log_auth_attempt(data):
    try:
        ref = get_auth_logs_collection().document()
        data.setdefault('created_at', datetime.now())
        ref.set(data); return ref.id
    except Exception as e: print(f"log_auth_attempt: {e}"); return None

def get_auth_logs(filters=None, limit=100):
    try:
        q = get_auth_logs_collection() \
            .order_by('created_at', direction=firestore.Query.DESCENDING) \
            .limit(limit)
        if filters:
            for k, v in filters.items():
                q = q.where(k, '==', v)
        return [{**d.to_dict(), 'id': d.id} for d in q.get()]
    except Exception as e: print(f"get_auth_logs: {e}"); return []


# ── OTP ───────────────────────────────────────────────────────────────────────
def save_otp(data):
    try:
        ref = get_otp_codes_collection().document()
        data.setdefault('created_at', datetime.now())
        ref.set(data); return ref.id
    except Exception as e: print(f"save_otp: {e}"); return None

def get_valid_otp(user_id, otp_code):
    try:
        r = list(get_otp_codes_collection()
                 .where('user_id', '==', user_id)
                 .where('otp_code', '==', otp_code)
                 .where('is_used', '==', False)
                 .limit(1).get())
        if r:
            d = r[0].to_dict(); d['id'] = r[0].id; return d
    except Exception as e: print(f"get_valid_otp: {e}")
    return None


# ── Risk Rules ────────────────────────────────────────────────────────────────
def get_risk_rules(active_only=True):
    try:
        q = get_risk_rules_collection()
        if active_only: q = q.where('is_active', '==', True)
        q = q.order_by('priority', direction=firestore.Query.DESCENDING)
        return [{**d.to_dict(), 'id': d.id} for d in q.get()]
    except Exception as e: print(f"get_risk_rules: {e}"); return []


# ── Action Logs ───────────────────────────────────────────────────────────────
def log_action(data):
    try:
        ref = get_action_logs_collection().document()
        data.setdefault('created_at', datetime.now())
        ref.set(data); return ref.id
    except Exception as e: print(f"log_action: {e}"); return None

def get_recent_action_logs(limit=50):
    try:
        return [{**d.to_dict(), 'id': d.id} for d in
                get_action_logs_collection()
                .order_by('created_at', direction=firestore.Query.DESCENDING)
                .limit(limit).get()]
    except Exception as e: print(f"get_recent_action_logs: {e}"); return []


# ── Sessions ──────────────────────────────────────────────────────────────────
def save_session(data):
    try:
        ref = get_sessions_collection().document(data['session_id'])
        data.setdefault('created_at', datetime.now())
        ref.set(data); return ref.id
    except Exception as e: print(f"save_session: {e}"); return None

def get_session(session_id):
    try:
        doc = get_sessions_collection().document(session_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e: print(f"get_session: {e}"); return None

def delete_session(session_id):
    try:
        get_sessions_collection().document(session_id).delete(); return True
    except Exception as e: print(f"delete_session: {e}"); return False
