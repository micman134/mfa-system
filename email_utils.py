# email_utils.py - Fixed for Streamlit Cloud
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging
from datetime import datetime

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

logger = logging.getLogger(__name__)

def _secret(key, default=""):
    """Read from st.secrets (Streamlit Cloud) or os.environ (local)."""
    try:
        import streamlit as st
        # Check if secrets exist
        if hasattr(st, 'secrets') and key in st.secrets:
            val = st.secrets[key]
            if val:
                return val
    except Exception:
        pass
    return os.getenv(key, default)


def send_otp_email(to_email, to_name, otp_code, role='user', risk_score=None):
    """Send OTP email. Falls back to console if credentials are missing."""
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Get email configuration
    smtp_server = _secret('EMAIL_HOST', 'smtp.gmail.com')
    smtp_port = int(_secret('EMAIL_PORT', '587'))
    sender_email = _secret('EMAIL_USER', '')
    sender_password = _secret('EMAIL_PASSWORD', '')
    
    # Debug logging
    print(f"[Email Config] Host: {smtp_server}, Port: {smtp_port}, User: {sender_email}")
    print(f"[Email Config] Password set: {'Yes' if sender_password else 'No'}")
    
    # If no credentials, just log to console
    if not sender_email or not sender_password:
        logger.warning("Email credentials not configured — OTP printed to console only.")
        _print_otp(to_name, to_email, otp_code)
        return True
    
    # HTML template
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8">
<style>
  body {{ font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }}
  .wrap {{ max-width: 560px; margin: 30px auto; background: #fff;
           border-radius: 12px; overflow: hidden;
           box-shadow: 0 4px 20px rgba(0,0,0,.1); }}
  .hdr  {{ background: linear-gradient(135deg,#667eea,#764ba2);
           color: #fff; padding: 28px; text-align: center; }}
  .hdr h2 {{ margin: 0; font-size: 1.4rem; }}
  .hdr p  {{ margin: 6px 0 0; opacity: .85; font-size: .9rem; }}
  .body {{ padding: 28px; }}
  .otp  {{ background: #f0f4ff; border: 2px dashed #667eea;
           border-radius: 10px; padding: 20px; text-align: center;
           font-size: 2rem; font-weight: 800; letter-spacing: 8px;
           color: #1a1a2e; margin: 20px 0; }}
  .risk {{ background: #f0fdf4; border-left: 4px solid #22c55e;
           padding: 10px 16px; border-radius: 0 8px 8px 0;
           font-size: .85rem; margin: 16px 0; }}
  .warn {{ background: #fff8e1; border-left: 4px solid #ffc107;
           padding: 10px 16px; border-radius: 0 8px 8px 0;
           font-size: .85rem; color: #555; margin-top: 16px; }}
  .foot {{ text-align: center; padding: 16px; color: #aaa;
           font-size: .75rem; background: #fafafa; }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="hdr">
      <h2>🔐 EduAuth MFA Verification</h2>
      <p>{role.upper()} Login • {timestamp}</p>
    </div>
    <div class="body">
      <p>Hello <strong>{to_name}</strong>,</p>
      <p>Your one-time verification code is:</p>
      <div class="otp">{otp_code}</div>
      <p>This code expires in <strong>5 minutes</strong>.</p>
      {f'<div class="risk">⚠️ Risk Score: {risk_score:.1f}/100 — Additional verification required.</div>' if risk_score and risk_score > 30 else ''}
      <div class="warn">
        🔒 <strong>Security Notice:</strong> Never share this code with anyone.<br>
        EduAuth staff will never ask for your OTP.
      </div>
    </div>
    <div class="foot">EduAuth MFA System • This is an automated message</div>
  </div>
</body>
</html>"""
    
    msg = MIMEMultipart('alternative')
    msg['From'] = f"EduAuth MFA <{sender_email}>"
    msg['To'] = to_email
    msg['Subject'] = f"[EduAuth] Your verification code: {otp_code}"
    msg.attach(MIMEText(html, 'html'))
    
    try:
        # Try to send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        logger.info(f"✅ OTP email sent to {to_email}")
        print(f"✅ Email sent successfully to {to_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"❌ SMTP Authentication failed: {e}")
        print(f"❌ Email authentication failed. Please check EMAIL_PASSWORD.")
        print("   For Gmail, use an App Password: https://myaccount.google.com/apppasswords")
        _print_otp(to_name, to_email, otp_code)
        return False
        
    except smtplib.SMTPException as e:
        logger.error(f"❌ SMTP error: {e}")
        print(f"❌ SMTP error: {e}")
        _print_otp(to_name, to_email, otp_code)
        return False
        
    except Exception as e:
        logger.error(f"❌ Failed to send email: {e}")
        print(f"❌ Email error: {e}")
        _print_otp(to_name, to_email, otp_code)
        return False


def _print_otp(name, email, code):
    """Always print OTP to console as fallback."""
    print(f"\n{'='*55}")
    print(f"  🔐 OTP VERIFICATION CODE")
    print(f"  To:   {name} <{email}>")
    print(f"  Code: {code}")
    print(f"  Valid for 5 minutes")
    print(f"{'='*55}\n")
