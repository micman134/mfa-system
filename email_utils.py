# email_utils.py - Shows OTP in UI as fallback when email fails
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
        val = st.secrets.get(key)
        if val: return val
    except Exception:
        pass
    return os.getenv(key, default)


def send_otp_email(to_email, to_name, otp_code, role='user', risk_score=None):
    """Send OTP email. Shows OTP in UI as fallback if email fails."""
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    smtp_server    = _secret('EMAIL_HOST', 'smtp.gmail.com')
    smtp_port      = int(_secret('EMAIL_PORT', '587'))
    sender_email   = _secret('EMAIL_USER', '')
    sender_password= _secret('EMAIL_PASSWORD', '')
    
    # Try to send email if credentials exist
    email_sent = False
    if sender_email and sender_password:
        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><style>
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
           font-size: 2.4rem; font-weight: 800; letter-spacing: 12px;
           color: #1a1a2e; margin: 20px 0; }}
  .risk {{ background: #fef3c7; border-left: 4px solid #f59e0b;
           padding: 10px 16px; border-radius: 0 8px 8px 0;
           font-size: .85rem; margin-top: 16px; }}
  .warn {{ background: #fff8e1; border-left: 4px solid #ffc107;
           padding: 12px 16px; border-radius: 0 8px 8px 0;
           font-size: .88rem; color: #555; margin-top: 16px; }}
  .foot {{ text-align: center; padding: 16px; color: #aaa;
           font-size: .78rem; background: #fafafa; }}
</style></head>
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
        ⚠️ <strong>Security Notice:</strong> Never share this code with anyone.
        EduAuth staff will never ask for your OTP.
      </div>
    </div>
    <div class="foot">EduAuth MFA System • This is an automated message</div>
  </div>
</body>
</html>"""
        
        msg = MIMEMultipart('alternative')
        msg['From']    = f"EduAuth MFA <{sender_email}>"
        msg['To']      = to_email
        msg['Subject'] = f"[EduAuth] Your verification code: {otp_code}"
        msg.attach(MIMEText(html, 'html'))
        
        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(sender_email, sender_password)
                server.send_message(msg)
            logger.info(f"✅ OTP email sent to {to_email}")
            email_sent = True
        except Exception as e:
            logger.warning(f"Email failed: {e}")
            email_sent = False
    else:
        logger.warning("Email credentials not configured")
    
    # Always print to console
    print(f"\n{'='*55}")
    print(f"  🔐 OTP VERIFICATION CODE")
    print(f"  To:   {to_name} <{to_email}>")
    print(f"  Role: {role.upper()}")
    print(f"  Code: {otp_code}")
    if risk_score:
        print(f"  Risk: {risk_score:.1f}/100")
    print(f"  Valid for 5 minutes")
    print(f"{'='*55}\n")
    
    # Show OTP in UI as fallback if email failed
    if not email_sent:
        _show_otp_in_ui(to_name, to_email, otp_code, risk_score)
    
    return email_sent


def _show_otp_in_ui(name, email, code, risk_score=None):
    """Display OTP directly in Streamlit UI as fallback."""
    try:
        import streamlit as st
        
        risk_html = f'<span class="risk-high" style="background:#dc354520; padding:2px 8px; border-radius:12px;">Risk: {risk_score:.0f}</span>' if risk_score else ''
        
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                    border-radius: 16px; 
                    padding: 1.5rem; 
                    margin: 1rem 0;
                    border: 2px solid #667eea;
                    text-align: center;">
            <div style="font-size: 0.9rem; color: #a0aec0; margin-bottom: 0.5rem;">
                📧 Email delivery pending — use this code instead
            </div>
            <div style="font-size: 2.5rem; 
                        font-weight: 800; 
                        letter-spacing: 8px;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        margin: 0.5rem 0;">
                {code}
            </div>
            <div style="font-size: 0.85rem; color: #718096;">
                Valid for <strong>5 minutes</strong> • {risk_html}
            </div>
        </div>
        """, unsafe_allow_html=True)
    except Exception as e:
        print(f"UI fallback error: {e}")


def _print_otp(name, email, code):
    """Legacy function - kept for compatibility."""
    print(f"\n{'='*55}")
    print(f"  OTP FALLBACK (email not sent)")
    print(f"  To:   {name} <{email}>")
    print(f"  Code: {code}")
    print(f"{'='*55}\n")
