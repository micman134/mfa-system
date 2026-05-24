import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
import logging
from datetime import datetime

load_dotenv()

logger = logging.getLogger(__name__)

def send_otp_email(to_email, to_name, otp_code, role='user', risk_score=None):
    """Send OTP verification email"""
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Email configuration
    smtp_server = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
    smtp_port = int(os.getenv('EMAIL_PORT', 587))
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASSWORD')
    
    if not sender_email or not sender_password:
        logger.warning("Email credentials not configured. Printing OTP to console.")
        print(f"\n{'='*50}")
        print(f"OTP for {to_name} ({to_email}): {otp_code}")
        print(f"{'='*50}\n")
        return True
    
    # HTML Email Template
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>MFA Verification Code</title>
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 20px; text-align: center; }}
            .otp-box {{ background: #f4f4f4; padding: 20px; font-size: 32px; font-weight: bold; text-align: center; letter-spacing: 10px; }}
            .warning {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🔐 Multi-Factor Authentication</h2>
                <p>{role.upper()} Access</p>
            </div>
            <div style="padding: 20px;">
                <p>Hello <strong>{to_name}</strong>,</p>
                <p>Use the following verification code to complete your login:</p>
                <div class="otp-box">{otp_code}</div>
                <p><strong>This code expires in 5 minutes.</strong></p>
                <div class="warning">
                    <strong>⚠️ Security Alert:</strong><br>
                    Never share this code with anyone. Our staff will never ask for this code.
                </div>
                <hr>
                <p><small>Requested at: {timestamp}</small></p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Create message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = f"MFA Verification Code - {role.upper()} Login"
    
    msg.attach(MIMEText(html_template, 'html'))
    
    try:
        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        
        logger.info(f"OTP email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        print(f"\n{'='*50}")
        print(f"OTP for {to_name} ({to_email}): {otp_code}")
        print(f"{'='*50}\n")
        return False