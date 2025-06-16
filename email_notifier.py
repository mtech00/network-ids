import smtplib
from email.message import EmailMessage
import datetime
from config import SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, FROM_EMAIL, TO_EMAIL

class EmailNotifier:
    def __init__(self):
        self.smtp_server = SMTP_SERVER
        self.smtp_port = SMTP_PORT
        self.username = SMTP_USERNAME
        self.password = SMTP_PASSWORD
        self.from_email = FROM_EMAIL
        self.to_email = TO_EMAIL
    def send_alert_email(self, alert):
        try:
            msg = EmailMessage()
            
            subject = f"IDS ALERT - {alert['severity']} - {alert['attack_type']}"
            
            content = f"""
NETWORK INTRUSION DETECTION SYSTEM ALERT

Timestamp: {alert['timestamp']}
Severity: {alert['severity']}
Attack Type: {alert['attack_type']}
Confidence: {alert['confidence']:.3f}

Source: {alert['src']}
Destination: {alert['dst']}
Protocol: {alert['protocol']}

Flow Key: {alert['flow_key']}

Source IP: {alert['src_ip']}
Destination IP: {alert['dst_ip']}
Source Port: {alert['src_port']}
Destination Port: {alert['dst_port']}

This is an automated alert from the Network IDS system.
Please investigate immediately if this is a Critical or High severity alert.
"""
            
            msg.set_content(content)
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = self.to_email
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
                


            print(f" Alert email sent: {alert['severity']} - {alert['attack_type']}")
            return True
            
        except Exception as e:
            print(f" Email sending failed: {e}")
            return False
    
    def send_test_email(self):
        try:
            msg = EmailMessage()
            msg.set_content("IDS Email notification system is working correctly. This is a test message.")
            msg["Subject"] = "IDS System - Test Email"
            msg["From"] = self.from_email
            msg["To"] = self.to_email
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
                
            print("Test email sent successfully")
            return True
            
        except Exception as e:
            print(f"Test email failed: {e}")
            return False

if __name__ == "__main__":

    notifier = EmailNotifier()
    notifier.send_test_email()