import smtplib
from email.message import EmailMessage

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

FROM_EMAIL = "pbibhuti628@gmail.com"
TO_EMAIL = "bibhutipokharel112@gmail.com"

APP_PASSWORD = "hdcdspivesxictxs"


def send_alert(subject: str, body: str):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(FROM_EMAIL, APP_PASSWORD)
        s.send_message(msg)

