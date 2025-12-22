import os
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

MY_APP_KEY = os.getenv("MY_APP_KEY")
MY_EMAIL = os.getenv("MY_EMAIL")

SUPPORT_TO = MY_EMAIL

def send_email(name: str, email: str, subject: str, message: str) -> bool:
    body = (
        f"Você recebeu uma nova solicitação:\n\n"
        f"Contato: {name} <{email}>\n\n"
        f"Assunto: {subject}\n\n"
        f"Mensagem:\n{message}\n"
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"[Sinu Support] {subject}"
    msg["From"] = formataddr(("Sinu", MY_EMAIL))
    msg["To"] = SUPPORT_TO
    msg["Reply-To"] = formataddr((name, email))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=200) as server:
            server.starttls()
            server.login(MY_EMAIL, MY_APP_KEY)
            server.sendmail(MY_EMAIL, [SUPPORT_TO], msg.as_string())
            return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False