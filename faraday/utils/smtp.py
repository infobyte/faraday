"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Local application imports
from faraday.settings.smtp import SMTPSettings

logger = logging.getLogger(__name__)


class MailNotification:
    def __init__(self, smtp_host: str, smtp_sender: str,
                 smtp_username: str = None, smtp_password: str = None,
                 smtp_port: int = 0, smtp_ssl: bool = False):
        self.smtp_username = smtp_username or SMTPSettings.settings.username
        self.smtp_sender = smtp_sender or SMTPSettings.settings.sender
        self.smtp_password = smtp_password or SMTPSettings.settings.password
        self.smtp_host = smtp_host or SMTPSettings.settings.host
        self.smtp_port = smtp_port or SMTPSettings.settings.port
        self.smtp_ssl = smtp_ssl or SMTPSettings.settings.ssl

    def send_mail(self, to_addr: str, subject: str, body: str):
        msg = MIMEMultipart()
        msg['From'] = self.smtp_sender
        msg['To'] = to_addr
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))
        smtp = smtplib.SMTP
        try:
            with smtp(host=self.smtp_host, port=self.smtp_port) as server_mail:
                if self.smtp_ssl:
                    server_mail.starttls()
                if self.smtp_username and self.smtp_password:
                    server_mail.login(self.smtp_username, self.smtp_password)
                text = msg.as_string()
                server_mail.sendmail(msg['From'], msg['To'], text)
        except (smtplib.SMTPException, ssl.SSLError) as error:
            logger.error("Error: unable to send email")
            logger.exception(error)
