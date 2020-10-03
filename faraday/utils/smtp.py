import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from faraday.server.config import smtp

logger = logging.getLogger(__name__)


class MailNotification:
    def __init__(self, smtp_host: str, smtp_sender: str,
                 smtp_username: str = None, smtp_password: str = None,
                 smtp_port: int = 0, smtp_ssl: bool = False):
        self.smtp_username = smtp_username or smtp.username
        self.smtp_sender = smtp_sender or smtp.sender
        self.smtp_password = smtp_password or smtp.password
        self.smtp_host = smtp_host or smtp.host
        self.smtp_port = smtp_port or smtp.port
        if smtp.keyfile is not None and smtp.certfile is not None:
            self.smtp_ssl = True
            self.smtp_keyfile = smtp.keyfile
            self.smtp_certfile = smtp.certfile
        else:
            self.smtp_ssl = smtp_ssl or smtp.ssl
            self.smtp_keyfile = None
            self.smtp_certfile = None

    def send_mail(self, to_addr: str, subject: str, body: str):
        msg = MIMEMultipart()
        msg['From'] = self.smtp_sender
        msg['To'] = to_addr
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))
        SMTP = smtplib.SMTP
        try:
            with SMTP(host=self.smtp_host, port=self.smtp_port) as server_mail:
                if self.smtp_ssl:
                    server_mail.starttls(keyfile=smtp.keyfile,
                                         certfile=smtp.certfile)
                if self.smtp_username and self.smtp_password:
                    server_mail.login(self.smtp_username, self.smtp_password)
                text = msg.as_string()
                server_mail.sendmail(msg['From'], msg['To'], text)
        except (smtplib.SMTPException, ssl.SSLError) as error:
            logger.error("Error: unable to send email")
            logger.exception(error)
