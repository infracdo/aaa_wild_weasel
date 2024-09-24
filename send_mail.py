import smtplib

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.header import Header

def send_mail(recipient, message, subject="This is the email subject", sender="pipolkonek@apolloglobal.net"):
#def send_mail(recipient, message, subject="Password Reset", sender="pipolkonek@apolloglobal.net"):
    smtp = smtplib.SMTP()
    smtp.connect('mail.apolloglobal.net')

    msgRoot = MIMEMultipart("alternative")
    msgRoot['Subject'] = Header(subject, "utf-8")
    msgRoot['From'] = sender
    msgRoot['To'] = recipient
    text = MIMEText(message, "html", "utf-8")
    msgRoot.attach(text)
    # html = MIMEText(open('template.html', 'r').read(), "html", "utf-8")
    # msgRoot.attach(html)
    smtp.sendmail(sender, recipient, msgRoot.as_string())
