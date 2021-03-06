from flask_mail import Message
from flask import current_app as app
from flask import render_template
from . import mail

def send_email(to, subject, template, **kwargs):
    msg = Message(app.config['BAZAAR_MAIL_SUBJECT_PREFIX'] + subject,
            sender=app.config['BAZAAR_MAIL_SENDER'], recipients=[to])
    msg.body = render_template(template + '.txt', **kwargs)
    #msg.html = render_template(template + '.html', **kwargs)
    mail.send(msg)
