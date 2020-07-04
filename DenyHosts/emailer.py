import logging
import logging.handlers
import time

import smtplib
from smtplib import SMTP, SMTP_SSL
from smtplib import SMTPResponseException
from smtplib import SMTPHeloError
from email.mime.text import MIMEText
from subprocess import Popen, PIPE
from textwrap import dedent

from .util import is_true

debug = logging.getLogger("util").debug
error = logging.getLogger("util").error
exception = logging.getLogger("util").exception
info = logging.getLogger("util").info
warning = logging.getLogger("util").warning


class Email(object):

    def __init__(self, prefs):
        self.prefs = prefs
        self.smtp_from = prefs.get('SMTP_FROM')
        self.smtp_host = prefs.get('SMTP_HOST')
        self.smtp_port = prefs.get('SMTP_PORT')
        self.admin_email = prefs.get('ADMIN_EMAIL')
        self.smtp_subject = prefs.get('SMTP_SUBJECT')
        self.smtp_date = time.strftime(
            prefs.get('SMTP_DATE_FORMAT')
        )
        self.recipients = prefs['ADMIN_EMAIL'].split(',')
        self.method = prefs.get('EMAIL_METHOD')
        self.use_smtp_ssl = prefs.get('SMTP_SSL')
        self.username = prefs.get('SMTP_USERNAME')
        self.password = prefs.get('SMTP_PASSWORD')

    def smtp_setup(self):
        try:
            if is_true(self.use_smtp_ssl):
                self.smtp = SMTP_SSL()
            else:
                self.smtp = SMTP()
        except Exception as e:
            exception('Error Setting up smtp: {}'.format(e))

    def smtp_connect(self):
        try:
            # this applies a fix for a python 3.7 bug
            self.smtp(host=self.smtp_host, port=self.smtp_port)
            # https://github.com/ansible/ansible/pull/44552
            self.smtp.connect(
                self.smtp_host,
                self.smtp_port
            )
        except Exception as e:
            exception('Error connecting to the SMTP Host: {}'.format(e))

    def send_email(self, report_str):
        try:
            if self.method == 'SMTP':
                self.__send_with_smtp(report_str)
            elif self.method == 'SENDMAIL':
                self.__send_with_sendmail(report_str)
            elif self.method == 'MAIL':
                self.__send_with_system_mail(report_str)
            elif self.method == 'MAILX':
                self.__send_with_system_mailx(report_str)
            elif self.method == 'STDOUT':
                print(report_str)
            else:
                exc_msg = 'Unknown e-mail method: {}'.format(self.method)
                exception(exc_msg)
                raise Exception(exc_msg)
        except Exception as e:
            exception('Error sending email'.format(e))
            exception('Email message follows: {}'.format(report_str))

    def __create_smtp_message(self, report_str):
        msg_headers = dedent("""
        From: {}
        To: {}
        Subject: {}
        Date: {}

        """).lstrip().format(self.smtp_from, self.admin_email, self.smtp_subject, self.smtp_date)
        return '{}{}'.format(msg_headers, report_str)

    def __send_with_smtp(self, report_str):
        msg = self.__create_smtp_message(report_str)

        self.smtp_setup()
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            self.smtp.set_debuglevel(1)

        self.smtp_connect()

        try:
            """
            If the server supports ESMTP and TLS
            Then convert the message exchange to TLS via the STARTTLS command.
            """
            if self.smtp.ehlo()[0] == 250:
                if self.smtp.has_extn('starttls'):
                    (code, resp) = self.smtp.starttls()
                    if code != 220:
                        raise SMTPResponseException(code, resp)
                    (code, resp) = self.smtp.ehlo()
                    if code != 250:
                        raise SMTPResponseException(code, resp)
                else:  # The server does not support esmtp.
                    """"
                    The Python library SMTP class handles executing HELO/EHLO commands inside
                    login/sendmail methods when neither helo()/ehlo() methods have been
                    previously called.  Because we have already called ehlo() above, we must
                    manually fallback to calling helo() here.
                    """

                    (code, resp) = self.smtp.helo()
                    if not (200 <= code <= 299):
                        raise SMTPHeloError(code, resp)

                if self.username and self.password:
                    self.smtp.login(self.username, self.password)

                self.smtp.sendmail(self.smtp_from, self.recipients, msg)
                debug("sent email to: {}".format(self.admin_email))
        except Exception as e:
            exception('Error sending email using smtp: {}'.format(e))

        try:
            self.smtp.quit()
        except Exception:
            pass

    def __send_with_sendmail(self, report_str):
        try:
            msg = MIMEText(report_str)
            msg["From"] = self.smtp_from
            msg["To"] = self.admin_email
            msg["Subject"] = self.smtp_subject
            p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE)
            p.communicate(msg.as_string())
            debug("sent email to: {}".format(self.admin_email))
        except Exception as e:
            exception('Error sending email using sendmail: {}'.format(e))

    def __send_with_system_mail(self, report_str):
        try:
            p = Popen(['mail', '-s', self.smtp_subject] + self.recipients, stdin=PIPE)
            p.communicate(report_str)
            debug("sent email to: {}".format(self.admin_email))
        except Exception as e:
            exception('Error sending email using mail: {}'.format(e))

    def __send_with_system_mailx(self, report_str):
        try:
            p = Popen(['mailx', '-s', self.smtp_subject] + self.recipients, stdin=PIPE)
            p.communicate(report_str)
            debug("sent email to: {}".format(self.admin_email))
        except Exception as e:
            exception('Error sending email using mailx: {}'.format(e))
