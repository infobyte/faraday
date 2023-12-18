"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Related third party imports
from flask_security.utils import hash_password
from flask import current_app

# Local application imports
from faraday.server.models import User, db


def changes_password(username, password):
    with current_app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = hash_password(password)
            db.session.add(user)
            db.session.commit()
            print("Password changed successfully")
        else:
            print("User not found in Faraday's Database")
