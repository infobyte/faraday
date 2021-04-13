from faraday.server.web import get_app
from faraday.server.models import User, db
from flask_security.utils import hash_password


def changes_password(username, password):
    with get_app().app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = hash_password(password)
            db.session.add(user)
            db.session.commit()
            print("Password changed succesfully")
        else:
            print("User not found in Faraday's Database")
