from faraday.server.web import app
from faraday.server.models import User, db

def changes_password(username, password):
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = password
            db.session.add(user)
            db.session.commit()
            print "Password changed succesfully"
        else:
            print "User not found in Faraday's Database"
        

