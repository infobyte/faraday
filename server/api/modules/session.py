from flask import jsonify, session
from server.web import app


@app.route('/session')
def session_info():
    user = app.user_datastore.get_user(session['user_id'])
    return jsonify(user.get_security_payload())
