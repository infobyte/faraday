from flask import jsonify, session
from server.app import app, user_datastore

@app.route('/session')
def session_info():
    user = user_datastore.get_user(session['user_id'])
    return jsonify(user.get_security_payload())
