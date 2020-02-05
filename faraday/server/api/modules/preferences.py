from faraday.server.api.base import GenericView
from faraday.server.models import User
from flask import Blueprint, request, session, abort, jsonify

preferences_api = Blueprint('preferences_api', __name__)

# TODO: login?
class PreferencesView(GenericView):
    model_class = User
    route_base = 'preferences'

    def post(self):
        # TODO: validate user id
        user = User.query.get(session['user_id'])
        if not user:
            abort(404)
        preferences = request.json.get('preferences', {})
        user.preferences = preferences
        return jsonify(''), 201

        session.add(user)
        session.commit()

    def get(self):
        user = User.query.get(session['user_id'])
        if not user:
            abort(404)
        return jsonify({'preferences': user.preferences}), 200

PreferencesView.register(preferences_api)
