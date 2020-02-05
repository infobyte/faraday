from faraday.server.api.base import GenericView
from faraday.server.models import User
from flask import Blueprint, request, jsonify, g

preferences_api = Blueprint('preferences_api', __name__)

# TODO: login?
class PreferencesView(GenericView):
    model_class = User
    route_base = 'preferences'

    def post(self):
        user = g.user
        preferences = request.json.get('preferences', {})
        user.preferences = preferences

        return jsonify(''), 201

    def get(self):
        return jsonify({'preferences': g.user.preferences}), 200

PreferencesView.register(preferences_api)
