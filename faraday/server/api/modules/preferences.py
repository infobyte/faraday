from faraday.server.api.base import GenericView
from faraday.server.models import User, db
from flask import Blueprint, request, jsonify, g, abort

preferences_api = Blueprint('preferences_api', __name__)


class PreferencesView(GenericView):
    model_class = User
    route_base = 'preferences'

    def post(self):
        user = g.user

        if request.json and 'preferences' not in request.json:
            abort(400)

        preferences = request.json.get('preferences', {})
        user.preferences = preferences

        db.session.commit()

        return jsonify(''), 200

    def get(self):
        return jsonify({'preferences': g.user.preferences}), 200

PreferencesView.register(preferences_api)
