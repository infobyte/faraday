from faraday.server.api.base import GenericView
from faraday.server.models import User, db
from flask import Blueprint, request, jsonify, g, abort
from marshmallow import Schema, fields

preferences_api = Blueprint('preferences_api', __name__)


class PreferenceSchema(Schema):
    preferences = fields.Dict()


class PreferencesView(GenericView):
    model_class = User
    route_base = 'preferences'
    schema_class = PreferenceSchema

    def post(self):
        """
        ---
        set:
          tags: ["User"]
          description: Set the user preferences
          responses:
            200:
              description: Ok
        """
        user = g.user

        if request.json and 'preferences' not in request.json:
            abort(400)

        preferences = request.json.get('preferences', {})
        user.preferences = preferences

        db.session.commit()

        return jsonify(''), 200

    def get(self):
        """
        ---
        get:
          tags: ["User"]
          description: Show the user preferences
          responses:
            200:
              description: Ok
        """
        return jsonify({'preferences': g.user.preferences}), 200


class PreferencesV3View(PreferencesView):
    route_prefix = '/v3'
    trailing_slash = False


PreferencesView.register(preferences_api)
PreferencesV3View.register(preferences_api)
