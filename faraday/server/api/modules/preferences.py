from faraday.server.api.base import GenericView
from faraday.server.models import User, db
from flask import Blueprint, request, jsonify, abort
from marshmallow import Schema, fields
import flask_login

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
        user = flask_login.current_user

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
        return jsonify({'preferences': flask_login.current_user.preferences}), 200


PreferencesView.register(preferences_api)
