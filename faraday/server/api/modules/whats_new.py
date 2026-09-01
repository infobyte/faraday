"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import Blueprint, send_file
from marshmallow import Schema

# Local application imports
from faraday.server.api.base import GenericView
from faraday.server.config import WHATS_NEW_FILE

whats_new_api = Blueprint('whats_new_api', __name__)


class EmptySchema(Schema):
    pass


class WhatsNewView(GenericView):
    route_base = 'whats_new'
    schema_class = EmptySchema

    def get(self):
        """
        ---
        get:
          tags: ["Informational"]
          summary: "Get the What's New changelog."
          responses:
            200:
              description: Ok
        """
        return send_file(WHATS_NEW_FILE)


WhatsNewView.register(whats_new_api)
