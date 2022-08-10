from pathlib import Path

from flask import Blueprint, send_file
from marshmallow import Schema

from faraday.server.api.base import GenericView
from faraday.server.config import LOCAL_OPENAPI_FILE

swagger_api = Blueprint('swagger_api', __name__)


class EmptySchema(Schema):
    pass


class SwaggerView(GenericView):
    route_base = 'swagger'
    schema_class = EmptySchema

    def get(self):
        """
        ---
          get:
            summary: "Get the swagger documentation."
            tags: ["Swagger"]
            responses:
              200:
                description: Ok
        """
        if LOCAL_OPENAPI_FILE.exists():
            return send_file(LOCAL_OPENAPI_FILE)
        default_swagger_path = Path(__file__).parent.parent.parent.parent / 'openapi' / 'faraday_swagger.json'
        return send_file(default_swagger_path)


SwaggerView.register(swagger_api)
