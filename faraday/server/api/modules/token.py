from itsdangerous import TimedJSONWebSignatureSerializer
from flask import Blueprint, g

from faraday.server.config import faraday_server
from faraday.server.api.base import GenericView

token_api = Blueprint('token_api', __name__)


class TokenAuthView(GenericView):
    route_base = 'token'

    def get(self):
        from faraday.server.web import app
        user_id = g.user.id
        serializer = TimedJSONWebSignatureSerializer(app.config['SECRET_KEY'], salt="token", expires_in=faraday_server.api_token_expiration)
        return serializer.dumps({'user_id': user_id})


TokenAuthView.register(token_api)