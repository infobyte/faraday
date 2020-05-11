from itsdangerous import TimedJSONWebSignatureSerializer
from flask import Blueprint, g
from flask_security.utils import hash_data
from flask import current_app as app


from faraday.server.config import faraday_server
from faraday.server.api.base import GenericView

token_api = Blueprint('token_api', __name__)


class TokenAuthView(GenericView):
    route_base = 'token'

    def get(self):
        user_id = g.user.id
        serializer = TimedJSONWebSignatureSerializer(
            app.config['SECRET_KEY'],
            salt="api_token",
            expires_in=faraday_server.api_token_expiration
        )
        hashed_data = hash_data(g.user.password) if g.user.password else None
        return serializer.dumps({'user_id': user_id, "validation_check": hashed_data}).decode('utf-8')


TokenAuthView.register(token_api)

# I'm Py3
