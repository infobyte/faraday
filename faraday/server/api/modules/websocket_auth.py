# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from flask import Blueprint
from flask import current_app as app
from itsdangerous import TimestampSigner
from faraday.server.api.base import GenericWorkspacedView

websocket_auth_api = Blueprint('websocket_auth_api', __name__)


class WebsocketAuthView(GenericWorkspacedView):
    route_base = 'websocket_token'

    def post(self, workspace_name):
        workspace = self._get_workspace(workspace_name)
        signer = TimestampSigner(app.config['SECRET_KEY'], salt="websocket")
        token = signer.sign(str(workspace.id))
        return {"token": token}


WebsocketAuthView.register(websocket_auth_api)
