# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import flask
from flask import Blueprint, request
from faraday_agent_parameters_types.utils import type_validate

param_type_validate = Blueprint('param_type_validate', __name__)


@param_type_validate.route('/v2/validate_param', methods=['POST'])
def validate():
    """
    ---
    post:
      tags: ["Agent"]
      description: Validates an executor parameter
      responses:
        200:
          description: Ok
        400:
          description: Bad Request
    """
    if flask.request.content_type != 'application/json':
        flask.abort(400, "Only application/json is a valid content-type")
    valid = True
    data = request.json
    if "type" not in data or "data" not in data:
        flask.abort(400, 'type and data needed in json format')
    errors = type_validate(data["type"], data["data"])
    if errors:
        valid = False
    return flask.jsonify({"valid": valid, "errors": errors})


@param_type_validate.route('/v3/validate_param', methods=['POST'])
def validate_v3():
    return validate()


validate_v3.__doc__ = validate.__doc__

validate.is_public = True
validate_v3.is_public = True
