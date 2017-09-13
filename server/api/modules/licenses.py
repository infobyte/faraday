# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from marshmallow import Schema, fields

from server.models import License
from server.api.base import ReadWriteView

license_api = Blueprint('license_api', __name__)


class LicenseSchema(Schema):
    id = fields.Integer(required=True, dump_only=True)
    product = fields.String()
    start_date = fields.DateTime()
    end_date = fields.DateTime()


class LicenseView(ReadWriteView):
    route_base = 'licenses'
    model_class = License
    schema_class = LicenseSchema
    unique_fields = []

LicenseView.register(license_api)
