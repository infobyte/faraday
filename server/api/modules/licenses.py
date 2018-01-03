# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint
from marshmallow import fields

from server.models import License
from server.api.base import ReadWriteView, AutoSchema

license_api = Blueprint('license_api', __name__)


class LicenseSchema(AutoSchema):

    class Meta:
        model = License
        fields = ('id', 'product', 'start_date', 'end_date')


class LicenseView(ReadWriteView):
    route_base = 'licenses'
    model_class = License
    schema_class = LicenseSchema
    unique_fields = []

LicenseView.register(license_api)
