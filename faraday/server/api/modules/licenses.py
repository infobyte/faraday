# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from flask import Blueprint
from marshmallow import fields

from faraday.server.models import License
from faraday.server.api.base import (
    ReadWriteView,
    AutoSchema
)
from faraday.server.schemas import (
    StrictDateTimeField,
    NullToBlankString
)

license_api = Blueprint('license_api', __name__)


class LicenseSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    end = StrictDateTimeField(load_as_tz_aware=False, attribute='end_date')
    start = StrictDateTimeField(load_as_tz_aware=False, attribute='start_date')
    lictype = NullToBlankString(attribute='type')

    class Meta:
        model = License
        fields = ('_id', 'id', 'product',
                  'start', 'end', 'lictype',
                  'notes')


class LicenseView(ReadWriteView):
    route_base = 'licenses'
    model_class = License
    schema_class = LicenseSchema


LicenseView.register(license_api)
