#-*- coding: utf8 -*-

"""Tests for many API endpoints that do not depend on workspace_name"""

import pytest
from test_cases import factories
from test_api_non_workspaced_base import ReadWriteAPITests
from server.models import License

class TestLicensesAPI(ReadWriteAPITests):
    model = License
    factory = factories.LicenseFactory
    api_endpoint = 'licenses'
    unique_fields = ['ip']
    update_fields = ['ip', 'description', 'os']


