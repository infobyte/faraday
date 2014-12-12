#!/usr/bin/python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import unittest
import sys
sys.path.append('.')
import model.controller
import managers.mapper_manager
from mockito import mock
from persistence.mappers.abstract_mapper import NullPersistenceManager
from model.hosts import Host
from model.diff import ModelObjectDiff

import test_cases.common as test_utils


class DiffTests(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_diff_between_equal_hosts(self):
        """
        This test case creates a host and the compares it
        with another equal host using the ModelObjectDiff class
        """
        h1 = Host(name='host1', os='Windows')
        h2 = Host(name='host1', os='Windows')

        diff = ModelObjectDiff(h1, h2)

        self.assertFalse(diff.existDiff())

    def test_diff_between_different_hosts(self):
        """
        This test case creates a host and the compares it
        with another different host using the ModelObjectDiff class
        """
        h1 = Host(name='host1', os='Windows')
        h2 = Host(name='host1', os='Linux')

        diff = ModelObjectDiff(h1, h2)

        self.assertTrue(diff.existDiff())


class UpdatesTests(unittest.TestCase):

    def setUp(self):
        self._mappers_manager = managers.mapper_manager.MapperManager()
        self._persistence_manager = NullPersistenceManager()
        self._mappers_manager.createMappers(self._persistence_manager)
        self.model_controller = model.controller.ModelController(
            mock(), self._mappers_manager)

    def tearDown(self):
        pass

    def test_add_host_and_generate_solvable_update(self):
        """
        This test case creates a host within the Model Controller context
        and then creates another with the same key elements, but different
        non-key attributes with default value to generate an automatic
        solvable update
        """
        # When
        hostname = 'host'
        host1a = test_utils.create_host(self, host_name=hostname, os='windows')

        host = self._mappers_manager.find(host1a.getID())
        self.assertEquals(
            host.getOS(),
            'windows',
            'Host\'s OS should be windows')

        # Then, we generate an update
        host1b = test_utils.create_host(self, host_name=hostname, os='unknown')

        self.assertEquals(
            host1a.getID(),
            host1b.getID(),
            'Both hosts should have the same id')

        self.assertEquals(
            len(self.model_controller.getConflicts()),
            0,
            'Update was generated')

        host = self._mappers_manager.find(host1a.getID())

        self.assertEquals(
            host.getOS(),
            'windows',
            'Host\'s OS should still be windows')

    def test_add_host_and_generate_solvable_update_with_edition(self):
        """
        This test case creates a host with a default value in a non-key
        attrribute within the Model Controller context and then creates
        another with the same key elements, but different non-key
        attributes to generate an automatic solvable update
        """
        # When
        hostname = 'host'
        host1a = test_utils.create_host(self, host_name=hostname, os='unknown')

        host = self._mappers_manager.find(host1a.getID())

        self.assertEquals(
            host.getOS(),
            'unknown',
            'Host\'s OS should be unknown')

        # Then, we generate an update
        host1b = test_utils.create_host(self, host_name=hostname, os='windows')

        self.assertEquals(
            host1a.getID(),
            host1b.getID(),
            'Both hosts should have the same id')

        self.assertEquals(
            len(self.model_controller.getConflicts()),
            0,
            'Update was generated')

        host = self._mappers_manager.find(host1a.getID())

        self.assertEquals(
            host.getOS(),
            'windows',
            'Host\'s OS should now be windows')

    def test_add_host_and_generate_unsolvable_update(self):
        """
        This test case creates a host within the Model Controller
        context and then creates another with the same key elements,
        but different non-key attributes to generate an update to
        be resolved by the user
        """
        # When
        hostname = 'host'
        host1a = test_utils.create_host(self, host_name=hostname, os='windows')

        host = self._mappers_manager.find(host1a.getID())

        self.assertEquals(
            host.getOS(),
            'windows',
            'Host\'s OS should be windows')

        # Then, we generate an update
        host1b = test_utils.create_host(self, host_name=hostname, os='linux')

        self.assertEquals(
            host1a.getID(),
            host1b.getID(),
            'Both hosts should have the same id')

        self.assertEquals(
            len(self.model_controller.getConflicts()),
            1,
            'Update was not generated')

        host = self._mappers_manager.find(host1a.getID())

        self.assertEquals(
            host.getOS(),
            'windows',
            'Host\'s OS should still be windows')

        self.assertEquals(
            len(host.getUpdates()),
            1,
            'The host should have a pending update')


if __name__ == '__main__':
    unittest.main()
