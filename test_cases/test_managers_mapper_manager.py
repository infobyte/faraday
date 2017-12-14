from functools import partial
from managers.mapper_manager import MapperManager
from persistence.server.models import Host, Service
import persistence.server.server
from test_cases.factories import WorkspaceFactory, CommandFactory, HostFactory, \
    ServiceFactory

# OBJ_DATA is like a fixture.
# We use it to test all model classes.
# to add more tests you need to add items in the list or more objects in the dict.

OBJ_DATA = {
    Host: [{
        'factory': HostFactory,
        'api_end_point': 'hosts',
        'parent': {},
        'data': {
            '_id': 1,
            'name': '192.168.0.20',
            'description': 'My computer',
            'default_gateway': '192.168.0.1',
            'os': 'Debian',
            'owned': False,
            'owner': 'leo'
        },
        'expected_payload': {
                'command_id': None,
                'default_gateway': '192.168.0.1',
                'description': 'My computer',
                'ip': '192.168.0.20',
                'os': 'Debian',
                'owned': False,
                'owner': 'leo',
                'parent': None,
                'type': 'Host'
        },
    }],
    Service: [{
        'factory': ServiceFactory,
        'api_end_point': 'services',
        'parent': {
            'parent_type': 'Service',
            'parent_factory': HostFactory
        },
        'data': {
            '_id': 1,
            'name': 'Service port 60',
            'description': 'My service',
            'owned': False,
            'owner': 'leo',
            'protocol': 'tcp',
            'ports': [60],
            'version': '2',
            'status': 'open',
            'vulns': 0,
        },
        'expected_payload': {
            'command_id': None,
            'name': 'Service port 60',
            'description': 'My service',
            'protocol': 'tcp',
            'ports': [60],
            'version': '2',
            'status': 'open',
            'owned': False,
            'owner': 'leo',
            'type': 'Service'
        },
    }]
}

class TestMapperManager():

    def test_save_without_command(self, monkeypatch, session):
        workspace = WorkspaceFactory.create(name='test')
        session.commit()
        mapper_manager = MapperManager()
        mapper_manager.createMappers(workspace.name)
        for obj_class, many_test_data in OBJ_DATA.items():
            for test_data in many_test_data:
                raw_data = test_data['data']
                if test_data['parent']:
                    parent = test_data['parent']['parent_factory'].create()
                    session.commit()
                    test_data['data']['parent'] = parent.id
                    test_data['data']['parent_type'] = test_data['parent']['parent_type']
                    test_data['expected_payload']['parent'] = parent.id
                def mock_server_post(test_data, post_url, update=False, expected_response=201, **params):
                    assert post_url == 'http://localhost:5985/_api/v2/ws/test/{0}/'.format(test_data['api_end_point'])
                    assert expected_response == 201
                    assert update == False
                    metadata = params.pop('metadata')
                    assert metadata['owner'] == test_data['expected_payload']['owner']
                    assert params == test_data['expected_payload']
                    return {
                        'id': 1,
                        'ok': True,
                        'rev': ''
                    }

                monkeypatch.setattr(persistence.server.server, '_post', partial(mock_server_post, test_data))
                obj = obj_class(raw_data, workspace.name)
                mapper_manager.save(obj)

    def test_save_with_command(self, monkeypatch, session):
        workspace = WorkspaceFactory.create(name='test')
        command = CommandFactory.create(workspace=workspace)
        session.commit()
        mapper_manager = MapperManager()
        mapper_manager.createMappers(workspace.name)
        for obj_class, many_test_data in OBJ_DATA.items():
            for test_data in many_test_data:
                raw_data = test_data['data']
                if test_data['parent']:
                    parent = test_data['parent']['parent_factory'].create()
                    session.commit()
                    test_data['data']['parent'] = parent.id
                    test_data['data']['parent_type'] = test_data['parent']['parent_type']
                    test_data['expected_payload']['parent'] = parent.id
                def mock_server_post(test_data, post_url, update=False, expected_response=201, **params):
                    assert post_url == 'http://localhost:5985/_api/v2/ws/test/{0}/?command_id={1}'.format(test_data['api_end_point'], params['command_id'])
                    assert expected_response == 201
                    assert update == False
                    metadata = params.pop('metadata')
                    assert metadata['owner'] == test_data['expected_payload']['owner']
                    params.pop('command_id')
                    test_data['expected_payload'].pop('command_id')
                    assert params == test_data['expected_payload']
                    return {
                        'id': 1,
                        'ok': True,
                        'rev': ''
                    }

                monkeypatch.setattr(persistence.server.server, '_post', partial(mock_server_post, test_data))
                obj = obj_class(raw_data, workspace.name)
                mapper_manager.save(obj, command.id)

    def test_update_without_command(self, monkeypatch, session):
        workspace = WorkspaceFactory.create(name='test')
        mapper_manager = MapperManager()
        mapper_manager.createMappers(workspace.name)
        for obj_class, many_test_data in OBJ_DATA.items():
            for test_data in many_test_data:
                relational_model = test_data['factory'].create()
                session.commit()
                raw_data = test_data['data']
                if test_data['parent']:
                    parent = test_data['parent']['parent_factory'].create()
                    session.commit()
                    test_data['data']['parent'] = parent.id
                    test_data['data']['parent_type'] = test_data['parent']['parent_type']
                    test_data['expected_payload']['parent'] = parent.id
                def mock_server_put(test_data, put_url, update=False, expected_response=201, **params):
                    assert put_url == 'http://localhost:5985/_api/v2/ws/test/{0}/{1}/'.format(test_data['api_end_point'], test_data['id'])
                    assert expected_response == 200
                    assert update == False
                    metadata = params.pop('metadata')
                    assert metadata['owner'] == test_data['expected_payload']['owner']
                    params.pop('command_id')
                    test_data['expected_payload'].pop('command_id', None)
                    assert params == test_data['expected_payload']

                    return {
                        'id': 1,
                        'ok': True,
                        'rev': ''
                    }

                raw_data['id'] = relational_model.id
                test_data['id'] = relational_model.id
                monkeypatch.setattr(persistence.server.server, '_put', partial(mock_server_put, test_data))

                obj = obj_class(raw_data, workspace.name)
                mapper_manager.update(obj)

    def test_update_with_command(self, monkeypatch, session):
        session.commit()
        workspace = WorkspaceFactory.create(name='test')
        command = CommandFactory.create(workspace=workspace)
        session.commit()
        mapper_manager = MapperManager()
        mapper_manager.createMappers(workspace.name)
        for obj_class, many_test_data in OBJ_DATA.items():
            for test_data in many_test_data:
                raw_data = test_data['data']
                if test_data['parent']:
                    parent = test_data['parent']['parent_factory'].create()
                    session.commit()
                    test_data['data']['parent'] = parent.id
                    test_data['data']['parent_type'] = test_data['parent']['parent_type']
                    test_data['expected_payload']['parent'] = parent.id
                relational_model = test_data['factory'].create()
                session.commit()
                def mock_server_put(put_url, update=False, expected_response=201, **params):
                    assert put_url == 'http://localhost:5985/_api/v2/ws/test/{0}/{1}/?command_id={2}'.format(test_data['api_end_point'], test_data['id'], params['command_id'])
                    assert expected_response == 200
                    assert update == False

                    return {
                        'id': 1,
                        'ok': True,
                        'rev': ''
                    }

                raw_data['id'] = relational_model.id
                test_data['id'] = relational_model.id
                monkeypatch.setattr(persistence.server.server, '_put', mock_server_put)
                obj = obj_class(raw_data, workspace.name)
                mapper_manager.update(obj, command.id)