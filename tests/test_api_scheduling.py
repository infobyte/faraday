"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import datetime
from unittest import mock

import pytest
from sqlalchemy import text

from faraday.server.api.modules.agents_schedule import AgentsScheduleView
from faraday.server.models import AgentsSchedule
from tests.test_api_non_workspaced_base import ReadWriteAPITests
from tests.factories import (
    AgentScheduleFactory,
    AgentFactory,
    WorkspaceFactory,
    ExecutorFactory,
    AgentExecutionFactory
)
from posixpath import join

ORDER = [
        [{'field': 'description', 'direction': 'desc'}],
        [{'field': 'create_date', 'direction': 'desc'}],
        [{'field': 'type', 'direction': 'desc'}],
        [
            {'field': 'description', 'direction': 'desc'},
            {'field': 'create_date', 'direction': 'desc'},
            {'field': 'type', 'direction': 'desc'}
        ],
    ]

GROUP = [
        [{'field': 'description'}],
        [{'field': 'type'}],
        [
            {'field': 'description'},
            {'field': 'type'}
        ],
    ]


def test_both_schedule_and_manual_agents(session):
    workspace = WorkspaceFactory.create()
    agent = AgentFactory.create()
    executor = ExecutorFactory.create(agent=agent)
    schedule = AgentScheduleFactory.create(crontab='*/5 * * * *', workspaces=[workspace], executor=executor)

    agents = (agent, schedule)
    agents_execution = [AgentExecutionFactory.create(executor=executor, workspace=workspace) for _ in agents]

    keys = ['executor', 'workspace', 'parameters_data']
    for key in keys:
        assert getattr(agents_execution[0], key) == getattr(agents_execution[1], key)
    assert getattr(agents_execution[0], 'command') != getattr(agents_execution[1], 'command')


SCHEDULES_LIMIT = 999


@mock.patch('faraday.server.api.modules.scheduler.SCHEDULES_LIMIT', SCHEDULES_LIMIT)
class TestAgentScheduleView(ReadWriteAPITests):
    model = AgentsSchedule
    factory = AgentScheduleFactory
    api_endpoint = 'agents_schedule'
    view_class = AgentsScheduleView
    patchable_fields = ["description"]

    @pytest.mark.parametrize("method", ["PUT", "PATCH"])
    def test_update_an_object(self, test_client, user, session, method):
        super().test_update_an_object(test_client, user, method)

    def test_retrieve_one_object(self, test_client, user, session):
        super().test_retrieve_one_object(test_client, user)

    def test_delete_scheduling_when_deleting_agent(self, test_client, session, user):
        workspaces = [WorkspaceFactory.create()]
        agent = AgentFactory.create()
        session.add(agent)

        executor = ExecutorFactory.create(agent=agent)
        session.add(executor)

        agent_schedule = AgentScheduleFactory.create(crontab='*/5 * * * *',
                                                    workspaces=workspaces,
                                                    executor=executor)
        session.add(agent_schedule)

        session.commit()

        delete_agent_res = test_client.delete(f'/v3/agents/{agent.id}')

        assert delete_agent_res.status_code == 204

        find_agent_schedule_res = test_client.get(self.url(agent_schedule))

        assert find_agent_schedule_res.status_code == 404

    def test_create_valid_cron(self, test_client, session, user):
        workspaces = [WorkspaceFactory.create()]
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        session.commit()
        agent_schedule = AgentScheduleFactory.build_dict(workspace=workspaces,
                                                         executor=executor)
        agent_schedule['crontab'] = '*/5 * * * *'
        res = test_client.post(self.url(), data=agent_schedule)
        assert res.status_code == 201

    def test_create_invalid_cron(self, test_client, session, user):
        workspaces = [WorkspaceFactory.create()]
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        session.commit()
        agent_schedule = AgentScheduleFactory.build_dict(workspace=workspaces,
                                                         executor=executor)
        agent_schedule['crontab'] = 'daily'
        res = test_client.post(self.url(), data=agent_schedule)
        assert res.status_code == 400

    def test_create_valid_complex_cron(self, test_client, session, user):
        workspaces = [WorkspaceFactory.create()]
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        session.commit()
        agent_schedule = AgentScheduleFactory.build_dict(workspace=workspaces,
                                                         executor=executor)
        agent_schedule['crontab'] = '30-42/2,20-30 18-20/92 11-21/39 2-12/8 3-4/1,4'
        res = test_client.post(self.url(), data=agent_schedule)
        assert res.status_code == 201

    @pytest.mark.parametrize("bad_cron", [
        '*/0 * * * *',   # step zero
        '60 * * * *',    # minute out of range
        '* 24 * * *',    # hour out of range
        '* * 0 * *',     # day-of-month out of range
        '* * * 13 *',    # month out of range
    ])
    def test_create_out_of_range_cron_rejected(self, test_client, session, user, bad_cron):
        workspaces = [WorkspaceFactory.create()]
        agent = AgentFactory.create()
        executor = ExecutorFactory.create(agent=agent)
        session.commit()
        agent_schedule = AgentScheduleFactory.build_dict(workspace=workspaces,
                                                         executor=executor)
        agent_schedule['crontab'] = bad_cron
        res = test_client.post(self.url(), data=agent_schedule)
        assert res.status_code == 400

    def test_next_run_is_none_for_unparseable_crontab(self, session):
        # A row that bypassed validation (legacy/import/direct DB) must not raise on serialization
        schedule = AgentScheduleFactory.create(crontab='*/0 * * * *',
                                               workspaces=[WorkspaceFactory.create()],
                                               executor=ExecutorFactory.create())
        session.commit()
        assert schedule.next_run is None

    def test_refresh_schedule_skips_invalid_crontab(self, app, session):
        # An active bad-cron row must not crash the scheduler thread / app boot
        from faraday.server.threads.crontab import CronTab
        schedule = AgentScheduleFactory.create(crontab='*/0 * * * *', active=True,
                                               workspaces=[WorkspaceFactory.create()],
                                               executor=ExecutorFactory.create())
        session.commit()
        crontab_thread = CronTab(app=app)
        assert schedule.id not in crontab_thread.jobs

    def test_create_until_limit(self, test_client, session):
        with mock.patch('faraday.server.api.modules.scheduler.SCHEDULES_LIMIT', 7):
            for i in range(2):
                workspaces = [WorkspaceFactory.create()]
                agent = AgentFactory.create()
                executor = ExecutorFactory.create(agent=agent)
                session.commit()
                agent_schedule = AgentScheduleFactory.build_dict(workspace=workspaces,
                                                                 executor=executor)
                res = test_client.post(self.url(), data=agent_schedule)
                assert res.status_code == 201
            # Agent schedules 7 - limit 7
            workspaces = [WorkspaceFactory.create()]
            agent = AgentFactory.create()
            executor = ExecutorFactory.create(agent=agent)
            session.commit()
            agent_schedule = AgentScheduleFactory.build_dict(workspace=workspaces,
                                                             executor=executor)
            res = test_client.post(self.url(), data=agent_schedule)
            assert res.status_code == 403

    def test_patch_update_an_object_does_not_fail_with_partial_data(self, test_client, logged_user):
        super().test_patch_update_an_object_does_not_fail_with_partial_data(test_client, logged_user)

    @pytest.mark.parametrize('filter_params', [
        {
            'test_name': 'filter_by_description',
            'filter_field_name': 'description',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"Agent scheduler description"',
                    'res_status_code': 200,
                    'count': 1
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_vuln_tag',
            'filter_field_name': 'vuln_tag',
            'filter_operations': [
                {
                    'filter_operation': 'like',
                    'filter_value': '"%vuln_tag_1%"',
                    'res_status_code': 200,
                    'count': 1
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_description_nonexistent',
            'filter_field_name': 'description',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"Nonexistent description"',
                    'res_status_code': 200,
                    'count': 0
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        },
        {
            'test_name': 'filter_by_vuln_tag_nonexistent',
            'filter_field_name': 'vuln_tag',
            'filter_operations': [
                {
                    'filter_operation': 'eq',
                    'filter_value': '"vuln_tag_3"',
                    'res_status_code': 200,
                    'count': 0
                }
            ],
            'order_operations': ORDER,
            'group_operations': GROUP,
        }
    ])
    def test_filter_agent_scheduler(self, test_client, session, filter_params):

        # Create agent scheduler entries
        scheduler1 = AgentScheduleFactory.create(
            description="Agent scheduler description",
            vuln_tag="vuln_tag_1",
            type="agent",
            create_date="2024-01-01T00:00:00"
        )
        scheduler2 = AgentScheduleFactory.create(
            description="Another agent scheduler description",
            vuln_tag="vuln_tag_2",
            type="agent",
            create_date="2023-12-31T23:59:59"
        )
        session.add_all([scheduler1, scheduler2])
        session.commit()

        for operation in filter_params['filter_operations']:
            qparams = f'filter?q={{"filters":[' \
                      f'{{"name": "{filter_params["filter_field_name"]}", ' \
                      f'"op":"{operation["filter_operation"]}",' \
                      f'"val": {operation["filter_value"]} }}]}}'
            res = test_client.get(join(self.url(), qparams))

            assert res.status_code == operation['res_status_code']
            assert len(res.json['rows']) == operation['count']

    def test_count_agent_schedulers(self, test_client, session):
        # Cleanup - Delete all schedules from the AgentsSchedule table
        session.execute(text('DELETE FROM agents_schedule_workspace_table'))
        session.query(AgentsSchedule).delete()
        session.commit()

        workspaces = [WorkspaceFactory.create()]

        # Create and add two AgentSchedulers
        agent1 = AgentFactory.create()
        session.add(agent1)

        executor1 = ExecutorFactory.create(agent=agent1)
        session.add(executor1)

        agent_schedule1 = AgentScheduleFactory.create(
            crontab='*/5 * * * *',
            workspaces=workspaces,
            executor=executor1,
            type='agent',
            description='agent scheduler 1'
        )
        session.add(agent_schedule1)

        agent2 = AgentFactory.create()
        session.add(agent2)

        executor2 = ExecutorFactory.create(agent=agent2)
        session.add(executor2)

        agent_schedule2 = AgentScheduleFactory.create(
            crontab='*/5 * * * *',
            workspaces=workspaces,
            executor=executor2,
            type='agent',
            description='agent scheduler 2'
        )
        session.add(agent_schedule2)
        session.commit()

        response = test_client.get("/v3/agents_schedule/count_schedulers")

        # Assert that the status code is 200
        assert response.status_code == 200

        # Extract the count from the response
        counts = response.json

        # Assert that only agent schedulers are counted
        assert counts['agent_schedulers'] == 2


@pytest.mark.usefixtures('logged_user')
class TestGenericSchedulerView:

    def test_delete_removes_the_schedule(self, test_client, session):
        schedule = AgentScheduleFactory.create(workspaces=[WorkspaceFactory.create()])
        session.commit()
        schedule_id = schedule.id

        res = test_client.delete(f'/v3/scheduler/{schedule_id}')

        assert res.status_code == 204
        assert session.get(AgentsSchedule, schedule_id) is None

    def test_list_includes_agent_schedules(self, test_client, session):
        schedule = AgentScheduleFactory.create(workspaces=[WorkspaceFactory.create()])
        session.commit()

        res = test_client.get('/v3/scheduler')

        assert res.status_code == 200
        assert schedule.id in {row['id'] for row in res.json['rows']}


BUENOS_AIRES_OFFSET = datetime.timezone(datetime.timedelta(hours=-3))


def _iso_in(days=0, minutes=0):
    """ISO 8601 datetime relative to now, with the offset of the schedules' timezone."""
    moment = datetime.datetime.now(BUENOS_AIRES_OFFSET) + datetime.timedelta(days=days, minutes=minutes)
    return moment.replace(microsecond=0).isoformat()


@pytest.fixture
def schedule_payload():
    def _payload(**overrides):
        payload = AgentScheduleFactory.build_dict(workspace=[WorkspaceFactory.create()],
                                                  executor=ExecutorFactory.create())
        payload['timezone'] = 'America/Argentina/Buenos_Aires'
        payload.update(overrides)
        return payload
    return _payload


@pytest.mark.usefixtures('logged_user')
@mock.patch('faraday.server.api.modules.scheduler.SCHEDULES_LIMIT', SCHEDULES_LIMIT)
class TestScheduleTypes:
    url = '/v3/agents_schedule'

    def test_cron_is_the_default(self, test_client, schedule_payload):
        res = test_client.post(self.url, data=schedule_payload())

        assert res.status_code == 201
        assert res.json['schedule_type'] == 'cron'

    def test_cron_requires_crontab(self, test_client, schedule_payload):
        payload = schedule_payload()
        del payload['crontab']

        res = test_client.post(self.url, data=payload)

        assert res.status_code == 400
        assert 'crontab' in res.json['messages']['json']

    def test_crontab_accepts_nth_weekday_of_month(self, test_client, schedule_payload):
        res = test_client.post(self.url, data=schedule_payload(crontab='0 4 * * 3#2'))

        assert res.status_code == 201

    def test_start_date_is_stored_as_utc_and_dumped_in_the_schedule_timezone(self, test_client, session,
                                                                             schedule_payload):
        res = test_client.post(self.url, data=schedule_payload(start_date='2030-10-14T07:00:00Z'))

        assert res.status_code == 201
        assert res.json['start_date'] == '2030-10-14T04:00:00-03:00'
        stored = session.get(AgentsSchedule, res.json['id'])
        assert stored.start_date == datetime.datetime(2030, 10, 14, 7, 0)

    def test_next_run_is_not_before_start_date(self, test_client, schedule_payload):
        res = test_client.post(self.url, data=schedule_payload(crontab='0 4 * * *',
                                                               start_date='2030-10-14T04:00:00-03:00'))

        assert res.json['next_run'] == '2030-10-14 04:00:00-03:00'

    def test_date_without_offset_is_rejected(self, test_client, schedule_payload):
        res = test_client.post(self.url, data=schedule_payload(start_date='2030-10-14T04:00:00'))

        assert res.status_code == 400
        assert 'start_date' in res.json['messages']['json']

    def test_once_requires_run_at(self, test_client, schedule_payload):
        res = test_client.post(self.url, data=schedule_payload(schedule_type='once', crontab=None))

        assert res.status_code == 400
        assert 'run_at' in res.json['messages']['json']

    def test_once_in_the_past_is_rejected(self, test_client, schedule_payload):
        res = test_client.post(self.url, data=schedule_payload(schedule_type='once', crontab=None,
                                                               run_at=_iso_in(minutes=-5)))

        assert res.status_code == 400
        assert 'run_at' in res.json['messages']['json']

    def test_create_once(self, test_client, schedule_payload):
        run_at = _iso_in(days=1)

        res = test_client.post(self.url, data=schedule_payload(schedule_type='once', crontab='', run_at=run_at))

        assert res.status_code == 201
        assert res.json['run_at'] == run_at
        assert res.json['crontab'] is None
        assert res.json['next_run'] is not None

    def test_switching_to_once_clears_cron_fields(self, test_client, session):
        schedule = AgentScheduleFactory.create(start_date=datetime.datetime(2030, 1, 1),
                                               workspaces=[WorkspaceFactory.create()])
        session.commit()

        res = test_client.patch(f'{self.url}/{schedule.id}',
                                data={'schedule_type': 'once', 'run_at': _iso_in(days=1)})

        assert res.status_code == 200
        assert res.json['crontab'] is None
        assert res.json['start_date'] is None

    def test_once_that_already_ran_can_still_be_edited(self, test_client, session):
        schedule = AgentScheduleFactory.create(schedule_type='once', crontab=None, active=False,
                                               run_at=datetime.datetime(2020, 1, 1),
                                               workspaces=[WorkspaceFactory.create()])
        session.commit()

        res = test_client.patch(f'{self.url}/{schedule.id}', data={'description': 'renamed'})

        assert res.status_code == 200
        assert res.json['next_run'] is None

    def test_reactivating_a_past_once_is_rejected(self, test_client, session):
        schedule = AgentScheduleFactory.create(schedule_type='once', crontab=None, active=False,
                                               run_at=datetime.datetime(2020, 1, 1),
                                               workspaces=[WorkspaceFactory.create()])
        session.commit()

        res = test_client.patch(f'{self.url}/{schedule.id}', data={'active': True})

        assert res.status_code == 400
        assert 'run_at' in res.json['messages']['json']


def test_next_run_of_once_with_unknown_timezone_does_not_raise(session):
    schedule = AgentScheduleFactory.create(schedule_type='once', crontab=None, timezone='Not/AZone',
                                           run_at=datetime.datetime(2030, 1, 1),
                                           workspaces=[WorkspaceFactory.create()])
    session.commit()

    assert schedule.next_run is not None
