"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import datetime
from types import SimpleNamespace
from unittest import mock

import dateutil.tz
import pytest

from faraday.server.models import AgentsSchedule
from faraday.server.threads.crontab import CronItem, FaradayCronTab
from faraday.server.utils.schedules import ONCE_GRACE_PERIOD
from tests.factories import AgentScheduleFactory, WorkspaceFactory

# Unusual offset (+05:45) so it never matches the timezone of the machine running the tests
SCHEDULE_TIMEZONE = 'Asia/Kathmandu'


@pytest.fixture
def schedule_tz():
    return dateutil.tz.gettz(SCHEDULE_TIMEZONE)


def make_schedule(**overrides):
    values = {
        'id': 1,
        'active': True,
        'crontab': '0 4 * * *',
        'timezone': SCHEDULE_TIMEZONE,
        'schedule_type': 'cron',
        'start_date': None,
        'run_at': None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(second=0, microsecond=0)


def next_tick():
    # Every-minute crons are anchored at the current minute, so they fire on the next tick
    return utc_now() + datetime.timedelta(minutes=1)


def naive_utc(value):
    return value.astimezone(datetime.timezone.utc).replace(tzinfo=None)


def next_fire(cron_item):
    return cron_item.schedule(cron_item.last_run).get_next(datetime.datetime)


class TestCronItemTimezone:

    def test_fires_at_the_crontab_hour_in_the_schedule_timezone(self, schedule_tz):
        cron_item = CronItem(make_schedule())

        fire = next_fire(cron_item).astimezone(schedule_tz)

        assert (fire.hour, fire.minute) == (4, 0)

    def test_anchor_is_in_the_schedule_timezone(self, schedule_tz):
        cron_item = CronItem(make_schedule())

        now = datetime.datetime.now(tz=schedule_tz)
        assert cron_item.last_run.utcoffset() == now.utcoffset()

    def test_unknown_timezone_falls_back_to_server_timezone(self):
        cron_item = CronItem(make_schedule(timezone='Not/AZone'))

        assert cron_item.timezone == dateutil.tz.tzlocal()

    def test_invalid_crontab_marks_the_item_as_invalid(self):
        cron_item = CronItem(make_schedule(crontab='99 * * * *'))

        assert cron_item.valid is False


class TestCronStartDate:

    def test_does_not_fire_before_start_date(self):
        now = next_tick()
        cron_item = CronItem(make_schedule(crontab='* * * * *',
                                           start_date=naive_utc(now + datetime.timedelta(days=1))))

        assert cron_item.run_pending(now=now) is False

    def test_fires_at_start_date(self):
        now = next_tick()
        cron_item = CronItem(make_schedule(crontab='* * * * *', start_date=naive_utc(now)))

        assert cron_item.run_pending(now=now) == cron_item.schedule_id

    def test_start_date_in_the_past_does_not_change_the_runs(self):
        now = next_tick()
        cron_item = CronItem(make_schedule(crontab='* * * * *',
                                           start_date=naive_utc(now - datetime.timedelta(days=30))))

        assert cron_item.run_pending(now=now) == cron_item.schedule_id


class TestOnceSchedule:

    @pytest.fixture
    def make_once_item(self):
        def _make(run_at, run_result=1):
            cron_item = CronItem(make_schedule(schedule_type='once', crontab=None, run_at=naive_utc(run_at)))
            cron_item.run = mock.Mock(return_value=run_result)
            return cron_item
        return _make

    def test_fires_when_due_and_deactivates(self, make_once_item):
        now = utc_now()
        cron_item = make_once_item(run_at=now - datetime.timedelta(minutes=1))

        assert cron_item.run_pending(now=now) == 1
        assert cron_item.active is False

    def test_fires_only_once(self, make_once_item):
        now = utc_now()
        cron_item = make_once_item(run_at=now - datetime.timedelta(minutes=1))

        cron_item.run_pending(now=now)
        cron_item.run_pending(now=now + datetime.timedelta(minutes=1))

        cron_item.run.assert_called_once()

    def test_does_not_fire_before_run_at(self, make_once_item):
        now = utc_now()
        cron_item = make_once_item(run_at=now + datetime.timedelta(minutes=5))

        assert cron_item.run_pending(now=now) is False
        cron_item.run.assert_not_called()
        assert cron_item.active is True

    def test_missed_beyond_grace_period_is_deactivated_without_running(self, make_once_item):
        now = utc_now()
        cron_item = make_once_item(run_at=now - ONCE_GRACE_PERIOD - datetime.timedelta(minutes=1))

        assert cron_item.run_pending(now=now) is False
        cron_item.run.assert_not_called()
        assert cron_item.active is False

    def test_late_within_grace_period_still_fires(self, make_once_item):
        now = utc_now()
        cron_item = make_once_item(run_at=now - ONCE_GRACE_PERIOD + datetime.timedelta(minutes=1))

        assert cron_item.run_pending(now=now) == 1

    def test_not_run_stays_active_to_retry(self, make_once_item):
        now = utc_now()
        cron_item = make_once_item(run_at=now - datetime.timedelta(minutes=1), run_result=False)

        assert cron_item.run_pending(now=now) is False
        assert cron_item.active is True

    def test_deactivation_is_persisted(self, app, session):
        schedule = AgentScheduleFactory.create(schedule_type='once', crontab=None, active=True,
                                               run_at=naive_utc(utc_now() + datetime.timedelta(days=1)),
                                               workspaces=[WorkspaceFactory.create()])
        session.commit()
        cron_item = CronItem(schedule, app=app)

        cron_item.deactivate()

        session.expire_all()
        assert session.get(AgentsSchedule, schedule.id).active is False


class TestCronItemUpdate:

    def test_unchanged_schedule_keeps_the_anchor(self):
        schedule = make_schedule()
        cron_item = CronItem(schedule)
        cron_item.last_run = anchor = cron_item.last_run - datetime.timedelta(days=3)

        cron_item.update(schedule)

        assert cron_item.last_run == anchor

    def test_changed_crontab_re_anchors_at_now(self):
        cron_item = CronItem(make_schedule())
        cron_item.last_run = cron_item.last_run - datetime.timedelta(days=3)

        cron_item.update(make_schedule(crontab='* * * * *'))

        assert next_fire(cron_item) > datetime.datetime.now(datetime.timezone.utc)

    def test_changed_timezone_is_applied(self, schedule_tz):
        cron_item = CronItem(make_schedule(timezone='UTC'))

        cron_item.update(make_schedule())

        assert next_fire(cron_item).astimezone(schedule_tz).hour == 4

    def test_switch_to_once(self):
        cron_item = CronItem(make_schedule())

        cron_item.update(make_schedule(schedule_type='once', crontab=None,
                                       run_at=naive_utc(utc_now() + datetime.timedelta(days=1))))

        assert cron_item.schedule_type == 'once'


class TestCronTabIsolation:

    def test_a_failing_job_does_not_stop_the_others(self):
        now = next_tick()
        failing = CronItem(make_schedule(id=1, crontab='* * * * *'))
        failing.run = mock.Mock(side_effect=RuntimeError('boom'))
        healthy = CronItem(make_schedule(id=2, crontab='* * * * *'))
        crontab = FaradayCronTab()
        crontab.append(failing)
        crontab.append(healthy)

        assert list(crontab.run_pending(now=now)) == [healthy.schedule_id]
