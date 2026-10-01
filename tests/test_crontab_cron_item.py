"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import datetime
from types import SimpleNamespace

import dateutil.tz
import pytest

from faraday.server.threads.crontab import CronItem

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
    }
    values.update(overrides)
    return SimpleNamespace(**values)


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
