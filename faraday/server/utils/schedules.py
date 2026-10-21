"""
Faraday Penetration Test IDE
Copyright (C) 2026  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
from datetime import datetime, timedelta, timezone

# Related third party imports
from croniter import croniter

SCHEDULE_TYPE_CRON = 'cron'
SCHEDULE_TYPE_ONCE = 'once'
SCHEDULE_TYPES = [SCHEDULE_TYPE_CRON, SCHEDULE_TYPE_ONCE]

# How late a 'once' schedule may still fire (e.g. the server was down at run_at).
# Past this window the run is considered missed and the schedule is deactivated.
ONCE_GRACE_PERIOD = timedelta(hours=1)

# croniter.get_next is exclusive, so start from just before start_date to make
# start_date itself eligible as the first run.
_JUST_BEFORE = timedelta(seconds=1)


def to_aware(value, tz=timezone.utc):
    """Stored datetimes are naive UTC; returns them as aware datetimes in tz."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc).astimezone(tz)


def to_naive_utc(value):
    """Normalizes an aware datetime to the storage format (naive UTC)."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def next_cron_run(crontab, tz, after, start_date=None):
    """
    Next run of crontab strictly after `after`, never before start_date.
    @param crontab: cron expression, evaluated in tz
    @param tz: schedule timezone
    @param after: aware datetime
    @param start_date: naive UTC datetime (as stored) or None
    @return: aware datetime in tz
    """
    after = after.astimezone(tz)
    start = to_aware(start_date, tz)
    if start is not None and after < start:
        after = start - _JUST_BEFORE
    return croniter(crontab, after, ret_type=datetime).get_next(datetime)
