"""
Faraday Penetration Test IDE
Copyright (C) 2022  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Local application imports


class Command:
    def __init__(self, name, fnc):
        self.name = name
        self.fnc = fnc


class Schedule:
    def __init__(self, cmd, crontab, active=True):
        self.id = f'c_{id(cmd.name)}'
        self.cmd = cmd
        self.active = active
        self.crontab = crontab
        self.timezone = ""
        self.last_run = None


# TODO: Add ff check before scheduling this

SCHEDULE_COMMANDS = []
