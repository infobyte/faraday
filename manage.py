#!/usr/bin/env python


from flask_script import Manager

from server.web import app
from server.commands.initdb import InitDB
from server.commands.faraday_schema_display import DatabaseSchema

manager = Manager(app)


if __name__ == "__main__":
    manager.add_command('initdb', InitDB())
    manager.add_command('faraday_schema_display', DatabaseSchema())
    manager.run()
