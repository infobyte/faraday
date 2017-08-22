# manage.py

from flask_script import Manager

from server.web import app
from server.commands import InitDB

manager = Manager(app)


if __name__ == "__main__":
    manager.add_command('initdb', InitDB())
    manager.run()
