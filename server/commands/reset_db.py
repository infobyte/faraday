from flask_script import Command
from server.models import db

class ResetDB(Command):
    def run(self):
        # It might be  required to do a cascade delete to correctly the
        # vulnerability table
        try:
            db.engine.execute('DROP TABLE vulnerability CASCADE')
        except:
            pass
        db.drop_all()
        db.create_all()

