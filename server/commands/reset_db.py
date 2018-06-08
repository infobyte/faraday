'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import sys
import os
sys.path.append(os.getcwd())

from server.models import db
from server.web import app

def reset_db_all():
    # It might be  required to do a cascade delete to correctly the
    # vulnerability table
    for table in ('vulnerability', 'vulnerability_template', 'comment',
                  'faraday_user'):
        try:
            db.engine.execute('DROP TABLE {} CASCADE'.format(table))
        except:
            pass
    db.drop_all()
    db.create_all()


def reset_db():
    with app.app_context():
        reset_db_all()


if __name__ == '__main__':
    option = False
    while True:
        print "You are going to delete all info from the DB, this is not undoable, are you sure to follow? [Y/N]",
        option = raw_input()

        if option.upper() in ['Y', 'N', 'YES', 'NO']:
            break
        else:
            print(str(option) + " option is invalid.")

    if option.upper() in ['Y', 'YES']:
        reset_db()
