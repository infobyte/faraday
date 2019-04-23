#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import sys
import os
sys.path.append(os.getcwd())

import click
from faraday.server.models import db
from faraday.server.web import app


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

    # db.create_all()
    # Ugly hack to create tables and also setting alembic revision
    import faraday.server.config
    conn_string = faraday.server.config.database.connection_string
    from faraday.server.commands.initdb import InitDB
    InitDB()._create_tables(conn_string)


def reset_db():
    with app.app_context():
        reset_db_all()


@click.command()
@click.option('--confirm/--no-confirme', prompt='Confirm database reset?')
def main(confirm):
    if confirm:
        reset_db()


if __name__ == '__main__':
    main()
