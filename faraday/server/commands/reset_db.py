#!/usr/bin/env python3
"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import click

from faraday.server.models import db
from faraday.server.web import get_app
from faraday.server.commands.initdb import InitDB
import faraday.server.config


def reset_db_all():
    # It might be  required to do a cascade delete to correctly the
    # vulnerability table
    for table in ('vulnerability', 'vulnerability_template', 'comment',
                  'faraday_user'):
        try:
            db.engine.execute(f'DROP TABLE {table} CASCADE')
        except Exception as ex:
            print(ex)
    db.drop_all()

    # db.create_all()
    # Ugly hack to create tables and also setting alembic revision
    conn_string = faraday.server.config.database.connection_string
    InitDB()._create_tables(conn_string)


def reset_db():
    with get_app().app_context():
        reset_db_all()


@click.command()
@click.option('--confirm/--no-confirme', prompt='Confirm database reset?')
def main(confirm):
    if confirm:
        reset_db()


if __name__ == '__main__':
    main()
