import sqlalchemy as sa

INDICES = [
    ('ix_user_notification_user_id_id', 'user_notification', '(user_id, id)'),
]


def _index_valid(connection, name):
    return connection.execute(sa.text(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = :name"
    ), {'name': name}).scalar()


def optimize_indices(engine, echo=print):
    with engine.connect().execution_options(isolation_level='AUTOCOMMIT') as connection:
        for name, table, columns in INDICES:
            if _index_valid(connection, name):
                echo(f"{name} already exists, skipping")
                continue
            echo(f"Creating {name} on {table} ...")
            # An interrupted CONCURRENTLY build leaves an invalid index behind
            connection.execute(sa.text(f"DROP INDEX CONCURRENTLY IF EXISTS {name}"))
            connection.execute(sa.text(f"CREATE INDEX CONCURRENTLY {name} ON {table} {columns}"))
            echo(f"{name} created")
