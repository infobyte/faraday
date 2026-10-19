import importlib.util
import io
import multiprocessing
import time

import pytest
import sqlalchemy as sa

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory

from faraday.server.config import FARADAY_BASE


class TestMigrations:

    def test_migrations_check_revision_hashes(self):
        config = Config()
        config.set_main_option(
            "script_location",
            str(FARADAY_BASE / "migrations")
        )
        script = ScriptDirectory.from_config(config)

        alembic_hashes = []
        for revision in script.walk_revisions():
            alembic_hashes.append(revision.revision)

        migrations_hashes = []
        for migration in (FARADAY_BASE / 'migrations' / 'versions').glob('*.py'):
            filename = migration.name
            migrations_hashes.append(filename.split('_')[0])

        assert set(alembic_hashes) == set(migrations_hashes)


USER_NOTIFICATION_INDEX = 'ix_user_notification_user_id_id'


def _load_user_notification_index_migration():
    path = FARADAY_BASE / 'migrations' / 'versions' / 'a0b302b596ac_add_user_notification_user_id_id_index.py'
    spec = importlib.util.spec_from_file_location('migration_a0b302b596ac', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    return migration


def _run_upgrade(engine):
    migration = _load_user_notification_index_migration()
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        with Operations.context(context), context.begin_transaction():
            migration.upgrade()


def _run_upgrade_in_process(url, results):
    engine = sa.create_engine(url)
    try:
        _run_upgrade(engine)
        results.put('ok')
    except Exception as e:
        results.put(repr(e))
    finally:
        engine.dispose()


def _autocommit(engine):
    return engine.connect().execution_options(isolation_level='AUTOCOMMIT')


def _index_state(engine):
    with engine.connect() as connection:
        return connection.execute(sa.text(
            "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) FROM pg_index i "
            "JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = :name"
        ), {'name': USER_NOTIFICATION_INDEX}).first()


@pytest.fixture
def without_user_notification_index(database):
    engine = database.engine
    with _autocommit(engine) as connection:
        connection.execute(sa.text(f'DROP INDEX IF EXISTS {USER_NOTIFICATION_INDEX}'))
    yield engine
    with _autocommit(engine) as connection:
        connection.execute(sa.text(f'DROP INDEX IF EXISTS {USER_NOTIFICATION_INDEX}'))
        connection.execute(sa.text(f'CREATE INDEX {USER_NOTIFICATION_INDEX} ON user_notification (user_id, id)'))


def _wait_for_index(engine, timeout=30):
    deadline = time.monotonic() + timeout
    while _index_state(engine) is None:
        assert time.monotonic() < deadline
        time.sleep(0.05)


def test_user_notification_index_migration_rebuilds_invalid_index(without_user_notification_index):
    engine = without_user_notification_index
    with _autocommit(engine) as blocker, _autocommit(engine) as builder:
        blocker.execute(sa.text('BEGIN'))
        blocker.execute(sa.text('LOCK TABLE user_notification IN ROW EXCLUSIVE MODE'))
        builder.execute(sa.text("SET statement_timeout = '200ms'"))
        with pytest.raises(sa.exc.OperationalError):
            builder.execute(sa.text(f'CREATE INDEX CONCURRENTLY {USER_NOTIFICATION_INDEX} ON user_notification (user_id)'))
        blocker.execute(sa.text('ROLLBACK'))
    assert _index_state(engine)[0] is False

    _run_upgrade(engine)
    _run_upgrade(engine)

    valid, definition = _index_state(engine)
    assert valid is True
    assert definition.endswith('(user_id, id)')


def test_user_notification_index_migration_concurrent_upgrades(without_user_notification_index):
    engine = without_user_notification_index
    url = engine.url.render_as_string(hide_password=False)
    ctx = multiprocessing.get_context('fork')
    results = ctx.Queue()
    engine.dispose()
    with _autocommit(engine) as blocker:
        # Holds the first build in progress (index present but not valid yet) while the second one starts
        blocker.execute(sa.text('BEGIN'))
        blocker.execute(sa.text('LOCK TABLE user_notification IN ROW EXCLUSIVE MODE'))
        first = ctx.Process(target=_run_upgrade_in_process, args=(url, results))
        first.start()
        _wait_for_index(engine)
        second = ctx.Process(target=_run_upgrade_in_process, args=(url, results))
        second.start()
        time.sleep(1.5)
        blocker.execute(sa.text('COMMIT'))
    first.join(60)
    second.join(60)

    assert [results.get(timeout=5), results.get(timeout=5)] == ['ok', 'ok']
    valid, definition = _index_state(engine)
    assert valid is True
    assert definition.endswith('(user_id, id)')


def test_user_notification_index_migration_generates_offline_sql():
    migration = _load_user_notification_index_migration()

    buffer = io.StringIO()
    context = MigrationContext.configure(dialect_name='postgresql',
                                         opts={'as_sql': True, 'output_buffer': buffer})
    with Operations.context(context):
        migration.upgrade()

    assert 'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_notification_user_id_id' in buffer.getvalue()
