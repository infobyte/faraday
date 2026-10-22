import pytest
import sqlalchemy as sa
from click.testing import CliRunner

from faraday import manage
from faraday.server.commands.optimize_indices import optimize_indices

USER_NOTIFICATION_INDEX = 'ix_user_notification_user_id_id'


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


def test_optimize_indices_rebuilds_invalid_index(without_user_notification_index):
    engine = without_user_notification_index
    with engine.connect() as blocker, _autocommit(engine) as builder:
        blocker.execute(sa.text('LOCK TABLE user_notification IN ROW EXCLUSIVE MODE'))
        builder.execute(sa.text("SET statement_timeout = '200ms'"))
        with pytest.raises(sa.exc.OperationalError):
            builder.execute(sa.text(f'CREATE INDEX CONCURRENTLY {USER_NOTIFICATION_INDEX} ON user_notification (user_id)'))
        blocker.rollback()
    assert _index_state(engine)[0] is False

    optimize_indices(engine)
    optimize_indices(engine)

    valid, definition = _index_state(engine)
    assert valid is True
    assert definition.endswith('(user_id, id)')


@pytest.mark.parametrize('answer, created', [('n', False), ('y', True)])
def test_optimize_indices_command_asks_confirmation(app, without_user_notification_index, monkeypatch,
                                                    answer, created):
    monkeypatch.setattr(manage, 'get_app', lambda **kwargs: app)

    result = CliRunner().invoke(manage.optimize_indices, [], input=f'{answer}\n')

    assert 'may take a long time' in result.output
    assert result.exit_code == (0 if created else 1)
    assert (_index_state(without_user_notification_index) is not None) is created
