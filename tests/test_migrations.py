import importlib.util
import io

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


def test_user_notification_index_migration_generates_offline_sql():
    path = FARADAY_BASE / 'migrations' / 'versions' / 'a0b302b596ac_add_user_notification_user_id_id_index.py'
    spec = importlib.util.spec_from_file_location('migration_a0b302b596ac', path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)

    buffer = io.StringIO()
    context = MigrationContext.configure(dialect_name='postgresql',
                                         opts={'as_sql': True, 'output_buffer': buffer})
    with Operations.context(context):
        migration.upgrade()

    assert 'CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_notification_user_id_id' in buffer.getvalue()
