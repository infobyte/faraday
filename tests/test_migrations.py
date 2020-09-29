from alembic.script import ScriptDirectory
from alembic.config import Config

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
