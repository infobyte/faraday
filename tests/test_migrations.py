from alembic.script import ScriptDirectory
from alembic.config import Config
from alembic import command
from os.path import (
    split,
    join,
)
import pytest
import glob

from faraday.server.config import FARADAY_BASE

class TestMigrations():


    def test_migrations_check_revision_hashes(self):
        config = Config()
        config.set_main_option("script_location", join(FARADAY_BASE,"migrations"))
        script = ScriptDirectory.from_config(config)

        alembic_hashes = []
        for revision in script.walk_revisions():
            alembic_hashes.append(revision.revision)

        migrations_hashes = []
        for migration in glob.glob(join(FARADAY_BASE, 'migrations', 'versions', '*.py')):
            path, filename = split(migration)
            migrations_hashes.append(filename.split('_')[0])

        assert set(alembic_hashes) == set(migrations_hashes)
