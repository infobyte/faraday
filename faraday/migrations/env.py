import logging
from logging.config import fileConfig

from alembic import context

from faraday.server.app import get_app
import faraday.server.config
from faraday.server.models import db
# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
target_metadata = db.metadata
alembic_logger = logging.getLogger('alembic.runtime.migration')
LOG_FILE = faraday.server.config.CONST_FARADAY_HOME_PATH / 'logs' \
           / 'alembic.log'
fh = logging.FileHandler(LOG_FILE)
fh.setLevel(logging.INFO)
alembic_logger.addHandler(fh)

# target_metadata = None

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


app = get_app()


def include_object(object, type_, name, reflected, compare_to):
    bind_key = object.info.get("bind_key", None)
    if bind_key:
        return False
    return True


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = faraday.server.config.database.connection_string
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True, include_object=include_object)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    with app.app_context():
        connectable = db.engine

        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
                transaction_per_migration=True,
                include_object=include_object
            )

            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
