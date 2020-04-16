"""remove ticketing tools credentials

Revision ID: b1d15a55556d
Revises: f00247a92a14
Create Date: 2020-04-02 20:41:41.083048+00:00

"""
from alembic import op
import sqlalchemy as sa
from configparser import ConfigParser

from faraday.server.config import LOCAL_CONFIG_FILE


# revision identifiers, used by Alembic.
revision = 'b1d15a55556d'
down_revision = 'f00247a92a14'
branch_labels = None
depends_on = None


def upgrade():
    config = ConfigParser()
    config.read(LOCAL_CONFIG_FILE)
    config.remove_option('ticketing_tool', 'tool_username')
    config.remove_option('ticketing_tool', 'tool_password')

    with open(LOCAL_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)


def downgrade():
    pass
