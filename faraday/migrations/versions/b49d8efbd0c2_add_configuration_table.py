"""add configuration table

Revision ID: b49d8efbd0c2
Revises: ed403da439d4
Create Date: 2020-08-12 13:53:50.672454+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from configparser import ConfigParser

from faraday.server.config import LOCAL_CONFIG_FILE

# revision identifiers, used by Alembic.
revision = 'b49d8efbd0c2'
down_revision = 'ed403da439d4'
branch_labels = None
depends_on = None


def upgrade():
    configuration_table = op.create_table(
        'configuration',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('integrations', JSONB, nullable=False, default={}),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer)
    )

    config = ConfigParser()
    config.read(LOCAL_CONFIG_FILE)

    if config.has_section('ticketing_tool'):
        ticketing_tool = config['ticketing_tool']
        tool = ticketing_tool.get('tool')
        url = ticketing_tool.get('url')
        project_key = ticketing_tool.get('project_key')

        config.remove_section('ticketing_tool')
        with open(LOCAL_CONFIG_FILE, 'w') as configfile:
            config.write(configfile)

        if not tool or (not url and not project_key):
            pass
        else:
            integration_data = {'url': url}
            if project_key and tool == 'jira':
                integration_data['project_key'] = project_key

            integration_config = {
                tool: integration_data
            }

            op.bulk_insert(
                configuration_table,
                [{"integrations": integration_config}]
            )


def downgrade():
    connection = op.get_bind()
    query = connection.execute('SELECT integrations FROM configuration').first()
    integration_config = query[0] if query else None

    if integration_config:
        tool = list(integration_config.keys())[0]
        url = integration_config[tool].get('url', '')
        project_key = integration_config[tool].get('project_key', '')
    else:
        tool = ''
        url = ''
        project_key = ''

    config = ConfigParser()
    config.read(LOCAL_CONFIG_FILE)

    if not config.has_section('ticketing_tool'):
        config.add_section('ticketing_tool')
    ticketing_tool = config['ticketing_tool']
    ticketing_tool['tool'] = tool
    ticketing_tool['url'] = url
    ticketing_tool['project_key'] = project_key

    with open(LOCAL_CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

    op.drop_table('configuration')
