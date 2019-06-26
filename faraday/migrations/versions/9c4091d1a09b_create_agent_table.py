"""create agent table

Revision ID: 9c4091d1a09b
Revises: 0d216660da28
Create Date: 2019-05-22 19:17:31.444968+00:00

"""
import uuid
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
from sqlalchemy.dialects import postgresql

revision = '9c4091d1a09b'
down_revision = '2db31733fb78'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'agent',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('token', sa.String(256), nullable=True),
        sa.Column('description', sa.String(256), nullable=True),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('projects', sa.Integer),
        sa.Column('jobs', sa.Integer),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer),
        sa.Column('workspace_id', sa.Integer,  nullable=False),
    )
    # There is a bug with alembic and postgresql with enum types
    # alembic tries to create the enum type when creating a new table.
    # the syntax os the sql is invalid for postgresql and it also tries to
    # create the enum when it already exists.

    agent_types = postgresql.ENUM('shared', 'specific', name='agent_types')
    agent_types.create(op.get_bind())

    agent_status = postgresql.ENUM('locked', 'paused', 'offline', 'running', name='agent_status')
    agent_status.create(op.get_bind())

    op.add_column('agent', sa.Column('type', sa.Enum(('shared', 'specific'), name='agent_types'), nullable=False, default='specific'))
    op.add_column('agent',
                  sa.Column('status', sa.Enum(('locked', 'paused', 'offline', 'running'), name='agent_status'), nullable=False, default='running'))

    op.create_foreign_key(
        'agent_creator_id_fkey',
        'agent',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'agent_update_user_id_fkey',
        'agent',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_foreign_key(
        'agent_workspace_id_fkey',
        'agent',
        'workspace', ['workspace_id'], ['id']
    )

    conn = op.get_bind()
    conn.execute("ALTER TYPE OBJECT_TYPES RENAME TO _OBJECT_TYPES;")

    conn.execute("CREATE TYPE OBJECT_TYPES as enum "
                 "( 'vulnerability', 'host', 'credential', 'service', 'source_code', 'comment', "
                 "'executive_report', 'workspace', 'task', 'agent');")

    conn.execute("ALTER table tag_object rename column object_type to _object_type;")
    conn.execute("ALTER table command_object rename column object_type to _object_type;")
    conn.execute("ALTER table comment rename column object_type to _object_type;")
    conn.execute("ALTER table notification rename column object_type to _object_type;")
    conn.execute("ALTER table file rename column object_type to _object_type;")

    conn.execute("ALTER table tag_object add object_type OBJECT_TYPES not null default 'vulnerability';")
    conn.execute("ALTER table command_object add object_type OBJECT_TYPES not null default 'vulnerability';")
    conn.execute("ALTER table comment add object_type OBJECT_TYPES not null default 'vulnerability';")
    conn.execute("ALTER table notification add object_type OBJECT_TYPES not null default 'vulnerability';")
    conn.execute("ALTER table file add object_type OBJECT_TYPES not null default 'vulnerability';")

    conn.execute("UPDATE tag_object set object_type = _object_type::text::OBJECT_TYPES;")
    conn.execute("UPDATE command_object set object_type = _object_type::text::OBJECT_TYPES;")
    conn.execute("UPDATE comment set object_type = _object_type::text::OBJECT_TYPES;")
    conn.execute("UPDATE notification set object_type = _object_type::text::OBJECT_TYPES;")
    conn.execute("UPDATE file set object_type = _object_type::text::OBJECT_TYPES;")

    conn.execute("ALTER table tag_object drop column _object_type;")
    conn.execute("ALTER table command_object drop column _object_type;")
    conn.execute("ALTER table comment drop column _object_type;")
    conn.execute("ALTER table notification drop column _object_type;")
    conn.execute("ALTER table file drop column _object_type;")

    conn.execute("DROP TYPE _OBJECT_TYPES CASCADE;")

    op.create_table(
        'agent_auth_token',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('token', sa.String(256), nullable=False, default=str(uuid.uuid4())),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer),
    )
    op.create_table(
        'agent_schedule',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('description', sa.String(1024), nullable=False),
        sa.Column('crontab', sa.String(128)),
        sa.Column('timezone', sa.String(128)),
        sa.Column('active', sa.Boolean),
        sa.Column('owner_id', sa.Integer),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('workspace_id', sa.Integer)
        # last_pipeline
        # agent_id
    )

    op.create_foreign_key(
        'agent_schedule_user_id_fkey',
        'agent_schedule',
        'faraday_user', ['owner_id'], ['id']
    )

    op.create_foreign_key(
        'agent_schedule_id_fkey',
        'agent_schedule',
        'workspace', ['workspace_id'], ['id']
    )


def downgrade():
    op.drop_table('agent_schedule')
    op.drop_table('agent_auth_token')
    op.drop_table('agent')

    agent_types = postgresql.ENUM('shared', 'specific', name='agent_types')
    agent_types.drop(op.get_bind())

    agent_status = postgresql.ENUM('locked', 'paused', 'offline', 'running', name='agent_status')
    agent_status.drop(op.get_bind())
