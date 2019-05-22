"""create agent table

Revision ID: 9c4091d1a09b
Revises: 0d216660da28
Create Date: 2019-05-22 19:17:31.444968+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
from sqlalchemy.dialects import postgresql

revision = '9c4091d1a09b'
down_revision = '0d216660da28'
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
    )
    # There is a bug with alembic and postgresql with enum types
    # alembic tries to create the enum type when creating a new table.
    # the syntax os the sql is invalid for postgresql and it also tries to
    # create the enum when it already exists.

    agent_types = postgresql.ENUM('shared', 'specific', name='agent_types')
    agent_types.create(op.get_bind())

    agent_status = postgresql.ENUM('locked', 'pause', 'offline', name='agent_status')
    agent_status.create(op.get_bind())

    op.add_column('agent', sa.Column('type', sa.Enum(('shared', 'specific'), name='agent_types'), nullable=False))
    op.add_column('agent', sa.Column('status', sa.Enum(('locked', 'pause', 'offline'), name='agent_status'), nullable=True))


def downgrade():
    agent_types = postgresql.ENUM('shared', 'specific', name='agent_types')
    agent_types.drop(op.get_bind())

    agent_status = postgresql.ENUM('locked', 'pause', 'offline', name='agent_status')
    agent_status.drop(op.get_bind())

    op.drop_table('agent')
