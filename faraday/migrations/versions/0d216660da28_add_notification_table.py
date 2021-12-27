"""add notification table

Revision ID: 0d216660da28
Revises: 1b2533cc16fe
Create Date: 2019-04-26 20:17:48.639684+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0d216660da28'
down_revision = '1b2533cc16fe'
branch_labels = None
depends_on = None

OBJECT_TYPES = (
    'vulnerability',
    'host',
    'credential',
    'service',
    'source_code',
    'comment',
    'executive_report',
    'workspace',
    'task'
)


def upgrade():
    op.create_table(
        'notification',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('user_notified_id', sa.Integer),
        sa.Column('workspace_id', sa.Integer),
        sa.Column('object_id', sa.Integer),
        sa.Column('create_date', sa.DateTime),
        sa.Column('mark_read', sa.Boolean),
        sa.Column('notification_text', sa.String(256), nullable=False)
    )
    # There is a bug with alembic and postgresql with enum types
    # alembic tries to create the enum type when creating a new table.
    # the syntax os the sql is invalid for postgresql and it also tries to
    # create the enum when it already exists.
    op.add_column('notification',
                  sa.Column(
                      'object_type',
                      sa.Enum(OBJECT_TYPES, name='object_types'),
                      nullable=False
                  )
                  )

    op.create_foreign_key(
        'notification_user_id_fkey',
        'notification',
        'faraday_user', ['user_notified_id'], ['id']
    )

    op.create_foreign_key(
        'notification_workspace_id_fkey',
        'notification',
        'workspace', ['workspace_id'], ['id']
    )


def downgrade():
    op.drop_table('notification')
    # op.drop_constraint(None, 'notification_user_id_fkey', type_='foreignkey')
    # op.drop_constraint(None, 'notification_workspace_id_fkey', type_='foreignkey')
