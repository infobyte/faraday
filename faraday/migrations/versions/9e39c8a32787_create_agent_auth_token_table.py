"""create Agent Auth Token table

Revision ID: 9e39c8a32787
Revises: 9c4091d1a09b
Create Date: 2019-05-23 16:36:23.308907+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '9e39c8a32787'
down_revision = '9c4091d1a09b'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'agent_auth_token',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('token', sa.String(256), nullable=False),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer),
    )


def downgrade():
    op.drop_table('agent_auth_token')
