"""add application model

Revision ID: 0305c9db7c32
Revises: 2db31733fb78
Create Date: 2019-06-11 20:43:12.710694+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0305c9db7c32'
down_revision = '2db31733fb78'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'application',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String(256), nullable=False),
sa.Column('workspace_id', sa.Integer),
    )

    op.add_column('vulnerability',
        sa.Column(
            'application_id',
		sa.Integer(),
            nullable=False
        )
    )

    op.create_foreign_key(
        'application_user_id_fkey',
        'vulnerability',
        'application', ['application_id'], ['id']
    )

    op.create_foreign_key(
        'app_workspace_id_fkey',
        'application',
        'workspace', ['workspace_id'], ['id']
    )


def downgrade():
    op.drop_table('application')
