"""Add Agent execution data

Revision ID: f00247a92a14
Revises: 282ac9b6569f
Create Date: 2020-04-01 18:51:29.071191+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f00247a92a14'
down_revision = '282ac9b6569f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'agent_execution',
        sa.Column(
            'parameters_data',
            sa.JSON(),
            nullable=False,
            default=lambda: {},
            server_default="{}"
        )
    )


def downgrade():
    op.drop_column(
        'agent_execution',
        'parameters_data',
    )
