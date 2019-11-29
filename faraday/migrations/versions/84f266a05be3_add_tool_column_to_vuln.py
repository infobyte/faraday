"""add tool column to vuln

Revision ID: 84f266a05be3
Revises: 2a0de6132377
Create Date: 2019-11-28 15:19:31.097481+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '84f266a05be3'
down_revision = '2a0de6132377'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('vulnerability', sa.Column(
            'tool',
            sa.Text(),
            nullable=False,
            server_default=""
        )
    )
    

def downgrade():
    op.drop_column('vulnerability','tool')
    
