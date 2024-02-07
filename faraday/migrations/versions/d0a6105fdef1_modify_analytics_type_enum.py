"""modify analytics type enum

Revision ID: d0a6105fdef1
Revises: 443a136bb5f2
Create Date: 2023-11-14 20:48:56.645881+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'd0a6105fdef1'
down_revision = '443a136bb5f2'
branch_labels = None
depends_on = None


def upgrade():
    # add entry "vulnerabilities_by_risk_score" to enum "analytics_types"
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE analytics_types ADD VALUE IF NOT EXISTS 'vulnerabilities_by_risk_score'")


def downgrade():
    # CANT REMOVE ENUM VALUES, NOT SUPPORTED BY POSTGRES
    pass
