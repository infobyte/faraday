"""modify analytics type enum

Revision ID: d0a6105fdef1
Revises: 901344f297fb
Create Date: 2023-11-14 20:48:56.645881+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'd0a6105fdef1'
down_revision = 'b87b1de2f348'
branch_labels = None
depends_on = None


def upgrade():
    # add entry "vulnerabilities_by_risk_score" to enum "analytics_types"
    op.execute("ALTER TYPE analytics_types ADD VALUE IF NOT EXISTS 'vulnerabilities_by_risk_score'")


def downgrade():
    # CANT REMOVE ENUM VALUES, NOT SUPPORTED BY POSTGRES
    pass
