"""end_date on agent and cloud agent executions

Adds end_date to agent_execution and cloud_agent_execution. Runs that are already
over get their update_date, the closest value available: it's set by the last
status report, which is the one that ends the run.

Revision ID: a53dbe714833
Revises: 120c7b0c8b12
Create Date: 2026-10-01 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a53dbe714833'
down_revision = '120c7b0c8b12'
branch_labels = None
depends_on = None

TABLES = ('agent_execution', 'cloud_agent_execution')


def upgrade():
    for table in TABLES:
        op.add_column(table, sa.Column('end_date', sa.DateTime(), nullable=True))
        op.execute(f"UPDATE {table} SET end_date = update_date WHERE running IS FALSE")


def downgrade():
    for table in TABLES:
        op.drop_column(table, 'end_date')
