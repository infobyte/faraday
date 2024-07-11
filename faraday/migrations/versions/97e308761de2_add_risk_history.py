"""add risk history

Revision ID: 97e308761de2
Revises: 44e7fc2b6223
Create Date: 2023-10-23 18:56:22.503518+00:00

"""
from alembic import op
import sqlalchemy as sa
from datetime import date, timedelta
import json

# revision identifiers, used by Alembic.
revision = '97e308761de2'
down_revision = '44e7fc2b6223'
branch_labels = None
depends_on = None


def upgrade():

    # create list of date.today().isoformat() for the last 30 days
    today = date.today()
    last_30_days = [today - timedelta(days=i) for i in range(30)]
    last_30_days = [day.isoformat() for day in last_30_days]

    json_default = json.dumps([{"date": day, "risk": 0} for day in last_30_days])

    op.add_column('workspace', sa.Column('risk_history_total',
                                         sa.JSON(),
                                         nullable=False,
                                         default=json_default,
                                         server_default=sa.text(f"'{json_default}'")))

    op.add_column('workspace', sa.Column('risk_history_avg',
                                         sa.JSON(),
                                         nullable=False,
                                         default=json_default,
                                         server_default=sa.text(f"'{json_default}'")))


def downgrade():

    op.drop_column('workspace', 'risk_history_total')
    op.drop_column('workspace', 'risk_history_avg')
