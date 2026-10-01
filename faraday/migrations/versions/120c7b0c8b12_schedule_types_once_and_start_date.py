"""schedule types (cron / once) and start_date

Adds schedule_type, start_date and run_at to agent_schedule, and makes crontab
nullable (only 'cron' schedules use it).

Revision ID: 120c7b0c8b12
Revises: 6ed6d0c4a21c
Create Date: 2026-10-01 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '120c7b0c8b12'
down_revision = '6ed6d0c4a21c'
branch_labels = None
depends_on = None

schedule_frequency_types = sa.Enum('cron', 'once', name='schedule_frequency_types')


def upgrade():
    schedule_frequency_types.create(op.get_bind(), checkfirst=True)
    op.add_column('agent_schedule', sa.Column('schedule_type', schedule_frequency_types,
                                              nullable=False, server_default='cron'))
    op.add_column('agent_schedule', sa.Column('start_date', sa.DateTime(), nullable=True))
    op.add_column('agent_schedule', sa.Column('run_at', sa.DateTime(), nullable=True))
    op.alter_column('agent_schedule', 'crontab', existing_type=sa.Text(), nullable=True)


def downgrade():
    # 'once' schedules can't be represented without schedule_type: keep the rows,
    # turned off, with a placeholder crontab so they never start firing.
    op.execute("UPDATE agent_schedule SET crontab = '0 0 1 1 *', active = false WHERE crontab IS NULL")
    op.alter_column('agent_schedule', 'crontab', existing_type=sa.Text(), nullable=False)
    op.drop_column('agent_schedule', 'run_at')
    op.drop_column('agent_schedule', 'start_date')
    op.drop_column('agent_schedule', 'schedule_type')
    schedule_frequency_types.drop(op.get_bind(), checkfirst=True)
