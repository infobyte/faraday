"""report subscriptions

Revision ID: f3a8c1d0b9e2
Revises: 82a05afc9c2f
Create Date: 2026-09-14 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = 'f3a8c1d0b9e2'
down_revision = '82a05afc9c2f'
branch_labels = None
depends_on = None

# The old cron ran every Monday at 02:00 for every active report, so
# existing rows are backfilled with that schedule and with both delivery
# methods enabled (they were always emailed and always persisted as runs),
# preserving current behavior for existing subscribers.
BACKFILL_DAY = 'monday'
BACKFILL_TIME = '02:00:00'


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE summary_period_types ADD VALUE IF NOT EXISTS 'biweekly'")

    op.add_column('workspace_summary_report', sa.Column('schedule_day', sa.String(), nullable=True))
    op.add_column('workspace_summary_report', sa.Column('schedule_time', sa.Time(), nullable=True))
    op.add_column('workspace_summary_report', sa.Column('next_delivery', sa.DateTime(), nullable=True))
    op.add_column(
        'workspace_summary_report',
        sa.Column('content_preset', sa.String(), nullable=False, server_default='custom'),
    )
    op.add_column(
        'workspace_summary_report',
        sa.Column('content_sections', JSONType(), nullable=False, server_default='[]'),
    )
    op.add_column(
        'workspace_summary_report',
        sa.Column('send_by_email', sa.Boolean(), nullable=False, server_default=sa.text('true')),
    )
    op.add_column(
        'workspace_summary_report',
        sa.Column('save_in_faraday', sa.Boolean(), nullable=False, server_default=sa.text('true')),
    )
    op.create_index(
        op.f('ix_workspace_summary_report_next_delivery'),
        'workspace_summary_report',
        ['next_delivery'],
        unique=False,
    )

    # Backfill: preserve today's fixed weekly/Monday-02:00 behavior for
    # existing rows, and select all 6 sections (equivalent to the current
    # fixed template) so no content is dropped for existing subscribers.
    # Bound params (not an f-string) even though these values are hardcoded
    # constants, not user input - avoids a string-built UPDATE altogether.
    all_sections = (
        '["period_activity_summary", "current_snapshot", "open_vulns_4m", '
        '"closed_vulns_4m", "last_5_confirmed", "workspace_status"]'
    )
    op.execute(
        sa.text(
            "UPDATE workspace_summary_report SET "
            "schedule_day = :schedule_day, "
            "schedule_time = :schedule_time, "
            "content_sections = :content_sections, "
            "next_delivery = ("
            "  date_trunc('week', now()) + interval '7 days' + interval '02:00:00'"
            ")"
        ).bindparams(
            schedule_day=BACKFILL_DAY,
            schedule_time=BACKFILL_TIME,
            content_sections=all_sections,
        )
    )

    op.drop_constraint(
        'uix_workspace_summary_report_creator_workspace',
        'workspace_summary_report',
        type_='unique',
    )
    op.create_unique_constraint(
        'uix_workspace_summary_report_workspace_user_period',
        'workspace_summary_report',
        ['workspace_id', 'user_id', 'summary_period_type'],
    )


def downgrade():
    # The upgrade's constraint (workspace_id, user_id, summary_period_type)
    # allows up to 3 rows (weekly/biweekly/monthly) per (creator, workspace) -
    # more than the old (creator_id, workspace_id) constraint being restored
    # below can represent. This downgrade already discards every field the
    # new schema added (cadence, content, delivery toggles), so keeping only
    # one row per (creator_id, workspace_id) - the oldest - is consistent
    # with an otherwise-lossy downgrade; without this, create_unique_constraint
    # below fails outright for any user with more than one cadence on the
    # same workspace. workspace_summary_report_run rows for the dropped ones
    # cascade-delete at the DB level.
    op.execute(
        "DELETE FROM workspace_summary_report "
        "WHERE id NOT IN ("
        "  SELECT MIN(id) FROM workspace_summary_report GROUP BY creator_id, workspace_id"
        ")"
    )

    op.drop_constraint(
        'uix_workspace_summary_report_workspace_user_period',
        'workspace_summary_report',
        type_='unique',
    )
    op.create_unique_constraint(
        'uix_workspace_summary_report_creator_workspace',
        'workspace_summary_report',
        ['creator_id', 'workspace_id'],
    )

    op.drop_index(op.f('ix_workspace_summary_report_next_delivery'), table_name='workspace_summary_report')
    op.drop_column('workspace_summary_report', 'save_in_faraday')
    op.drop_column('workspace_summary_report', 'send_by_email')
    op.drop_column('workspace_summary_report', 'content_sections')
    op.drop_column('workspace_summary_report', 'content_preset')
    op.drop_column('workspace_summary_report', 'next_delivery')
    op.drop_column('workspace_summary_report', 'schedule_time')
    op.drop_column('workspace_summary_report', 'schedule_day')
    # 'biweekly' enum value is intentionally left in place on downgrade:
    # Postgres cannot drop a single enum value without recreating the type.
