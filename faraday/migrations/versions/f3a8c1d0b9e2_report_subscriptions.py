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
    # next_delivery: the next Monday-02:00 strictly after the real current
    # time, matching the old cron's actual next trigger - not unconditionally
    # "+7 days". date_trunc('week', clock_timestamp()) + '02:00:00' is *this*
    # week's Monday-02:00; if that's already past (any day other than
    # Monday-before-02:00), it's pushed a further week out. Running the
    # migration on a Monday before 02:00 would otherwise record
    # next_delivery a full week later than the delivery the old cron was
    # about to fire that same day.
    # clock_timestamp(), not now(): now() is frozen to this transaction's
    # start for every statement inside it, not just this one - if the
    # transaction started before Monday 02:00 but wall-clock time crosses
    # 02:00 before this UPDATE actually runs, now() still reports "before
    # 02:00", so this would pick this week's Monday-02:00 even though that
    # moment has already passed by the time the row is written - the exact
    # opposite of "strictly after". clock_timestamp() always reflects the
    # real current time, regardless of the transaction's own start.
    op.execute(
        sa.text(
            "UPDATE workspace_summary_report SET "
            "schedule_day = :schedule_day, "
            "schedule_time = :schedule_time, "
            "content_sections = :content_sections, "
            "next_delivery = ("
            "  CASE"
            "    WHEN date_trunc('week', clock_timestamp()) + interval '02:00:00' > clock_timestamp()"
            "    THEN date_trunc('week', clock_timestamp()) + interval '02:00:00'"
            "    ELSE date_trunc('week', clock_timestamp()) + interval '7 days' + interval '02:00:00'"
            "  END"
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
    #
    # creator_id is nullable (ON DELETE SET NULL when the creator user is
    # removed) - restricted to NOT NULL here because a plain GROUP BY treats
    # every NULL as equal, unlike the UNIQUE constraint it's standing in for
    # (which never conflicts on NULL): several unrelated, creator-less
    # reports in the same workspace would otherwise collapse into a single
    # "duplicate" group, deleting every one but the oldest even though the
    # old constraint always allowed them all to coexist.
    op.execute(
        "DELETE FROM workspace_summary_report "
        "WHERE creator_id IS NOT NULL "
        "AND id NOT IN ("
        "  SELECT MIN(id) FROM workspace_summary_report "
        "  WHERE creator_id IS NOT NULL "
        "  GROUP BY creator_id, workspace_id"
        ")"
    )

    # The upgrade's constraint being dropped below allows one user to have
    # both a weekly and a biweekly row in the same workspace (they differ by
    # summary_period_type). The fold-back right after this would turn such a
    # pair into two identical (workspace_id, user_id, 'weekly') rows - a
    # duplicate key under that same constraint, if it were still active.
    # Drop it first: the dedup above already guarantees the constraint being
    # restored below (creator_id, workspace_id) can't be violated, so nothing
    # needs it to stick around any longer.
    op.drop_constraint(
        'uix_workspace_summary_report_workspace_user_period',
        'workspace_summary_report',
        type_='unique',
    )

    # A surviving row may still be 'biweekly' - the dedup above only picks
    # one row per (creator_id, workspace_id), it doesn't care about its
    # period type. The old model being downgraded to doesn't know that enum
    # value (it's added to the DB enum type, not removed, by this same
    # migration's upgrade() - see the note at the bottom of this function),
    # so SQLAlchemy raises a LookupError the first time old code reads such
    # a row. Fold it back into 'weekly' - the closest equivalent, and what
    # the old fixed weekly-cron behavior already assumed for every row.
    op.execute(
        "UPDATE workspace_summary_report SET summary_period_type = 'weekly' "
        "WHERE summary_period_type = 'biweekly'"
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
