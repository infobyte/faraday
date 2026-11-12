"""vuln triage

Adds false_positive, triaged, triaged_by_id and triaged_at to vulnerability, so a
finding nobody reviewed can be told apart from one dismissed as a false positive.
Confirmed vulns are backfilled as triaged, with no user or date since that was
never stored. vulnerability_status_history gets field/value so the trace can
record confirmed and false_positive changes besides status ones.

Revision ID: c4e1f8a2b7d9
Revises: fda55c44495c
Create Date: 2026-10-23 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'c4e1f8a2b7d9'
down_revision = 'fda55c44495c'
branch_labels = None
depends_on = None

HISTORY_FIELDS = postgresql.ENUM('status', 'confirmed', 'false_positive', name='vulnerability_status_history_fields')


def upgrade():
    op.add_column('vulnerability', sa.Column('false_positive', sa.Boolean(), nullable=False,
                                             server_default=sa.text('false')))
    op.add_column('vulnerability', sa.Column('triaged', sa.Boolean(), nullable=False,
                                             server_default=sa.text('false')))
    op.add_column('vulnerability', sa.Column('triaged_at', sa.DateTime(), nullable=True))
    op.add_column('vulnerability', sa.Column('triaged_by_id', sa.Integer(), nullable=True))
    op.create_foreign_key('vulnerability_triaged_by_id_fkey', 'vulnerability', 'faraday_user',
                          ['triaged_by_id'], ['id'], ondelete='SET NULL')
    op.execute("UPDATE vulnerability SET triaged = true WHERE confirmed IS TRUE")

    HISTORY_FIELDS.create(op.get_bind(), checkfirst=True)
    op.add_column('vulnerability_status_history', sa.Column('field', HISTORY_FIELDS, nullable=False,
                                                            server_default='status'))
    op.add_column('vulnerability_status_history', sa.Column('value', sa.Boolean(), nullable=True))
    op.alter_column('vulnerability_status_history', 'status', nullable=True)


def downgrade():
    op.execute("DELETE FROM vulnerability_status_history WHERE field != 'status'")
    op.alter_column('vulnerability_status_history', 'status', nullable=False)
    op.drop_column('vulnerability_status_history', 'value')
    op.drop_column('vulnerability_status_history', 'field')
    HISTORY_FIELDS.drop(op.get_bind(), checkfirst=True)

    op.drop_constraint('vulnerability_triaged_by_id_fkey', 'vulnerability', type_='foreignkey')
    op.drop_column('vulnerability', 'triaged_by_id')
    op.drop_column('vulnerability', 'triaged_at')
    op.drop_column('vulnerability', 'triaged')
    op.drop_column('vulnerability', 'false_positive')
