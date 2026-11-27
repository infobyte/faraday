"""workspace triage stats

Adds the dashboard counters of false positives (total, by type, by severity,
hosts and services) and of vulns pending triage to workspace. The false
positive counters start at 0 since no vuln is a false positive yet; the
pending ones are backfilled from vulnerability.triaged.

Revision ID: d7a3e9b1c5f2
Revises: c4e1f8a2b7d9
Create Date: 2026-10-26 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd7a3e9b1c5f2'
down_revision = 'c4e1f8a2b7d9'
branch_labels = None
depends_on = None

COLUMNS = (
    'host_false_positive_count',
    'service_false_positive_count',
    'vulnerability_false_positive_count',
    'vulnerability_web_false_positive_count',
    'vulnerability_code_false_positive_count',
    'vulnerability_standard_false_positive_count',
    'vulnerability_high_false_positive_count',
    'vulnerability_critical_false_positive_count',
    'vulnerability_medium_false_positive_count',
    'vulnerability_low_false_positive_count',
    'vulnerability_informational_false_positive_count',
    'vulnerability_unclassified_false_positive_count',
    'vulnerability_triage_pending_count',
)


def upgrade():
    for column in COLUMNS:
        op.add_column('workspace', sa.Column(column, sa.Integer(), nullable=False, server_default=sa.text('0')))
    op.execute("""
        UPDATE workspace SET vulnerability_triage_pending_count = pending.count
        FROM (
            SELECT workspace_id, COUNT(*) AS count
            FROM vulnerability
            WHERE triaged IS FALSE
            GROUP BY workspace_id
        ) AS pending
        WHERE pending.workspace_id = workspace.id
    """)


def downgrade():
    for column in COLUMNS:
        op.drop_column('workspace', column)
