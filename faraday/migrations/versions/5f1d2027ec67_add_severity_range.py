"""add severity range

Revision ID: 5f1d2027ec67
Revises: 39ddd3ca3a20
Create Date: 2025-05-13 15:45:25.683218+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5f1d2027ec67'
down_revision = '39ddd3ca3a20'
branch_labels = None
depends_on = None


def upgrade():
    # Create enum type for severity levels
    conn = op.get_bind()
    conn.execute("CREATE TYPE scheduler_severities AS ENUM ('UNCLASSIFIED', 'INFO', 'LOW', 'MED', 'HIGH', 'CRITICAL')")
    op.add_column('agent_schedule', sa.Column('min_severity', sa.Enum('UNCLASSIFIED', 'INFO', 'LOW', 'MED', 'HIGH', 'CRITICAL', name='scheduler_severities', create_type=False), nullable=True))
    op.add_column('agent_schedule', sa.Column('max_severity', sa.Enum('UNCLASSIFIED', 'INFO', 'LOW', 'MED', 'HIGH', 'CRITICAL', name='scheduler_severities', create_type=False), nullable=True))


def downgrade():
    op.drop_column('agent_schedule', 'max_severity')
    op.drop_column('agent_schedule', 'min_severity')
    conn = op.get_bind()
    conn.execute("DROP TYPE scheduler_severities")
