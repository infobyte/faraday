"""stats columns on ws

Revision ID: f2435999bc54
Revises: 293724cb146d
Create Date: 2025-02-06 16:13:43.952670+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import Session
from faraday.server.models import Host, Workspace
from faraday.server.tasks import update_host_stats


revision = 'f2435999bc54'
down_revision = '293724cb146d'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('workspace', sa.Column('host_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('host_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('host_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('host_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('open_service_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('total_service_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('service_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('service_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('service_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_web_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_code_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_standard_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_open_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_re_opened_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_risk_accepted_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_closed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_total_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_high_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_critical_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_medium_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_low_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_informational_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_unclassified_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_web_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_code_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_standard_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_open_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_re_opened_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_risk_accepted_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_closed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_high_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_critical_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_medium_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_low_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_informational_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_unclassified_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_web_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_code_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_standard_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_high_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_critical_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_medium_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_low_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_informational_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_unclassified_notclosed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_web_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_code_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_standard_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_high_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_critical_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_medium_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_low_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_informational_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('workspace', sa.Column('vulnerability_unclassified_notclosed_confirmed_count', sa.Integer(), nullable=False, server_default='0'))

    bind = op.get_bind()
    session = Session(bind=bind)

    try:
        # Fetch all hosts and workspaces
        all_hosts = [host.id for host in session.query(Host).all()]
        all_workspaces = [workspace.id for workspace in session.query(Workspace).all()]

        # Call the update_host_stats function
        update_host_stats(
            hosts=all_hosts,
            services=[],
            workspace_ids=all_workspaces,
            sync=True,
        )
    finally:
        session.close()


def downgrade():
    op.drop_column('workspace', 'vulnerability_unclassified_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_informational_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_low_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_medium_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_critical_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_high_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_standard_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_code_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_web_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_unclassified_notclosed_count')
    op.drop_column('workspace', 'vulnerability_informational_notclosed_count')
    op.drop_column('workspace', 'vulnerability_low_notclosed_count')
    op.drop_column('workspace', 'vulnerability_medium_notclosed_count')
    op.drop_column('workspace', 'vulnerability_critical_notclosed_count')
    op.drop_column('workspace', 'vulnerability_high_notclosed_count')
    op.drop_column('workspace', 'vulnerability_standard_notclosed_count')
    op.drop_column('workspace', 'vulnerability_code_notclosed_count')
    op.drop_column('workspace', 'vulnerability_web_notclosed_count')
    op.drop_column('workspace', 'vulnerability_unclassified_confirmed_count')
    op.drop_column('workspace', 'vulnerability_informational_confirmed_count')
    op.drop_column('workspace', 'vulnerability_low_confirmed_count')
    op.drop_column('workspace', 'vulnerability_medium_confirmed_count')
    op.drop_column('workspace', 'vulnerability_critical_confirmed_count')
    op.drop_column('workspace', 'vulnerability_high_confirmed_count')
    op.drop_column('workspace', 'vulnerability_closed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_risk_accepted_confirmed_count')
    op.drop_column('workspace', 'vulnerability_re_opened_confirmed_count')
    op.drop_column('workspace', 'vulnerability_open_confirmed_count')
    op.drop_column('workspace', 'vulnerability_standard_confirmed_count')
    op.drop_column('workspace', 'vulnerability_code_confirmed_count')
    op.drop_column('workspace', 'vulnerability_web_confirmed_count')
    op.drop_column('workspace', 'vulnerability_unclassified_count')
    op.drop_column('workspace', 'vulnerability_informational_count')
    op.drop_column('workspace', 'vulnerability_low_count')
    op.drop_column('workspace', 'vulnerability_medium_count')
    op.drop_column('workspace', 'vulnerability_critical_count')
    op.drop_column('workspace', 'vulnerability_high_count')
    op.drop_column('workspace', 'vulnerability_total_count')
    op.drop_column('workspace', 'vulnerability_notclosed_confirmed_count')
    op.drop_column('workspace', 'vulnerability_notclosed_count')
    op.drop_column('workspace', 'vulnerability_confirmed_count')
    op.drop_column('workspace', 'vulnerability_closed_count')
    op.drop_column('workspace', 'vulnerability_risk_accepted_count')
    op.drop_column('workspace', 'vulnerability_re_opened_count')
    op.drop_column('workspace', 'vulnerability_open_count')
    op.drop_column('workspace', 'vulnerability_standard_count')
    op.drop_column('workspace', 'vulnerability_code_count')
    op.drop_column('workspace', 'vulnerability_web_count')
    op.drop_column('workspace', 'service_notclosed_confirmed_count')
    op.drop_column('workspace', 'service_notclosed_count')
    op.drop_column('workspace', 'service_confirmed_count')
    op.drop_column('workspace', 'total_service_count')
    op.drop_column('workspace', 'open_service_count')
    op.drop_column('workspace', 'host_notclosed_confirmed_count')
    op.drop_column('workspace', 'host_notclosed_count')
    op.drop_column('workspace', 'host_confirmed_count')
    op.drop_column('workspace', 'host_count')
