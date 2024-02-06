"""add delete workspace missing cascades

Revision ID: b87b1de2f348
Revises: d0a6105fdef1
Create Date: 2023-10-18 19:30:09.640602+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'b87b1de2f348'
down_revision = 'd0a6105fdef1'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('alter table workspace_permission_association drop constraint workspace_permission_association_workspace_id_fkey;')
    op.execute('alter table workspace_permission_association add constraint workspace_permission_association_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE;')
    op.execute('alter table severities_histogram drop constraint severities_histogram_workspace_id_fkey;')
    op.execute('alter table severities_histogram add constraint severities_histogram_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE;')
    op.execute('alter table reference drop constraint reference_workspace_id_fkey;')
    op.execute('alter table reference add constraint reference_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE;')
    op.execute('alter table policy_violation drop constraint policy_violation_workspace_id_fkey;')
    op.execute('alter table policy_violation add constraint policy_violation_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE;')
    op.execute('alter table command_object drop constraint command_object_workspace_id_fkey;')
    op.execute('alter table command_object add constraint command_object_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) ON DELETE CASCADE;')

    op.execute('alter table vulnerability_hit_count drop constraint vulnerability_hit_count_workspace_id_fkey;')
    op.execute('alter table vulnerability_hit_count add constraint vulnerability_hit_count_workspace_id_fkey  FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete CASCADE;')
    op.execute('alter table reference_vulnerability_association drop constraint reference_vulnerability_association_reference_id_fkey;')
    op.execute('alter table reference_vulnerability_association add constraint reference_vulnerability_association_reference_id_fkey  FOREIGN KEY (reference_id) REFERENCES reference(id) on delete CASCADE;')
    op.execute('alter table websocket_notification drop constraint websocket_notification_id_fkey;')
    op.execute('alter table websocket_notification add constraint websocket_notification_id_fkey  FOREIGN KEY (id) REFERENCES notification_base(id) on delete CASCADE;')
    op.execute('alter table notification_base drop constraint notification_base_notification_event_id_fkey;')
    op.execute('alter table notification_base add constraint notification_base_notification_event_id_fkey  FOREIGN KEY (notification_event_id) REFERENCES notification_event(id) on delete CASCADE;')
    op.execute('alter table notification_event drop constraint notification_event_workspace_id_fkey;')
    op.execute('alter table notification_event add constraint notification_event_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete CASCADE;')
    op.execute('alter table comment drop constraint comment_workspace_id_fkey;')
    op.execute('alter table comment add constraint comment_workspace_id_fkey  FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete CASCADE;')
    op.execute('alter table scope drop constraint scope_workspace_id_fkey;')
    op.execute('alter table scope add constraint scope_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete CASCADE;')

    op.execute('alter table executive_report drop constraint executive_report_workspace_id_fkey;')
    op.execute('alter table executive_report add constraint executive_report_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete CASCADE;')
    op.execute('alter table pipeline drop constraint pipeline_workspace_id_fkey;')
    op.execute('alter table pipeline add constraint pipeline_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete SET NULL;')
    op.execute('alter table agents_schedule_workspace_table drop constraint agents_schedule_workspace_table_workspace_id_fkey;')
    op.execute('alter table agents_schedule_workspace_table add constraint agents_schedule_workspace_table_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id) on delete CASCADE;')


# workspace_permission_association,  policy_violation,   websocket_notification


def downgrade():
    # perform downgrade of the previews actions
    op.execute('alter table workspace_permission_association drop constraint workspace_permission_association_workspace_id_fkey;')
    op.execute('alter table workspace_permission_association add constraint workspace_permission_association_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table severities_histogram drop constraint severities_histogram_workspace_id_fkey;')
    op.execute('alter table severities_histogram add constraint severities_histogram_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table reference drop constraint reference_workspace_id_fkey;')
    op.execute('alter table reference add constraint reference_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table policy_violation drop constraint policy_violation_workspace_id_fkey;')
    op.execute('alter table policy_violation add constraint policy_violation_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table command_object drop constraint command_object_workspace_id_fkey;')
    op.execute('alter table command_object add constraint command_object_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table vulnerability_hit_count drop constraint vulnerability_hit_count_workspace_id_fkey;')
    op.execute('alter table vulnerability_hit_count add constraint vulnerability_hit_count_workspace_id_fkey  FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table reference_vulnerability_association drop constraint reference_vulnerability_association_reference_id_fkey;')
    op.execute('alter table reference_vulnerability_association add constraint reference_vulnerability_association_reference_id_fkey  FOREIGN KEY (reference_id) REFERENCES reference(id);')
    op.execute('alter table websocket_notification drop constraint websocket_notification_id_fkey;')
    op.execute('alter table websocket_notification add constraint websocket_notification_id_fkey  FOREIGN KEY (id) REFERENCES notification_base(id);')
    op.execute('alter table notification_base drop constraint notification_base_notification_event_id_fkey;')
    op.execute('alter table notification_base add constraint notification_base_notification_event_id_fkey  FOREIGN KEY (notification_event_id) REFERENCES notification_event(id);')
    op.execute('alter table notification_event drop constraint notification_event_workspace_id_fkey;')
    op.execute('alter table notification_event add constraint notification_event_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table comment drop constraint comment_workspace_id_fkey;')
    op.execute('alter table comment add constraint comment_workspace_id_fkey  FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table scope drop constraint scope_workspace_id_fkey;')
    op.execute('alter table scope add constraint scope_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table executive_report drop constraint executive_report_workspace_id_fkey;')
    op.execute('alter table executive_report add constraint executive_report_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table pipeline drop constraint pipeline_workspace_id_fkey;')
    op.execute('alter table pipeline add constraint pipeline_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
    op.execute('alter table agents_schedule_workspace_table drop constraint agents_schedule_workspace_table_workspace_id_fkey;')
    op.execute('alter table agents_schedule_workspace_table add constraint agents_schedule_workspace_table_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES workspace(id);')
