"""empty message

Revision ID: 38bb251889e6
Revises: 15d70093d262
Create Date: 2021-07-30 02:12:00.706416+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '38bb251889e6'
down_revision = '15d70093d262'
branch_labels = None
depends_on = None


def upgrade():

    # Agent table
    op.drop_constraint('executor_agent_id_fkey', 'executor')
    op.create_foreign_key(
        'executor_agent_id_fkey',
        'executor',
        'agent', ['agent_id'], ['id'],
        ondelete='CASCADE'
    )
    op.drop_constraint('association_workspace_and_agents_table_agent_id_fkey',
                       'association_workspace_and_agents_table')
    op.create_foreign_key(
        'association_workspace_and_agents_table_agent_id_fkey',
        'association_workspace_and_agents_table',
        'agent', ['agent_id'], ['id'],
        ondelete='CASCADE'
    )

    # Vulnerability_template table
    op.drop_constraint('knowledge_base_vulnerability_template_id_fkey',
                       'knowledge_base')
    op.create_foreign_key(
        'knowledge_base_vulnerability_template_id_fkey', 'knowledge_base',
        'vulnerability_template', ['vulnerability_template_id'], ['id'],
        ondelete='CASCADE'
    )

    # Comment table
    op.drop_constraint('comment_reply_to_id_fkey',
                       'comment')
    op.create_foreign_key(
        'comment_reply_to_id_fkey', 'comment',
        'comment', ['reply_to_id'], ['id'],
        ondelete='SET NULL'
    )

    # Service table
    op.drop_constraint('credential_service_id_fkey', 'credential')
    op.create_foreign_key(
        'credential_service_id_fkey', 'credential',
        'service', ['service_id'], ['id'],
        ondelete='CASCADE'
    )

    # Command table
    op.drop_constraint('command_object_command_id_fkey', 'command_object')
    op.create_foreign_key(
        'command_object_command_id_fkey', 'command_object',
        'command', ['command_id'], ['id'],
        ondelete='SET NULL'
    )
    op.drop_constraint('agent_execution_command_id_fkey', 'agent_execution')
    op.create_foreign_key(
        'agent_execution_command_id_fkey', 'agent_execution',
        'command', ['command_id'], ['id'],
        ondelete='SET NULL'
    )
    op.drop_constraint('rule_execution_command_id_fkey', 'rule_execution')
    op.create_foreign_key(
        'rule_execution_command_id_fkey', 'rule_execution',
        'command', ['command_id'], ['id'],
        ondelete='CASCADE'
    )

    # Host table
    op.drop_constraint('hostname_host_id_fkey', 'hostname')
    op.create_foreign_key(
        'hostname_host_id_fkey', 'hostname',
        'host', ['host_id'], ['id'],
        ondelete='CASCADE'
    )
    op.drop_constraint('service_host_id_fkey', 'service')
    op.create_foreign_key(
        'service_host_id_fkey', 'service',
        'host', ['host_id'], ['id'],
        ondelete='CASCADE'
    )
    op.drop_constraint('vulnerability_host_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_host_id_fkey', 'vulnerability',
        'host', ['host_id'], ['id'],
        ondelete='CASCADE'
    )
    op.drop_constraint('credential_host_id_fkey', 'credential')
    op.create_foreign_key(
        'credential_host_id_fkey', 'credential',
        'host', ['host_id'], ['id'],
        ondelete='CASCADE'
    )

    # Vulnerability Table
    op.drop_constraint('vulnerability_vulnerability_duplicate_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_vulnerability_duplicate_id_fkey', 'vulnerability',
        'vulnerability', ['vulnerability_duplicate_id'], ['id'],
        ondelete='SET NULL'
    )

    # VulnerabilityTemplate Table
    op.drop_constraint('vulnerability_vulnerability_template_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_vulnerability_template_id_fkey', 'vulnerability',
        'vulnerability_template', ['vulnerability_template_id'], ['id'],
        ondelete='SET NULL'
    )

    # SourceCode Table
    op.drop_constraint('vulnerability_source_code_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_source_code_id_fkey', 'vulnerability',
        'source_code', ['source_code_id'], ['id'],
        ondelete='CASCADE'
    )


def downgrade():

    # Agent table
    op.drop_constraint('executor_agent_id_fkey',
                       'executor')
    op.create_foreign_key(
        'executor_agent_id_fkey',
        'executor',
        'agent', ['agent_id'], ['id']
    )
    op.drop_constraint('association_workspace_and_agents_table_agent_id_fkey',
                       'association_workspace_and_agents_table')
    op.create_foreign_key(
        'association_workspace_and_agents_table_agent_id_fkey',
        'association_workspace_and_agents_table',
        'agent', ['agent_id'], ['id']
    )

    # Vulnerability_template table
    op.drop_constraint('knowledge_base_vulnerability_template_id_fkey',
                       'knowledge_base')
    op.create_foreign_key(
        'knowledge_base_vulnerability_template_id_fkey', 'knowledge_base',
        'vulnerability_template', ['vulnerability_template_id'], ['id']
    )

    # Comment table
    op.drop_constraint('comment_reply_to_id_fkey',
                       'comment')
    op.create_foreign_key(
        'comment_reply_to_id_fkey', 'comment',
        'comment', ['reply_to_id'], ['id']
    )

    # Service table
    op.drop_constraint('credential_service_id_fkey', 'credential')
    op.create_foreign_key(
        'credential_service_id_fkey', 'credential',
        'service', ['service_id'], ['id']
    )

    # Command table
    op.drop_constraint('command_object_command_id_fkey', 'command_object')
    op.create_foreign_key(
        'command_object_command_id_fkey', 'command_object',
        'command', ['command_id'], ['id']
    )
    op.drop_constraint('agent_execution_command_id_fkey', 'agent_execution')
    op.create_foreign_key(
        'agent_execution_command_id_fkey', 'agent_execution',
        'command', ['command_id'], ['id']
    )
    op.drop_constraint('rule_execution_command_id_fkey', 'rule_execution')
    op.create_foreign_key(
        'rule_execution_command_id_fkey', 'rule_execution',
        'command', ['command_id'], ['id']
    )

    # Host table
    op.drop_constraint('credential_host_id_fkey', 'credential')
    op.create_foreign_key(
        'credential_host_id_fkey', 'credential',
        'host', ['host_id'], ['id']
    )
    op.drop_constraint('hostname_host_id_fkey', 'hostname')
    op.create_foreign_key(
        'hostname_host_id_fkey', 'hostname',
        'host', ['host_id'], ['id']
    )
    op.drop_constraint('service_host_id_fkey', 'service')
    op.create_foreign_key(
        'service_host_id_fkey', 'service',
        'host', ['host_id'], ['id']
    )
    op.drop_constraint('vulnerability_host_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_host_id_fkey', 'vulnerability',
        'host', ['host_id'], ['id']
    )

    op.drop_constraint('vulnerability_vulnerability_duplicate_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_vulnerability_duplicate_id_fkey', 'vulnerability',
        'vulnerability', ['vulnerability_duplicate_id'], ['id']
    )

    # VulnerabilityTemplate Table
    op.drop_constraint('vulnerability_vulnerability_template_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_vulnerability_template_id_fkey', 'vulnerability',
        'vulnerability_template', ['vulnerability_template_id'], ['id']
    )

    # SourceCode Table
    op.drop_constraint('vulnerability_source_code_id_fkey', 'vulnerability')
    op.create_foreign_key(
        'vulnerability_source_code_id_fkey', 'vulnerability',
        'source_code', ['source_code_id'], ['id']
    )
