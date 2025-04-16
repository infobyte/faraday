"""rework credentials

Revision ID: 39ddd3ca3a20
Revises: 618a59151523
Create Date: 2025-02-18 15:17:51.883711+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39ddd3ca3a20'
down_revision = '615a6fdd9af4'
branch_labels = None
depends_on = None


def upgrade():

    op.execute('DROP TABLE IF EXISTS credential')
    op.create_table('credential',
    sa.Column('id', sa.Integer(), nullable=False, autoincrement=True, primary_key=True),
    sa.Column('password', sa.Text(), nullable=False),
    sa.Column('username', sa.Text(), nullable=False),
    sa.Column('endpoint', sa.Text(), nullable=False, server_default=''),
    sa.Column('leak_date', sa.DateTime(), nullable=True),
    sa.Column('owned', sa.Boolean(), nullable=False, server_default='false'),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('create_date', sa.DateTime(), nullable=False),
    sa.Column('update_date', sa.DateTime(), nullable=False),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ondelete='CASCADE'),
    sa.UniqueConstraint('username', 'password', 'endpoint', 'workspace_id',
                        name='uix_credential_username_password_endpoint_workspace'),
    sa.CheckConstraint("username != ''", name="check_username_not_empty"),
    sa.CheckConstraint("password != ''", name="check_password_not_empty")
    )

    op.create_index('ix_credential_leak_date', 'credential', ['leak_date'])
    op.create_index('ix_credential_leak_date_workspace_id', 'credential', ['workspace_id', 'leak_date'])

    op.create_table('association_table_vulnerabilities_credentials',
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('credential_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['credential_id'], ['credential.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerability.id'], ondelete='CASCADE')
    )

    op.create_index('ix_association_vuln_creds_vuln_id',
                    'association_table_vulnerabilities_credentials',
                    ['vulnerability_id'])

    op.create_index('ix_association_vuln_creds_cred_id',
                    'association_table_vulnerabilities_credentials',
                    ['credential_id'])


def downgrade():
    op.drop_index('ix_association_vuln_creds_vuln_id',
                 table_name='association_table_vulnerabilities_credentials')
    op.drop_index('ix_association_vuln_creds_cred_id',
                 table_name='association_table_vulnerabilities_credentials')

    op.drop_table('association_table_vulnerabilities_credentials')

    op.drop_index('ix_credential_leak_date_workspace_id', table_name='credential')
    op.drop_index('ix_credential_leak_date', table_name='credential')
    op.drop_table('credential')
    # Recreate the old table to restore the previous schema during downgrade
    op.create_table('credential',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.Text(), nullable=False),
    sa.Column('password', sa.Text(), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('name', sa.Text(), nullable=True),
    sa.Column('host_id', sa.Integer(), nullable=True),
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['host_id'], ['host.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_id'], ['service.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint(
            'username',
            'host_id',
            'service_id',
            'workspace_id',
            name='uix_credential_username_host_service_workspace'
        )
    )
