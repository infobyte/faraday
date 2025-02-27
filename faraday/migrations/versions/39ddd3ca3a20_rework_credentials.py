"""rework credentials

Revision ID: 39ddd3ca3a20
Revises: 618a59151523
Create Date: 2025-02-18 15:17:51.883711+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39ddd3ca3a20'
down_revision = '618a59151523'
branch_labels = None
depends_on = None


def upgrade():

    op.execute('DROP TABLE IF EXISTS credential')
    op.create_table('credential',
    sa.Column('id', sa.Integer(), nullable=False, autoincrement=True, primary_key=True),
    sa.Column('password', sa.Text(), nullable=False),
    sa.Column('username', sa.Text(), nullable=False),
    sa.Column('endpoint', sa.Text(), nullable=True),
    sa.Column('leak_date', sa.DateTime(), nullable=True),
    sa.Column('owned', sa.Boolean(), nullable=False, server_default='false'),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('create_date', sa.DateTime(), nullable=False),
    sa.Column('update_date', sa.DateTime(), nullable=False),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ondelete='CASCADE')
    )

    op.create_table('association_table_vulnerabilities_credentials',
    sa.Column('vulnerability_id', sa.Integer(), nullable=True),
    sa.Column('credential_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['credential_id'], ['credential.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerability.id'], ondelete='CASCADE')
    )


def downgrade():
    op.drop_table('association_table_vulnerabilities_credentials')
    op.drop_table('credential')
