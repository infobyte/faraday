"""create searcher's tables

Revision ID: 085188e0a016
Revises: 2db31733fb78
Create Date: 2019-06-18 18:07:41.834191+00:00

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '085188e0a016'
down_revision = '9c4091d1a09b'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'rule',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('model', sa.String, nullable=False),
        sa.Column('object_parent', sa.String, nullable=True),
        sa.Column('fields', sa.JSON, nullable=True),
        sa.Column('object', sa.JSON, nullable=False),
        sa.Column('workspace_id', sa.Integer, nullable=False),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer, nullable=True)
    )

    op.create_foreign_key(
        'rule_creator_id_fkey',
        'rule',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'rule_update_user_id_fkey',
        'rule',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_foreign_key(
        'rule_workspace_id_fkey',
        'rule',
        'workspace', ['workspace_id'], ['id']
    )

    op.create_table(
        'action',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String, nullable=True),
        sa.Column('command', sa.String, nullable=False),
        sa.Column('field', sa.String, nullable=True),
        sa.Column('value', sa.String, nullable=True),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer, nullable=True)
    )

    op.create_foreign_key(
        'action_creator_id_fkey',
        'action',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'action_update_user_id_fkey',
        'action',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_table(
        'rule_action',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('rule_id', sa.Integer),
        sa.Column('action_id', sa.Integer),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer, nullable=True)
    )

    op.create_foreign_key(
        'rule_action_creator_id_fkey',
        'rule_action',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'rule_action_update_user_id_fkey',
        'rule_action',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_foreign_key(
        'rule_action_rule_id_fkey',
        'rule_action',
        'rule', ['rule_id'], ['id']
    )

    op.create_foreign_key(
        'rule_action_action_id_fkey',
        'rule_action',
        'action', ['action_id'], ['id']
    )

    op.create_unique_constraint("rule_action_uc", "rule_action", ["rule_id", "action_id"])

    op.create_table(
        'condition',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('field', sa.String, nullable=False),
        sa.Column('value', sa.String, nullable=False),
        sa.Column('operator', sa.String, nullable=True),
        sa.Column('rule_id', sa.Integer, nullable=False),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer, nullable=True)
    )

    op.create_foreign_key(
        'condition_creator_id_fkey',
        'condition',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'condition_update_user_id_fkey',
        'condition',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_foreign_key(
        'condition_rule_id_fkey',
        'condition',
        'rule', ['rule_id'], ['id']
    )

    op.create_table(
        'rule_execution',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('rule_id', sa.Integer, nullable=False),
        sa.Column('command_id', sa.Integer, nullable=False),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer, nullable=True)
    )

    op.create_foreign_key(
        'rule_execution_creator_id_fkey',
        'rule_execution',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'rule_execution_update_user_id_fkey',
        'rule_execution',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_foreign_key(
        'rule_execution_rule_id_fkey',
        'rule_execution',
        'rule', ['rule_id'], ['id']
    )

    op.create_foreign_key(
        'rule_execution_command_id_fkey',
        'rule_execution',
        'command', ['command_id'], ['id']
    )


def downgrade():
    op.drop_table('rule_execution')
    op.drop_table('condition')
    op.drop_table('rule_action')
    op.drop_table('action')
    op.drop_table('rule')
