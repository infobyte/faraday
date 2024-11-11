"""custom roles

Revision ID: f97cce2cf15c
Revises: 4423dd3f90be
Create Date: 2024-11-11 19:28:38.706850+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f97cce2cf15c'
down_revision = '4423dd3f90be'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'method',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'module',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'endpoint',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('path', sa.String(), nullable=False),
        sa.Column('module_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['module_id'], ['module.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_endpoint_module_id'), 'endpoint', ['module_id'], unique=False)
    op.create_table(
        'endpoint_method_association',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('endpoint_id', sa.Integer(), nullable=False),
        sa.Column('method_id', sa.Integer(), nullable=False),
        sa.Column('display_name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['endpoint_id'], ['endpoint.id'], ),
        sa.ForeignKeyConstraint(['method_id'], ['method.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_endpoint_method_association_endpoint_id'), 'endpoint_method_association', ['endpoint_id'], unique=False)
    op.create_index(op.f('ix_endpoint_method_association_method_id'), 'endpoint_method_association', ['method_id'], unique=False)
    op.create_table(
        'role_permission',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('endpoint_method_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('allowed', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['endpoint_method_id'], ['endpoint_method_association.id'], ),
        sa.ForeignKeyConstraint(['role_id'], ['faraday_role.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_role_permission_endpoint_method_id'), 'role_permission', ['endpoint_method_id'], unique=False)
    op.create_index(op.f('ix_role_permission_role_id'), 'role_permission', ['role_id'], unique=False)
    op.add_column('faraday_role', sa.Column('custom', sa.Boolean(), nullable=False, server_default='f'))


def downgrade():
    op.drop_column('faraday_role', 'custom')
    op.drop_index(op.f('ix_role_permission_role_id'), table_name='role_permission')
    op.drop_index(op.f('ix_role_permission_endpoint_method_id'), table_name='role_permission')
    op.drop_table('role_permission')
    op.drop_index(op.f('ix_endpoint_method_association_method_id'), table_name='endpoint_method_association')
    op.drop_index(op.f('ix_endpoint_method_association_endpoint_id'), table_name='endpoint_method_association')
    op.drop_table('endpoint_method_association')
    op.drop_index(op.f('ix_endpoint_module_id'), table_name='endpoint')
    op.drop_table('endpoint')
    op.drop_table('module')
    op.drop_table('method')
