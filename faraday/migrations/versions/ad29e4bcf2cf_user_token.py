"""user token

Revision ID: ad29e4bcf2cf
Revises: 97e308761de2
Create Date: 2024-07-23 20:15:17.676850+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ad29e4bcf2cf'
down_revision = '97e308761de2'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user_token',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(), nullable=False),
    sa.Column('alias', sa.String(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('scope', sa.Enum('gitlab', name='token_scopes'), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('hide', sa.Boolean(), nullable=False),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['faraday_user.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token')
    )
    op.create_index(op.f('ix_user_token_user_id'), 'user_token', ['user_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_user_token_user_id'), table_name='user_token')
    op.drop_table('user_token')
    op.execute("DROP TYPE token_scopes")
