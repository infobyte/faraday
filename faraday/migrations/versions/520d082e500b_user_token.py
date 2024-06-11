"""user token

Revision ID: 520d082e500b
Revises: 27d7eff884e7
Create Date: 2024-04-25 17:58:32.826785+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '520d082e500b'
down_revision = '27d7eff884e7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user_token',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('token', sa.String(), nullable=False),
    sa.Column('alias', sa.String(), nullable=True),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.Column('scope', sa.Enum('api', 'gitlab', 'jira', name='token_scopes'), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
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
