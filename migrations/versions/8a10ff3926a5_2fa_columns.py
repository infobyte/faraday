"""empty message

Revision ID: 8a10ff3926a5
Revises:
Create Date: 2018-11-29 16:34:44.081899+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8a10ff3926a5'
down_revision = 'e61afb450465'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('faraday_user', sa.Column('otp_secret', sa.String(16)))
    op.execute("CREATE TYPE user_otp_states AS ENUM('disabled', 'requested', 'confirmed')")
    op.add_column('faraday_user', sa.Column(
        'state_otp',
        sa.Enum(("disabled", "requested", "confirmed"), name='user_otp_states'),
        nullable=False,
        server_default='disabled'))


def downgrade():
    op.drop_column('faraday_user', 'otp_secret')
    op.drop_column('faraday_user', 'state_otp')
    op.execute('DROP TYPE user_otp_states')
