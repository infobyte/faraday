"""alter otp secret length in user

Revision ID: a4def820a5bb
Revises: 077b7c925ded
Create Date: 2021-03-17 20:23:03.864089+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4def820a5bb'
down_revision = 'fa12b8322112'
branch_labels = None
depends_on = None


def upgrade():

    op.alter_column('faraday_user',
                    'otp_secret',
                    type_=sa.String(32),
                    existing_type=sa.String(16),
                    existing_nullable=True)


OTP_STATES = ["disabled", "requested", "confirmed"]


def downgrade():
    print("The otp secret is going down from 32-char to 16-char length. If its actual values can't fix, "
          "we are deactivating 2FA in that user!")

    users = sa.table(
        'faraday_user',
        sa.column('otp_secret', sa.String),
        sa.column('id', sa.Integer),
        sa.Column('state_otp', sa.Enum(*OTP_STATES, 'user_otp_states')),
    )

    conn = op.get_bind()
    res = conn.execute('SELECT otp_secret, id FROM faraday_user').fetchall()

    for user in res:
        if user[0] and len(user[0]) > 16:
            op.execute(
                users.update().where(users.c.id == user[1]).values({'otp_secret': None, 'state_otp': "disabled"})
            )

    op.alter_column('faraday_user',
                    'otp_secret',
                    type_=sa.String(16),
                    existing_type=sa.String(32),
                    existing_nullable=True)
