"""alter otp secret length in user

Revision ID: a4def820a5bb
Revises: 077b7c925ded
Create Date: 2021-03-17 20:23:03.864089+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4def820a5bb'
down_revision = '077b7c925ded'
branch_labels = None
depends_on = None


def upgrade():
    secrets = sa.table('faraday_user',
                       sa.column('otp_secret', sa.String),
                       sa.column('id', sa.Integer)
                       )

    conn = op.get_bind()
    res = conn.execute('SELECT otp_secret, id FROM faraday_user').fetchall()

    op.alter_column('faraday_user',
                    'otp_secret',
                    type_=sa.String(32),
                    existing_type=sa.String(16),
                    existing_nullable=True)

    for user in res:
        if user[0]:
            op.execute(
                secrets.update().where(secrets.c.id == user[1]).values({'otp_secret': user[0]})
            )


def downgrade():
    op.alter_column('faraday_user',
                    'otp_secret',
                    type_=sa.String(16),
                    existing_type=sa.String(32),
                    existing_nullable=True)
