"""rename not active users

Revision ID: 4d7a8fdd94e4
Revises: 905261860ad0
Create Date: 2022-06-10 20:04:02.729956+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4d7a8fdd94e4'
down_revision = '99a740945c44'
branch_labels = None
depends_on = None


def upgrade():
    t_users = sa.table('faraday_user',
                       sa.column('username', sa.String),
                       sa.column('email', sa.String)
                       )

    conn = op.get_bind()
    res = conn.execute('SELECT username FROM faraday_user WHERE active = FALSE').fetchall()

    for user in res:
        op.execute(
            t_users.update().where(t_users.c.username == user[0]).values({'username': f'DELETED_USER_{user[0]}_0',
                                                                          'email': None})
        )


def downgrade():
    pass
