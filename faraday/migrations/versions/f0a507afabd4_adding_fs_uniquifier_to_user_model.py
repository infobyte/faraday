"""adding fs uniquifier to user model

Revision ID: f0a507afabd4
Revises: a4def820a5bb
Create Date: 2021-02-24 22:08:24.237037+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f0a507afabd4'
down_revision = 'a4def820a5bb'
branch_labels = None
depends_on = None


def upgrade():
    # be sure to MODIFY this line to make nullable=True:
    op.add_column('faraday_user', sa.Column('fs_uniquifier', sa.String(length=64), nullable=True))

    # update existing rows with unique fs_uniquifier
    import uuid
    user_table = sa.Table('faraday_user', sa.MetaData(), sa.Column('id', sa.Integer, primary_key=True),
                          sa.Column('fs_uniquifier', sa.String))
    conn = op.get_bind()
    for row in conn.execute(sa.select([user_table.c.id])):
        conn.execute(user_table.update().values(fs_uniquifier=uuid.uuid4().hex).where(user_table.c.id == row['id']))

    # finally - set nullable to false
    op.alter_column('faraday_user', 'fs_uniquifier', nullable=False)


def downgrade():
    op.drop_column(
        'faraday_user',
        'fs_uniquifier',
    )
