"""add tool column to vuln

Revision ID: 84f266a05be3
Revises: 2a0de6132377
Create Date: 2019-11-28 15:19:31.097481+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '84f266a05be3'
down_revision = 'a39a3a6e3f99'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('vulnerability', sa.Column(
        'tool',
        sa.Text(),
        nullable=False,
        server_default=""
    )
                  )
    conn = op.get_bind()
    conn.execute("""UPDATE vulnerability
SET tool=SUBQUERY.tool
FROM (select v.id, c.tool from vulnerability v, command_object co, command c where v.id = co.object_id and co.object_type = 'vulnerability' and co.command_id = c.id) AS SUBQUERY
WHERE vulnerability.id=SUBQUERY.id""")
    conn.execute("UPDATE vulnerability set tool='Web UI' where tool=''")


def downgrade():
    op.drop_column('vulnerability', 'tool')
