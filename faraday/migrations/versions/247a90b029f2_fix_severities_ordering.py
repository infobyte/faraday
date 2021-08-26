"""Fix severities ordering

Revision ID: 247a90b029f2
Revises: a9fcf8444c79
Create Date: 2021-08-02 12:52:34.453541+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '247a90b029f2'
down_revision = 'a9fcf8444c79'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE vulnerability_severity rename to vulnerability_severity_temporal")
    op.execute("CREATE TYPE vulnerability_severity AS ENUM ("
               " 'unclassified', 'informational', 'low', 'medium', 'high', 'critical')")
    op.execute("ALTER TABLE vulnerability_template ALTER severity TYPE vulnerability_severity "
               "USING severity::TEXT::vulnerability_severity")
    op.execute("ALTER TABLE vulnerability ALTER severity TYPE vulnerability_severity "
               "USING severity::TEXT::vulnerability_severity")
    op.execute("DROP TYPE vulnerability_severity_temporal")


def downgrade():
    op.execute("ALTER TYPE vulnerability_severity rename to vulnerability_severity_temporal")
    op.execute("CREATE TYPE vulnerability_severity AS ENUM ("
               " 'critical', 'high', 'medium', 'low', 'informational', 'unclassified' )")
    op.execute("ALTER TABLE vulnerability_template ALTER severity TYPE vulnerability_severity"
               " USING severity::TEXT::vulnerability_severity")
    op.execute("ALTER TABLE vulnerability ALTER severity TYPE vulnerability_severity"
               " USING severity::TEXT::vulnerability_severity")
    op.execute("DROP TYPE vulnerability_severity_temporal")
