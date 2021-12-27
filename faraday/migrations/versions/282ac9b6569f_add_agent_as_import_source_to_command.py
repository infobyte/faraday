"""empty message

Revision ID: 282ac9b6569f
Revises: 84f266a05be3
Create Date: 2020-03-27 05:37:11.000671+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '282ac9b6569f'
down_revision = '84f266a05be3'
branch_labels = None
depends_on = None

IMPORT_SOURCE = [
        'report',
        'shell'
    ]

old_types = IMPORT_SOURCE
new_types = list(set(IMPORT_SOURCE + ['agent']))
new_options = sorted(new_types)

old_type = sa.Enum(*IMPORT_SOURCE, name='import_source_enum')
new_type = sa.Enum(*new_options, name='import_source_enum')
tmp_type = sa.Enum(*new_options, name='_import_source_enum')

cmd = sa.sql.table('command',
                   sa.Column('import_source', new_type, nullable=True))


def upgrade():
    tmp_type.create(op.get_bind(), checkfirst=False)
    op.execute('ALTER TABLE command ALTER COLUMN import_source TYPE _import_source_enum'
               ' USING import_source::text::_import_source_enum')
    old_type.drop(op.get_bind(), checkfirst=False)
    # Create and convert to the "new" status type
    new_type.create(op.get_bind(), checkfirst=False)
    op.execute('ALTER TABLE command ALTER COLUMN import_source TYPE import_source_enum'
               ' USING import_source::text::import_source_enum')
    tmp_type.drop(op.get_bind(), checkfirst=False)


def downgrade():
    # Convert 'asset_owner' status into 'client'
    op.execute(cmd.update().where(cmd.c.import_source == 'agent')
               .values(import_source=None))
    # Create a temporary "_role" type, convert and drop the "new" type
    tmp_type.create(op.get_bind(), checkfirst=False)
    op.execute('ALTER TABLE command ALTER COLUMN import_source TYPE _import_source_enum'
               ' USING import_source::text::_import_source_enum')
    new_type.drop(op.get_bind(), checkfirst=False)
    # Create and convert to the "old" role type
    old_type.create(op.get_bind(), checkfirst=False)
    op.execute('ALTER TABLE command ALTER COLUMN import_source TYPE import_source_enum'
               ' USING import_source::text::import_source_enum')
    tmp_type.drop(op.get_bind(), checkfirst=False)
