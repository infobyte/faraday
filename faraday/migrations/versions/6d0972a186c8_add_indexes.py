"""add indexes

Revision ID: 6d0972a186c8
Revises: 5fecdb3d57ae
Create Date: 2026-04-02 15:23:42.699535+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = '6d0972a186c8'
down_revision = '5fecdb3d57ae'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('command', 'tasks',
               existing_type=postgresql.JSON(astext_type=sa.Text()),
               type_=JSONType(),
               existing_nullable=True)
    op.create_index('ix_command_object_command_id_type', 'command_object', ['command_id', 'object_type'], unique=False)
    op.create_index('ix_tag_object_type_object_id', 'tag_object', ['object_type', 'object_id'], unique=False)


def downgrade():
    op.drop_index('ix_tag_object_type_object_id', table_name='tag_object')
    op.drop_index('ix_command_object_command_id_type', table_name='command_object')
    op.alter_column('command', 'tasks',
               existing_type=JSONType(),
               type_=postgresql.JSON(astext_type=sa.Text()),
               existing_nullable=True)
