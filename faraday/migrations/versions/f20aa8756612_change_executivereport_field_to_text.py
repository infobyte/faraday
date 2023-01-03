"""change executivereport field to text

Revision ID: f20aa8756612
Revises: 699402156cf4
Create Date: 2022-11-17 20:56:30.646510+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f20aa8756612'
down_revision = '699402156cf4'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        table_name="executive_report",
        column_name="advanced_filter_parsed",
        nullable=False,
        existing_type=sa.String,
        type_=sa.Text,
    )


def downgrade():
    op.alter_column(
        table_name="executive_report",
        column_name="advanced_filter_parsed",
        nullable=False,
        existing_type=sa.Text,
        type_=sa.String,
    )
