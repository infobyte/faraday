"""add risk score profile

Introduces the risk_score_profile catalog table (Risk Score Profiles epic):
a reusable, named set of severity_base + multiplier values assignable to
workspaces, replacing the single global risk-score configuration approach.

Seeds a single immutable "Faraday Default" profile with the historical
hardcoded values from faraday/enrichment/enrichment.py, and backfills every
existing workspace to use it (workspace.risk_score_profile_id is NOT NULL).

MAX_RISK, MULTIPLIER_CAP and RISK_SEVERITY_THRESHOLDS are intentionally not
part of this table: they remain hardcoded invariants regardless of profile.

Revision ID: 73198eab4b2a
Revises: f3a8c1d0b9e2
Create Date: 2026-09-08 18:29:23.004679+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '73198eab4b2a'
down_revision = 'f3a8c1d0b9e2'
branch_labels = None
depends_on = None

# Historical defaults, copied here rather than imported so this migration keeps working
# even if the constants in faraday/enrichment/enrichment.py change or are removed later.
DEFAULT_PROFILE_NAME = 'Faraday Default'
DEFAULT_PROFILE_DESCRIPTION = (
    "Default risk score profile shipped by Faraday. Immutable: cannot be edited or deleted."
)
SEVERITY_BASE_CRITICAL = 93
SEVERITY_BASE_HIGH = 76
SEVERITY_BASE_MEDIUM = 42
SEVERITY_BASE_LOW = 12
SEVERITY_BASE_INFORMATIONAL = 2
CONFIRMED_MULTIPLIER = 1.15
CISA_MULTIPLIER = 1.25
EXPLOIT_MULTIPLIER = 1.15
TRENDING_MULTIPLIER = 1.07
INTERNET_FACING_MULTIPLIER = 1.20
ATTACK_VECTOR_MULTIPLIER = 1.15
IMPORTANT_HOST_MULTIPLIER = 1.10


def upgrade():
    op.create_table(
        'risk_score_profile',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('is_system_default', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('severity_base_critical', sa.Float(), nullable=False),
        sa.Column('severity_base_high', sa.Float(), nullable=False),
        sa.Column('severity_base_medium', sa.Float(), nullable=False),
        sa.Column('severity_base_low', sa.Float(), nullable=False),
        sa.Column('severity_base_informational', sa.Float(), nullable=False),
        sa.Column('confirmed_multiplier', sa.Float(), nullable=False),
        sa.Column('cisa_multiplier', sa.Float(), nullable=False),
        sa.Column('exploit_multiplier', sa.Float(), nullable=False),
        sa.Column('trending_multiplier', sa.Float(), nullable=False),
        sa.Column('internet_facing_multiplier', sa.Float(), nullable=False),
        sa.Column('attack_vector_multiplier', sa.Float(), nullable=False),
        sa.Column('important_host_multiplier', sa.Float(), nullable=False),
        sa.Column('creator_id', sa.Integer(), nullable=True),
        sa.Column('update_user_id', sa.Integer(), nullable=True),
        sa.Column('create_date', sa.DateTime(), nullable=True),
        sa.Column('update_date', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name', name='uix_risk_score_profile_name'),
    )

    op.execute(
        "INSERT INTO risk_score_profile ("  # nosec B608
        "name, description, is_system_default, "
        "severity_base_critical, severity_base_high, severity_base_medium, "
        "severity_base_low, severity_base_informational, "
        "confirmed_multiplier, cisa_multiplier, exploit_multiplier, trending_multiplier, "
        "internet_facing_multiplier, attack_vector_multiplier, important_host_multiplier"
        ") VALUES ("
        f"'{DEFAULT_PROFILE_NAME}', '{DEFAULT_PROFILE_DESCRIPTION}', true, "
        f"{SEVERITY_BASE_CRITICAL}, {SEVERITY_BASE_HIGH}, {SEVERITY_BASE_MEDIUM}, "
        f"{SEVERITY_BASE_LOW}, {SEVERITY_BASE_INFORMATIONAL}, "
        f"{CONFIRMED_MULTIPLIER}, {CISA_MULTIPLIER}, {EXPLOIT_MULTIPLIER}, {TRENDING_MULTIPLIER}, "
        f"{INTERNET_FACING_MULTIPLIER}, {ATTACK_VECTOR_MULTIPLIER}, {IMPORTANT_HOST_MULTIPLIER})"
    )

    op.add_column('workspace', sa.Column('risk_score_profile_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'workspace_risk_score_profile_id_fkey', 'workspace', 'risk_score_profile',
        ['risk_score_profile_id'], ['id'],
    )
    op.create_index(
        op.f('ix_workspace_risk_score_profile_id'), 'workspace', ['risk_score_profile_id'],
    )

    op.execute(
        "UPDATE workspace SET risk_score_profile_id = "  # nosec B608
        f"(SELECT id FROM risk_score_profile WHERE name = '{DEFAULT_PROFILE_NAME}') "
        "WHERE risk_score_profile_id IS NULL"
    )
    op.alter_column('workspace', 'risk_score_profile_id', nullable=False)

    op.add_column('faraday_user', sa.Column('default_risk_score_profile_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'faraday_user_default_risk_score_profile_id_fkey', 'faraday_user', 'risk_score_profile',
        ['default_risk_score_profile_id'], ['id'], ondelete='SET NULL',
    )


def downgrade():
    op.drop_constraint('faraday_user_default_risk_score_profile_id_fkey', 'faraday_user', type_='foreignkey')
    op.drop_column('faraday_user', 'default_risk_score_profile_id')

    op.drop_index(op.f('ix_workspace_risk_score_profile_id'), table_name='workspace')
    op.drop_constraint('workspace_risk_score_profile_id_fkey', 'workspace', type_='foreignkey')
    op.drop_column('workspace', 'risk_score_profile_id')

    op.drop_table('risk_score_profile')
