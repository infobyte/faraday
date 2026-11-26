import importlib.util
from datetime import datetime

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text

from faraday.server.config import FARADAY_BASE
from faraday.server.models import VulnerabilityStatusHistory
from faraday.server.utils.triage import build_history_rows
from tests.factories import VulnerabilityFactory

MIGRATION_PATH = FARADAY_BASE / 'migrations' / 'versions' / '2820045ab99e_fix_status_history_status_enum.py'


def run_upgrade(session):
    spec = importlib.util.spec_from_file_location('fix_status_history_status_enum', MIGRATION_PATH)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    with Operations.context(MigrationContext.configure(session.connection())):
        migration.upgrade()


def status_column_type(session):
    return session.execute(text(
        "SELECT udt_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() "
        "AND table_name = 'vulnerability_status_history' AND column_name = 'status'"
    )).scalar()


def history_storage(session):
    return session.execute(text(
        "SELECT relfilenode FROM pg_class WHERE oid = 'vulnerability_status_history'::regclass"
    )).scalar()


def as_left_by_the_migrations(session):
    """Type the column as eb9b98d0b4d0 did, without the model's enum type."""
    session.execute(text(
        "ALTER TABLE vulnerability_status_history "
        "ALTER COLUMN status TYPE vulnerability_statuses USING status::text::vulnerability_statuses"
    ))
    session.execute(text("DROP TYPE vulnerability_status_history_statuses"))


class TestStatusHistoryEnumMigration:

    def test_upgraded_database_records_several_changes_at_once(self, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.commit()
        as_left_by_the_migrations(session)

        run_upgrade(session)

        assert status_column_type(session) == 'vulnerability_status_history_statuses'
        # Rows with the same columns are inserted in one statement that casts to the model's enum type
        events = [('confirmed', True), ('false_positive', False), ('status', 're-opened')]
        session.add_all([
            VulnerabilityStatusHistory(**row)
            for row in build_history_rows({vuln.id: events}, None, datetime.utcnow())
        ])
        session.commit()
        assert [
            (row.field, row.status, row.value)
            for row in session.query(VulnerabilityStatusHistory)
            .filter_by(vulnerability_id=vuln.id)
            .order_by(VulnerabilityStatusHistory.id)
        ] == [('confirmed', None, True), ('false_positive', None, False), ('status', 're-opened', None)]

    def test_existing_history_keeps_its_statuses(self, session, workspace):
        vuln = VulnerabilityFactory.create(workspace=workspace)
        session.add_all([
            VulnerabilityStatusHistory(vulnerability_id=vuln.id, status=status)
            for status in ('open', 'closed', 're-opened', 'risk-accepted')
        ])
        session.add(VulnerabilityStatusHistory(vulnerability_id=vuln.id, field='confirmed', value=True))
        session.commit()
        as_left_by_the_migrations(session)

        run_upgrade(session)

        rows = session.execute(text(
            "SELECT field::text, status::text, value FROM vulnerability_status_history "
            "WHERE vulnerability_id = :id ORDER BY id"
        ), {'id': vuln.id}).all()
        assert [tuple(row) for row in rows] == [
            ('status', 'open', None),
            ('status', 'closed', None),
            ('status', 're-opened', None),
            ('status', 'risk-accepted', None),
            ('confirmed', None, True),
        ]

    def test_database_created_with_initdb_is_left_untouched(self, session):
        storage = history_storage(session)

        run_upgrade(session)

        assert status_column_type(session) == 'vulnerability_status_history_statuses'
        assert history_storage(session) == storage
