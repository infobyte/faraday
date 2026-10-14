from sqlalchemy import text

from faraday.server.models import UserNotification
from tests.factories import UserFactory


def test_latest_notifications_query_uses_user_id_id_index(session):
    users = UserFactory.create_batch(200)
    session.commit()
    user_ids = [user.id for user in users]
    session.execute(
        text("INSERT INTO user_notification (message, type, subtype, user_id, event_date, read) "
             "SELECT 'msg', 'vulnerabilities', 'new', (:user_ids)[1 + i % 200], now(), false "
             "FROM generate_series(1, 10000) AS i"),
        {'user_ids': user_ids},
    )
    session.execute(text('ANALYZE user_notification'))
    session.execute(text('SET LOCAL enable_seqscan = off'))

    query = UserNotification.query.filter(
        UserNotification.user_id == user_ids[0]
    ).order_by(UserNotification.id.desc()).limit(4)
    compiled = query.statement.compile(dialect=session.get_bind().dialect,
                                       compile_kwargs={'literal_binds': True})
    plan = '\n'.join(row[0] for row in session.execute(text(f'EXPLAIN {compiled}')))

    assert 'Index Scan Backward using ix_user_notification_user_id_id' in plan
    assert 'Filter' not in plan
