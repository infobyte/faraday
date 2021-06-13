from flask_security.utils import hash_password, verify_password

from faraday.server.commands.change_password import changes_password
from faraday.server.models import User
from tests.factories import UserFactory


def test_changes_password_command(session):
    UserFactory.create(
        username='test_change_pass',
        password=hash_password('old_pass')
    )
    changes_password('test_change_pass', 'new_pass')

    user = User.query.filter_by(username='test_change_pass').first()

    assert not verify_password('old_pass', user.password)
    assert verify_password('new_pass', user.password)
