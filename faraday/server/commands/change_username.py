"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import sys

# Related third party imports
import click

# Local application imports
from faraday.server.models import User, db
from faraday.server.web import get_app


def change_username(current_username, new_username):
    with get_app().app_context():
        user = User.query.filter_by(username=current_username).first()
        if not user:
            print(f"\nERROR: User {current_username} was not found in Faraday's Database.")
            sys.exit(1)
        else:
            print(f"\nThe user named {current_username} will be changed to {new_username}.")
            confirm = click.prompt("Do you want to continue? (y/n)")
            print("")

            if confirm == "y":
                user.username = new_username
                db.session.add(user)
                db.session.commit()
                print(f"Username {current_username} changed to {new_username}")
            else:
                print("Username not changed.")
