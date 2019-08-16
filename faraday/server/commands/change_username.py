import sys
import click

from faraday.server.web import app
from faraday.server.models import User, db

def change_username(current_username, new_username):
    with app.app_context():
        user = User.query.filter_by(username=current_username).first()
        if not user:
            print("\nERROR: User '{username}' was not found in Faraday's Database.".format(username=current_username))
            sys.exit(1)
        else:
            print("\nThe user named '{old}' will be changed to '{new}'.".\
                format(old=current_username, new=new_username))
            confirm = click.prompt("Do you want to continue? (y/n)")
            print("")

            if confirm == "y":
                user.username = new_username
                db.session.add(user)
                db.session.commit()
                print("Username '{old}' changed to '{new}'" \
                    .format(old=current_username, new=new_username))
            else:
                print("Username not changed.")
