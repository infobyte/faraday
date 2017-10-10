from flask_script import Command

from server.web import app


class AppUrls(Command):
    def run(self):
        print(app.url_map)