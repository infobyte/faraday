from server.web import app


def show_all_urls():
    print(app.url_map)