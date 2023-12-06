from gunicorn.app.base import BaseApplication


class GunicornApp(BaseApplication):
    """Convert a Flask application to a Gunicorn one.
    """

    def __init__(self, flask_app, settings=None):
        """Initialize GunicornApp.

        If no settings are provided the class is initialized using the
        documented default parameters in
        http://docs.gunicorn.org/en/stable/settings.html#config-file.

        Args:
            flask_app (flask.app.Flask): Application to be wrapped by
                gunicorn.
            settings (dict): Settings defining the configuration to use
                when lounching the gunicorn application. If any setting
                is missing, the corresponding the default value is used.
        """
        self.flask_app = flask_app
        self.settings = settings or {}
        super().__init__()

    def load_config(self):
        """Update application configuration with given parameters.

        We update element by element instead of using dict.update()
        because we want the method to fail if a setting was given in
        the __init__ which does not exist or it is misspelled.
        """
        for k, v in self.settings.items():
            self.cfg.set(k, v)

    def load(self):
        return self.flask_app
