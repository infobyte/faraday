from threading import Timer
from datetime import datetime
from faraday.server.models import db, Workspace


def update_workspace_update_date(workspace_dates_dict):
    from faraday.server.app import get_app  # pylint:disable=import-outside-toplevel
    app = get_app()
    with app.app_context():
        for workspace_id, update_date in workspace_dates_dict.items():
            db.session.query(Workspace).filter(Workspace.id == workspace_id).update(
                {Workspace.update_date: update_date},
                synchronize_session=False
            )
        db.session.commit()


def update_workspace_update_date_with_name(workspace_dates_dict):
    from faraday.server.app import get_app, logger  # pylint:disable=import-outside-toplevel
    app = get_app()
    with app.app_context():
        sorted_workspaces = sorted(workspace_dates_dict.items(), key=lambda item: item[1])  # Preserve execution order
        for workspace_name, update_date in sorted_workspaces:
            logger.debug(f"Updating workspace: {workspace_name}")
            db.session.query(Workspace).filter(Workspace.name == workspace_name).update(
                {Workspace.update_date: update_date},
                synchronize_session=False
                )
            db.session.commit()


def debounce_workspace_update(workspace_name, debouncer=None, update_date=None):
    from faraday.server.app import get_debouncer  # pylint:disable=import-outside-toplevel
    if not debouncer:
        debouncer = get_debouncer()
    if not update_date:
        update_date = datetime.utcnow()
    debouncer.debounce(update_workspace_update_date_with_name,
                       {'workspace_name': workspace_name, 'update_date': update_date})
    return debouncer


class Debouncer:

    """

    Debouncer class recieves functions (with their parameters) and delays the execution of those functions using one Timer thread.
    The function is saved in a set, so if the same function is received with the same parameters within the execution wait time,
    it will not be added to the set, and it will reset the wait time.

    Something to improve: Currently it resolves the logic for updating workspace update_date using a dictionary that saves the
    workspace_id and the last update_date for that workspace. This could resolve other update issues for other tables, adding
    another dictionary for that table with the same structure.

    """

    def __init__(self, wait=10):
        self.wait = wait
        self.timer = None
        self.actions = set()  # Dic structure: {'action':function, 'parameters': {'param1':1, 'param2':b}}
        self.update_dates = {"workspaces": {}}

    def debounce(self, action, parameters):

        """Recieves a function and a dict with its parameters, and saves them in a set.
        The dict is converted to tuple to ensure that the set overrides duplicated functions.
        As updates dates will always be different, it saves the workspaces and their update dates
        in a dict, so if the same workspace calls the update function, the previous update date will
        be overwritten. Then it uses a timer to execute the functions saved in the set."""

        if action == update_workspace_update_date_with_name:
            self.update_dates['workspaces'][parameters['workspace_name']] = parameters['update_date']
            self.actions.add(tuple({'action': action}.items()))
        else:
            self.actions.add(tuple({'action': action, 'parameters': tuple(parameters.items())}.items()))
        if self.timer:
            self.timer.cancel()

        self.timer = Timer(self.wait, self._debounced_actions)
        self.timer.start()

    def _debounced_actions(self):
        for item in self.actions:
            item = dict(item)
            action = item['action']
            if action == update_workspace_update_date_with_name:
                action(self.update_dates['workspaces'])
            else:
                parameters = dict(item['parameters'])
                action(**parameters)
        self.actions = set()
        self.update_dates = {"workspaces": {}}
