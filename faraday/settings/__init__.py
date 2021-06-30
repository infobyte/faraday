from typing import List

from faraday.settings.base import LOADED_SETTINGS


def get_settings(name: str):
    name_key = f'{name}_settings'
    return LOADED_SETTINGS.get(name_key, None)


def get_all_settings() -> List:
    return [x.settings_id for x in LOADED_SETTINGS.values()]


def load_settings():
    from faraday.settings.smtp import init_setting as smtp_init  # pylint: disable=import-outside-toplevel
    smtp_init()
    from faraday.settings.dashboard import init_setting as dashboard_init  # pylint: disable=import-outside-toplevel
    dashboard_init()
    from faraday.settings.reports import init_setting as reports_init  # pylint: disable=import-outside-toplevel
    reports_init()
