from typing import List

from faraday.settings.base import LOADED_SETTINGS


def get_settings(name: str):
    name_key = f'{name}_settings'
    return LOADED_SETTINGS.get(name_key, None)


def get_all_settings() -> List:
    return [x.settings_id for x in LOADED_SETTINGS.values()]


def load_settings():
    import faraday.settings.smtp  # pylint: disable=import-outside-toplevel
    import faraday.settings.dashboard  # pylint: disable=import-outside-toplevel  # noqa: F401
