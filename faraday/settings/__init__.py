from typing import List

from faraday.settings.base import LOADED_SETTINGS


def get_settings(name: str):
    name_key = f'{name}_settings'
    return LOADED_SETTINGS.get(name_key, None)


def get_all_settings() -> List:
    return list(map(lambda x: x.settings_id, LOADED_SETTINGS.values()))


def load_settings():
    import faraday.settings.smtp  # pylint: disable=import-outside-toplevel noqa: F401
    import faraday.settings.dashboard  # pylint: disable=import-outside-toplevel  # noqa: F401
