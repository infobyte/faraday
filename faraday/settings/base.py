import logging
from functools import lru_cache
from typing import Dict, Optional
from copy import deepcopy

from faraday.settings.exceptions import InvalidConfigurationError
from faraday.server.models import (
    db,
    Configuration
)

logger = logging.getLogger(__name__)

LOADED_SETTINGS = {}


class classproperty:

    def __init__(self, fget):
        self.fget = fget

    def __get__(self, owner_self, owner_cls):
        return self.fget(owner_cls)


class Settings:
    settings_id = None
    settings_key = None

    def __init__(self):
        if self.settings_key not in LOADED_SETTINGS:
            logger.debug(f"Loading settings [{self.settings_id}]")
            LOADED_SETTINGS[self.settings_key] = self

    def load_configuration(self) -> Dict:
        from faraday.server.web import get_app   # pylint: disable=import-outside-toplevel
        with get_app().app_context():
            query = db.session.query(Configuration).filter(Configuration.key == self.settings_key).first()
            settings_config = self.get_default_config()
            if query:
                settings_config.update(query.value)
                settings_config = self.clear_configuration(settings_config)
        return settings_config

    def get_default_config(self):
        return {}

    def clear_configuration(self, config: Dict):
        return config

    def custom_validation(self, validated_config):
        pass

    def after_update(self):
        pass

    def update_configuration(self, new_config: dict, old_config: Optional[Dict] = None) -> Dict:
        if old_config:
            config = deepcopy(old_config)
            config.update(new_config)
        else:
            config = new_config
        self.after_update()
        return config

    def validate_configuration(self, config: Dict):
        valid_config = self.schema.load(config)
        try:
            self.custom_validation(valid_config)
        except InvalidConfigurationError as e:
            raise
        return valid_config

    @property
    @lru_cache
    def value(self) -> Dict:
        return self.load_configuration()

    def __getattr__(self, item):
        return self.value.get(item, None)

    @classproperty
    def settings(cls):
        return LOADED_SETTINGS.get(cls.settings_key, cls())
