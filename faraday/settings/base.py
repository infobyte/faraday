"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
import os
import signal
from copy import deepcopy
from functools import lru_cache
from typing import Dict, Optional

from flask import current_app

# Local application imports
from faraday.server.models import (
    db,
    Configuration
)
from faraday.server.utils.database import get_or_create

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
    must_restart_threads = False

    def __init__(self):
        if self.settings_key not in LOADED_SETTINGS:
            logger.debug(f"Loading settings [{self.settings_id}]")
            LOADED_SETTINGS[self.settings_key] = self

    def load_configuration(self) -> Dict:
        with current_app.app_context():
            query = db.session.query(Configuration).filter(Configuration.key == self.settings_key).first()
            settings_config = self.get_default_config()
            if query:
                settings_config.update(query.value)
                settings_config = self.clear_configuration(settings_config)
        return settings_config

    def delete_configuration(self):
        from faraday.server.app import get_app   # pylint: disable=import-outside-toplevel
        with get_app().app_context():
            db.session.query(Configuration).filter(Configuration.key == self.settings_key).delete()
            db.session.commit()
            self.__class__.value.fget.cache_clear()

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
        self.custom_validation(valid_config)
        return valid_config

    @property
    @lru_cache(maxsize=None)
    def value(self) -> Dict:
        return self.load_configuration()

    def __getattr__(self, item):
        return self.value.get(item, None)

    @classproperty
    def settings(cls):
        return LOADED_SETTINGS.get(cls.settings_key, cls())

    def update(self, new_config=None):
        saved_config, created = get_or_create(db.session, Configuration, key=self.settings_key)
        if created:
            saved_config.value = self.update_configuration(new_config)
        else:
            # SQLAlchemy doesn't detect in-place mutations to the structure of a JSON type.
            # Thus, we make a deepcopy of the JSON so SQLAlchemy can detect the changes.
            saved_config.value = self.update_configuration(new_config, saved_config.value)
        db.session.commit()
        self.__class__.value.fget.cache_clear()
        if self.must_restart_threads:
            os.kill(os.getpid(), signal.SIGUSR1)
