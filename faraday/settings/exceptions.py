"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""


class MissingConfigurationError(Exception):
    """Raised when setting configuration is missing"""
    pass


class InvalidConfigurationError(Exception):
    """Raised when setting configuration is invalid"""
    pass
