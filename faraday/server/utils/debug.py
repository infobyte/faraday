"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import contextlib
import cProfile
import logging
import pstats
import time
from io import StringIO

debug_logger = logging.getLogger(__name__)


class Timer:
    def __init__(self, tag, logger=None):
        self.__tag = tag
        self.__logger = debug_logger if logger is None else logger

    def __enter__(self):
        self.__start = time.time()
        return self

    def __exit__(self, *args):
        self.__end = time.time()
        diff = (self.__end - self.__start) * 1000
        self.__logger.debug(f'elapsed time in {self.__tag}: {diff} ms')

#
# Debug utility extracted from http://docs.sqlalchemy.org/en/latest/faq/performance.html
#


@contextlib.contextmanager
def profiled():
    pr = cProfile.Profile()
    pr.enable()
    yield
    pr.disable()
    s = StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats()
    # uncomment this to see who's calling what
    # ps.print_callers()
    debug_logger.debug(s.getvalue())
