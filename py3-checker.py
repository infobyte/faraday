#!/usr/bin/env python3

# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

"""
Internal script used to detect if the auto-claimer v3 python files
are actually executable with python3
"""
from __future__ import absolute_import
from __future__ import print_function
from __future__ import division

import argparse
import logging
import os
import re

from pylint import epylint as lint

BLACK_LIST = ["build"]


#   Pylint code	    Message	                    Final return code
#   0	            Ok                  	    0
#   1	            Fatal message issued	    1
#   2	            Error message issued	    0
#   4	            Warning message issued	    0
#   8	            Refactor message issued	    0
#   16	            Convention message issued	0
#   32	            Usage error	                1
OK = 0
FATAL = 1
ERROR = 2
WARNING = 4
REFACTOR = 8
CONVENTION = 16
USAGE = 32

PY3_MSG = r"# I'm Py3"


def find_py3_msg(path):
    with open(path) as origin_file:
        for line in origin_file:
            line = re.search(PY3_MSG, line)
            if line:
                return True
    return False

class Analyser:

    def __init__(self):
        logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
        self.logger = logging  # TODO FIXME

    def analyse_file(self, path):
        if path[-3:] != ".py":
            return 0, 0, [], []

        find_py3_ok_result = find_py3_msg(path)
        lint_ok_result = lint.lint(path, ["--py3k"]) in [OK]
        error_list = []
        if find_py3_ok_result and not lint_ok_result:
            self.logger.error("The auto-claimed python file {path} as python is not python3".format(path=path))
            error_list.append(path)
        if not find_py3_ok_result and lint_ok_result:
            self.logger.info("The file {path} is python3, adding the signature comment in the last line".format(path=path))
            with open(path,"a+") as py3_file:
                py3_file.writelines(["\n\n", PY3_MSG, "\n"])

        if not lint_ok_result:
            self.logger.info("The file {path} is python2".format(path=path))
        return 1 if lint_ok_result else 0, 1, [], error_list

    def analyse_folder(self, parent_path):
        are3, total, strs, error_files = 0, 0, [], []
        for subpath in os.listdir(parent_path):
            if subpath[0] != '.' and subpath not in BLACK_LIST:
                path = os.path.join(parent_path, subpath)
                s_are3, s_total, s_strs, s_error_files = \
                    self.analyse_folder(path) \
                    if not os.path.isfile(path) \
                    else self.analyse_file(path)
                are3 += s_are3
                total += s_total
                strs.extend(s_strs)
                error_files.extend(s_error_files)
        if 0 < total:
            strs.append('Analysed {path}, {are3}/{total} {prtg}%'
                        .format(path=parent_path, are3=are3, total=total, prtg=100.0*are3/total))
        return are3, total, strs, error_files

    def run(self):
        _, _, strs, error_files = self.analyse_folder(os.getcwd())
        for s in strs:
            self.logger.info(s)
        if len(error_files) > 0:
            for error_file in error_files:
                self.logger.error("The auto-claimed python file {path} as python is not python3".format(path=error_file))
            raise Exception("One or more auto-claimed python file(s) as python is(are) not python3")


def main(filename):
    PYTLINT = ".pylintrc"
    RENAMED = ".to_be_renamed"
    os.rename(PYTLINT, RENAMED)

    if filename:
        import sys
        sys.stdout = open(filename, 'w')
    try:
        Analyser().run()
    finally:
        os.rename(RENAMED, PYTLINT)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--only-coverage', default=False)
    parser.add_argument('-l', '--log-level', default='debug')
    parser.add_argument('-o', '--output-file', dest='filename', default=None)
    args = parser.parse_args()
    import time
    t = time.time()
    main(args.filename)
    print(t - time.time())


# pylint --py3k