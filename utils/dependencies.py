'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import sys
try:
    from pip import main
except ImportError:
    # pip 10 compat
    from pip._internal import main
import pkg_resources


def check_dependencies(requirements_file='requirements.txt'):
    dependencies_file = open(requirements_file, 'r')
    filtered_deps = [x for x in dependencies_file.readlines() if not
    x.startswith('git+')]

    requirements = list(pkg_resources.parse_requirements(filtered_deps))

    installed = []
    missing = []
    conflict = []

    for package in requirements:
        try:
            pkg_resources.working_set.resolve([package])
            installed += [package]
        except pkg_resources.DistributionNotFound:
            missing += [package.key]
        except pkg_resources.VersionConflict:
            conflict += [package.key]

    return installed, missing, conflict


def install_packages(packages):
    for package in packages:
        pip_cmd = ['install', package, '-U']
        if not hasattr(sys, 'real_prefix'):
            pip_cmd.append('--user')
        main(pip_cmd)
