'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pip
import pkg_resources


class DependencyChecker(object):
    def __init__(self, requirements_file):
        self.mandatory = []
        self.optional = []

        dependencies_file = open(requirements_file, 'r')

        for line in dependencies_file:
            if line.find('#') > -1:
                # Optional dependencies after the '#' character
                break
            self.mandatory.append(line.strip())

        for line in dependencies_file:
            self.optional.append(line.strip())

        dependencies_file.close()

    def __check_dependency(self, package):
        try:
            pkg_resources.require(package)
            return True
        except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
            return False

    def check_dependencies(self, with_optional=True):
        print "Checking dependencies"
        missing = []
        dependencies = self.mandatory
        if with_optional:
            dependencies += self.optional
        for package in dependencies:
            if not self.__check_dependency(package):
                missing.append(package)
        return missing

    def install_packages(self, packages):
        for package in packages:
            pip.main(['install', package, '--user'])
