#!/usr/bin/env python3

# Faraday Penetration Test IDE
# Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

'''
Internal script used to detect merge conflicts to branch with
our propiertary code. Not useful if you don't have access to
the code of Faraday Professional or Faraday Corporate
'''

import os
import sys
import subprocess
import logging
import argparse
from contextlib import contextmanager
from tempfile import mkdtemp
from shutil import rmtree

VERSIONS = ['white', 'black']
BRANCH_FORMAT = 'origin/{}/dev'


@contextmanager
def chdir(directory):
    """Context manager to work in the specified directory"""
    current = os.getcwd()
    os.chdir(directory)
    yield
    os.chdir(current)


@contextmanager
def temp_worktree(branch=None):
    """Context manager that creates a temporal worktree and
    changes the current working directory, and when finished
    removes the dir and runs a git worktree prune"""
    directory = mkdtemp()
    cmd = ["git", "worktree", "add", directory]
    if branch is not None:
        cmd.append(branch)
    subprocess.check_output(cmd)
    with chdir(directory):
        yield
    rmtree(directory)
    subprocess.check_output(['git', 'worktree', 'prune'])


def check_merge(dst_branch, cur_branch='HEAD'):
    """Return a boolean indicating if the merge from cur_branch
    to dst_branch will merge without causing conflicts that need
    manual resolution"""
    # https://stackoverflow.com/questions/501407/is-there-a-git-merge-dry-run-option
    with temp_worktree(dst_branch):
        exit_code = subprocess.call(
            ['git', 'merge', '--no-commit', '--no-ff', cur_branch])
        # Use call because it will have exit code 128 when there is nothing to
        # abort
        subprocess.call(['git', 'merge', '--abort'])
    return exit_code == 0


def get_current_branch():
    """Return the current branch of the current workspace"""
    # https://stackoverflow.com/questions/6245570/how-to-get-the-current-branch-name-in-git
    branch = subprocess.check_output(
        ['git', 'rev-parse', '--abbrev-ref', 'HEAD']).decode().strip()
    if branch == 'HEAD':
        # Probably in a detached state inside gitlab CI
        # Fallback to the branch name defined in an env var
        branch = 'origin/' + os.environ['CI_COMMIT_REF_NAME']
    return branch


def branch_exists(branch_name):
    exit_code = subprocess.call(
        ['git', 'rev-parse', '--verify', '--quiet', branch_name])
    if exit_code == 0:
        return True
    elif exit_code == 1:
        return False
    else:
        raise ValueError('Error when checking for branch existence')


def version_of_branch(branch_name):
    """
    >>> version_of_branch('tkt_white_this_is_not_a_ee_branch')
    'white'
    """
    positions = {version: branch_name.find(version)
                 for version in VERSIONS}
    if all((pos < 0) for pos in positions.values()):
        # The branch name doesn't contain white, pink or black
        return
    positions = {version: pos
                 for (version, pos) in positions.items()
                 if pos >= 0}
    return min(positions.keys(), key=positions.get)


def main(branch):
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    logger = logging  # TODO FIXME
    logger.info('Checking merge conflicts for branch %s', branch)
    version = version_of_branch(branch)
    if version is None:
        logger.error('Unknown version name. Exiting')
        sys.exit(-1)

    versions_to_test = VERSIONS[VERSIONS.index(version):]
    branches_to_test = []
    logger.info(f'versions to test: {versions_to_test}')
    for target_version in versions_to_test:
        logger.info(f'Target version: {target_version}')
        logger.info(f'Version: {version}')
        overriden_branch = branch.replace(version, target_version)
        logger.info(f'Overriden branch: {overriden_branch}')
        if target_version != version and \
                branch_exists(overriden_branch):
            branches_to_test.append(overriden_branch)
            # break  # Uncomment if want to cut the checker on merging to black if has overridden pink branch
        else:
            logger.info("Entro por else")
            branches_to_test.append(BRANCH_FORMAT.format(target_version))
    logger.info(f'BRANCHES TO TEST: {branches_to_test}')

    logger.info(f'Testing merges in branches {branches_to_test}')

    success = True
    cur_branch = branch
    for dst_branch in branches_to_test:
        result = check_merge(dst_branch, cur_branch)
        if result:
            logger.info("Merge into %s succeeded!", dst_branch)
        else:
            success = False
            logger.error("Merge into %s failed :(", dst_branch)

    if not success:
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--branch', default=get_current_branch())
    parser.add_argument('-l', '--log-level', default='debug')
    args = parser.parse_args()
    main(args.branch)
