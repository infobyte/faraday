#!/usr/bin/env bash

set -e

if [[ -z "$VIRTUAL_ENV" ]]
then
    echo You must run this script with inside a virtualenv!
    exit 1
fi

SITE_PACKAGES="$(echo $VIRTUAL_ENV/lib/python*/site-packages)"

if [[ ! -d $SITE_PACKAGES ]]
then
    echo "$SITE_PACKAGES is not a directory"
    echo "site-packages directory detection failed"
    exit 1
fi

# The _install directory will be added to the path, so it should
# have a directory (or in this case, a symlink) named as the
# module name
mkdir -p _install
rm -f _install/faraday
ln -s .. _install/faraday

# Add a .pth file in site-packages to make python use the _install
# directory as an extension of site-packages
realpath _install >$SITE_PACKAGES/faraday-fix-for-editable-mode.pth

# Finally, run setup.py develop
# This shouldn't fail if the user already ran it
python setup.py develop
