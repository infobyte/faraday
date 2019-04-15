#!/usr/bin/env bash

# Faraday Penetration Test IDE
# Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

# Move files using the old files structure to the new one

set -eu -o pipefail

CLIENT_DIRS=(apis bin gui helpers managers model persistence plugins zsh)

for dir in "${CLIENT_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        for subfile in $(find "${dir}" -type f); do
            mkdir -p "client/$(dirname "${subfile}")"
            git mv "${subfile}" "client/${subfile}"
        done
        rmdir --ignore-fail-on-non-empty "${dir}"
    fi
done
