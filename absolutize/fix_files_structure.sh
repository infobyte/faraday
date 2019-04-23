#!/usr/bin/env bash

# Faraday Penetration Test IDE
# Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

# Move files using the old files structure to the new one

set -eu -o pipefail

CLIENT_DIRS=(apis bin gui helpers managers model persistence plugins zsh)
FARADAY_PACKAGE_DIRS=(client config server utils)

DRY_RUN_PREFIX=""
DRY_RUN_GIT_MV=""
while getopts ":d" opt; do
  case $opt in
    d)
        DRY_RUN_PREFIX="echo "
        DRY_RUN_GIT_MV="-n"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

for dir in "${CLIENT_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        for subfile in $(find "${dir}" -type f); do
            $DRY_RUN_PREFIX mkdir -p "faraday/client/$(dirname "${subfile}")"
            git mv $DRY_RUN_GIT_MV -k "${subfile}" "faraday/client/${subfile}"
        done
        $DRY_RUN_PREFIX rmdir --ignore-fail-on-non-empty "${dir}"
    fi
done


for dir in "${FARADAY_PACKAGE_DIRS[@]}"; do
    if [[ -d "${dir}" ]]; then
        for subfile in $(find "${dir}" -type f); do
            $DRY_RUN_PREFIX mkdir -p "faraday/$(dirname "${subfile}")"
            git mv $DRY_RUN_GIT_MV -k "${subfile}" "faraday/${subfile}"
        done
        $DRY_RUN_PREFIX rmdir --ignore-fail-on-non-empty "${dir}"
    fi
done
