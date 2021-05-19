#!/usr/bin/env python3
from pathlib import Path
import argparse
import os

parser = argparse.ArgumentParser()
parser.add_argument('--version', default=None)
args = parser.parse_args()


def main(version_id):
    changelog_folder = Path(__file__).parent
    current_folder = changelog_folder / "current"
    for file in os.listdir(current_folder):
        assert file == "keep", file
    version_folder = changelog_folder / version_id
    for file in os.listdir(version_folder):
        assert file in ["date.md", "community.md", "prof.md", "corp.md"], file


if __name__ == '__main__':
    version = os.environ.get("FARADAY_VERSION", args.version)
    main(version)
