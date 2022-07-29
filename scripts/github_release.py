#!/usr/bin/env python3
from pathlib import Path
import os
import requests
import click
import mimetypes


VERSION = os.environ.get('FARADAY_VERSION')
TOKEN = os.environ.get('GH_TOKEN')


@click.command()
@click.option("--deb-file", required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option("--rpm-file", required=True, type=click.Path(exists=True, dir_okay=False, resolve_path=True))
def main(deb_file, rpm_file):
    release_data = dict()
    release_data["tag_name"] = f"v{VERSION}"
    release_data["name"] = f"v{VERSION}"
    with open(
            Path(__file__).parent.parent / 'CHANGELOG' / VERSION / 'community.md'
    ) as body_file:
        release_data["body"] = body_file.read()

    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': 'token ' + TOKEN,
    }
    res = requests.post(
        "https://api.github.com/repos/infobyte/faraday/releases",
        json=release_data,
        headers=headers
    )
    res.raise_for_status()
    release_id = res.json()['id']
    for asset_file in (Path(deb_file), Path(rpm_file)):
        mimetype = mimetypes.guess_type(asset_file)[0] or "application/octet-stream"
        print(f"Add asset {asset_file.name} to release: {VERSION} with mimetype: {mimetype}")
        headers["Content-Type"] = mimetype
        params = (('name', asset_file.name),)
        data = open(asset_file, mode="rb").read()
        url = f"https://uploads.github.com/repos/infobyte/faraday/releases/{release_id}/assets"
        res = requests.post(url, headers=headers, params=params, data=data)
        res.raise_for_status()
        print(res.json())


if __name__ == '__main__':
    main()
