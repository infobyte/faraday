from pathlib import Path
import os
import requests


VERSION = os.environ.get('FARADAY_VERSION')


def main():
    release_data = dict()
    release_data["tag_name"] = f"v{VERSION}"
    release_data["name"] = f"v{VERSION}"
    with open(
            Path(__file__).parent.parent / 'CHANGELOG' / VERSION / 'white.md'
    ) as body_file:
        release_data["body"] = body_file.read()

    headers = {'Accept': 'application/vnd.github.v3+json'}
    res = requests.post(
        "https://api.github.com/repos/infobyte/faraday/releases",
        json=release_data,
        headers=headers
    )
    res.raise_for_status()
    release_id = res.json()['id']
    # TODO ADD THIS
    # for asset_file in ["rpm", "deb"]:
    #
    #     res = requests.post(
    #         "https://api.github.com/repos/infobyte/faraday/releases/"
    #         f"{release_id}/assets",
    #         headers=headers,
    #         files={
    #             'file': (
    #                 asset_file, # TODO FIX NAME
    #                 open(asset_file, mode="rb"), # TODO FIX NAME
    #                 asset_file # TODO FIX TYPE
    #             )
    #         }
    #     )
    #     res.raise_for_status()


if __name__ == '__main__':
    main()
