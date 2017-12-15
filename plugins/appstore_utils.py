from HTMLParser import HTMLParser
import os
import requests
import subprocess
from config.configuration import getInstanceConfiguration

CONF = getInstanceConfiguration()

BASE_URL = "https://appstore.faradaysec.com/api/rest"
PARAMS = "limit=100&filter[1][attribute]=git_repository&filter[1][neq]="
HEADERS = {
    'Accept': 'application/json'
}
APPSTORE_PATH = "appstore"


class TimeoutException(Exception):
    pass


class RequestException(Exception):
    pass


class InstallationException(Exception):
    pass


def _get_url(endpoint):
    return "{0}/{1}?{2}".format(BASE_URL, endpoint, PARAMS)


def get_appstore_applications():
    url = _get_url('products')

    try:
        r = requests.get(url, headers=HEADERS, timeout=1)
        return r.json()
    except requests.exceptions.Timeout:
        raise TimeoutException()
    except requests.exceptions.RequestException:
        raise RequestException()


class MLStripper(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.reset()
        self.fed = []

    def handle_data(self, d):
        self.fed.append(d)

    def get_data(self):
        return ''.join(self.fed)


def strip_tags(html):
    s = MLStripper()
    s.feed(html)
    return s.get_data()


def install_app(git_repository):
    path = os.path.join(CONF.getConfigPath(), APPSTORE_PATH)

    if not os.path.exists(path):
        os.mkdir(path)

    args = ['git', 'clone', git_repository]

    process = subprocess.Popen(args, cwd=path, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    process.wait()
