import requests

BASE_URL = "https://appstore.faradaysec.com/api/rest"
PARAMS = "limit=100"
HEADERS = {
    'Accept': 'application/json'
}


def _get_url(endpoint):
    return "{0}/{1}?{2}".format(BASE_URL, endpoint, PARAMS)


def get_appstore_applications():
    url = _get_url('products')

    r = requests.get(url, headers=HEADERS)

    products = r.json()

    return products
