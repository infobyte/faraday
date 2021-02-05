def v2_to_v3(url):
    if url.endswith("/"):
        url = url[:-1]
    return url.replace("v2", "v3", 1)
