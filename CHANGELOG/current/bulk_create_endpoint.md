Add an API endpoint to to perform a bulk create of many objects (hosts,
services, vulns, commands and credentials). This is used to avoid doing a lot
of API requests to upload data. Now one request should be enough.
