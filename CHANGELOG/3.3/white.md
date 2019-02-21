 * Add workspace disable feature
 * Add mac vendor to host and services
 * Fix typos and add sorting in workspace name (workspace list view)
 * Improve warning when you try to select hosts instead of services as targets of a Vulnerability Web
 * Deleted old Nexpose plugin. Now Faraday uses Nexpose-Full.
 * Update sqlmap plugin
 * Add updated zap plugin
 * Add hostnames to nessus plugin
 * Python interpreter in SSLCheck plugin is not hardcoded anymore.
 * Fix importer key error when some data from couchdb didn't contain the "type" key
 * Fix AttributeError when importing vulns without exploitation from CouchDB
 * Fix KeyError in importer.py. This issue occurred during the import of Vulnerability Templates
 * Fix error when file config.xml doesn't exist as the moment of executing initdb
 * Improve invalid credentials warning by indicating the user to run Faraday GTK with --login option
 * Fix typos in VulnDB and add two new vulnerabilities (Default Credentials, Privilege Escalation)
 * Improved tests performance with new versions of the Faker library
 * `abort()` calls were checked and changed to `flask.abort()`
