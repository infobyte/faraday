 * Fix CSRF (Cross-Site Request Forgery) vulnerability in vulnerability attachments API.
   This allowed an attacker to upload evidence to vulns. He/she required to know the
   desired workspace name and vulnerability id so it complicated the things a bit. We
   classified this vuln as a low impact one.
 * Readonly and disabled workspaces
 * Add fields 'impact', 'easeofresolution' and 'policyviolations' to vulnerability_template
 * Add pagination in  'Command history', 'Last Vulnerabilities', 'Activity logs' into dashboard
 * Add status_code field to web vulnerability
 * Preserve selection after bulk edition of vulnerabilities in the Web UI
 * Faraday's database will be created using UTF-8 encoding
 * Fix bug of "select a different workspace" from an empty list loop.
 * Fix bug when creating duplicate custom fields
 * Fix bug when loading in server.ini with extra configs
 * Fix `./manage.py command`. It wasn't working since the last schema migration
 * `./manage.py createsuperuser` command renamed to `./manage.py create-superuser`
 * Fix bug when non-numeric vulnerability IDs were passed to the attachments API
 * Fix logic in search exploits
 * Add ability to 'Searcher' to execute rules in loop with dynamic variables
 * Send searcher alert with custom mail
 * Add gitlab-ci.yml file to execute test and pylint on gitlab runner
 * Fix 500 error when updating services and vulns with specific read-only parameters set
 * Fix SQLMap plugin to support newer versions of the tool
 * Improve service's parser for Lynis plugin
 * Fix bug when parsing URLs in Acunetix reports
 * Fix and update NetSparker Plugin
 * Fix bug in nessus plugin. It was trying to create a host without IP. Enabled logs on the server for plugin processing (use --debug)
 * Fix bug when parsing hostnames in Nessus reports
 * Fix SSLyze report automatic detection, so reports can be imported from the web ui
 * Update Dnsmap Plugin
