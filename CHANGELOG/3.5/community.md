 * Redesgin of new/edit vulnerability forms
 * Add new custom fields feature to vulnerabilities
 * Add ./manage.py migrate to perform alembic migrations
 * Faraday will use webargs==4.4.1 because webargs==5.0.0 fails with Python2
 * New system for online plugins using Threads, a few fixes for metasploit plugin online also.
 * Fix Command "python manage.py process-reports" now stops once all reports have been processed
 * Fix bug in query when it checks if a vulnerability or a workspace exists
 * Fix Once a workspace is created through the web UI, a folder with its name is created inside ~/.faraday/report/
 * The manage.py now has a new support funtionality that creates a .zip file with all the information faraday's support team will need to throubleshoot your issue
 * Status-check checks PostgreSQL encoding
 * Fix a bug when fail importation of reports, command duration say "In Progress" forever.
 * Fix confirmed bug in vulns API
 * Update websockets code to use latest lib version
 * bootstrap updated to v3.4.0
 * Manage.py support now throws a message once it finishes the process.
 * Update Lynis to its version 2.7.1
 * Updated arp-scan plugin, added support in the Host class for mac address which was deprecated before v3.0
 * OpenVAS Plugin now supports OpenVAS v-9.0.3
