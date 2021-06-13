 * Refactor the project to use absolute imports to make the installation easier
(with a setup.py file). This also was a first step to make our codebase
compatible with python 3.
 * Change the commands used to run faraday. `./faraday-server.py`,
   `./manage.py`, `./faraday.py` and `bin/flugin` are replaced for `faraday-server`, `faraday-manage`,
   `faraday-client` and `fplugin` respectively
 * Changed suggested installation method. Now we provide binary executables with all python dependencies
   embedded into them
 * Add admin panel to the Web UI to manage custom fields
 * Fix slow host list when creating vulns in a workspace with many hosts
 * Usability improvements in status report: change the way vulns are selected and confirmed
 * Improve workspace workspace creation from the Web UI
 * Fix attachment api when file was not found in .faraday/storage
 * Fix visualization of the fields Policy Violations and References.
 * Add a setting in server.ini to display the Vulnerability Cost widget of the Dashboard
 * Fix status report resize when the browser console closes.
 * Fix severity dropdown when creating vulnerability templates
 * Update OS icons in the Web UI.
 * Fix bug when using custom fields, we must use the field\_name instead of the display\_name
 * Prevent creation of custom fields with the same name
 * Add custom fields to vuln templates.
 * Fix user's menu visibily when vuln detail is open
 * Remove "show all" option in the status report pagination
 * The activity feed widget of the dashboard now displays the hostname of the
   machine that runned each command
 * Add loading spinner in hosts report.
 * Fix "invalid dsn" bug in sql-shell
 * Fix hostnames bug in Nikto and Core Impact plugins
 * Change Openvas plugin: Low and Debug threats are not taken as vulnerabilities.
 * Add fplugin command to close vulns created after a certain time
 * Add list-plugins command to faraday-manage to see all available plugins
 * Fix a logging error in PluginBase class
 * Fix an error when using NexposePlugin from command line.
 * Add CSV parser to Dnsmap Plugin
 * Fix bug when creating web vulnerabilities in dirb plugin
 * Change Nexpose Severity Mappings.
