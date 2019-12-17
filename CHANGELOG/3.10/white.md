 * Use Python 3 instead of Python 2 in the Faraday Server
 * Add ability to manage agents with multiple executors
 * Agents can be run with custom arguments
 * Improved processing of uploaded reports. Now it is much faster!
 * Add custom fields of type `choice`
 * Fix vuln status transition in bulk create API (mark closed vulns as re-opened when they are triggered again)
 * Fix bug when using non-existent workspaces in Faraday GTK Client
 * Set service name as required in the Web UI
 * Validate the start date of a workspace is not greater than the end date
 * Fix command API when year is invalid
 * When SSL misconfigurations cause websockets to fails it doesn't block server from starting
 * Check for invalid service port number in the Web UI
 * Fix dashboard tooltips for vulnerability
 * Fix bug when GTK client lost connection to the server
 * Fix style issues in "Hosts by Service" modal of the dashboard
 * Add API for bulk delete of vulnerabilities
 * Add missing vuln attributes to exported CSV
 * `faraday-manage support` now displays the Operating System version
 * Notify when `faraday-manage` can't run becasue of PostgreSQL HBA config error
