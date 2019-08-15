 * Add agents feature for distributed plugin execution
 * Add an API endpoint to to perform a bulk create of many objects (hosts,
services, vulns, commands and credentials). This is used to avoid doing a lot
of API requests to upload data. Now one request should be enough.
 * Modify color of styles and .png files.
 * Add API token authentication method
 * Add "New" button to create credentials without host or service assigned yet
were doing a lot of SQL queries because of a programming bug)
 * Allow filtering hosts by its service's ports in the Web UI
 * Performance improvements in vulnerabilities and vulnerability templates API (they
 * Require being in the faraday-manage group when running faraday from a .deb or .rpm package
 * Change the first page shown after the user logs in. Now it displays a workspace
selection dialog.
 * Add API endpoint to import Vuln Templates from a CSV file
 * Create the exported CSV of the status report in the backend instead of in the
problem, which was much slower
 * Add API endpoint to import hosts from a CSV file
 * Allow resizing columns in Vulnerability Templates view
 * Avoid copying technical details when a vuln template is generated from the status report.
 * Add API endpoint to get which tools impacted in a host
 * Add pagination to activity feed.
 * Add ordering for date and creator to vuln templates view.
 * Modify tabs in vuln template, add Details tab.
 * Add copy IP to clipboard button in hosts view.
 * Add creator and create date columns to vuln template view.
 * When a plugin creates a host with its IP set to a domain name,
   resolve the IP address of that domain
 * Add support for logging in RFC5254 format
 * Add active filter in workspaces view. Only show active workspaces
   in other parts of the Web UI.
 * Fix bug in many plugins that loaded hostnames incorrectly (one hostname per chararcter)
 * Fix bug hostname search is now working in status-report.
 * Fix broken select all hosts checkbox
 * Fix bug viewing an attachment/evidence when its filename contained whitespaces
 * Fix "Are you sure you want to quit Faraday?" dialog showing twice in GTK
