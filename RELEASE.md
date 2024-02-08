New features in the latest update
=====================================

5.1.0 [Feb 8th, 2024]:
---
 * [ADD] Performance improved in `assets` views making several vulnerabilities stats statics in asset's model. #7634
 * [ADD] Now `custom fields` are available for filtering vulnerabilities. Also add `date` type for custom fields. #7625
 * [MOD] We changed the order in which we set the path constant of `faraday_home` in order to fix a bug with faraday_manage when is installed by deb/rpm. #7653
 * [MOD] Modify analytics type enum. #7615
 * [FIX] Fix references. #7648

5.0.1 [Jan 2nd, 2024]:
---
 * [MOD] Code refactor.

5.0.0 [Dec 13th, 2023]:
---
 * [ADD] **Breaking change** We now use Celery as the main way to import reports. In addition, we have removed twisted and replaced raw websockets with socket.io. #7352
 * [ADD] Added option to faraday-server to run workers. #7623

4.6.2 [Nov 10th, 2023]:
---
 * [ADD] Exclude unnecessary fields from VulnerabilitySchema in filter endpoint. #7608

4.6.1 [Oct 19th, 2023]:
---
 * [ADD] New `exclude_stats` query param in workspace endpoint. #7595
 * [MOD] Optimize hosts API when stats aren't needed. #7596
 * [FIX] Filter .webp files in vulns attachment endpoint because CVE-2023-4863. #7603

4.6.0 [Sep 6th, 2023]:
---
 * [FIX] Delete Cascade from KB. #7569

4.5.1 [Jul 15th, 2023]:
---
 * [FIX] Fix pillow version to 9.4.0. #7531

4.5.0 [Jul 7th, 2023]:
---
 * [MOD] Upgrade nixpkgs version to 23.05. Also update version of packages in requirements. #7518
 * [FIX] Add missing `scope` cvss3 field. #7493
 * [FIX] Improve performance in `hosts` and `hosts/filter` views. #7501

4.4.0 [May 29th, 2023]:
---
 * [ADD] Now it's possible to modify the host or service assigned of a vulnerability. #7476
 * [MOD] Now `/get_manifest` separates the optional environment variables from the rest. #7481
 * [FIX] Add `not_any` filter operator which will retrieve results that not contains the value requested. #7394
 * [FIX] Make `get_manifest` compatible with all versions of dispatcher. #7500

4.3.5 [Apr 12th, 2023]:
---
 * [FIX] Modify migration with autocommit. #7487

4.3.4 [Apr 3rd, 2023]:
---
 * [FIX] Fix bandit vulns. #7430
 * [FIX] Return public IP when behind a proxy. #7417
 * [ADD] Add report_template as an object type. #7463

4.3.3 [Feb 9th, 2023]:
---
 * [FIX] Add tags columns in AgentSchedule model in white version. #7341
 * [FIX] Now sending a patching a vuln with empty list will remove all the relationships with all references. #7405
 * [FIX] Migration cascade on KB #7396

4.3.2 [Jan 3rd, 2023]:
---
 * Change column type of advanced field in executive reports

4.3.1 [Dec 15th, 2022]:
---
 * [ADD] Workspace api stats refactor

4.3.0 [Dec 1st, 2022]:
---
 * [FIX] Update the associated command when a agent execution return empty
 * [ADD] cvss3 scope field to vulnerability schema
 * [ADD] Add cvss2/3 and cwe to export_csv
 * Improve command object creation in bulk create.
 * Fix open and closed stats in ws filter endpoint.
 * Add error command status in every validation of reports upload process
 * [ADD] BulkDelete with filters
 * Change filter logic on numeric fields.

4.2.0 [Oct 27th, 2022]:
---
 * Add `stats` param in hosts endpoint.
 * [FIX] Now get agents dosent returns tokens
 * [FIX] Now when a constrain is violated faraday use the actual object to query if there is another object
 * [MOD] Improve agents logs
 * Add global commands and summary field in command's model

4.1.0 [Sep 12th, 2022]:
---
 * Now error 403 will respond a json, not a html
 * [FIX] Change resolve_hotname for resolve_hostname in agents
 * Add filters as params for bulk_update
 * Add Swagger view
 * Modify way of filtering dates with `filters`. Now only 'YYYYMMDD' format supported.
 * Add cvss v2 and v3 into model and api
 * [ADD] Now if command_id is sent in a post for hosts, services or vulns, the created object is associated with that command_id if exist
 * Add support for tagging when running an agent
 * Clean up of commented code that's not needed anymore
 * [FIX] Change dns_resolution to resolve_hostname
 * Add CWE into model and api

4.0.4 [Jul 28th, 2022]:
---
 * Remove workspaces agents relationship an now agent can run to multiple workspaces
 * Fix migration f82a9136c408 checking if index and constrains exist before deleting
 * Added count to vulns closed
 * Fix order_by `cve_instances__name` when no filter was provided
 * Add index into vulnerability

4.0.3 [Jun 16th, 2022]:
---
 * Replace usage of strings for user_types enumerator constants
 * Increase the default duration of faraday token
 * Fix order by Role in Filters API
 * Refactor of bulk create API
 * Remove attachments and attachments_count properties from vulnerability. This improves performance.
 * Get token from user model
 * Ignore info and dns resolution as params when uploading report
 * Replace usage of is_ldap field of User model for user_type
 * Add user type enumerator
 * Add `weight` in role model to sort arbitrarily
 * Move export CSV from its own endpoint to /filter endpoint as a request's argument

4.0.2 [Apr 4th, 2022]:
---
 * models.py refactor
 * add check to see if workspace name is longer than 250 characters. In that case raises an error
 * Generate token with pyjwt

4.0.1 [Mar 18th, 2022]:
---
 * Improve the logs

4.0.0 [Feb 25th, 2022]:
---
 * Add a None limit and 0 offset to GET queries.

3.19.0 [Dec 27th, 2021]:
---
 * ADD v3 bulks endpoints DELETE and EDIT (PATCH)
 * Add logs of loggin, logout and log error to main log
 * Fix bug in bulk update for m2m fields
 * ADD clear settings command
 * Add open medium, high and critical vulns histogram
 * Fix integrity constraint error on cve update
 * FIX static content for react
 * Add cvss within vulnerability model
 * add check to see if workspace name is longer than 250 characters. In that case raises an error
 * change concat in urlstrings for join or urljoin
 * Add cve to csv export

3.18.1 [Nov 5th, 2021]:
---
Fix CVE issue

3.18.0 [Oct 21st, 2021]:
---
 * Remove attachments in vulns filter endpoint
 * Add open and confirmed vulns in workspace stats
 * Add migration disabling several notifications.
 * Add user id to session API endpoint
 * Add cve to vulnerability model
 * Change funcs to views
 * FIX report import
 * Add `last_run_agent_date` field to workspace endpoint
 * Fix cve parsing in `vulnerability create` and `bulk create`
 * ADD check if postgres db is running during server start
 * Fix order_by in filters api
 * Fix 500 status code with invalid executor arguments

3.17.1 [Aug 20th, 2021]:
---
 * FIX bug when starting the server, creates a pool for reporting that breaks.

3.17.0 [Aug 10th, 2021]:
---
 * ADD `--data` parameter to `faraday-manage settings`
 * MOD Process report files in a separate process
 * MOD Make `bulk_create` requests asynchronous

3.16.1 [Jul 2nd, 2021]:
---
 * MOD only show settings of this version in faraday-manage settings
 * FIX update minimum version of click dependency

3.16.0 [Jun 29th, 2021]:
---
 * BREAKING CHANGE: API V2 discontinued
 * BREAKING CHANGE: Changed minimum version of python to 3.7
 * ADD agent parameters has types (protocol with agent and its APIs)
 * ADD move settings from `server.in` to a db model
 * ADD (optional) query logs
 * MOD new threads management
 * MOD vulnerabilities' endpoint no longer loads evidence unless requested with `get_evidence=true`
 * FIX now it is not possible to create workspace of name "filter"
 * FIX bug with dates in the future
 * FIX bug with click 8
 * FIX bug using --port command
 * FIX endpoints returning 500 as status code
 * REMOVE the need tom CSRF token from evidence upload api

3.15.0 [May 18th, 2021]:
---
 * ADD `Basic Auth` support
 * ADD support for GET method in websocket_tokens, POST will be deprecated in the future
 * ADD CVSS(String), CWE(String), CVE(relationship) columns to vulnerability model and API
 * ADD agent token's API says the renewal cycling duration
 * MOD Improve database model to be able to delete workspaces fastly
 * MOD Improve code style and uses (less flake8 exceptions, py3 `super` style, Flask app as singleton, etc)
 * MOD workspaces' names regex to verify they cannot contain forward slash (`/`)
 * MOD Improve bulk create logs
 * FIX Own schema breaking Marshmallow 3.11.0+
 * UPD flask_security_too to version 4.0.0+

3.14.4 [Apr 15th, 2021]:
---
 * Updated plugins package, which update appscan plugin

3.14.3 [Mar 30th, 2021]:
---
 * MOD MAYOR Breaking change: Use frontend from other repository
 * ADD `last_run` to executors and agents
 * ADD ignore info vulns option (from faraday-plugins 1.4.3)
 * ADD invalid logins are registered in `audit.log`
 * ADD agent registration tokens are now 6-digit short and automatically regenerated every 30 seconds
 * MOD Fix logout redirect loop
 * REMOVE support for native SSL

3.14.2 [Feb 26th, 2021]:
---
 * ADD New plugins:
    * microsoft baseline security analyzer
    * nextnet
    * openscap
 * FIX old versions of Nessus plugins bugs

3.14.1 [Feb 17th, 2021]:
---
 * ADD forgot password
 * ADD update services by bulk_create
 * ADD FARADAY_DISABLE_LOGS varibale to disable logs to filesystem
 * ADD security logs in `audit.log` file
 * UPD security dependency Flask-Security-Too v3.4.4
 * MOD rename total_rows field in filter host response
 * MOD improved Export cvs performance by reducing the number of queries
 * MOD sanitize the content of vulns' request and response
 * MOD dont strip new line in description when exporting csv
 * MOD improved threads management on exception
 * MOD improved performance on vulnerability filter
 * MOD improved [API documentation](www.api.faradaysec.com)
 * FIX upload a report with invalid custom fields
 * ADD v3 API, which includes:
    * All endpoints ends without `/`
    * `PATCH {model}/id` endpoints
    * ~~Bulk update via PATCH `{model}` endpoints~~ In a future release
    * ~~Bulk delete via DELETE `{model}` endpoints~~ In a future release
    * Endpoints removed:
      * `/v2/ws/<workspace_id>/activate/`
      * `/v2/ws/<workspace_id>/change_readonly/`
      * `/v2/ws/<workspace_id>/deactivate/`
      * `/v2/ws/<workspace_name>/hosts/bulk_delete/`
      * `/v2/ws/<workspace_name>/vulns/bulk_delete/`
    * Endpoints updated:
      * `/v2/ws/<workspace_name>/vulns/<int:vuln_id>/attachments/` => \
        `/v3/ws/<workspace_name>/vulns/<int:vuln_id>/attachment`

3.14.0 [Dec 23th, 2020]:
---
 * ADD RESTless filter to multiples views, improving the searchs
 * ADD "extras" modal in options menu, linking to other Faraday resources
 * ADD `import vulnerability templates` command to faraday-manage
 * ADD `generate nginx config` command to faraday-manage
 * ADD vulnerabilities severities count to host
 * ADD Active Agent columns to workspace
 * ADD critical vulns count to workspace
 * ADD `Remember me` login option
 * ADD distinguish host flag
 * ADD a create_date field to comments
 * FIX to use new webargs version
 * FIX Custom Fields view in KB (Vulnerability Templates)
 * FIX bug on filter endpoint for vulnerabilities with offset and limit parameters
 * FIX bug raising `403 Forbidden` HTTP error when the first workspace was not active
 * FIX bug when changing the token expiration change
 * FIX bug in Custom Fields type Choice when choice name is too long.
 * FIX Vulnerability Filter endpoint Performance improvement using joinedload. Removed several nplusone uses
 * MOD Updating the template.ini for new installations
 * MOD Improve SMTP configuration
 * MOD The agent now indicates how much time it had run (faraday-agent-dispatcher v1.4.0)
 * MOD Type "Vulnerability Web" cannot have "Host" type as a parent when creating data in bulk
 * MOD Expiration default time from 1 month to 12 hour
 * MOD Improve data reference when uploading a new report
 * MOD Refactor Knowledge Base's bulk create to take to take also multiple creation from vulns in status report.
 * MOD All HTTP OPTIONS endpoints are now public
 * MOD Change documentation and what's new links in about
 * REMOVE Flask static endpoint
 * REMOVE of our custom logger

3.12 [Sep 3rd, 2020]:
---
 * Now agents can upload data to multiples workspaces
 * Add agent and executor data to Activity Feed
 * Add session timeout configuration to server.ini configuration file
 * Add hostnames to already existing hosts when importing a report
 * Add new faraday background image
 * Display an error when uploading an invalid report
 * Use minimized JS libraries to improve page load time
 * Fix aspect ratio distortion in evidence tab of vulnerability preview
 * Fix broken Knowledge Base upload modal
 * Fix closing of websocket connections when communicating with Agents
 * Change Custom Fields names in exported CSV to make columns compatible with
   `faraday_csv` plugin
 * Fix import CSV for vuln template: some values were overwritten with default values.
 * Catch errors in faraday-manage commands when the connection string is not
   specified in the server.ini file
 * Fix bug that generated a session when using Token authentication
 * Fix bug that requested to the API when an invalid filter is used
 * Cleanup old sessions when a user logs in
 * Remove unmaintained Flask-Restless dependency
 * Remove pbkdf2\_sha1 and plain password schemes. We only support bcrypt

3.11.2:
---

3.11.1 [Jun 3rd, 2020]:
---
 * Fix missing shodan icon and invalid link in dashboard and hosts list
 * Upgrade marshmallow, webargs, werkzeug and flask-login dependencies to
   latest versions in order to make packaging for distros easier

3.11 [Apr 22nd, 2020]:
---
 * Move GTK client to [another repository](https://github.com/infobyte/faraday-client) to improve release times.
 * Fix formula injection vulnerability when exporting vulnerability data to CSV. This was considered a low impact vulnerability.
 * Remove "--ssl" parameter. Read SSL information from the config file.
 * Add OpenAPI autogenerated documentation support
 * Show agent information in command history
 * Add bulk delete endpoint for hosts API
 * Add column with information to track agent execution data
 * Add tool attribute to vulnerability to avoid incorrectly showing "Web UI" as creator tool
 * Add sorting by target in credentials view
 * Add creator information when uploading reports or using de bulk create api
 * Add feature to disable rules in the searcher
 * Add API endpoint to export Faraday data to Metasploit XML format
 * Change websocket url route from / to /websockets
 * Use run date instead of creation date when plugins report specifies it
 * Improve knowledge base UX
 * Improve workspace table and status report table UX.
 * Improve format of exported CSV to include more fields
 * Sort results in count API endpoint
 * Limit description width in knowledge base
 * Change log date format to ISO 8601
 * Fix parsing server port config in server.ini
 * Fix bug when \_rev was send to the hosts API
 * Send JSON response when you get a 500 or 404 error
 * Fix bug parsing invalid data in NullToBlankString

Changes in plugins (only available through Web UI, not in GTK client yet):

New plugins:

* Checkmarx
* Faraday\_csv (output of exported Faraday csv)
* Qualyswebapp
* Whitesource

Updated plugins:

* Acunetix
* AppScan
* Arachni
* Nessus
* Netspaker
* Netspaker cloud
* Nexpose
* Openvas
* QualysGuard
* Retina
* W3af
* WPScan
* Webinspect
* Zap

3.10.2 [Jan 30th, 2020]:
---
 * Fix Cross-Site Request Forgery (CSRF) vulnerability in all JSON API endpoints.
This was caused because a third-party library doesn't implement proper
Content-Type header validation. To mitigate the vulnerability, we set the
session cookie to have the `SameSite: Lax` property.
 * Fix Faraday Server logs were always in debug
 * Add update date column when exporting vulnerabilities to CSV
 * Fix unicode error when exporting vulnerabilities to CSV

3.10.1 [Jan 10th, 2020]:
---
 * Fix installation with `pip install --no-binary :all: faradaysec`
 * Force usage of webargs 5 (webargs 6 broke backwards compatibility)
 * Use latest version of faraday-plugins
 * Fix broken "Faraday Plugin" menu entry in the GTK client
 * Extract export csv to reuse for reports

3.10 [Dec 19th, 2019]:
---
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

3.9.3 [Nov 12th, 2019]:
---
 * Fix unicode error when exporting vulns to CSV
 * Add vuln attributes to CSV
 * Fix hostname parsing and add external ID to Qualys plugin

3.9 [Oct 3th, 2019]:
---
 * Add agents feature for distributed plugin execution
 * Add an API endpoint to to perform a bulk create of many objects (hosts,
   services, vulns, commands and credentials). This is used to avoid doing a lot
   of API requests to upload data. Now one request should be enough
 * Major style and color changes to the Web UI
 * Add API token authentication method
 * Use server side stored sessions to properly invalidate cookies of logged out users
 * Add "New" button to create credentials without host or service assigned yet
 * Allow filtering hosts by its service's ports in the Web UI
 * Performance improvements in vulnerabilities and vulnerability templates API (they
   were doing a lot of SQL queries because of a programming bug)
 * Require being in the faraday-manage group when running faraday from a .deb or .rpm package
 * Change the first page shown after the user logs in. Now it displays a workspace
   selection dialog
 * Add API endpoint to import Vuln Templates from a CSV file
 * Create the exported CSV of the status report in the backend instead of in the
problem, which was much slower
 * Add API endpoint to import hosts from a CSV file
 * Add `faraday-manage rename-user` command to change a user's username
 * Allow resizing columns in Vulnerability Templates view
 * Avoid copying technical details when a vuln template is generated from the status report
 * Use exact matches when searching vulns by target
 * Add API endpoint to get which tools impacted in a host
 * Add pagination to activity feed
 * Add ordering for date and creator to vuln templates view
 * Modify tabs in vuln template, add Details tab
 * Add copy IP to clipboard button in hosts view
 * Add creator and create date columns to vuln template view
 * When a plugin creates a host with its IP set to a domain name,
   resolve the IP address of that domain
 * Add support for logging in RFC5254 format
 * Add active filter in workspaces view. Only show active workspaces
   in other parts of the Web UI
 * Enforce end date to be greater than start date in workspaces API
 * Fix bug in `faraday-manage create-tables` that incorrectly marked schema
   migrations as applied
 * Fix bug in many plugins that loaded hostnames incorrectly (one hostname per chararcter)
 * Improve references parsing in OpenVAS plugin
 * Fix a bug in Nessus plugin when parsing reports without host\_start
 * Fix bug hostname search is now working in status-report
 * Fix showing of services with large names in the Web UI
 * Fix broken select all hosts checkbox
 * Fix bug viewing an attachment/evidence when its filename contained whitespaces
 * Fix "Are you sure you want to quit Faraday?" dialog showing twice in GTK

3.8.1 [Jun 19th, 2019]:
---
* Add configurations for websocket ssl

3.8 [Jun 4th, 2019]:
---
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

3.7.3 [May 3rd, 2019]:
---
 * Add parser for connection string at PGCli connection
 * Fix bug when using custom fields, we must use the field_name instead of the display_name
 * Fix user's menu visibily when vuln detail is open.
 * Fix bug in status report that incorrectly showed standard vulns like if they were vulnwebs

3.7:
---
 * Add vulnerability preview to status report
 * Update Fierce Plugin. Import can be done from GTK console.
 * Update Goohost plugin and now Faraday imports Goohost .txt report.
 * Update plugin for support WPScan v-3.4.5
 * Update Qualysguard plugin to its 8.17.1.0.2 version
 * Update custom fields with Searcher
 * Update Recon-ng Plugin so that it accepts XML reports
 * Add postres version to status-change command
 * Couchdb configuration section will not be added anymore
 * Add unit test for config/default.xml

3.6 [Feb 21th, 2019]:
---
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

3.5 [Jan 16th, 2019]:
---
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

3.4 [December 6th, 2018]:
---
 * In GTK, check active_workspace its not null
 * Add fbruteforce services fplugin
 * Attachments can be added to a vulnerability through the API.
 * Catch gaierror error on lynis plugin
 * Add OR and NOT with parenthesis support on status report search
 * Info API now is public
 * Web UI now detects Appscan plugin
 * Improve performance on the workspace using cusotm query
 * Workspaces can be set as active/disable in welcome page.
 * Change Nmap plugin, response field in VulnWeb now goes to Data field.
 * Update code to support latest SQLAlchemy version
 * Fix `create_vuln` fplugin bug that incorrectly reported duplicated vulns
 * Attachments on a vulnerability can be deleted through the API.
 * Improvement in the coverage of the tests.

3.3 [Novemeber 14th, 2018]:
---
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

3.2 [October 17th, 2018]:
---
 * Added logical operator AND to status report search
 * Restkit dependency removed.
 * Improvement on manage.py change-password
 * Add feature to show only unconfirmed vulns.
 * Add ssl information to manage.py status-check
 * Update wpscan plugin to support latest version.
 * Allow workspace names starting with numbers.

September 21, 2018:
---
* Fix bug: manage.py status_check
* Fix bug: manage.py initdb

September 17, 2018:
---
* Fix get exploits API
* New searcher feature
* Added host_os column to status report
* Fix and error while trying to execute server with --start
* Added option --choose-password to initdb
* Continous scan updated for Nessus 7
* Refactor on server.config to remove globals
* Added a directory for custom templates for executive reports (pro and corp)
* Activity feed shows more results and allows to filter empty results
* Allow ot create workspace that start with numbers
* Added more variables to executive reports (pro and corp)
* Fixed some value checking on tasks api (date field)
* OpenVas plugin updated
* Appscan plugin update
* Added no confirmed vulns to report api
* Fixed a bug on workspace API when the workspace already exists on database
* Fix owner filter on status report
* Fixes on import_csv fplugin when the api returned 409
* Fixes on status_check
* Fixed a bug on webui when workspace permission was changed (pro and corp)
* Update nexpose plugin
* uigrid library updated to latest version
* Bug fix on plugin automatic detection
* Fixed a bug on executive reports when multiple reports were scheduled
* Avoid closing the executive report and new vuln modal when the form has data
* Status report open new tab for evidence
* added change_password to manage.py
* Update wapiti plugin
* Fixed vuln count on executive report (pro and corp)
* Fixed css align in some tables
* Fixed No ports available error on the client

August 17, 2018:
---
* Updated code to use Flask 1.0
* Add threadfix integration (corp only)
* Fix create_service fplugin
* Executive report bug fix on tags
* Persistence server bug fix on impact and ease of resolution
* Fix unicode error bug on executive reports
* Updated code to support latest Twisted version
* Updated all requirements to use >=
* Fix dry run on create_host fplugin
* Fixed del_all_vulns_with and del_all_hosts
* Improved executive reports status update refresh
* Websocket port is configurable now
* Change minimum font size in tag cloud
* Fixed a problem with shodan icon on dashboard
* Updated license check on deleted users
* Users with role client was not able to change password, bug fixed
* Updated code to support pip 10
* Added ldap to status check
* Credentials icon aligned
* Deamon now allows to execute faraday sever in more than one port and more than one process for multiplexation
* All views now check for permissions on workspace
* Pull requests #229, #231, #239 and #240 are merged
* Avoid polling deleted executive reports
* Added documentation to project
* Fix self xss on webshell
* Add postgres locks check on status_check
* Vuln counter fix when confirmed is on

July 26, 2018:
---
* Interface removed from model and from persistence server lib (fplugin)
* Performance iprovements on the backend
* Add quick change workspace name (from all views)
* Changed the scope field of a workspace from a free text input to a list of targets
* New faraday styles in all webui views
* Add search by id for vulnerabilities
* Add new plugin sslyze
* Add new plugin wfuzz
* Add xsssniper plugin
* Fix W3af, Zap plugins
* Add brutexss plugin
* Allow to upload report file from external tools from the web
* Fix sshcheck import file from GTK
* Add reconng plugin
* Add sublist3r plugin
* Add HP Webinspect plugin
* Add dirsearch plugin
* Add ip360 plugin
* CouchDB was replaced by PostgreSQL :)
* Host object changed, now the name property is called ip
* Interface object was removed
* Note object was removed and replaced with Comment
* Communication object was removed and replaced with Comment
* Show credentials count in summarized report on the dashboard
* Remove vuln template CWE fields, join it with references
* Allow to search hosts by hostname, os and service name
* Allow the user to specify the desired fields of the host list table
* Add optional hostnames, services, MAC and description fields to the host list
* Workspace names can be changed from the Web UI
* Exploitation and severity fields only allow certain values. CWE CVEs were fixed to be valid. A script to convert custom CSVs was added.
* Web UI path changed from /_ui/ to / (_ui has now a redirection to / for keeping backwards compatibility)
* dirb plugin creates an informational vulnerability instead of a note.
* Add confirmed column to exported csv from webui
* Fixes in Arachni plugin
* Add new parameters --keep-old and --keep-new for faraday CLI
* Add new screenshot fplugin which takes a screenshot of the ip:ports of a given protocol
* Add fix for net sparker regular and cloud fix on severity
* Removed Chat feature (data is kept inside notes)
* Add CVSS score to reference field in Nessus plugin.
* Fix unicode characters bug in Netsparker plugin.
* Fix qualys plugin.
* Fix bugs with MACOS and GTK.

April 10, 2018:
---
* Fix bug with tornado version 5.0 and GTK client.

November 17, 2017:
---
* Fix bug with tags in models.

November 5, 2017:
---
* Added "Last modified" and "Created" in Hosts view
* Fixed bug when trying to run Faraday as second process and closing the terminal (&!)
* Fixed bug where it asked for dependencies eternally when you have a different version than the one required
* Fixed small bug in the update_from_document method
* Fixed bug, makes the python library dependencies specific to the desired version
* Fixed GitHub language bar to reflect real code percentage
* Merge PR #195: Create gentoo_requirements_extras.txt (New Github wiki page)
* Merge PR #225: Add references to found vulnerabilities in nmap plugin
* New plugin: Netsparker cloud
* New plugin: Lynis (Winner of Faraday Challenge 2017)
* New Fplugin: changes the status of all vulnerabilities of an specific workspace to closed
* New Fplugin: combines the "create_interface" and "create_host" scripts into one (create_interface_and_host script)
* New Fplugin: import_csv , now you can import Faraday objects from a CSV

August 11, 2017:
---
* Add check to the vuln creation modal for empty targets in the Web UI

August 9, 2017:
---
No changes

August 7, 2017:
---
* Updated Core Impact plugin to be compatible with 2016 version
* Improved loading of fields request and website in Burp Plugin
* Improved Nexpose Full plugin
* Improved Acunetix plugin to avoid conflicts and missing imported data, and to correctly parse URLs and resolutions

July 19, 2017:
---
* Added the ability to select more than one target when creating a vuln in the Web UI
* Merged PR #182 - problems with zonatransfer.me
* Fixed bug in Download CSV of Status report with old versions of Firefox.
* Fixed formula injection vulnerability in export to CSV feature
* Fixed DOM-based XSS in the Top Services widget of the dashboard
* Fix in AppScan plugin.
* Fix HTML injection in Vulnerability template.
* Add new plugin: Junit XML
* Improved pagination in new vuln modal of status report
* Added "Policy Violations" field for Vulnerabilities

May 24, 2017:
---
* Fixed bug when editing workspaces created in GTK
* Improved host search in the WEB UI
* Extended the config to support different searching engines in the WEB UI
* Check that client and server versions match when connecting
* Adds the 'v' and 'version' argument for both the server and the client
* Fixed "refresh" button in the Web UI
* Fix API on /ws/<workspace> with duration object None
* Added a CRUD for Credentials to the Web UI
* Bug fixes on the Burp Online Plugin
* Added a script to connect with Reposify
* Fixed Hostname import in Nessus Plugin
* Make plugin methods log() and devlog() work again
* Fixed bug in SQLMap plugin that made the client freeze
* Improved SQLMap plugin to support more options and to show errors in GTK log console
* Fixed bug when creating/updating Credentials
* Improve plugins usage of vulnweb URL fields
* Fixed order of Report Plugins in the GTK import list

March 17, 2017:
---
* Added link to name column in Hosts list
* Created a requirements_extras.txt file to handle optional packages for specific features
* Fixed bug in SQLMap plugin that made the client freeze
* Fixed bug when creating/updating Credentials
* Fixed bug in the WEB UI - menu explanation bubbles were hidden behind inputs
* Fixed conflict resolution when the object was deleted from another client before resolving the conflict
* Improved fplugin
* Improved the installation process
* Improved SQLMap plugin to support --tables and --columns options
* Improved navigation in Web UI
* Merged PR #137 - CScan improvements: bug fixing, change plugin format and removed unnecessary file output
* Merged PR #173 - Hostnames: added hostnames to plugins
* Merged PR #105 - OSint: added the possibility of using a DB other than Shodan
* The Status Report now remembers the sorting column and order

February 8, 2017:
---
* Fixed max amount of vulns pagination bug in Web UI
* Fixed Maltego plugin

January 30, 2017:
---
* Added an activity feed panel in the Dashboard.
* Added AppScan plugin.
* Improved Burp's Online plugin. Added fields and removed HTML tags.
* Refactor remaining modules to be compatible with JS Strict Mode.
* Fixed bug that prevented GTK from closing when user clicked CANCEL on WS creation.
* Fixed size of Workspace creation dialog.
* New cwe databases: English and Spanish.
* Added Hping plugin.
* Enhancements to Wpscan plugin.

November 10, 2016:
---
* New library to connect with Faraday Server.
* Fixed Fplugin, now it uses the new library to communicate with the Server.
* New field for Vulnerabilities: plugin creator and status.
* Refactor in Faraday Core and GTK Client.
* Bug fixing in Faraday Client and Server.
* Added Faraday news notifications in GTK and Web UI.
* New plugins: Dirb, Netdiscover, FruityWifi, Sentinel.
* Improvements on the WPscan plugin.
* Fixed Licenses search.
* Refactor Licenses module to be compatible with JS Strict Mode.

September 19, 2016:
---
* Major refactor of Faraday Client: now we support massive workspaces (100.000+ hosts).
* Fixed more than 10 minor bugs on the Web UI.
* Fixed searching with spaces character on Web UI
* Updated URL shown when starting Faraday.
* Dashboard is now refreshed automatically every 60 seconds.
* Fixed Propecia plugin.
* New plugin: WPscan
* Host Sidebar on GTK now adds information more intelligently and will never block the application.
* Evidence screenshots in report generation is now bigger.
* Help menu in GTK with links to interesting links.
* Added Help section to WEB UI.

August 12, 2016:
---
* Added Faraday Server
* Improved performance in web UI
* Added some basic APIs to Faraday Server
* Added licenses management section in web UI
* Totally removed QT3, GTK is now the only GUI
* Deprecated FileSystem databses: now Faraday works exclusively with Faraday Server and CouchDB
* Added a button to go to the Faraday Web directly from GTK
* Fixed bug when deleting objects from Faraday Web
* Fixed bug where icons where not copied to correct folder on initialization
* Fixed bug where current workspace wouldn't correspond to selected workspace on the sidebar on GTK
* Fixed bug in 'Refresh Workspace' button on GTK
* Fixed bug where Host Sidebar and Statusbar information wasn't correctly updated on GTK
* Fixed bug in service editing
* Fixed sqlmap plugin
* Fixed metapsloit plugin

Jul 1, 2016:
---
* GTK is the default interface now.
* Added new plugin : Ndiff.
* Added new plugin : Netcat (Gnu netcat - OpenBSD netcat - Original netcat)
* Added button to edit your host in the GTK interface.
* Hosts sidebar now can be sorted by amout of vulnerabilities and OS.
* Changes in installation: install.sh now installs only GTK, QT is considered deprecated.
* Changes in installation: Faraday now runs with the last versions of Python modules.
* Changes in installation: fixed names of packages in setup_server.sh
* Usability: Enter key in GTK dialogs works as OK button
* Improved handling of lost connection to CouchDB database
* First steps towards deprecating Filesystem databases
* Fixed a bug when workspace was changed
* Fixed a bug with Import Reports Dialog in GTK GUI on OS X.
* Fixed a bug with Ctrl+Shift+C and Ctrl+Shift+V in some desktops managers.
* Fixed a bug with mapper of vulnerabilities.

Jun 13, 2016:
---
* Added Import Report dialog to Faraday GTK
* Added a 'Loading workspace...' dialog to Faraday GTK
* Added host sidebar to Faraday GTK
* Added host information dialog to Faraday GTK with the full data about a host, its interfaces, services and vulnerabilities
* Added support for run faraday from other directories.
* Fixed log reapparing after being disabled if user created a new tab
* Fixed bug regarding exception handling in Faraday GTK
* Now Faraday GTK supports Ctrl+Shift+C / Ctrl+Shift+V to Copy/Paste
* Faraday will now not crash if you suddenly lose connection to your CouchDB

May 23, 2016:
---
* Removed description from Hosts list in WEB UI
* Fixed sort in Hosts list in WEB UI
* Fixed ports sorting in Host view in WEB UI
* Added search link for OS in Hosts list in WEB UI
* Removed description from Services list in WEB UI
* Added version to Services list in WEB UI
* Modified false values in Hosts list in WEB UI
* Added search links in Services list in WEB UI
* Added scrollbar in Gtk Terminal.
* Added workspace status in Gtk interface
* Added conflict resolution support for the Gtk interface
* Added search entry for workspaces in Gtk
* Added support for 'exit' command inside Faraday's Gtk terminal
* Improved handling of uncaught exceptions in Gtk interface
* Improved text formatting in Gtk's log console
* Fixed several small bugs in Faraday GTK
* Added support for resize workspace bar.
* Added a quote for imported reports in WEB UI.
* Added support for a new type of report in Qualysguard plugin.
* Fixed bugs in plugins: Acunetix - Nmap - Nikto.

Apr 29, 2016:
---
* Added Open services count to Hosts list in WEB UI
* Improved zsh integration
* Added GTK3 interface prototype
* Added plugin detection through report name
* Fixed an error in wcscan script
* Fixed nikto plugin
* Fixed openvas plugin

Apr 04, 2016
---
* Added cli mode (see wiki for usage instructions)
* Support for multiple Faraday instances in the same host
* Fixed bug for editing web vulns in bulk
* Fixed bug for select all in web UI
* Fixed bugs in Qualys, ZAP, nikto, w3af, openVas plugins
* Added some new scripts and helpers


Feb 26, 2016:
---
* Fixed bug in pip debian
* BugFix pip install.
* Checks additionals about dependencies in installation.
* Warning about a upgrade to experimental in debian installation.
* Fixed small bug in CSV importing
* Fixed styles for Status Report
* Fixed bug on Status Report filter after editing
* Added support for Kali Rolling Edition
* Notify user when the current Workspace doesn't exist
* Show all evidence files in Status Report
* Added script to remove all vulns with a specific severity value (parameterized)
* Fixed Arachni Plugin bugs
* Added new version for Maltego Plugin
* Added support for Mint 17

Dec 18, 2015:
---
* Immunity Canvas plugin added
* Added Dig plugin
* Added Traceroute plugin
* Fixed bug in first run of Faraday with log path and API errors
* Added parametrization for port configuration on APIs
* Refactor Plugin Base to update active WS name in var
* Refactor Plugins to use current WS in temp filename under $HOME/.faraday/data. Affected Plugins:
    - amap
    - dnsmap
    - nmap
    - sslcheck
    - wcscan
    - webfuzzer
    - nikto
* Fixed bug get_installed_distributions from handler exceptions
* Added Wiki information about running Faraday without configuring CouchDB
* Fixed Unicode bug in Nexpose-full Plugin
* Filter false-positives in Status Report
* Fixed bug that prevented the use of "reports" and "cwe" strings in Workspace names
* Added port to Service type target in new vuln modal
* Added new scripts for faraday plugin:
    - /bin/delAllVulnsWith.py - delete all vulns that match a regex
    - /bin/getAllbySrv.py - get all IP addresses that have defined open port
    - /bin/getAllIpsNotServices.py added - get all IPs from targets without services
* Fixed bug null last workspace
* Fixed bugs in CSV export/import in QT

Oct 2, 2015:
---
* Continuous Scanning Tool cscan added to ./scripts/cscan
* Fix for saving objects without parent
* Hosts and Services views now have pagination and search
* Updates version number on Faraday Start
* Visual fixes on Firefox
* Migrate graphs from D3.js to Chart.js
* Added Services columns to Status Report
* Added sections of Commercial versions
* Converted references to links in Status Report. Support for CVE, CWE, Exploit Database and Open Source Vulnerability Database
* Added Peepingtom, SSHdefaultscan and pasteAnalyzer plugins
* Fixed Debian install

Sep 10, 2015:
---
* Adding filename path information of report imported in history command
* Remove old couchdb upgrade process
* Adding Iceweasel browser > 38.2.0 support
* Adding more navigability in differents GUI Web (Dashboard/Services/Views)
* Fixed bug copy clipboard offline (update path of ngClip dependeces)
* Added class to set colors to severities in new/edit vuln view
* Medusa, Hydra & Metasploit plug-in now added discovered weak credentials as a vulnerability
* Nmap plug-in applyies a severity depending on the result of a NSE script
* Fixed small bug for empty ease of resolution
* Adding more time to generation shells QT
* Added "Search in Shodan" links in different views (Status Report, Host View, Service View)
* Removed required of name field service bulk edition
* Added ng-disabled on Edit button if select more of 1 host on Host View WEB UI
* Refactored GUI Web:
  Icon added for Modal Error
  OS, Creator, Date for modal-services-by-host.html
  Fixed typo in Host Edit, the popup message was wrong
  First version for in estilos.css for clear mode
  Also, added hover to grey boxes in the Dashboard.
* Added vulns count for Hosts in WEB UI
* Updated w3af plugin to support report version 1.7.6
* Ignored cwe database from updater and QT views
* Plugin for Nexpose XML Export 2.0
* Added masscan plugin (1.0.3)

Aug 19, 2015:
---
* Exported CSV contains filters and columns from Status Report in WEB UI
* Vulnerability counter on Status Report in WEB UI
* Added quick vuln edit and delete in WEB UI
* Expanded Unit Tests for WEB UI
* XML Cleaner
* Kali 2.0 support
* Improve plugins running status log (Adding log information on report importing)
* Clean dev log on plugins
* w3af plugin refactoring
* Fix Debian 7/8.1 install support

Aug 05, 2015:
---

* Added CWE database and integration with vulns creation
* Added ENTER shortcut on modals
* Progress bar for workspace in the dashboard
* Bug fixing in workspaces and status report components
* Unit testing for vulns, status report and workspaces components
* Debian 8.1 support


Jun 30, 2015:
---

* Added hosts CRUD
* Added services CRUD
* Fix ubuntu 15.04 installation bug
* Small bug in burp plugin "Import new vulnerabilities" checkbox issue
* Added an interactive visualization to calculate the value of a Workspace
* Fixed several bugs in WEB UI
* Added a URL filter functionality to the status report, allowing searches by fields


Apr 17, 2015:
---
* You can get the new version here:
* https://github.com/infobyte/faraday/archive/v1.0.10.tar.gz

Changes:

* Styles changes in WEB UI: fancy component selection, improved workspaces selection.

Bugfixes:
* Date on Workspace creation
* Tables in Firefox


Apr 7, 2015:
---
You can get the new version here:
* https://github.com/infobyte/faraday/archive/v1.0.9.tar.gz

Changes:

* Performance improvement in the dashboard
* Fix bug OSX install
* Bug fixes


Mar 9, 2015:
---
You can get the new version here:

* https://github.com/infobyte/faraday/archive/v1.0.8.tar.gz

Changes:

* WcScan script and plugin (scripts/wcscan.py)
* New Dashboard D3 with AngularJS
* Easy access to Vulnerability pages in the Status Report
* Easy access to the Host pages on the dashboard
* Creation and Editing capabilities for the Workspace from the UI Web
* Support installation for the latest version of Debian/Ubuntu/Kali
* sqlmap version 1.0-dev support updated
* API Status Check in both ZSH & QT GUI
* Field added for resolution of vulnerabilities classification with plug-ins updated to support the new function.
* Field added for rating "ease of resolution" for vulnerabilities
* Adjustments for Resolution field

* New Faraday plugin for Burp. Version 1.2
 -Corrections for the vulnerabilities duplication for the burp plugin
 -New tab section to configure the new Vulnerabilities downloads for Faraday

* Automated backup for couch database
* Ability to upload evidence of a vulnerability (as an attachment)
* Ability to assign Vulnerability Impact (confidentiality, integrity, availability).

Dec 12, 2014:
---
You can get the new version here:

* https://github.com/infobyte/faraday/archive/v1.0.7.tar.gz

Changes:

* Improved Vulnerability Edition usability, selecting a vuln will load it's content.
* ZSH UI now is showing notifications.
* ZSH UI now is showing active workspace.
* Faraday now asks confirmation on exit, If you have pending conflicts to solve it will show the number of each.
* Vulnerability creation is now suported in the status report.
* Introducing SSLCheck, a tool for verify bugs in SSL/TLS Certificates on remote hosts. This is integrated with Faraday with a plugin.
* Shodan Plugin is now working with the new API.
* Some cosmetic changes in the status report.

Bugfixes:

* Sorting collumns in the Status Report now is working.
* Workspace icon is based on the type of the workspace.
* Opening the reports in QT UI now opens the active workspace.
* UI Web dates fixes, we were showing dates with a off-by-one error.
* Vulnerability edition was missing 'critical' severity.
* Objects merge bugfixing
* Metadata recursive save fix



Nov 7, 2014:
---
You can get the new version here:

* https://github.com/infobyte/faraday/archive/v1.0.6.tar.gz

Changes:

* Status report modifications:
* Web vulnerability edition support.
* Variable columns in status report.
* New field called "Data" with extra information about a vulnerability.
* Bug fixes


Oct 17, 2014:
----
* https://github.com/infobyte/faraday/commit/a81c6376ed47a2f7b501c8f48f2179eb7c5d58b9

Status report now have edition capabilities
Introducing batch vulnerability edition and deletion. Now you can edit your status report.

Lots of bug fixes

Ubuntu 14.04 support fixes
Mac support fixes


Sep 26, 2014:
----
* https://github.com/infobyte/faraday/commit/440858ec8172193ce401bbf6a5f4b3052edb6edb

New Dashboard design with summarized information.

D3.js Fancy visualizations.

Vulnerability Status report.

Command run user/host identification.

Vulnerability Statistics.

Optimization Refactor.

Jun 06, 2014:
----

* https://github.com/infobyte/faraday/commit/e616bdb44b089bfccf2405e51837eeae5d403b9f

Notifications: Updating objets on faraday now results in a beautiful
notification in the QT ui.

Performance: Enhacing performance when lots of workspaces are available.
We now load each workspace whe it's needed instead of loading ahead the
full workspace list.

UI: Workspace split, now you can select the workspace to visualize. We
are now using bootstrap.

API: New operations on the Rest API (this is just for the following UI
modifications). Vulnerability update and delete operations.

May 14, 2014:
----

* https://github.com/infobyte/faraday/commit/9dfa9ad23dfe450ceb65d38074d55f07425aa90a

Improving (web interface, vulnerability classification)

Apr 30, 2014:
----

* https://github.com/infobyte/faraday/commit/931865fd4bd9c5fbd1a237b52659b1c873e1fcbf

MacOS Support

Apr 04, 2014:
----
* https://github.com/infobyte/faraday/commit/0fe6978fe41dc85cd8540c2f26074f3e3f57507f

We are proud to present two new features that will enhace the Faraday experience.
Taking feedback from our users we took account that each of them had particular needs from their consoles (completion, size, fonts, so on so forth)  and their need to be able to know what commands where run during an engagement.

    * A brand new ZSH based Terminal UI
    * The Command Run execution history
