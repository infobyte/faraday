IMPORTANT
===========

Please be kind to remove all your pyc files before running faraday if you are updating this piece of software.
Make sure you run ```./faraday.py --update``` the first time after an update!


New features in the latest update
=====================================


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
