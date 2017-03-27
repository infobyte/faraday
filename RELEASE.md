IMPORTANT
===========

Please be kind to remove all your pyc files before running faraday if you are updating this piece of software.
Make sure you run ```./faraday.py --update``` the first time after an update!


New features in the latest update
=====================================

TBA
---
* Check that client and server versions match when reconnecting

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
