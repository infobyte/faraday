IMPORTANT
===========

Please be kind to remove all your pyc files before running faraday if you are updating this piece of software.  
We made a big refactor in the latest iteration moving some code into a diferent package.

Please run ./faraday.py --update


New features in the latest update
=====================================

TBA:
---
* Added parametrization for port configuration on APIs.
* Bug cwe, reports name in workspaces
* Adding port in vulnerability new gui web target/service

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
* Added Pippingtom, SSHdefaultscan and pasteAnalyzer plugins
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

* Performance improvment in the dahsboard
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


