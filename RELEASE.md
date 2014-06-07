Notes
--------

IMPORTANT
===========

Please be kind to remove all your pyc files before running faraday if you are updating this piece of software.  
We made a big refactor in the latest iteration moving some code into a diferent package.


New features in the latest update
=====================================

Jun 06, 2014:

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

* https://github.com/infobyte/faraday/commit/9dfa9ad23dfe450ceb65d38074d55f07425aa90a

Improving (web interface, vulnerability classification)
 
Apr 30, 2014:

* https://github.com/infobyte/faraday/commit/931865fd4bd9c5fbd1a237b52659b1c873e1fcbf

* MacOS Support

Apr 04, 2014:
* https://github.com/infobyte/faraday/commit/0fe6978fe41dc85cd8540c2f26074f3e3f57507f

We are proud to present two new features that will enhace the Faraday experience.
Taking feedback from our users we took account that each of them had particular needs from their consoles (completion, size, fonts, so on so forth)  and their need to be able to know what commands where run during an engagement.

    * A brand new ZSH based Terminal UI
    * The Command Run execution history


