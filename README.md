![Faraday Logo](https://raw.github.com/wiki/infobyte/faraday/images/Faraday-Logo.png)

Faraday introduces a new concept - IPE (Integrated Penetration-Test Environment) a multiuser Penetration test IDE. Designed for distribution, indexation and analysis of the data generated during a security audit.

The main purpose of Faraday is to re-use the available tools in the community to take advantage of them in a multiuser way.

Designed for simplicity, users should notice no difference between their own terminal application and the one included in Faraday. Developed with a specialized set of functionalities that help users improve their own work. Do you remember yourself programming without an IDE? Well, Faraday does the same as an IDE does for you when programming, but from the perspective of a penetration test.

![GUI - QT](https://raw.github.com/wiki/infobyte/faraday/images/Faraday-Mainwindow.png)

Once the data is loaded Faraday crunches it into different visualizations useful not only for managers, but also for pentesters.

![GUI - Web](https://raw.github.com/wiki/infobyte/faraday/images/GUI_Dashboard_new.png)

Please read the [RELEASE notes](https://github.com/infobyte/faraday/blob/master/RELEASE.md)!

Plugins list
---
Right now Faraday has more than [40 supported tools](https://github.com/infobyte/faraday/wiki/Plugin-List), among them you will find: 
![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/Plugins.png)


Installation
---

The following platform are supported - [More information] (https://github.com/infobyte/faraday/wiki/Installation) :

![platform](https://raw.github.com/wiki/infobyte/faraday/images/platform/supported.png) 


Quick install:

Download the latest tarball by clicking [here] (https://github.com/infobyte/faraday/tarball/master) 

Preferably, you can download faraday by cloning the [Git] (https://github.com/infobyte/faraday) repository:

    $ git clone https://github.com/infobyte/faraday.git faraday-dev
    $ cd faraday-dev
    $ ./install.sh
    


Usage 
----- 

To get started, simply execute faraday and use the new console to start working in the pentest: 

       $ ./faraday.py
    
Plugins types:
---
We have 3 kind of plugins:
 * Plugins that intercept commands (directly detected when you execute commands in the console)  
 * Plugins that import file reports (you have to copy the report to $HOME/.faraday/report/[workspacename] and faraday will automatically detect the report, process and added to the HostTree.
 * Plugins connectors or online (BeEF, Metasploit, Burp) connect directly with external API or database or connect with Faraday RPC API.   

Get it now!
---
[![Download Tarball](https://raw.github.com/wiki/infobyte/faraday/images/download.png)]
(https://github.com/infobyte/faraday/tarball/master)

Links
---

* Homepage: http://faradaysec.com
* User's manual: https://github.com/infobyte/faraday/wiki
* Download: [.tar.gz] (https://github.com/infobyte/faraday/tarball/master)
* Commits RSS feed: https://github.com/infobyte/faraday/commits/master.atom
* Issue tracker: https://github.com/infobyte/faraday/issues
* Frequently Asked Questions (FAQ): https://github.com/infobyte/faraday/wiki/FAQ
* Mailing list subscription: https://groups.google.com/forum/#!forum/faradaysec
* Twitter: [@faradaysec] (https://twitter.com/faradaysec)
* [Demos] (https://github.com/infobyte/faraday/wiki/Demos)
* IRC: [ircs://irc.freenode.net/faraday-dev] (ircs://irc.freenode.net/faraday-dev)
* Screenshots: https://github.com/infobyte/faraday/wiki/Screenshots

