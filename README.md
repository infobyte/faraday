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
Don't change the way you work today! Faraday plays well with other, right now it has more than [40 supported tools](https://github.com/infobyte/faraday/wiki/Plugin-List), among them you will find: 

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/Plugins.png)

There are 3 kind of plugins:
 * Plugins that intercept commands, fired directly when a command is detected in the console. These are transparent to you and no additional action on your part is needed.
 * Plugins that import file reports. You have to copy the report to **$HOME/.faraday/report/[workspacename]** (replacing **[workspacename]** with the actual name of your Workspace) and Faraday will automatically detect, process and add it to the HostTree.
 * Plugin connectors or online (BeEF, Metasploit, Burp), these connect to external APIs or databases, or talk directly to Faraday's RPC API.

Getting started
---
The following platforms are supported.

![platform](https://raw.github.com/wiki/infobyte/faraday/images/platform/supported.png) 

Read more about [supported platforms and installation specifics] (https://github.com/infobyte/faraday/wiki/Installation).

##### Quick install

Download the [latest tarball](https://github.com/infobyte/faraday/tarball/master) or clone the [Faraday Git Project](https://github.com/infobyte/faraday repository):

```
$ git clone https://github.com/infobyte/faraday.git faraday-dev
$ cd faraday-dev
$ ./install.sh
$ ./faraday.py
```

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

