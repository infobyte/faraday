## About

Faraday introduces a new concept - IPE (Integrated Penetration-Test Environment) a multiuser Penetration test IDE. Designed for distributing, indexing, and analyzing the data generated during a security audit.

> Made for true pentesters!

Faraday was made to let you take advantage of the available tools in the community in a truly multiuser way.

Designed for simplicity, users should notice no difference between their own terminal application and the one included in Faraday. Developed with a specialized set of functionalities, users improve their own work. Do you remember the last time you programmed without an IDE? What IDEs are to programming, Faraday is to pentesting.

![GUI - GTK](https://raw.github.com/wiki/infobyte/faraday/images/client/gtk_main_window.png)

Faraday crunches the data you load into different visualizations that are useful to managers and pentesters alike.

![GUI - Web](https://raw.github.com/wiki/infobyte/faraday/images/dashboard/dashboard.png)

To read about the latest features check out the [release notes](https://github.com/infobyte/faraday/blob/master/RELEASE.md)!

## Getting Started!

Check out our documentacion for datailed information on how to install Faraday in all of our supported platforms:

![Supported Os](https://raw.github.com/wiki/infobyte/faraday/images/platform/supported.png)

To begin the instalation process check our out [First Step](https://raw.github.com/wiki/infobyte/faraday/First-steps) Wiki.

## New Features!
All of Faraday's latest features and updates are always available on our [blog](http://blog.infobytesec.com/search/label/english).
There are new entries every few weeks, don't forget to check out our amaizing new improvements on it's last entry!


## Plugins list

You feed data to Faraday from your favorite tools through Plugins. Right now there are more than [60+ supported tools](https://github.com/infobyte/faraday/wiki/Plugin-List), among which you will find:

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/Plugins.png)

There are three Plugin types: **console** plugins which intercept and interpret the output of the tools you execute, **report** plugins which allows you to import previously generated XMLs, and **online** plugins which access Faraday's API or allow Faraday to connect to external APIs and databases.

[Read more about Plugins](http://github.com/infobyte/faraday/wiki/Plugin-List).

## Features

### Workspaces
Information is organized into various **Workspaces**. Each Workspace contains a pentest team's assignments and all the intel that is discovered.

### Conflicts
If two plugins produce clashing information for an individual element, a conflict that the user will have to resolve is generated.  An example is if **user1** incorporates host *127.0.0.1 OS:Linux* and **user2** incorporates *127.0.0.1 OS: Linux Ubuntu 13.10*.

On our [GTK interface](https://github.com/infobyte/faraday/wiki/Usage#gtk-gui) there's a button on the bottom right corner of the main window displaying the number of conflicts in the current workspace. To resolve them, just click on the button and a window will open where you can edit the conflicting objects and select which one to keep.

### Faraday plugin

Using our plugin you can perform various actions using the command line, for example:

    $ cd faraday-dev/bin/
    $ ./fplugin create_host 192.154.33.222 Android
    1a7b2981c7becbcb3d5318056eb29a58817f5e67
    $ ./fplugin filter_services http ssh -p 21 -a
    Filtering services for ports: 21, 22, 80, 443, 8080, 8443

    192.168.20.1    ssh     [22]    tcp open    None
    192.168.20.1    http    [443]   tcp open    None
    192.168.20.7    ssh     [22]    tcp open    Linux
    192.168.20.7    http    [443]   tcp open    Linux
    192.168.20.11   ssh     [22]    tcp open    Linux


Read more about the [Faraday Plugin](https://github.com/infobyte/faraday/wiki/faraday-plugin).

### Notifications
Updating objects on other Faraday instances result in notifications on your
Faraday GTK Client.

![](https://raw.github.com/wiki/infobyte/faraday/images/client/gtk_notifications_dialog.png)


### CSV Exporting
Faraday supports CSV Exporting from its WEB UI.
[More information](Exporting-the-information)

## Links

* Homepage: https://www.faradaysec.com
* User forum: https://forum.faradaysec.com
* User's manual: https://github.com/infobyte/faraday/wiki
* Download: [.tar.gz](https://github.com/infobyte/faraday/tarball/master)
* Commits RSS feed: https://github.com/infobyte/faraday/commits/master.atom
* Issue tracker: https://github.com/infobyte/faraday/issues
* Frequently Asked Questions (FAQ): https://github.com/infobyte/faraday/wiki/FAQ
* Mailing list subscription: https://groups.google.com/forum/#!forum/faradaysec
* Twitter: [@faradaysec](https://twitter.com/faradaysec)
* [Demos](https://github.com/infobyte/faraday/wiki/Demos)
* IRC: [ircs://irc.freenode.net/faraday-dev](ircs://irc.freenode.net/faraday-dev) [WebClient](https://webchat.freenode.net/?nick=wikiuser&channels=faraday-dev&prompt=1&uio=d4)
* Screenshots: https://github.com/infobyte/faraday/wiki/Screenshots
* Send your ideas and suggestions here: [https://www.faradaysec.com/ideas](https://www.faradaysec.com/ideas)

## Presentations

* Ekoparty Security Conference - 2017:
   * http://blog.infobytesec.com/2017/10/ekoparty-2017-review_23.html

* Black Hat Arsenal Asia - 2017:
   * https://www.blackhat.com/asia-17/arsenal.html#faraday

* Zero Nights - 2016
   * https://www.slideshare.net/AlexanderLeonov2/enterprise-vulnerability-management-zeronights16

* AV Tokio - 2016:
   * http://en.avtokyo.org/avtokyo2016/event

* Black Hat Arsenal USA - 2016:

   * https://www.blackhat.com/us-16/arsenal.html#faraday

* Black Hat Arsenal Europe - 2016
   * https://www.blackhat.com/eu-16/arsenal.html#faraday

* SecurityWeekly - 2016:
   * http://securityweekly.com/2016/08/02/security-weekly-475-federico-kirschbaum/

* Bsides Latam - 2016:
   * http://www.infobytesec.com/down/Faraday_BsideLatam_2016.pdf

* Black Hat Arsenal Asia - 2016:
   * https://www.blackhat.com/asia-16/arsenal.html#faraday

* Black Hat Arsenal Europe - 2015:
   * https://www.blackhat.com/eu-15/arsenal.html#faraday

* Black Hat Arsenal USA - 2015:
   * https://www.blackhat.com/us-15/arsenal.html#faraday
   * http://blog.infobytesec.com/2015/08/blackhat-2015_24.html

* RSA - 2015:
   * http://www.rsaconference.com/events/us15/expo-sponsors/exhibitor-list/1782/infobyte-llc
   * http://blog.infobytesec.com/2015/05/infobyte-en-la-rsa-2015.html

* Ekoparty Security Conference - 2014:
   * https://www.youtube.com/watch?v=_j0T2S6Ppfo

* Black Hat Arsenal - 2011
   * http://www.infobytesec.com/down/Faraday_BH2011_Arsenal.pdf

* Ekoparty Security Conference - 2010:
   * http://prezi.com/fw46zt6_zgi8/faraday/
   * http://vimeo.com/16516987
