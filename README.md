## About

Faraday introduces a new concept - IPE (Integrated Penetration-Test Environment) a multiuser Penetration test IDE. Designed for distributing, indexing, and analyzing the data generated during a security audit.

> Made for true pentesters!

Faraday was made to let you take advantage of the available tools in the community in a truly multiuser way.

Faraday crunches the data you load into different visualizations that are useful to managers and pentesters alike.

![GUI - Web](https://raw.github.com/wiki/infobyte/faraday/images/dashboard/dashboard.png)

Designed for simplicity, users should notice no difference between their own terminal application and the one included in Faraday. Developed with a specialized set of functionalities, users improve their own work. Do you remember the last time you programmed without an IDE? What IDEs are to programming, Faraday is to pentesting.

![GUI - GTK](https://raw.github.com/wiki/infobyte/faraday/images/client/gtk_main_window.png)

To read about the latest features check out the [release notes](https://github.com/infobyte/faraday/blob/master/RELEASE.md)!


# Installation

Refer to the [releases page](https://github.com/infobyte/faraday/releases) for the latest pre-made installers for all supported operating systems.

Check out our documentation for detailed information on how to install Faraday in all of our supported platforms:

![Supported Os](https://raw.github.com/wiki/infobyte/faraday/images/platform/supported.png)

To begin the installation process, check out our [Installation Wiki](https://github.com/infobyte/faraday/wiki/Install-Guide).

## Development

You need Python 3.6+ and postgres to run the faraday server.

If you want to develop for Faraday, please follow our [development setup for linux](https://github.com/infobyte/faraday/wiki/Development-setup) or [development setup for OSX](https://github.com/infobyte/faraday/wiki/Development-Installation-OSX).

## Quickstart

Once you installed faraday packages, you will need to initialize the faraday database:

```
sudo faraday-manage initdb
```

This will give you a *randomly generated password* to log into the web UI.
Now you can start the server with:

```
systemctl start faraday-server
```

In your browser, now you can go to localhost:5985 and login with "faraday" as username, and the password generated in the initdb step.


## New Features!

All of Faraday's latest features and updates are always available on our [blog](https://medium.com/faraday).
There are new entries every few weeks, don't forget to check out our amazing new improvements on its latest entry!

## API

This is a branch for a PoC of automatically generating the API documentation in the [OpenAPI/swagger](https://www.openapis.org/) format.
To generate the API docs, for example, to use with swagger UI, run:

```
faraday-manage openapi-yaml
```


## Plugins list

You feed data to Faraday from your favorite tools through Plugins. Right now there are more than [70+ supported tools](https://github.com/infobyte/faraday/wiki/Plugin-List), among which you will find:

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/Plugins.png)

There are three Plugin types: **console** plugins which intercept and interpret the output of the tools you execute, **report** plugins which allows you to import previously generated XMLs, and **online** plugins which access Faraday's API or allow Faraday to connect to external APIs and databases.

[Read more about Plugins](http://github.com/infobyte/faraday/wiki/Plugin-List).

Faraday plugins code can be found in [faraday-plugin repository](https://github.com/infobyte/faraday_plugins)

## Features

### Workspaces

Information is organized into various **Workspaces**. Each Workspace contains a pentest team's assignments and all the intel that is discovered.

### Agents

[Faraday Agents Dispatcher](https://github.com/infobyte/faraday_agent_dispatcher) helps user develop integrations with Faraday written in any language.
Agents collects information from different network location using different tools. You can use [FaradaySEC](https://www.faradaysec.com) to orchestrate tool execution.

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


### CSV Exporting

Faraday supports CSV Exporting from its WEB UI.
[More information](Exporting-the-information)

## Links

* Homepage: [FaradaySEC](https://www.faradaysec.com)
* User forum: [Faraday Forum](https://forum.faradaysec.com)
* User's manual: [Faraday Wiki](https://github.com/infobyte/faraday/wiki) or check our [support portal](https://support.faradaysec.com/portal/home)
* Download: [Download .deb/.rpm from releases page](https://github.com/infobyte/faraday/releases)
* Commits RSS feed: https://github.com/infobyte/faraday/commits/master.atom
* Issue tracker: [Github issue tracker](https://github.com/infobyte/faraday/issues)
* Frequently Asked Questions: [FaradaySEC FAQ](https://github.com/infobyte/faraday/wiki/FAQ)
* Twitter: [@faradaysec](https://twitter.com/faradaysec)
* [Demos](https://github.com/infobyte/faraday/wiki/Demos)
* IRC: [ircs://irc.freenode.net/faraday-dev](ircs://irc.freenode.net/faraday-dev) [WebClient](https://webchat.freenode.net/?nick=wikiuser&channels=faraday-dev&prompt=1&uio=d4)
* Releases: [Faraday Releases](https://github.com/infobyte/faraday/releases/)

## Presentations

* Ekoparty ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/argentina.png):
    [2010](http://vimeo.com/16516987) -
    [2014](https://www.youtube.com/watch?v=_j0T2S6Ppfo) -
    [2017](http://blog.infobytesec.com/2017/10/ekoparty-2017-review_23.html) -
    [2018](http://blog.infobytesec.com/2018/10/ekoparty-2018-review_18.html) -
    [2019](https://medium.com/faraday/ekoparty-2019-review-abd1940ac8c6?source=collection_home---4------5-----------------------)

* Black Hat:
    * USA ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/usa.png):
        [2011](http://www.infobytesec.com/down/Faraday_BH2011_Arsenal.pdf) -
        [2015](https://www.blackhat.com/us-15/arsenal.html#faraday) -
        [2016](https://www.blackhat.com/us-16/arsenal.html#faraday) -
        [2017](https://www.blackhat.com/us-17/event-sponsors.html#faraday) -
        [2018](https://www.blackhat.com/us-18/event-sponsors.html#faraday) -
        [2019](https://medium.com/faraday/another-year-at-las-vegas-with-faraday-21b0edcf8d6?source=collection_home---4------8-----------------------)

    * Asia ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/singapore.png):
        [2016](https://www.blackhat.com/asia-16/arsenal.html#faraday) -
        [2017](https://www.blackhat.com/asia-17/arsenal.html#faraday) -
        [2018](https://www.blackhat.com/asia-18/arsenal.html#faraday-v3-collaborative-penetration-test-and-vulnerability-management-platform)

    * Europe ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/europe.png):
        [2015](https://www.blackhat.com/eu-15/arsenal.html#faraday) -
        [2016](https://www.blackhat.com/eu-16/arsenal.html#faraday) -
        [2019](https://medium.com/faraday/the-end-of-the-year-is-always-jam-packed-it-is-a-period-for-looking-back-and-celebrating-the-road-fcf5cb007a3a)

* RSA USA ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/usa.png):
    [2015](https://www.rsaconference.com/events/us15/expo-sponsors/exhibitor-list/1782/infobyte-llc)

* HITBSecConf Dubai ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/uae.png):
   [2018](https://conference.hitb.org/hitbsecconf2018dxb/hitb-armory/)

* SecurityWeekly ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/usa.png):
   [2016](http://securityweekly.com/2016/08/02/security-weekly-475-federico-kirschbaum/)

* Zero Nights ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/russia.png):
   [2016](https://www.slideshare.net/AlexanderLeonov2/enterprise-vulnerability-management-zeronights16)

* AVTokyo ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/japan.png):
    [2016](http://en.avtokyo.org/avtokyo2016/event) -
    [2018](http://en.avtokyo.org/avtokyo2018/event)

* Tel Aviv-Yafo ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/israel.png):
   [2018](https://www.meetup.com/infobyte/events/254031671/)

* SECCON ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/japan.png):
   [2018](https://2018.seccon.jp/seccon/yorozu2018.html)


* PyConAr ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/argentina.png):
   [2018](https://eventos.python.org.ar/events/pyconar2018/activity/75/) -
   [2019](https://eventos.python.org.ar/events/pyconar2019/activity/251/)

* 8.8 Chile ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/chile.png):
   [2018](http://blog.infobytesec.com/2018/11/chronicles-of-trip-to-santiago-88-review.html)

* CharruaCon ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/uruguay.png):
   [2018](https://charrua.org/presentaciones2018/Love_is_in_the_air__Reverse_Engineering_a_hitty_drone.pdf)

* NotPinkCon ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/argentina.png):
   [2018](https://twitter.com/NotPinkCon)

* plusCODE ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/argentina.png):
   [2018](http://pluscode.cc/portfolio_page/introduccion-practica-al-hardware-hacking/)

* BSides LATAM ![](https://raw.github.com/wiki/infobyte/faraday/images/flags/brazil.png):
   [2016](http://www.infobytesec.com/down/Faraday_BsideLatam_2016.pdf)
