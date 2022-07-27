
## Made for our Community!

Offensive security had two difficult tasks: designing smart ways of getting new information, and keeping track of findings to improve further work. With Faraday, you may focus on pentesting while we help you with the rest. Just use it as your terminal and get your work organized on the run.
Faraday was made to let you take advantage of the available tools in the community in a truly multiuser way.

Faraday crunches the data you load into different visualizations that are useful to managers and pentesters alike.

![GUI - Web](https://docs.faradaysec.com/images/activity-dashboard/Activity_Dashboard.png)




To read about the latest features check out the [release notes](https://github.com/infobyte/faraday/blob/master/RELEASE.md)!


# Install Faraday!

Refer to the [releases page](https://github.com/infobyte/faraday/releases)

Check out our documentation for detailed information on how to install Faraday in all of our supported platforms

### Install with pypi
```shell
$ pip3 install faradaysec
```

### Install from repo
```shell
$ pip install virtualenv
$ virtualenv faraday_venv
$ source faraday_venv/bin/activate
$ git clone git@github.com:infobyte/faraday.git
$ pip install .
```
### Install with Docker

to run faraday in docker is mandatory to have a postgres instance running.

```shell
 docker run \
     -v $HOME/.faraday:/faraday-license \
     -v ~/.faraday/storage:/faraday-storage \
     -p 5985:5985 \
     -e PGSQL_HOST='YOUR-DB-IP' \
     -e PGSQL_PASSWD='mypgsqlpassword' \
     -e LISTEN_ADDR='0.0.0.0' \
     faradaysec/faraday:latest
  ```

Open the container and run Create tables

```shell
  faraday-manace create-tables
 ```


or use

Docker compose with the file
 ```shell
version: '3.8'
services:
  db:
    image: postgres:12.7-alpine
    restart: always
    container_name: faraday_db
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=faraday
    ports:
      - '5432:5432'
    volumes:
      - "db:/var/lib/postgresql/data:rw"
  redis:
    image: 'redis:6.2-alpine'
    container_name: faraday_redis
    ports:
      - '6379'
  app:
    image: index.docker.io/faradaysec/faraday
    restart: always
    volumes:
     - "$HOME/.faraday:/home/faraday/.faraday:rw"
    environment:
      - PGSQL_USER=postgres
      - PGSQL_PASSWD=postgres
      - PGSQL_HOST=db
      - PGSQL_DBNAME=faraday
      - REDIS_SERVER=redis
    depends_on:
     - db
     - redis
    ports:
     - "5985:5985"
volumes:
  db:
    driver: local
 ```

For more information about the installation, check out our [Installation Wiki](https://github.com/infobyte/faraday/wiki/Install-Guide).

## Quickstart for linux / pypi

Once you installed faraday packages, you will need to initialize the faraday database:

```shell
# first add your user to the faraday group
$ faraday-manage initdb
```

This will give you a **randomly generated password** to log into the web UI.
Now you can start the server with:

```
$ sudo systemctl start faraday-server
```

In your browser, now you can go to localhost:5985 and login with "faraday" as username, and the password generated in the initdb step.


## API

Check out the documentation of our API [here](https://api.faradaysec.com/).

## Faraday-Cli
Faraday-cli is an alternative to our GUI, providing easy access to the console tools, work in faraday from your own console!

Check the open source repo [faraday-cli](https://github.com/infobyte/faraday-cli)

Check out the documentation [here](https://docs.faraday-cli.faradaysec.com/).


![Example](./docs/images/general.gif)



## Plugins list

You feed data to Faraday from your favorite tools through Plugins. Right now there are more than [80+ supported tools](https://github.com/infobyte/faraday/wiki/Plugin-List), among which you will find:

![](https://raw.github.com/wiki/infobyte/faraday/images/plugins/Plugins.png)

There are three Plugin types: **console** plugins which intercept and interpret the output of the tools you execute, **report** plugins which allows you to import previously generated XMLs, and **online** plugins which access Faraday's API or allow Faraday to connect to external APIs and databases.

[Read more about Plugins](http://github.com/infobyte/faraday/wiki/Plugin-List).

Faraday plugins code can be found in [faraday-plugin repository](https://github.com/infobyte/faraday_plugins)

### Agents

[Faraday Agents Dispatcher](https://github.com/infobyte/faraday_agent_dispatcher) helps user develop integrations with Faraday written in any language.
Agents collects information from different network location using different tools. You can use [Faradaysec](https://www.faradaysec.com) to orchestrate tool execution.


## Links

* Homepage: [FaradaySEC](https://www.faradaysec.com)
* User forum: [Faraday Forum](https://github.com/infobyte/faraday/issues)
* User's manual: [Faraday Wiki](https://docs.faradaysec.com) or check our [support portal](https://support.faradaysec.com/portal/home)
* Download: [Download .deb/.rpm from releases page](https://github.com/infobyte/faraday/releases)
* Commits RSS feed: https://github.com/infobyte/faraday/commits/master.atom
* Issue tracker and feedback: [Github issue tracker](https://github.com/infobyte/faraday/issues)
* Frequently Asked Questions: [FaradaySEC FAQ](https://docs.faradaysec.com/FAQ/)
* Twitter: [@faradaysec](https://twitter.com/faradaysec)
* faraday / demo101 [Demos](https://demo101.faradaysec.com/#/login)
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
