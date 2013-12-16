![Faraday Logo](https://raw.github.com/wiki/infobyte/faraday/images/Faraday-Logo.png)

Faraday is the first multiuser Penetration test IDE. Designed for distribution, indexation and analysis of the generated data during the process of a security audit.

The main purpose of Faraday is to re-use the available tools in the community to take advantage of them in a multiuser way.

Design for simplicity, users should feel no difference between their own terminal application and the one included in Faraday. Developed with a specialized set of functionalities that help users improve their own work. Do you remember yourself programming without an IDE? Well, Faraday does the same an IDE does for you when programming, but from the perspective of a penetration test.

Requirements
----
Modern Linux (Tested Debian / Ubuntu  * / Kali / Backtrack)
* Python 2.6.x and 2.7.x
* Qt3
* CouchDB >= 1.2.0  
* The following python libs:
  * mockito 
  * couchdbkit 
  * whoosh 
  * argparse 
  * psycopg2
  * IPy
  * requests

Installation
---
Quick install:

    $ curl https://raw.github.com/infobyte/faradaysec/a6a7536e/install-faraday | bash -s stable
    $ chmod +x install-faraday && ./install-faraday

Download the latest tarball by clicking [here] (https://github.com/infobyte/faradaysec/tarball/master) 

Preferably, you can download faraday by cloning the [Git] (https://github.com/infobyte/faraday) repository:

    $ git clone https://github.com/infobyte/faraday.git faraday-dev
    $ cd faraday-dev
    $ ./install
    
Usage 
----- 

To get started, simply execute faraday and use the new console to start working in the pentest: 

       $ ./faraday
    

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

