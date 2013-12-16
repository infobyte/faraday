=======================
Client & Server details
=======================

******
Client
******

· Terminal with user prompt.

· Looks like and IDE.

· Local database.

The client, similar to an IDE because of it's visual design and how it allows users to handle each pentest as a separated project. Leaving design aside, what's most important about Faraday, is that the user should not feel the difference between its own terminal and Faraday's one, because it's an environment with a simple terminal with a specialized set of buttons around, a customized right click for quick actions, and a display on the right side to display gathered data as a tree.

Each client gathers information from security tools output/reports (mainly used for pentest) using plugins to select the sensitive data (There's a list of the supported tools by now). The gathered information is stored in a local database, which will be pulled, pushed, or updated to the central database, located in the Server, where all non-replicant data remains, which will be displayed for every Client connected to the same server, thus ensuring that all users share data in real time and in an updated way.

The database is relational, so as soon as more data becomes available to the database, Faraday will suggest the usage of available tools on available data according to: targets, open ports, services, for example: nmap to 127.0.0.1, and if that pushes to the database new ports on that target, then Faraday will suggest using amap on new ports. 

Faraday also allows its users to create user defined plugins and presets to save time doing one thing over and over again, for example: set some tool to fuzz a certain port on all available targets.

 
******
Server
******

It's just a relational database, and works as an SVN server providing users (authorized Clients connected to the Server) updated data of a current pentest.

The main purpose of Faraday is to reuse the tools available in the community to get more advantage from them in a multiuser way  having obtained information focused on one database.

Battlestation?

