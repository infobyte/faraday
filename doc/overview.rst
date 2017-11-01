========
Overview
========

This is the developer documentation of the Faraday server. If you are a user
instead, you should go to the `Faraday Wiki at GitHub
<https://github.com/infobyte/faraday/wiki>`_.

The Faraday server ecosystem
----------------------------
We are using the following Python libraries to keep our server running:

`Flask`_
^^^^^^^^

A minimalistic web framework for Python with a great (but a bit messy)
ecosystem.

`SQLAlchemy`_
^^^^^^^^^^^^^

A really powerful Object Relational Mapper for Python that allows us to map
results of SQL queries to instances of Python objects

`Flask-Classful`_
^^^^^^^^^^^^^^^^

A pretty simple library to create RESTful API endpoints inside a class defining
one or many routes related to that endpoint.  Is takes the idea of Flask
`Pluggable Views`_.

The library is a fork of `Flask-Classy`_, a library that stopped being
maintained 4 years ago.

`Marshmallow`_
^^^^^^^^^^^^^^

Framework-agnostic serialization and deserialization library to define the
input and output schema of our RESTful API in a declarative, pythonic web. It
is heavily inspired on `Django REST Framework serializers`_, but with the goal
of supporting many frameworks and ORMs

`Flask-Security`_
^^^^^^^^^^^^^^^^^

A library prodiving a users and role system with support with Flask and SQLAlchemy.
It gives us customizable registration and login endpoints.

It was build on top of other common Flask libraries such as:

* `Flask-Login`_
.. _`Flask-Login`: https://flask-login.readthedocs.io/en/latest/

* `Flask-Principal`_
.. _`Flask-Principal`: https://pythonhosted.org/Flask-Principal/

.. _flask: http://flask.pocoo.org/
.. _Pluggable Views: http://flask.pocoo.org/docs/0.12/views/
.. _Flask-Classful: https://github.com/teracyhq/flask-classful
.. _Flask-Classy: https://github.com/apiguy/flask-classy
.. _SQLAlchemy: https://www.sqlalchemy.org/
.. _Marshmallow: http://marshmallow.readthedocs.io/en/latest/
.. _Django Rest Framework serializers: http://www.django-rest-framework.org/api-guide/serializers/
.. _Flask-Security: https://flask-security.readthedocs.io/en/latest/

Other libraries we use
^^^^^^^^^^^^^^^^^^^^^^

* `Marshmallow-SQLAlchemy`_ To automatically create Marshmallow schemas based
  on SQLAlchemy models
.. _`Marshmallow-SQLAlchemy`: https://marshmallow-sqlalchemy.readthedocs.io/

* `Flask-SQLAlchemy`_ provides us a nice way to use the framework and the ORM together.
  It also has a good `pagination system` that is used on many API endpoints
.. _`Flask-SQLAlchemy`: http://flask-sqlalchemy.pocoo.org/
.. _pagination system: http://flask-sqlalchemy.pocoo.org/2.3/api/#utilities

* `Webargs`_ to parse the request arguments given a Marshmallow Schema
.. _`Webargs`: http://webargs.readthedocs.io/

* `Filteralchemy`_ to make query filters in a declarative way, inspired on
  `django-filter`_
.. _`django-filter`: https://github.com/carltongibson/django-filter
.. _`Filteralchemy`: http://filteralchemy.readthedocs.io/

* `Depot`_ to have pluggable file storage backends
.. _`Depot`: http://depot.readthedocs.io/
