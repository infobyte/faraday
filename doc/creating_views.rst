Creating simple views
=====================

The following page is a quick-start to our REST API framework. It allows you
create CRUD API Endpoints without so many boilerplate, repeated code. Its
class based-style of doing things, inspired in `Django Rest Framework`_, lets
you make fully functional endpoints with a few lines of code and customize
them based on your needs.

.. _`Django REST Framework`: http://django-rest-framework.org/

The first thing you will need is a working SQLAlchemy model. Based on wether
that model will be available on only one workspace (like the majority of out
models) or in all the workspaces (like vuln templates or licenses) the things
are a bit different.


Workspaced views
----------------

This are the most used in Faraday. Use it when you want a generic endpoint that
automatically performs the required workspace restrictions.

.. warning :: The base class of workspaced views does a good job preventing
              objects of one workspace showing in another one, but it won't
              do magic. If you are overriding or writing new methods ensure
              you always think on an object's workspace.

Lets take for example a fragment of the services API code (some parts were
omitted because they are not important right now)::

    from server.api.base import AutoSchema, ReadWriteWorkspacedView
    from server.models import Service

    class ServiceSchema(AutoSchema):

        class Meta:
            model = Service
            fields = ("name", "description", "owned")

    services_api = Blueprint('services_api', __name__)

    class ServiceView(ReadWriteWorkspacedView):
        route_base = 'services'
        model_class = Service
        schema_class = ServiceSchema

    ServiceView.register(services_api)

This registers our service endpoint in a `Flask blueprint`_ named
``services_api``. Then, the blueprint should be registered in the main
app in the ``server/app.py`` file::

    def register_blueprints(app):
        # ...
        from server.api.modules.services import services_api
        # ...
        app.register_blueprint(services_api)
        # ...


That is the code of the view. It will have list, detail, create, update, remove
and count endpoints, and all of them will be functional. If you want to only
enable some of them you should inherit from ``GenericWorkspacedView`` and from
some mixins that define each endpoint's behavior.

If you look at the view's code, the only thing it does is to define three
atrributes: ``route_base``, to define what is going on the URL, the class of
the model that the endpoint controls, and a Marshmallow schema defining the
serialization and deserialization proccess (this will be covered later). The
following endpoints will be generated:

* GET /_api/ws/<workspace_name>/services/  (list all the services)
* GET /_api/ws/<workspace_name>/services/count/  (count services)
* GET /_api/ws/<workspace_name>/services/<object_id>/  (get the info of some service)
* POST /_api/ws/<workspace_name>/services/  (create a service)
* PUT /_api/ws/<workspace_name>/services/<object_id>/  (update a service)
* DELETE /_api/ws/<workspace_name>/services/<object_id>/  (delete a service)


.. _`Flask blueprint`: http://flask.pocoo.org/docs/0.12/blueprints/

Non-workspaced views
--------------------

