====================
Extending your views
====================

This will cover common recipes used to make more advanced views.

*****************************
Customizing the list endpoint
*****************************

Enabling pagination and sorting
===============================

By default all views inherit from ``SortableMixin`` so they allow the user to
set the order field with the ``sort`` GET parameter, and the direction with the
``sort_dir`` parameter (it's value should be either "asc" or "desc").

To define the default field that will be used if this parameter is not set, you
should set the `order_field` attribute of your class. For example, the Hosts
view uses the IP field to sort the returned data by default::

    class HostsView(PaginatedMixin,
                    FilterAlchemyMixin,
                    ReadWriteWorkspacedView):
        route_base = 'hosts'
        model_class = Host
        order_field = Host.ip.asc()
        # ...

Note that you have to indicate both the field and the direction, like in the
example.

If you want to enable pagination you should explicitly inherit from
``PaginatedMixin``. Then, when the users specify both ``page`` and
``page_number`` GET parameters the view will paginate the results.

By default it won't show the pagination metadata (like the total number of
pages or elements), so you will have to follow the steps below to do it.

Changing returned JSON format
=============================

Since the new views were designed to fit the Web UI, the format of the
list endpoints of different models should be distinct in some cases. 

To do this, you can override the ``_envelope_list`` method of your view.  It
takes a list of serialized objects and a None-able ``pagination_metadata``
object with details of the pagination. If you don't use pagination, you won't
have to worry about this last one. In the case you are inheriting from
``PaginatedMixin``, it will be an instance of `flask_sqlalchemy.Pagination`_.

For example, lets see the code of the vulns API::

    class VulnerabilityView(PaginatedMixin,
                            FilterAlchemyMixin,
                            ReadWriteWorkspacedView):
        # ...
        def _envelope_list(self, objects, pagination_metadata=None):
            vulns = []
            for vuln in objects:
                vulns.append({
                    'id': vuln['_id'],
                    'key': vuln['_id'],
                    'value': vuln
                })
            return {
                'vulnerabilities': vulns,
                'count': (pagination_metadata.total
                        if pagination_metadata is not None else len(vulns))
        }

Ensure that you correctly handle the case of ``pagination_metadata`` being
None. This happens when the user doesn't specify the page number or size, so
all the objects will be shown.


.. _`flask_sqlalchemy.Pagination`: http://flask-sqlalchemy.pocoo.org/2.3/api/#utilities

Adding filters
==============

If you want to enable the API clients to filter by a specific field, you should
inherit from the ``PaginatedMixin`` (this isn't done by default like with
``SortableMixin``). Then you define a ``filterset_class`` attribute in your
class indicating the `filteralchemy filterset`_ to use::

    from filteralchemy import FilterSet, operators

    class HostFilterSet(FilterSet):
        class Meta(FilterSetMeta):
            model = Host
            fields = ('os',)
            operators = (operators.Equal, operators.Like, operators.ILike)

    class HostsView(PaginatedMixin,
                    FilterAlchemyMixin,
                    ReadWriteWorkspacedView):
        route_base = 'hosts'
        model_class = Host
        filterset_class = HostFilterSet

.. _`filteralchemy filterset`: http://filteralchemy.readthedocs.io/en/latest/quickstart.html

Then the user will be able to use GET parameters like ``os`` (exact match)
and ``os__like`` (SQL like) to filter the query.

**********************************************
Trigerring some actions when creating/updating
**********************************************

***********************************************
Using different schemas depending on the method
***********************************************
