API Reference
=============

Generic views
-------------

.. autoclass:: server.api.base.GenericView
    :members: model_class,schema_class,route_prefix,base_args,representations,
              lookup_field,lookup_field_type,unique_fields
    :private-members:

.. autoclass:: server.api.base.ListMixin
.. autoclass:: server.api.base.RetrieveMixin
.. autoclass:: server.api.base.CreateMixin
.. autoclass:: server.api.base.UpdateMixin
.. autoclass:: server.api.base.DeleteMixin
.. autoclass:: server.api.base.ReadOnlyView
.. autoclass:: server.api.base.ReadWriteView


