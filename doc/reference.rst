API Reference
=============

Generic views
-------------

.. autoclass:: server.api.base.GenericView
    :members: model_class,schema_class,route_prefix,base_args,representations,
              lookup_field,lookup_field_type,unique_fields,
              _get_schema_class, _get_lookup_field, _validate_object_id,
              _get_base_query, _filter_query, _get_object, _dump,
              _parse_data, _validate_uniqueness, register
    :private-members:

.. autoclass:: server.api.base.ListMixin
.. autoclass:: server.api.base.RetrieveMixin
.. autoclass:: server.api.base.CreateMixin
.. autoclass:: server.api.base.UpdateMixin
.. autoclass:: server.api.base.DeleteMixin
.. autoclass:: server.api.base.ReadOnlyView
.. autoclass:: server.api.base.ReadWriteView


