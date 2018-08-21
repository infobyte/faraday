API Reference
=============

Generic views
-------------

Use this ones to expose API endpoints that don't depend of a workspace, such as
users, vuln templates, or the workspaces API itself

.. autoclass:: server.api.base.GenericView
    :members: model_class,schema_class,route_prefix,base_args,representations,
              lookup_field,lookup_field_type,get_joinedloads, get_undefer,
              _get_schema_class, _get_lookup_field, _validate_object_id,
              _get_base_query, _get_eagerloaded_query, _filter_query,
              _get_object, _dump, _parse_data, register

    :private-members:

.. autoclass:: server.api.base.ListMixin
    :members: _envelope_list,_get_order_field,_paginate

.. autoclass:: server.api.base.RetrieveMixin
.. autoclass:: server.api.base.SortableMixin
.. autoclass:: server.api.base.ReadOnlyView
.. autoclass:: server.api.base.CreateMixin
    :members: _perform_create
.. autoclass:: server.api.base.UpdateMixin
    :members: _update_object, _perform_update

.. autoclass:: server.api.base.DeleteMixin
.. autoclass:: server.api.base.ReadWriteView


Generic workspaced views
------------------------

Use this type of views to make workspace-sensitive API endpoints. All views
created by this class need the user to specify a valid workspace name in the URL.

This is the most common type of views in Faraday.

.. autoclass:: server.api.base.GenericWorkspacedView
.. autoclass:: server.api.base.ListWorkspacedMixin
.. autoclass:: server.api.base.RetrieveWorkspacedMixin
.. autoclass:: server.api.base.ReadWriteWorkspacedView
.. autoclass:: server.api.base.CreateWorkspacedMixin
    :members: _perform_create

.. autoclass:: server.api.base.UpdateWorkspacedMixin
    :members: _update_object, _perform_update

.. autoclass:: server.api.base.DeleteWorkspacedMixin
.. autoclass:: server.api.base.CountWorkspacedMixin
.. autoclass:: server.api.base.ReadWriteWorkspacedView
