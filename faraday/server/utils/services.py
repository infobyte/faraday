# Meta fields in common for ServiceSchema and ServiceWorkspacedSchema
SCHEMA_FIELDS = (
    "_id",
    "_rev",
    "command_id",
    "credentials",
    "description",
    "host_id",
    "id",
    "metadata",
    "name",
    "owned",
    "owner",
    "parent",
    "parent_name",
    "port",
    "ports",
    "protocol",
    "status",
    "summary",
    "type",
    "version",
    "vulns",
    "workspace_name",
)

# Meta fields exclusive for ServiceFilterSet
FILTER_SET_FIELDS = (
    "host_id",
    "id",
    "name",
    "port",
    "protocol",
    "workspace_id",
)

WORKSPACED_SCHEMA_EXCLUDE_FIELDS = ("workspace_id",)
