# Meta fields in common for HostSchema and HostWorkspacedSchema
SCHEMA_FIELDS = (
    "_id",
    "_rev",
    "command_id",
    "credentials",
    "default_gateway",
    "description",
    "hostnames",
    "id",
    "importance",
    "ip",
    "mac",
    "metadata",
    "name",
    "os",
    "owned",
    "owner",
    "services",
    "vulns",
    "type",
    "service_summaries",
    "severity_counts",
    "versions",
    "workspace_name",
)

# Meta fields exclusive for HostFilterSet
FILTER_SET_FIELDS = (
    "id",
    "ip",
    "name",
    "os",
    "port",
    "service",
    "workspace_id",
)

WORKSPACED_SCHEMA_EXCLUDE_FIELDS = ("workspace_id",)
