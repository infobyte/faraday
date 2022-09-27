 * Now error 403 will respond a json, not a html
 * [FIX] Change resolve_hotname for resolve_hostname in agents
 * Add filters as params for bulk_update
 * Add Swagger view
 * Modify way of filtering dates with `filters`. Now only 'YYYYMMDD' format supported.
 * Add cvss v2 and v3 into model and api
 * [ADD] Now if command_id is sent in a post for hosts, services or vulns, the created object is associated with that command_id if exist
 * Add support for tagging when running an agent
 * Clean up of commented code that's not needed anymore
 * [FIX] Change dns_resolution to resolve_hostname
 * Add CWE into model and api
