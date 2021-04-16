 * ADD forgot password
 * ADD update services by bulk_create
 * ADD FARADAY_DISABLE_LOGS varibale to disable logs to filesystem
 * ADD security logs in `audit.log` file
 * UPD security dependency Flask-Security-Too v3.4.4
 * MOD rename total_rows field in filter host response
 * MOD improved Export cvs performance by reducing the number of queries
 * MOD sanitize the content of vulns' request and response
 * MOD dont strip new line in description when exporting csv
 * MOD improved threads management on exception
 * MOD improved performance on vulnerability filter
 * MOD improved [API documentation](www.api.faradaysec.com)
 * FIX upload a report with invalid custom fields
 * ADD v3 API, which includes:
    * All endpoints ends without `/`
    * `PATCH {model}/id` endpoints
    * ~~Bulk update via PATCH `{model}` endpoints~~ In a future release
    * ~~Bulk delete via DELETE `{model}` endpoints~~ In a future release
    * Endpoints removed:
      * `/v2/ws/<workspace_id>/activate/`
      * `/v2/ws/<workspace_id>/change_readonly/`
      * `/v2/ws/<workspace_id>/deactivate/`
      * `/v2/ws/<workspace_name>/hosts/bulk_delete/`
      * `/v2/ws/<workspace_name>/vulns/bulk_delete/`
    * Endpoints updated:
      * `/v2/ws/<workspace_name>/vulns/<int:vuln_id>/attachments/` => \
        `/v3/ws/<workspace_name>/vulns/<int:vuln_id>/attachment`
