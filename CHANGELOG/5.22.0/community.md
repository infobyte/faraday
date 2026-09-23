 * [ADD] Added workspace_name to the supported columns for vulnerabilities CSV export. #8272
 * [ADD] Expose creator command, parameters and per-service status on assets' API response. #8253
 * [ADD] Added float type support for custom attributes. #8079
 * [ADD] Added `Last Detected` as a filterable attribute in pipeline job rules. #8202
 * [MOD] Truncate large vulnerability fields to 100 chars in the table view; CSV export preserves full content. #8270
 * [MOD] Modify celery log handler to support log rotation with 5 historical files. #7649
 * [FIX] Include cloud agent executions in workspace last_run_agent_date. #8233
 * [FIX] Improved handling and validation of sorting parameters in the Filter API. #8327
 * [FIX] Fixed `Activity Feed` returning nonvisible items. #8003
 * [FIX] Fixed workflow conditions failing on asset date/numeric fields with `<`/`>`/`<=`/`>=`. #8296
 * [FIX] Fixed duplicate notifications and premature command close on multi-batch report imports. #8313
 * [FIX] Fixed random CI test failures. #8187
 * [FIX] Fixed assets filter dropping items with no creator when ordering, filtering or grouping by creator username. #7268
 * [FIX] Fixed several OpenAPI/Swagger generation bugs and document enum constraints on schema fields. #8181
