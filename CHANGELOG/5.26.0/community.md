 * [FIX] Loading hosts through the filter endpoint no longer freezes the instance on workspaces with many services and hostnames. #8603
 * [FIX] Fixed issue with object enums. #8336
 * [FIX] The dispatcher namespace only answers the client that sent a message, instead of every connected agent, so an invalid join no longer disconnects the other agents. #8651
 * [FIX] Sorting credentials by `password` no longer fails with `Invalid filters`. #8593
 * [ADD] Vulnerabilities can be marked as false positives and show their triage status. #8612
 * [ADD] Agents can now be created from the UI before their dispatcher exists. The dispatcher claims the pending agent when it registers with the new optional `dispatcher_id`, and the agents API exposes `pending_registration` and, while the agent is pending, its `dispatcher_id`. #8621
 * [FIX] Vulnerabilities can now be sorted by string, integer, float and date custom attributes. #8608
 * [FIX] Agents can only send bulk_create results to their own executions. #8605
 * [ADD] Services now expose and can be filtered by `creator_command_id`. #8546
 * [FIX] Neutralized spreadsheet formula injection in vulnerability and credential CSV exports. #8607
 * [ADD] Agents can now create, update, enable, disable, delete and read their executors remotely from Faraday, through the new `executor_config` endpoints. Executors expose `enabled` and `varenvs_set`, and agents expose `remote_config`, `remote_config_read` and `agent_capabilities`. #8575
