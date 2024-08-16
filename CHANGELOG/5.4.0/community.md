 * [ADD] Implemented Elasticsearch vulnerability ingest from Faraday for comprehensive statistical analysis. #7723
 * [ADD] Implemented workspace update functionality for changes to vulnerabilities, assets, and services. Introduced debouncer logic to prevent redundant updates to the database.#7688
 * [ADD] Added ping timeout, ping interval and logger parameters on faraday server config. #7740
 * [MOD] Changed session_timeout in config to float to allow for fractions of hours. #7737
 * [FIX] Improved SID logic to prevent inconsistencies when the server resets. Also fixed a bug where SIDs were removed using faraday-manage. #7744
 * [FIX] Improved workspaces performance. #7756
 * [FIX] Fix filtering numerical Custom Attributes with some operators. #7759
 * [DEL] Delete unnecessary websocket_port number for default server.ini configuration files. #7729
