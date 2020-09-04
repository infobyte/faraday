 * Now agents can upload data to multiples workspaces
 * Add agent and executor data to Activity Feed
 * Add session timeout configuration to server.ini configuration file
 * Add hostnames to already existing hosts when importing a report
 * Display an error when uploading an invalid report
 * Fix aspect ratio distortion in evidence tab of vulnerability preview
 * Change Custom Fields names in exported CSV to make columns compatible with
   `faraday_csv` plugin
 * Fix import CSV for vuln template: some values were overwritten with default values.
 * Catch errors in faraday-manage commands when the connection string is not
   specified in the server.ini file
 * Fix bug that generated a session when using Token authentication
 * Cleanup old sessions when a user logs in
 * Remove unmaintained Flask-Restless dependency
 * Remove pbkdf2\_sha1 and plain password schemes. We only support bcrypt
