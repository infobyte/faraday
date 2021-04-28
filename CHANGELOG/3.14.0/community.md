 * ADD RESTless filter to multiples views, improving the searchs
 * ADD "extras" modal in options menu, linking to other Faraday resources
 * ADD `import vulnerability templates` command to faraday-manage
 * ADD `generate nginx config` command to faraday-manage
 * ADD vulnerabilities severities count to host
 * ADD Active Agent columns to workspace
 * ADD critical vulns count to workspace
 * ADD `Remember me` login option
 * ADD distinguish host flag
 * ADD a create_date field to comments
 * FIX to use new webargs version
 * FIX Custom Fields view in KB (Vulnerability Templates)
 * FIX bug on filter endpoint for vulnerabilities with offset and limit parameters
 * FIX bug raising `403 Forbidden` HTTP error when the first workspace was not active
 * FIX bug when changing the token expiration change
 * FIX bug in Custom Fields type Choice when choice name is too long.
 * FIX Vulnerability Filter endpoint Performance improvement using joinedload. Removed several nplusone uses
 * MOD Updating the template.ini for new installations
 * MOD Improve SMTP configuration
 * MOD The agent now indicates how much time it had run (faraday-agent-dispatcher v1.4.0)
 * MOD Type "Vulnerability Web" cannot have "Host" type as a parent when creating data in bulk
 * MOD Expiration default time from 1 month to 12 hour
 * MOD Improve data reference when uploading a new report
 * MOD Refactor Knowledge Base's bulk create to take to take also multiple creation from vulns in status report.
 * MOD All HTTP OPTIONS endpoints are now public
 * MOD Change documentation and what's new links in about
 * REMOVE Flask static endpoint
 * REMOVE of our custom logger
