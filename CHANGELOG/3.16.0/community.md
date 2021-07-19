 * BREAKING CHANGE: API V2 discontinued
 * BREAKING CHANGE: Changed minimum version of python to 3.7
 * ADD agent parameters has types (protocol with agent and its APIs)
 * ADD move settings from `server.in` to a db model
 * ADD (optional) query logs
 * MOD new threads management
 * MOD vulnerabilities' endpoint no longer loads evidence unless requested with `get_evidence=true`
 * FIX now it is not possible to create workspace of name "filter"
 * FIX bug with dates in the future
 * FIX bug with click 8
 * FIX bug using --port command
 * FIX endpoints returning 500 as status code
 * REMOVE the need tom CSRF token from evidence upload api
