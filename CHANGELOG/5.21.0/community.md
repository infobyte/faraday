 * [FIX] Block pipeline execution on read-only workspaces. #8093
 * [FIX] Fixed internal CI tooling. #8271
 * [FIX] Users update conflicts now properly handle SQLAlchemy session rollback. #8246
 * [ADD] Added custom attributes to the tasks/fields endpoint for jobs. #8007
 * [ADD] Added automation during the CI process. #8241
 * [MOD] Improved internal CI review tooling. #8259
 * [FIX] Fixed pipeline getting permanently stuck in "running" state when Celery worker dies. Added automatic recovery via timeout and periodic cleanup. #8170
 * [ADD] Bulk Create now supports attaching credentials to vulnerabilities via a `credentials` field (works both sync and with Celery enabled). #8078
 * [ADD] Add bulk delete endpoint for agents. #8084
 * [MOD] Update dependencies to resolve security CVEs (flask-login, flask, pyjwt and others). #8058
 * [FIX] Fixed security issue related to filter. #8274
 * [FIX] Fixed filter order on notifications. #8178
 * [MOD] Improved internal CI review tooling. #8252
 * [FIX] Fix 500 error on some occasions when editing a vulnerability into a duplicate. #8232
