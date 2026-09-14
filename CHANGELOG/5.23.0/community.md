 * [ADD] Runners table now supports filtering by Status, Tools, Last Execution Date, Last Execution Tool, and Category. #8279
 * [MOD] Upgrade SQLAlchemy to 2.0 and Flask-SQLAlchemy to 3.x. #8308
 * [MOD] Invalidate the current session after a successful password change so users must re-authenticate. #8379
 * [FIX] Fix 500 error when filtering user tokens by the `expired` column. #8395
 * [FIX] Reject out-of-range cron expressions on agent schedules so an invalid crontab can no longer break the schedule list or the scheduler. #8355
