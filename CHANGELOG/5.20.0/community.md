 * [FIX] Fixed user password not being validated on create and edit actions. #8059
 * [MOD] Debouncer now uses Redis to ensure distributed, single execution of workspace updates across Celery workers. #8076
 * [MOD] Changed the packaging and build process to use uv. #8083
 * [FIX] Fix flaky tests. #8185
 * [FIX] Fixed vulnerability bulk update endpoint to improve memory usage and performance. #8094
 * [FIX] Optimized some internal queries. #8201
