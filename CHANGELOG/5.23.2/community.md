 * [FIX] Periodic maintenance tasks now run via Celery Beat instead of a self-rescheduling ETA chain, preventing task-storm redelivery. #8399
 * [FIX] Fixed `faraday-manage` failing on a clean installation after the SQLAlchemy 2 upgrade, which left `initdb` unable to create the database. #8465
