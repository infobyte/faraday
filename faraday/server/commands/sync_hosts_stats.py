from faraday.server.models import db, Host
from faraday.server.config import faraday_server


def _sync_hosts_stats():
    print("Syncing hosts stats ...")
    hosts_id = db.session.query(Host.id).all()
    if hosts_id:
        print(f"Found {len(hosts_id)} hosts ...")
        print("This may take a while ...")
        from faraday.server.tasks import update_host_stats  # pylint: disable=import-outside-toplevel
        _hosts_id = [host_id[0] for host_id in hosts_id]
        if faraday_server.celery_enabled:
            print("Processing updates in background ...")
            update_host_stats.delay(_hosts_id, [])
        else:
            update_host_stats(_hosts_id, [])
