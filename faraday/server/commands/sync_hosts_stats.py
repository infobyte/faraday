from faraday.server.models import db, Host, Workspace
from faraday.server.config import faraday_server
from colorama import Fore


def _sync_hosts_stats(async_mode=False):
    print(f"[{Fore.GREEN}*{Fore.RESET}] Syncing hosts stats ...")
    hosts_id = db.session.query(Host.id).all()
    workspaces_id = db.session.query(Workspace).all()
    if hosts_id and workspaces_id:
        print(f"[{Fore.GREEN}*{Fore.RESET}] Found {len(hosts_id)} hosts ...")
        print(f"[{Fore.YELLOW}!{Fore.RESET}] This may take a while ...")
        from faraday.server.tasks import update_host_stats  # pylint: disable=import-outside-toplevel
        _hosts_id = [host_id[0] for host_id in hosts_id]
        _workspaces_id = [workspace.id for workspace in workspaces_id]
        if async_mode:
            print(f"[{Fore.GREEN}*{Fore.RESET}] Updating asynchronously")
            if faraday_server.celery_enabled:
                print(f"[{Fore.GREEN}*{Fore.RESET}] Processing updates in background ...")
                update_host_stats.delay(_hosts_id, [], workspace_ids=_workspaces_id)
            else:
                print(f"[{Fore.RED}!{Fore.RESET}] Error: To use async mode you must have celery enabled in your settings")
        else:
            print(F"[{Fore.GREEN}*{Fore.RESET}] Updating synchronously")
            update_host_stats(_hosts_id, [], workspace_ids=_workspaces_id, sync=True)
