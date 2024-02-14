from faraday.server.models import db, Host
from faraday.server.config import faraday_server
from faraday.server.tasks import calc_vulnerability_stats
from tqdm import tqdm
from colorama import Fore


def _sync_hosts_stats(async_mode=False):
    print(f"[{Fore.GREEN}*{Fore.RESET}] Syncing hosts stats ...")
    hosts_id = db.session.query(Host.id).all()
    if hosts_id:
        print(f"[{Fore.GREEN}*{Fore.RESET}] Found {len(hosts_id)} hosts ...")
        print(f"[{Fore.YELLOW}!{Fore.RESET}] This may take a while ...")
        from faraday.server.tasks import update_host_stats  # pylint: disable=import-outside-toplevel
        _hosts_id = [host_id[0] for host_id in hosts_id]
        if async_mode:
            print(f"[{Fore.GREEN}*{Fore.RESET}] Updating asynchronously")
            if faraday_server.celery_enabled:
                print(f"[{Fore.GREEN}*{Fore.RESET}] Processing updates in background ...")
                update_host_stats.delay(_hosts_id, [])
            else:
                update_host_stats(_hosts_id, [])
        else:
            print(F"[{Fore.GREEN}*{Fore.RESET}] Updating synchronously")
            for host_id in tqdm(_hosts_id, colour="blue"):
                calc_vulnerability_stats(host_id)
