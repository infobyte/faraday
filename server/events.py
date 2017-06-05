from models import Host
from sqlalchemy import event

from server.websocket_factories import changes_queue


@event.listens_for(Host, 'after_insert')
def receive_after_insert_host(mapper, connection, target):
    msg = {
        'id': target.id,
        'action': 'CREATE',
        'type': 'Host',
        'name': target.name
    }
    changes_queue.put(msg)
