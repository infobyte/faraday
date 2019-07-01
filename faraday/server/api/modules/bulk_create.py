import sqlalchemy
from faraday.server.models import (
    db,
    Host,
    Hostname,
)
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation
    )
from faraday.server.api.modules.hosts import HostSchema

def get_or_create(ws, model_class, data):
    """Check for conflicts and create a new object

    Is is passed the data parsed by the marshmallow schema (it
    transform from raw post data to a JSON)
    """
    obj = model_class(**data)
    obj.workspace = ws
    # assert not db.session.new
    try:
        db.session.add(obj)
        db.session.commit()
    except sqlalchemy.exc.IntegrityError as ex:
        if not is_unique_constraint_violation(ex):
            raise
        db.session.rollback()
        conflict_obj = get_conflict_object(db.session, obj, data)
        if conflict_obj:
            return (False, obj)
        else:
            raise
    # self._set_command_id(obj, True)  # TODO check this
    return (True, obj)

def bulk_create(ws, data):
    for host in data['hosts']:
        create_host(ws, host)

def create_host(ws, raw_data):
    schema = HostSchema(strict=True)
    host_data = schema.load(raw_data).data
    hostnames = host_data.pop('hostnames', [])
    (_, host) = get_or_create(ws, Host, host_data)
    for name in hostnames:
        db.session.add(Hostname(name=name, host=host, workspace=ws))
    db.session.commit()
