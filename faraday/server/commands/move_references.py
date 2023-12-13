from sqlalchemy.dialects.postgresql import insert

from faraday.server.models import Workspace, db, VulnerabilityReference


def _move_references(all_workspaces=False, workspace_name=None):
    if all_workspaces:
        print("This could take a while ...")
        workspaces = Workspace.query.all()
    elif workspace_name:
        workspaces = Workspace.query.filter(Workspace.name == workspace_name).all()
    else:
        print("Options required")
        return

    for ws in workspaces:
        ws_references_count = 0
        print(f"Working on workspace {ws.name} ...")
        all_references = []
        query = f"SELECT r.name, r.type, v.id from reference r, vulnerability v, reference_vulnerability_association vr where r.id = vr.reference_id and vr.vulnerability_id = v.id and v.workspace_id = {ws.id}"  # nosec
        result = db.session.execute(query)
        for name, type, vulnerability_id in result:
            all_references.append({
                'name': name,
                'type': type,
                'vulnerability_id': vulnerability_id
            })
            ws_references_count += 1
        if all_references:
            stmt = insert(VulnerabilityReference).values(all_references).on_conflict_do_nothing()
            db.session.execute(stmt)
            db.session.commit()
            if check_migration(ws.id):
                print(f"Moved {ws_references_count} reference/s from {ws.name}")
                delete_old_associated_references(ws.id)
                db.session.commit()
            else:
                print("There are differences between old references and moved references...")
        else:
            print("No references found...")


def check_migration(workspace_id):
    query = f"SELECT count(*) from reference r, vulnerability v, reference_vulnerability_association vr where r.id = vr.reference_id and vr.vulnerability_id = v.id and v.workspace_id = {workspace_id}"  # nosec
    result = db.session.execute(query)
    old_ref_len = [dict(row) for row in result][0]

    query = f"SELECT COUNT(*) FROM vulnerability_reference WHERE vulnerability_id IN (SELECT id FROM vulnerability WHERE workspace_id = {workspace_id})"  # nosec
    result = db.session.execute(query)
    new_ref_len = [dict(row) for row in result][0]

    if old_ref_len['count'] == new_ref_len['count']:
        return True

    return False


def delete_old_associated_references(workspace_id):
    print("Deleting old references associations ...")
    query = f"DELETE from reference_vulnerability_association vr where vr.vulnerability_id IN (SELECT id FROM vulnerability WHERE workspace_id = {workspace_id})"  # nosec
    db.session.execute(query)
    db.session.commit()
    print("All associations were deleted successfully")
