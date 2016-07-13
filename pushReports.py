import os
from couchdbkit import Server, designer


__serv = Server(uri='http://faraday:faraday@127.0.0.1:5984')
reports = os.path.join(os.getcwd(), "views", "reports")

# views dbs update

views = os.path.join(os.getcwd(), "views", "reports", "_attachments", "views")
flist = filter(lambda x: not x.startswith('.'), os.listdir(views))
flist = map(lambda x: os.path.join(views, x), flist)
dbs = filter(
    lambda x: not x.startswith('_') and x != 'cwe' and x != 'reports',
    __serv.all_dbs())
for db in dbs:
    workspace = __serv.get_db(db)
    for view in flist:
        designer.push(view, workspace, atomic=False)

# reports upload
workspace = __serv.get_or_create_db("reports")
designer.push(reports, workspace, atomic=False)
