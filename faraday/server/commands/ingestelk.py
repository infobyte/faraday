import sys
import uuid
from datetime import datetime

import validators
from elasticsearch import Elasticsearch, helpers, __version__
import click
from sqlalchemy.orm import joinedload

from faraday.server.api.modules.vulns import VulnerabilitySchema
from faraday.server.models import Workspace, VulnerabilityGeneric
from faraday.settings import get_settings

CONFIG_SETTINGS_DOCS = "https://docs.faradaysec.com/Faraday-Manage-Settings-v4/"


def _test_connection(elastic_instance, ingest_settings):
    click.secho("Trying to connect to elasticsearch ...", fg="green")
    try:
        elastic_instance.info()
        click.secho(f"Connected successfully to {ingest_settings.host}:{ingest_settings.port}", fg="green")
        return True
    except Exception as e:
        click.secho(f"Could not connect to elasticsearch {ingest_settings.host}:{ingest_settings.port}\n{e}.",
                    fg="red")
        return False


def _ingest(all_workspaces=False,
            workspace_name=None,
            from_id=None,
            to_id=None,
            rename_as=None,
            extra_vuln_tags=[],
            index_name='faraday',
            from_update=None,
            ignore_duplicate_ids=False,
            test_connection=False):

    ingest_settings = get_settings('elk')

    if not ingest_settings.enabled:
        click.secho(f"Elastic ingest is not enabled. For further information go to {CONFIG_SETTINGS_DOCS}", fg="red")
        return

    try:
        elk_args = {
            "retry_on_timeout": True,
            "verify_certs": False
        }
        # Auth method arg changes from version 8
        if __version__[0] < 8:
            if not validators.url(ingest_settings.host):
                click.secho("Failed to connect to Elasticsearch. "
                            "For Python Elasticsearch versions earlier than 8, "
                            "ensure that the host parameter is a valid URL.", fg="red")
                return False
            elk_args.update({
                "http_auth": (ingest_settings.username, ingest_settings.password)
            })
        else:
            elk_args.update({
                "basic_auth": (ingest_settings.username, ingest_settings.password)
            })
        es = Elasticsearch(
            f"{ingest_settings.host}:{ingest_settings.port}",
            **elk_args
        )
    except Exception as e:
        click.secho(f"Could not connect to elasticsearch {ingest_settings.host}:{ingest_settings.port}\n{e}.", fg="red")
        return

    if test_connection:
        _test_connection(es, ingest_settings)
        sys.exit()

    if all_workspaces:
        workspaces = Workspace.query.all()
    elif workspace_name:
        workspaces = Workspace.query.filter(Workspace.name == workspace_name).all()
    else:
        from faraday.manage import ingest  # pylint: disable=import-outside-toplevel
        with click.Context(ingest) as ctx:
            click.secho("Use --workspace-name to specify the workspace from which to import vulnerabilities. "
                        "Alternatively, use --all-workspaces to import vulnerabilities from all workspaces.", fg="red")
        return

    for ws in workspaces:
        click.secho(f"Working on workspace {ws.name} ...", fg="magenta")

        elk_ids = []
        if ignore_duplicate_ids:
            hits = helpers.scan(es,
                                index=index_name,
                                query={"query": {"match": {"workspace": ws.name}}},
                                scroll='1m'
                                )
            elk_ids = [hit['_id'] for hit in hits]
            click.secho(f"Ids already in elasticsearch {len(elk_ids)}", fg="yellow")

        helpers.bulk(client=es, chunk_size=100,
                     actions=generate_actions(ws,
                                              elk_ids,
                                              from_id,
                                              to_id,
                                              rename_as,
                                              extra_vuln_tags,
                                              from_update),
                     index=index_name)


def generate_actions(ws, elk_ids, from_id=None, to_id=None, rename_as=None, extra_vuln_tags=[], from_update_date=None):
    click.secho("Processing vulnerabilities ...", fg="magenta")
    query = VulnerabilityGeneric.query.filter(VulnerabilityGeneric.workspace_id == ws.id)
    if from_update_date:
        query = query.filter(VulnerabilityGeneric.update_date >= from_update_date)
    if from_id:
        query = query.filter(VulnerabilityGeneric.id >= from_id)
        if to_id:
            query = query.filter(VulnerabilityGeneric.id <= to_id)
    count = query.count()
    current_offset = 0
    while current_offset < count:
        click.secho(f"Current offset is {current_offset} / Count {count}...", fg="magenta")
        vulnerabilities = query.options(
            [
                joinedload(VulnerabilityGeneric.cwe),
            ]
        ).order_by(VulnerabilityGeneric.id.asc()).offset(current_offset).limit(5000)
        for vulnerability in vulnerabilities:
            if vulnerability.id not in elk_ids:
                data = VulnerabilitySchema(exclude=['parent', '_id']).dump(vulnerability)
                data['_id'] = uuid.uuid4()
                data['workspace'] = ws.name
                if rename_as:
                    data['workspace'] = rename_as
                if extra_vuln_tags:
                    data['tags'].append(extra_vuln_tags)
                data['ingest_timestamp'] = datetime.utcnow()
                elk_ids.append(vulnerability.id)
                yield data
            else:
                click.secho(f"{vulnerability.id} already imported", fg="yellow")
        current_offset += 5000
