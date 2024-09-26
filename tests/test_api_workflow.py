import random
from time import sleep
from unittest import mock

import pytest
import sqlalchemy

from faraday.server.api.modules.workflow import JobView, TaskView, PipelineView, PipelineSchema, fields_lookup
from faraday.server.models import Workflow, Action, db, Pipeline
from faraday.server.utils.workflows import _process_entry, WORKFLOW_QUEUE
from tests import factories
from tests.factories import ActionFactory, HostFactory, ServiceFactory, VulnerabilityFactory, \
    VulnerabilityWebFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests


vulns_fields = fields_lookup.get("vulnerability")
hosts_fields = fields_lookup.get("host")

vuln_fields_list = [[x, y] for x, y in vulns_fields.items()]
host_fields_list = [[x, y] for x, y in hosts_fields.items()]


WORKFLOW_LIMIT = 999


jobs_url = "/v3/jobs"
pipelines_url = "/v3/pipelines"


def create_pipeline(test_client, model="host", cond=None, actions=None, jobs=None, ws=None):
    ws = factories.WorkspaceFactory.create() if ws is None else ws
    actions = [ActionFactory.create()] if actions is None else actions
    db.session.commit()
    if jobs is None:
        workflow_data = factories.WorkflowFactory.build_dict(
            tasks_ids=[x.id for x in actions],
            model=model,
            rules_json=cond if cond is not None else [
                {
                    "type": "leaf",
                    "field": "description",
                    "operator": "==",
                    "data": "testing"
                }
            ]
        )
        res = test_client.post(jobs_url, data=workflow_data)
        assert res.status_code == 201
        workflows = Workflow.query.filter(Workflow.id == res.json.get("id")).all()
    else:
        workflows = jobs
    fact_dict = factories.PipelineFactory.build_dict(
        jobs_ids=[x.id for x in workflows],
        workspace_id=ws.id
    )
    res = test_client.post(pipelines_url, data=fact_dict)
    assert res.status_code == 201
    pipeline = Pipeline.query.filter(Pipeline.id == res.json.get("id")).first()
    return ws, actions, workflows, pipeline


def patch_jobs_in_pipeline(test_client, pipeline, jobs):
    dict = {
        "jobs_ids": [x.id for x in jobs]
    }
    res = test_client.patch(pipelines_url + f"/{pipeline.id}", data=dict)
    assert res.status_code == 200


@mock.patch('faraday.server.api.modules.workflow.WORKFLOW_LIMIT', WORKFLOW_LIMIT)
class TestPipelineMixinsView(ReadWriteAPITests):
    model = Pipeline
    factory = factories.PipelineFactory
    api_endpoint = 'pipelines'
    view_class = PipelineView
    patchable_fields = ["name"]

    def test_create_fails_with_empty_dict(self):
        pass

    def test_update_an_object_fails_with_empty_dict(self):
        pass

    @pytest.mark.parametrize(
        "obj_type", [
            (HostFactory, "host"),
            # (ServiceFactory, "service"),
            (VulnerabilityFactory, "vulnerability"),
            (VulnerabilityWebFactory, "vulnerability")
        ]
    )
    def test_pipeline_executed(self, test_client, obj_type):
        ws, action, workflow, pipeline = create_pipeline(test_client, obj_type[1])
        obj = obj_type[0].create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)
        assert obj.description == "ActionExecuted"

    def test_pipeline_executed_multiple_actions(self, test_client):
        action1 = ActionFactory.create()
        action2 = ActionFactory.create(command="UPDATE", field="ip", value="1.1.1.1", target="asset")
        ws, action, workflow, pipeline = create_pipeline(test_client, "vulnerability", actions=[action1, action2])
        obj = VulnerabilityFactory.create(description="testing", workspace=ws, service=None)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)
        assert obj.description == "ActionExecuted"
        assert obj.host.ip == "1.1.1.1"

    @pytest.mark.skip(reason="doesn't work on CI, fails on Postgres")
    def test_pipeline_job_order_execute_and_change(self, test_client):
        action1 = ActionFactory.create(value="Workflow1")
        action2 = ActionFactory.create(value="Workflow2")
        db.session.commit()

        workflow_data = factories.WorkflowFactory.build_dict(
            tasks_ids=[action1.id],
            model="host",
            rules_json=[
                {
                    "type": "leaf",
                    "field": "description",
                    "operator": "==",
                    "data": "testing"
                }
            ]
        )
        workflow_data2 = factories.WorkflowFactory.build_dict(
            tasks_ids=[action2.id],
            model="host",
            rules_json=[
                {
                    "type": "leaf",
                    "field": "description",
                    "operator": "==",
                    "data": "Workflow1"
                }
            ]
        )
        res = test_client.post(jobs_url, data=workflow_data)
        assert res.status_code == 201
        job1 = Workflow.query.filter(Workflow.id == res.json.get("id")).first()
        res = test_client.post(jobs_url, data=workflow_data2)
        assert res.status_code == 201
        job2 = Workflow.query.filter(Workflow.id == res.json.get("id")).first()

        ws, action, workflows, pipeline = create_pipeline(test_client)
        patch_jobs_in_pipeline(test_client, pipeline, [job1, job2])

        obj = HostFactory.create(description="testing", workspace=ws)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)
        assert obj.description == "Workflow2"
        obj.description = "testing"
        db.session.add(obj)
        db.session.commit()
        res = test_client.patch(self.url() + f"/{pipeline.id}", data={"jobs_order": "2-1"})
        assert res.status_code == 200
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)
        assert obj.description == "Workflow1"

    def test_change_pipeline_workspace(self, test_client):
        ws1, actions, workflow, pipeline = create_pipeline(test_client)
        ws2 = factories.WorkspaceFactory.create()
        assert ws1.pipelines == [pipeline]
        assert ws2.pipelines == []
        obj = HostFactory.create(description="testing", workspace=ws1)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)
        assert obj.description == "ActionExecuted"
        res = test_client.patch(self.url() + f"/{pipeline.id}", data={"workspace_id": ws2.id})
        assert res.status_code == 200
        assert ws1.pipelines == []
        assert ws2.pipelines == [pipeline]
        obj2 = HostFactory.create(description="testing", workspace=ws2)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj2.__class__.__name__, [obj2.id], obj2.workspace.id)
        assert obj2.description == "ActionExecuted"

    def test_export_pipeline(self, test_client):
        ws, actions, workflow, pipeline = create_pipeline(test_client)
        res = test_client.get(self.url(obj=pipeline) + "/export")
        pipeline_json = PipelineSchema().dump(pipeline)
        assert res.status_code == 200
        assert res.json == {
            'jobs_order': pipeline_json.get("jobs_order"),
            'workspace_id': pipeline_json.get("workspace_id"),
            'name': pipeline_json.get("name"),
            'jobs_ids': [x.get("id") for x in pipeline_json.get("jobs")],
            "description": pipeline_json.get("description"),
            "running": pipeline_json.get("running")
        }

    # @pytest.mark.skip(reason="doesn't work on CI, maybe Queue?")
    def test_run_all(self, test_client):
        WORKFLOW_QUEUE.queue.clear()
        ws, actions, workflow, pipeline = create_pipeline(test_client)
        host = HostFactory.create(description="testing", workspace=ws)
        host2 = HostFactory.create(description="testing2", workspace=ws)
        host3 = HostFactory.create(description="testing", workspace=ws)
        host4 = HostFactory.create(description="testing4", workspace=ws)
        db.session.add(host)
        db.session.add(host2)
        db.session.add(host3)
        db.session.add(host4)
        db.session.commit()
        _process_entry(None, None, pipeline.workspace.id, None, True, pipeline_id=pipeline.id)
        assert host.description == "ActionExecuted"
        assert host2.description != "ActionExecuted"
        assert host3.description == "ActionExecuted"
        assert host4.description != "ActionExecuted"
        assert pipeline.running is False

    def test_disable_pipeline(self, test_client):
        ws, actions, workflow, pipeline = create_pipeline(test_client)
        res = test_client.post(self.url(obj=pipeline) + "/disable")
        assert res.status_code == 200
        assert pipeline.enabled is False

    def test_enable_pipeline(self, test_client):
        ws, actions1, workflow1, pipeline1 = create_pipeline(test_client)
        ws, actions2, workflow2, pipeline2 = create_pipeline(test_client, ws=ws)
        ws, actions3, workflow3, pipeline3 = create_pipeline(test_client, ws=ws)
        ws, actions4, workflow4, pipeline4 = create_pipeline(test_client, ws=ws)
        res = test_client.post(self.url(obj=pipeline1) + "/enable")
        assert res.status_code == 200
        assert pipeline1.enabled is True
        assert pipeline2.enabled is False
        assert pipeline3.enabled is False
        assert pipeline4.enabled is False
        res = test_client.post(self.url(obj=pipeline3) + "/enable")
        assert res.status_code == 200
        assert pipeline1.enabled is False
        assert pipeline2.enabled is False
        assert pipeline3.enabled is True
        assert pipeline4.enabled is False

    def test_can_clone_pipeline(self, test_client):
        ws, actions, workflow, pipeline = create_pipeline(test_client)
        res = test_client.post(f"{pipelines_url}/{pipeline.id}/clone")
        assert res.status_code == 200
        pipeline2 = Pipeline.query.filter(Pipeline.id == res.json.get("id")).first()
        assert pipeline2.name == f"{pipeline.name} - Copy 1"
        assert pipeline.jobs == pipeline2.jobs
        assert pipeline2.enabled is False


class TestActionMixinsView(ReadWriteAPITests):
    model = Action
    factory = factories.ActionFactory
    api_endpoint = 'tasks'
    view_class = TaskView
    patchable_fields = ["name", "description", "command", "field", "value", "target"]


@mock.patch('faraday.server.api.modules.workflow.WORKFLOW_LIMIT', WORKFLOW_LIMIT)
class TestWorkflowMixinsView(ReadWriteAPITests):
    model = Workflow
    factory = factories.WorkflowFactory
    api_endpoint = 'jobs'
    view_class = JobView
    patchable_fields = ["name", "description", "model", "enabled", "tasks_ids", "rules_json"]

    @pytest.mark.parametrize("argument", ["model", "rules_json", "tasks_ids"])
    def test_cannot_create_workflow_with_missing_argument(self, test_client, argument):
        data = self.factory.build_dict()
        data.pop(argument)
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 400
        assert res.json == {'messages': {'json': {argument: ['Missing data for required field.']}}}

    def test_can_create_workflow(self, test_client):
        data = self.factory.build_dict()
        res = test_client.post(self.url(), data=data)
        assert res.status_code == 201

    def test_can_clone_workflow(self, test_client):
        ws, actions, workflow, pipeline = create_pipeline(test_client)
        res = test_client.post(f"{jobs_url}/{workflow[0].id}/clone")
        assert res.status_code == 200
        workflow2 = Workflow.query.filter(Workflow.id == res.json.get("id")).first()
        assert workflow2.name == f"{workflow[0].name} - Copy 1"
        assert workflow[0].actions != workflow2.actions
        assert [workflow[0].actions[0].value,
                workflow[0].actions[0].command,
                workflow[0].actions[0].field] == \
               [workflow2.actions[0].value,
                workflow2.actions[0].command,
                workflow2.actions[0].field]

    def test_can_create_until_limit(self, test_client):
        with mock.patch('faraday.server.api.modules.workflow.WORKFLOW_LIMIT', 7):
            for i in range(2):
                data = self.factory.build_dict()
                res = test_client.post(self.url(), data=data)
                assert res.status_code == 201
            # Workflows created 7, limit 7
            data = self.factory.build_dict()
            res = test_client.post(self.url(), data=data)
            assert res.status_code == 403

    def test_create_workflow_with_action(self, test_client):
        action = ActionFactory.create()
        db.session.commit()
        workflow_data = self.factory.build_dict(tasks_ids=[action.id])
        res = test_client.post(self.url(), data=workflow_data)
        assert res.status_code == 201
        workflow = Workflow.query.filter(Workflow.id == res.json.get("id")).first()
        assert len(workflow.actions) == 1
        assert workflow.actions[0] == action
        assert len(workflow.conditions) == 1

    def test_patch_workflow_with_actions_conditions_executions_does_nothing(self, test_client):
        action = ActionFactory.create()
        workflow = self.factory.create(actions=[action])
        db.session.commit()
        patch_data = {
            "conditions": ["test"],
            "actions": ["test"],
            "executions": ["test"]
        }
        res = test_client.patch(self.url(obj=workflow), data=patch_data)
        assert res.status_code == 200
        assert workflow.conditions != ["test"]
        assert workflow.actions != ["test"]
        assert workflow.executions != ["test"]

    @pytest.mark.parametrize("field", ["name", "description"])
    def test_patch_workflow_with_new_actions_conditions(self, test_client, field):
        action = ActionFactory.create()
        workflow = self.factory.create(actions=[action], model="host")
        action2 = ActionFactory.create(field=field)
        db.session.commit()

        assert action in workflow.actions
        assert workflow.conditions == []

        patch_data = {
            "rules_json": [
                {
                    "type": "leaf",
                    "field": "description",
                    "operator": "==",
                    "data": "test_data"
                }
            ],
            "tasks_ids": [action2.id]
        }
        res = test_client.patch(self.url(obj=workflow), data=patch_data)
        if field == "name":
            assert res.status_code == 400
            assert workflow.conditions == []
            assert action in workflow.actions
        else:
            action = db.session.query(Action).filter(Action.id == action.id).first()
            assert action is None
            assert res.status_code == 200
            assert workflow.conditions is not []
            assert action2 in workflow.actions and action not in workflow.actions

    def test_conditions_fail(self, test_client):
        cond = [
            {
                "type": "leaf",
                "field": "description",
                "operator": "==",
                "data": "testing2"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, cond=cond)
        host = HostFactory.create(description="testing", workspace=ws)
        db.session.add(host)
        db.session.commit()
        _process_entry(host.__class__.__name__, [host.id], host.workspace.id)
        assert host.description != "ActionExecuted"
        assert host.description == "testing"

    def test_conditions_on_host_service(self, test_client):
        cond = [
            {
                "type": "leaf",
                "field": "services/name",
                "operator": "==",
                "data": "test"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, cond=cond)
        host = HostFactory.create(description="testing", workspace=ws)
        service = ServiceFactory.create(name="test", host=host, workspace=ws)
        service2 = ServiceFactory.create(name="test2", host=host, workspace=ws)
        db.session.add(host)
        db.session.add(service)
        db.session.add(service2)
        db.session.commit()
        _process_entry(host.__class__.__name__, [host.id], host.workspace.id)
        assert host.description == "ActionExecuted"

    def test_conditions_on_host_service_fails(self, test_client):
        cond = [
            {
                "type": "leaf",
                "field": "service/name",
                "operator": "==",
                "data": "test"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, cond=cond)
        host = HostFactory.create(description="testing", workspace=ws)
        service = ServiceFactory.create(name="test3", host=host, workspace=ws)
        service2 = ServiceFactory.create(name="test2", host=host, workspace=ws)
        db.session.add(host)
        db.session.add(service)
        db.session.add(service2)
        db.session.commit()
        _process_entry(host.__class__.__name__, [host.id], host.workspace.id)
        assert host.description != "ActionExecuted"

    def test_conditions_on_host_hostnames(self, test_client):
        cond = [
            {
                "type": "leaf",
                "field": "hostnames",
                "operator": "in",
                "data": "test"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, cond=cond)
        host = HostFactory.create(description="testing", workspace=ws)
        host.set_hostnames(["test", "test2"])
        db.session.add(host)
        db.session.commit()
        _process_entry(host.__class__.__name__, [host.id], host.workspace.id)
        assert host.description == "ActionExecuted"

    def test_custom_fields_conditions(self, test_client):
        cf = factories.CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name="test",
            field_type="string",
            field_order=1,
            field_display_name="test",
        )
        db.session.add(cf)
        db.session.commit()
        cond = [
            {
                "type": "leaf",
                "field": "custom_fields/test",
                "operator": "==",
                "data": "test"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, model="vulnerability", cond=cond)
        vuln = VulnerabilityFactory.create(description="asd", workspace=ws, custom_fields={"test": "test"})
        db.session.add(vuln)
        db.session.commit()
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert vuln.description == "ActionExecuted"

    def test_custom_fields_conditions_date(self, test_client):
        cf = factories.CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name="test_date",
            field_type="date",
            field_order=1,
            field_display_name="test_date",
        )
        db.session.add(cf)
        db.session.commit()
        cond = [
            {
                "type": "leaf",
                "field": "custom_fields/test_date",
                "operator": "==",
                "data": "2024-09-12"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, model="vulnerability", cond=cond)
        vuln = VulnerabilityFactory.create(description="asd", workspace=ws, custom_fields={"test_date": "2024-09-12"})
        db.session.add(vuln)
        db.session.commit()
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert vuln.description == "ActionExecuted"

    def test_condition_inverted_in(self, test_client):
        cond = [
            {
                "type": "leaf",
                "field": "host/ip",
                "operator": "inverted_in",
                "data": "New Tag, asd2"
            }
        ]
        ws, action, workflow, pipeline = create_pipeline(test_client, model="vulnerability", cond=cond)

        host = HostFactory.create(description="testing", workspace=ws, ip="asd2")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws, host=host)
        db.session.add(vuln)
        db.session.commit()
        # Fails if we dont wait, "host" not found in Vulnerability
        sleep(1)
        _process_entry(vuln.__class__.__name__, [vuln.id], ws.id)
        assert vuln.description == "ActionExecuted"

    def test_object_does_not_exist(self, test_client):
        action = ActionFactory.create()
        db.session.commit()
        workflow_data = self.factory.build_dict(
            tasks_ids=[action.id],
            model="host",
            rules_json=[
                {
                    "type": "leaf",
                    "field": "description",
                    "operator": "==",
                    "data": "testing"
                }
            ]
        )
        res = test_client.post(self.url(), data=workflow_data)
        assert res.status_code == 201
        host = HostFactory.create(description="testing")
        db.session.add(host)
        db.session.commit()
        host_class_name = host.__class__.__name__
        host_id = host.id
        host_ws_id = host.workspace.id
        db.session.delete(host)
        db.session.commit()
        _process_entry(host_class_name, [host_id], host_ws_id)

    def test_no_workflows_to_run_with_object(self, test_client):
        ws, action, workflow, pipeline = create_pipeline(test_client)
        host = HostFactory.create(description="testing", workspace=ws)
        pipeline.jobs = []
        db.session.add(pipeline)
        db.session.add(host)
        db.session.commit()
        _process_entry(host.__class__.__name__, [host.id], host.workspace.id)

    def test_action_field_valid_and_invalid(self, test_client):
        action = ActionFactory.create(field="ip")
        db.session.commit()
        workflow_data = self.factory.build_dict(
            tasks_ids=[action.id],
            model="host",
            rules_json=[]
        )
        res = test_client.post(self.url(), data=workflow_data)
        assert res.status_code == 201

    def test_action_execute_bool(self, test_client):
        action = ActionFactory.create(field="confirmed", value="true")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert vuln.confirmed is True

    def test_action_execute_references(self, test_client):
        action = ActionFactory.create(command="APPEND", field="references", value="New ref")
        action2 = ActionFactory.create(command="APPEND", field="references", value="New ref2")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action, action2], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        assert not vuln.refs
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert [x.name for x in vuln.refs] == ["New ref", "New ref2"]

    def test_action_execute_policy_violations(self, test_client):
        action = ActionFactory.create(field="policy_violations", value="Newpol")
        action2 = ActionFactory.create(field="policy_violations", value="Newpol2")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action, action2], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        assert not vuln.policy_violations
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert vuln.policy_violations == {"Newpol", "Newpol2"}

    @pytest.mark.parametrize(
        "cf_type", [
            ("test", "int", "4", 4),
            ("test2", "string", "TESTING", "TESTING"),
            ("test3", "list", "TESTING", ["TESTING"])
        ]
    )
    def test_action_execute_cf(self, test_client, cf_type):
        action = ActionFactory.create(field=cf_type[0],
                                      value=cf_type[2],
                                      command="APPEND" if cf_type[1] == "list"else False,
                                      custom_field=True)
        cf = factories.CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name=cf_type[0],
            field_type=cf_type[1],
            field_order=1,
            field_display_name=cf_type[0],
        )
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        assert vuln.custom_fields is None
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert vuln.custom_fields.get(cf_type[0]) == cf_type[3]

    def test_action_execute_on_vuln_asset(self, test_client):
        action = ActionFactory.create(command="UPDATE", field="ip", value="1.1.1.1", target="asset")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws, service=None)
        db.session.add(vuln)
        db.session.commit()
        host = vuln.host
        assert host.ip != "1.1.1.1"
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert host.ip == "1.1.1.1"

    def test_action_execute_on_vuln_web_asset(self, test_client):
        action = ActionFactory.create(command="UPDATE", field="ip", value="1.1.1.1", target="asset")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws, host=None)
        db.session.add(vuln)
        db.session.commit()
        host = vuln.service.host
        assert host.ip != "1.1.1.1"
        _process_entry(vuln.__class__.__name__, [vuln.id], vuln.workspace.id)
        assert host.ip == "1.1.1.1"

    def test_action_execute_on_vuln_asset_conflict_unique(self, test_client):
        action = ActionFactory.create(command="UPDATE", field="ip", value="1.1.1.1", target="asset")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws, service=None)
        vuln2 = VulnerabilityFactory.create(description="testing", workspace=ws, service=None)
        db.session.add(vuln, vuln2)
        db.session.commit()
        host = vuln.host
        host2 = vuln2.host
        assert host.ip != "1.1.1.1"
        assert host2.ip != "1.1.1.1"
        _process_entry(vuln.__class__.__name__, [vuln.id, vuln2.id], vuln.workspace.id)
        assert host.ip != "1.1.1.1"
        assert host2.ip != "1.1.1.1"

    @pytest.mark.skip(reason="Fails when running all tests")
    def test_action_delete(self, test_client):
        action2 = ActionFactory.create(command="DELETE")
        ws, action, workflow, pipeline = create_pipeline(test_client, "vulnerability", actions=[action2])
        obj = VulnerabilityFactory.create(description="testing", workspace=ws, service=None)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)
        # assert obj is deleted with a try except
        with pytest.raises(sqlalchemy.orm.exc.ObjectDeletedError):
            print(obj.id)

    @pytest.mark.parametrize("field", vuln_fields_list)
    def test_vuln_fields_execute_update(self, field, test_client):
        field_name = field[0]
        field_data = field[1]
        field_type = field_data.get("type")
        can_replace = field_data.get("replace")
        valid_values = field_data.get("valid")

        if not can_replace:
            return

        value = None

        if valid_values:
            value = random.choice(valid_values)
        else:
            if field_type in ("string", "policy_violations", "references"):
                value = "testing_new"
            elif field_type == "int":
                value = 123
            elif field_type == "bool":
                value = True

        action_update = ActionFactory.create(command="UPDATE", field=field_name, value=value)

        ws, action, workflow, pipeline = create_pipeline(test_client, "vulnerability", actions=[action_update])
        obj = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)

        if field_type in ("policy_violations"):
            assert getattr(obj, field_name) == {value}
        else:
            assert getattr(obj, field_name) == value

    @pytest.mark.parametrize("field", vuln_fields_list)
    def test_vuln_fields_execute_append(self, field, test_client):
        field_name = field[0]
        field_data = field[1]
        field_type = field_data.get("type")
        can_append = field_data.get("append")
        valid_values = field_data.get("valid")

        if not can_append:
            return

        value = None

        if valid_values:
            value = random.choice(valid_values)
        else:
            if field_type in ("string", "policy_violations", "references"):
                value = "testing_new"
            elif field_type == "int":
                value = 123
            elif field_type == "bool":
                value = True

        action_update = ActionFactory.create(command="APPEND", field=field_name, value=value)

        ws, action, workflow, pipeline = create_pipeline(test_client, "vulnerability", actions=[action_update])
        obj = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)

        if field_type in ("policy_violations"):
            assert getattr(obj, field_name) == {value}
        elif field_type == "references":
            assert [x.name for x in obj.refs] == [value]
        else:
            assert value in getattr(obj, field_name)

    @pytest.mark.parametrize("field", host_fields_list)
    def test_host_fields_execute_update(self, field, test_client):
        field_name = field[0]
        field_data = field[1]
        field_type = field_data.get("type")
        can_replace = field_data.get("replace")
        valid_values = field_data.get("valid")

        if not can_replace:
            return

        value = None

        if valid_values:
            value = random.choice(valid_values)
        else:
            if field_type in ("string", "hostnames"):
                value = "testing_new"
            elif field_type == "bool":
                value = True

        action_update = ActionFactory.create(command="UPDATE", field=field_name, value=value)

        ws, action, workflow, pipeline = create_pipeline(test_client, "host", actions=[action_update])
        obj = HostFactory.create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)

        if field_type == "hostnames":
            hostname_names = [x.name for x in obj.hostnames]
            assert hostname_names == [value]
        else:
            assert getattr(obj, field_name) == value

    @pytest.mark.parametrize("field", host_fields_list)
    def test_host_fields_execute_append(self, field, test_client):
        field_name = field[0]
        field_data = field[1]
        field_type = field_data.get("type")
        can_append = field_data.get("append")
        valid_values = field_data.get("valid")

        if not can_append:
            return

        value = None

        if valid_values:
            value = random.choice(valid_values)
        else:
            if field_type in ("string", "hostnames"):
                value = "testing_new"
            elif field_type == "bool":
                value = True

        action_update = ActionFactory.create(command="APPEND", field=field_name, value=value)

        ws, action, workflow, pipeline = create_pipeline(test_client, "host", actions=[action_update])
        obj = HostFactory.create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, [obj.id], obj.workspace.id)

        if field_type == "hostnames":
            hostname_names = [x.name for x in obj.hostnames]
            assert value in hostname_names
        else:
            assert value in getattr(obj, field_name)
