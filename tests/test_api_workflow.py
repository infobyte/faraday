from dataclasses import dataclass

import pytest

from faraday.server.api.modules.workflow import JobView, TaskView, PipelineView, PipelineSchema
from faraday.server.models import Workflow, Action, db, Pipeline, Comment
from faraday.server.utils.workflows import _process_entry, WORKFLOW_QUEUE
from tests import factories
from tests.factories import ActionFactory, HostFactory, CommentFactory, VulnerabilityFactory, \
    VulnerabilityWebFactory
from tests.test_api_non_workspaced_base import ReadWriteAPITests


@dataclass
class LicenseTest:
    pipeline_jobs_limit: int = 99


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
        _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
        assert obj.description == "ActionExecuted"

    def test_pipeline_executed_and_create_comment_log(self, test_client):
        ws, action, workflow, pipeline = create_pipeline(test_client, "host")
        obj = HostFactory.create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
        assert obj.description == "ActionExecuted"
        comments = db.session.query(Comment).filter(Comment.object_id == obj.id, Comment.object_type == "host").all()
        assert comments

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
        _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
        assert obj.description == "Workflow2"
        obj.description = "testing"
        db.session.add(obj)
        db.session.commit()
        res = test_client.patch(self.url() + f"/{pipeline.id}", data={"jobs_order": "2-1"})
        assert res.status_code == 200
        _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
        assert obj.description == "Workflow1"

    def test_change_pipeline_workspace(self, test_client):
        ws1, actions, workflow, pipeline = create_pipeline(test_client)
        ws2 = factories.WorkspaceFactory.create()
        assert ws1.pipelines == [pipeline]
        assert ws2.pipelines == []
        obj = HostFactory.create(description="testing", workspace=ws1)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
        assert obj.description == "ActionExecuted"
        res = test_client.patch(self.url() + f"/{pipeline.id}", data={"workspace_id": ws2.id})
        assert res.status_code == 200
        assert ws1.pipelines == []
        assert ws2.pipelines == [pipeline]
        obj2 = HostFactory.create(description="testing", workspace=ws2)
        db.session.add(obj)
        db.session.commit()
        _process_entry(obj2.__class__.__name__, obj2.id, obj2.workspace.id)
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
        _process_entry(host.__class__.__name__, host.id, host.workspace.id)
        assert host.description != "ActionExecuted"
        assert host.description == "testing"

    def test_object_not_supported(self, test_client):
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
        comment = CommentFactory.create()
        db.session.add(comment)
        db.session.commit()
        # TODO: Validate success output
        _process_entry(comment.__class__.__name__, comment.id, comment.workspace.id)

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
        _process_entry(host_class_name, host_id, host_ws_id)

    def test_no_workflows_to_run_with_object(self, test_client):
        ws, action, workflow, pipeline = create_pipeline(test_client)
        host = HostFactory.create(description="testing", workspace=ws)
        pipeline.jobs = []
        db.session.add(pipeline)
        db.session.add(host)
        db.session.commit()
        _process_entry(host.__class__.__name__, host.id, host.workspace.id)

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
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        assert vuln.confirmed is True

    @pytest.mark.parametrize("type", ["vulnerability", "host"])
    def test_action_execute_tag_and_check_tag(self, test_client, type):
        action = ActionFactory.create(field="tags", value="New Tag")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model=type)
        if type == "vulnerability":
            obj = VulnerabilityFactory.create(description="testing", workspace=ws)
        else:
            obj = HostFactory.create(description="testing", workspace=ws)
        db.session.add(obj)
        db.session.commit()
        assert not obj.tags
        _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
        assert obj.tags == {"New Tag"}
        if type == "vulnerability":
            action = ActionFactory.create(field="description", value="Tag_found")
            db.session.commit()
            cond = [
                    {
                        "type": "leaf",
                        "field": "tags",
                        "operator": "in",
                        "data": "New Tag"
                    }
                ]
            ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model=type, ws=ws,
                                                             cond=cond)
            test_client.post(f"{pipelines_url}/{pipeline.id}/enable")
            _process_entry(obj.__class__.__name__, obj.id, obj.workspace.id)
            assert obj.description == "Tag_found"

    def test_action_execute_multiple_tags_and_check_tag(self, test_client):
        action = ActionFactory.create(field="tags", value="New Tag, New Tag2,New Tag3")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        assert not vuln.tags
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        assert "New Tag" in vuln.tags
        assert "New Tag2" in vuln.tags
        assert "New Tag3" in vuln.tags

        action = ActionFactory.create(field="description", value="Tag_found")
        db.session.commit()
        cond = [
                {
                    "type": "leaf",
                    "field": "tags",
                    "operator": "in",
                    "data": "New Tag"
                }
            ]
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability", ws=ws,
                                                         cond=cond)
        test_client.post(f"{pipelines_url}/{pipeline.id}/enable")
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        assert vuln.description == "Tag_found"

    def test_action_execute_references(self, test_client):
        action = ActionFactory.create(command="APPEND", field="references", value="New ref")
        action2 = ActionFactory.create(command="APPEND", field="references", value="New ref2")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action, action2], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        assert not vuln.refs
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
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
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        assert vuln.policy_violations == {"Newpol", "Newpol2"}

    def test_action_execute_comment(self, test_client):
        action = ActionFactory.create(field="comments", value="New Comment", command="APPEND")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        comments = db.session.query(Comment)\
            .filter(Comment.object_id == vuln.id, Comment.object_type == "vulnerability").all()
        assert not comments
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        comments = db.session.query(Comment) \
            .filter(Comment.object_id == vuln.id, Comment.object_type == "vulnerability").all()
        assert len(comments) == 2

    @pytest.mark.parametrize(
        "cf_type", [
            ("test", "int", "4", 4),
            ("test", "string", "TESTING", "TESTING"),
            ("test", "list", "TESTING", ["TESTING"])
        ]
    )
    def test_action_execute_cf(self, test_client, cf_type):
        action = ActionFactory.create(field=cf_type[0],
                                      value=cf_type[2],
                                      command="APPEND" if cf_type[1] == "list"else False,
                                      custom_field=True)
        cf = factories.CustomFieldsSchemaFactory.create(
            table_name='vulnerability',
            field_name='test',
            field_type=cf_type[1],
            field_order=1,
            field_display_name='test',
        )
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws)
        db.session.add(vuln)
        db.session.commit()
        assert vuln.custom_fields is None
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        assert vuln.custom_fields.get("test") == cf_type[3]

    def test_action_execute_on_vuln_asset(self, test_client):
        action = ActionFactory.create(command="UPDATE", field="ip", value="1.1.1.1", target="asset")
        db.session.commit()
        ws, action, workflow, pipeline = create_pipeline(test_client, actions=[action], model="vulnerability")
        vuln = VulnerabilityFactory.create(description="testing", workspace=ws, service=None)
        db.session.add(vuln)
        db.session.commit()
        host = vuln.host
        assert host.ip != "1.1.1.1"
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
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
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
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
        _process_entry(vuln.__class__.__name__, vuln.id, vuln.workspace.id)
        _process_entry(vuln2.__class__.__name__, vuln2.id, vuln2.workspace.id)
        assert host.ip == "1.1.1.1"
        assert host2.ip != "1.1.1.1"
