"""reformat jira issue fields value

Revision ID: 06c48492f587
Revises: 4bb882a7f9b5
Create Date: 2022-03-31 18:46:21.552568+00:00

"""
from alembic import op
import sqlalchemy as sa

from faraday.server.models import Configuration


# revision identifiers, used by Alembic.
revision = '06c48492f587'
down_revision = '4bb882a7f9b5'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)
    config = session.query(Configuration).filter(Configuration.key == "jira_integration").first()
    if config:
        saved_config = config.value
        for project_key, project_data in saved_config.get("projects", {}).items():
            for it, it_data in project_data.get("ticket_config", {}).get("issue_types", {}).items():
                for field_name, field_data in it_data["fields"].items():
                    if field_data["schema"]["type"] == "array" and field_data["schema"]["items"] in ["option", "component", "group", "version", "string", "user"]:
                        if len(field_data["value"]) > 0 and isinstance(field_data["value"][0], dict):
                            field_data["value"] = [next(iter(i.values())) for i in field_data["value"]]
                    elif field_data["schema"]["type"] == "option-with-child":
                        if "value" in field_data["value"].keys():
                            field_data["value"]["parent"] = field_data["value"].pop("value")
                        if field_data["value"].get("child", {}) and isinstance(field_data["value"]["child"], dict):
                            field_data["value"]["child"] = field_data["value"]["child"].get("value", "")
                    elif field_data["schema"]["type"] in ["priority", "version", "securitylevel", "user", "option", "project"]:
                        if isinstance(field_data["value"], dict):
                            field_data["value"] = next(iter(field_data["value"].values()))
        sa.orm.attributes.flag_modified(config, "value")
        session.add(config)
        session.commit()


def downgrade():
    pass
