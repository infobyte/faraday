"""
Faraday Penetration Test IDE
Copyright (C) 2017  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from flask import abort, Blueprint
from marshmallow import fields, ValidationError
from marshmallow.validate import OneOf

# Local application imports
from faraday.server.models import (
    db,
    Host,
    Service,
    VulnerabilityGeneric,
    Comment,
)
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteWorkspacedView,
    InvalidUsage,
    CreateWorkspacedMixin,
    GenericWorkspacedView,
    BulkDeleteWorkspacedMixin, get_workspace
)

comment_api = Blueprint('comment_api', __name__)


class CommentSchema(AutoSchema):
    _id = fields.Integer(dump_only=True, attribute='id')
    object_id = fields.Integer(attribute='object_id', required=True)
    object_type = fields.String(attribute='object_type',
                                validate=OneOf(['host', 'service', 'comment', 'vulnerability']),
                                required=True)
    text = fields.String(attribute='text', required=True)

    class Meta:
        model = Comment
        fields = (
            'id', 'text', 'object_type', 'object_id'
        )


class CommentCreateMixing(CreateWorkspacedMixin):

    def _perform_create(self, data, workspace_name):
        model = {
            'host': Host,
            'service': Service,
            'vulnerability': VulnerabilityGeneric,
            'comment': Comment
        }
        obj = db.session.query(model[data['object_type']]).get(
            data['object_id'])
        workspace = get_workspace(workspace_name)
        if not obj:
            raise InvalidUsage('Can\'t comment non-existent object')
        if obj.workspace != workspace:
            raise InvalidUsage('Can\'t comment object of another workspace')
        return super()._perform_create(data, workspace_name)


class CommentView(CommentCreateMixing, ReadWriteWorkspacedView, BulkDeleteWorkspacedMixin):
    route_base = 'comment'
    model_class = Comment
    schema_class = CommentSchema
    order_field = 'create_date'


class UniqueCommentView(GenericWorkspacedView,
                        CommentCreateMixing):
    """
        This view is used by the plugin engine to avoid duplicate comments
        when the same plugin and data was ran multiple times.
    """
    route_base = 'comment_unique'
    model_class = Comment
    schema_class = CommentSchema

    def _perform_create(self, data, workspace_name):
        comment = db.session.query(Comment).filter_by(
            text=data['text'],
            object_type=data['object_type'],
            object_id=data['object_id'],
            workspace=get_workspace(workspace_name)
        ).first()

        if comment is not None:
            abort(409, ValidationError(
                {
                    'message': 'Comment already exists',
                    'object': self.schema_class().dump(comment),
                }
            ))
        res = super()._perform_create(data, workspace_name)
        return res


CommentView.register(comment_api)
UniqueCommentView.register(comment_api)
