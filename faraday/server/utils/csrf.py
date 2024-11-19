from flask_wtf.csrf import validate_csrf
from wtforms import ValidationError


def validate_file(request):
    if 'file' not in request.files:
        raise FileNotFoundError()

    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError as e:
        raise ValidationError(str(e)) from e

    return request.files['file']
