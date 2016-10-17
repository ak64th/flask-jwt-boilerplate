from __future__ import unicode_literals

from datetime import timedelta, datetime
from functools import wraps

import jwt
from flask import Blueprint, jsonify, _request_ctx_stack
from flask import current_app
from flask import request
from werkzeug.local import LocalProxy
from werkzeug.security import safe_str_cmp

from core.exceptions import APIError
from db import user_index, username_index

CONFIG_DEFAULTS = {
    'JWT_ALGORITHM': 'HS256',
    'JWT_LEEWAY': timedelta(seconds=10),
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',
    'JWT_EXPIRATION_DELTA': timedelta(seconds=300),
    'JWT_NOT_BEFORE_DELTA': timedelta(seconds=0),
    'JWT_VERIFY_CLAIMS': ['signature', 'exp', 'nbf', 'iat'],
    'JWT_REQUIRED_CLAIMS': ['exp', 'iat', 'nbf']
}


def username_login_callback(username, password):
    user = username_index.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user
    return {}


def jwt_encode_callback(identity):
    secret = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']

    iat = datetime.utcnow()
    exp = iat + current_app.config.get('JWT_EXPIRATION_DELTA')
    nbf = iat + current_app.config.get('JWT_NOT_BEFORE_DELTA')
    identity = getattr(identity, 'id') or identity['id']
    payload = {'exp': exp, 'iat': iat, 'nbf': nbf, 'identity': identity}
    return jwt.encode(payload, secret, algorithm=algorithm)


def request_callback():
    auth_header_value = request.headers.get('Authorization', None)
    auth_header_prefix = current_app.config['JWT_AUTH_HEADER_PREFIX']

    if not auth_header_value:
        return

    parts = auth_header_value.split()

    if parts[0].lower() != auth_header_prefix.lower():
        raise APIError('Unsupported authorization type')
    elif len(parts) == 1:
        raise APIError('Token missing')
    elif len(parts) > 2:
        raise APIError('Token contains spaces')

    return parts[1]


def _jwt_required():
    token = request_callback()

    if token is None:
        raise APIError('Authorization Required')

    secret = current_app.config['JWT_SECRET_KEY']
    algorithm = current_app.config['JWT_ALGORITHM']
    leeway = current_app.config['JWT_LEEWAY']
    verify_claims = current_app.config['JWT_VERIFY_CLAIMS']
    required_claims = current_app.config['JWT_REQUIRED_CLAIMS']

    try:
        options = {'verify_' + claim: True for claim in verify_claims}
        options.update({'require_' + claim: True for claim in required_claims})
        payload = jwt.decode(token, secret, options=options, algorithms=[algorithm], leeway=leeway)
    except jwt.InvalidTokenError as e:
        raise APIError('Invalid token: {}'.format(e.message))

    user_id = payload['identity']
    _request_ctx_stack.top.current_identity = identity = user_index.get(user_id, None)

    if identity is None:
        raise APIError('User does not exist')


def jwt_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            _jwt_required()
            return fn(*args, **kwargs)

        return decorator

    return wrapper


current_identity = LocalProxy(lambda: getattr(_request_ctx_stack.top, 'current_identity', None))


blueprint = Blueprint('auth', __name__, url_prefix='/auth')


@blueprint.record_once
def on_load(state):
    app = state.app
    for k, v in CONFIG_DEFAULTS.items():
        app.config.setdefault(k, v)
    app.config.setdefault('JWT_SECRET_KEY', app.config['SECRET_KEY'])


@blueprint.route('/login/', methods=['POST'])
def jwt_login():
    try:
        data = request.get_json()
        credential_type = data.get('type')
        credential = data.get('credential')
    except AttributeError:
        raise APIError('Invalid credentials')

    if credential_type == 'username':
        identity = username_login_callback(**credential)
    else:
        raise NotImplementedError

    if identity:
        access_token = jwt_encode_callback(identity)
        return jsonify({'access_token': access_token.decode('utf-8')})
    else:
        raise APIError('Invalid credentials')


@blueprint.route('/info/', methods=['GET'])
@jwt_required()
def info():
    user = current_identity
    return jsonify({'id': user.id, 'username': user.username})


@blueprint.route('/refresh/', methods=['GET'])
@jwt_required()
def refresh():
    access_token = jwt_encode_callback(current_identity)
    return jsonify({'access_token': access_token.decode('utf-8')})
