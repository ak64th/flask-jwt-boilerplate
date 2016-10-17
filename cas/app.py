from __future__ import unicode_literals

import importlib
import os

from flask import Flask, redirect, jsonify
from flask import url_for

import auth
from core.exceptions import APIError


def parse_config():
    mod_name = os.environ.get('CAS_CONFIG_MODULE', 'cas.config')
    return importlib.import_module(mod_name)


app = Flask('cas')
app.config.from_object(parse_config())
app.register_blueprint(auth.blueprint)


@app.errorhandler(APIError)
def on_api_error(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@app.errorhandler(NotImplementedError)
def not_implemented_error(error):
    response = jsonify({'message': 'Not implemented'})
    response.status_code = 400
    return response


@app.route('/')
def index():
    if auth.current_identity:
        return redirect(url_for('auth.info'))
    return redirect((url_for('auth.login')))
