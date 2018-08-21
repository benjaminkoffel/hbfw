#!/usr/bin/env python3
import argparse
import base64
import functools
import json
import logging
import re
import time
import uuid
from Cryptodome.PublicKey import RSA
import flask
import flask.logging
import jwt
import yaml

CONFIG_PATH = 'api/config.yaml'
ID_JWKS_PATH = 'api/id.jwks'
ID_PEM_PATH = 'api/id.pem'
ID_KID_PATH = 'api/id.kid'

CONFIG = {}
PEM = ''
JWKS = {}
KID = ''

HOSTS = {}

APP = flask.Flask(__name__)

def configure_logger(app):
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers if gunicorn_logger.handlers else [flask.logging.default_handler]
    app.logger.setLevel(logging.INFO)

def load_config(path):
    with open(path, 'r') as f:
        return yaml.load(f)

def load_key_data(jwks_path, pem_path, kid_path):
    with open(jwks_path, 'r') as f:
        jwks = json.loads(f.read())
    with open(pem_path, 'r') as f:
        pem = f.read()
    with open(kid_path, 'r') as f:
        kid = f.read()
    return jwks, pem, kid

def b64_bigendian(i):
    return base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8,'big')).decode('utf-8').replace('=', '')

def generate_keypair(jwks_path, pem_path, kid_path):
    kid = str(int(time.time()))
    key = RSA.generate(2048)
    pem = key.exportKey('PEM')
    pub = {
        'kid': kid,
        'kty': 'RSA',
        'alg': 'RS256',
        'e': b64_bigendian(key.e),
        'n': b64_bigendian(key.n)
    }
    with open(jwks_path, 'r') as f:
        jwks = json.loads(f.read())
    jwks['keys'].append(pub)
    with open(jwks_path, 'w') as f:
        f.write(json.dumps(jwks, indent=4))
    with open(pem_path, 'w') as f:
        f.write(pem.decode('utf-8'))
    with open(kid_path, 'w') as f:
        f.write(str(kid))

def generate_token(tags, pem, kid, uri):
    timestamp = int(time.time())
    claims = {
        'jti': str(uuid.uuid4()),
        'aud': uri,
        'iat': timestamp,
        'exp': timestamp + (86400 * 30),
        'scope': re.sub(r'[^a-zA-Z ]+', '', ' '.join(tags))
    }
    headers = {
        'kid': kid
    }
    return jwt.encode(claims, pem, 'RS256', headers).decode('utf-8')

def select_rules(config, hosts, tags):
    now = int(time.time())
    for key, value in config['rules'].items():
        if all(t for t in key.split(',') if t in tags):
            expanded = []
            for rule in value:
                match = re.match('.*TAG:([a-zA-Z]+).*', rule)
                if match:
                    for ip in {h['ip'] for h in hosts.values() if match.groups()[0] in h['tags'] and now - h['time'] < 60}:
                        expanded.append(rule.replace('TAG:' + match.groups()[0], ip))
                else:
                    expanded.append(rule)
            return expanded
    return ['DROP']

def authorize_admin(function):
    @functools.wraps(function)
    def decorator(*args, **kwargs):
        if flask.request.headers.get('Authorization', '') != 'Bearer {}'.format(CONFIG['key']):
            flask.abort(401)
        return function(*args, **kwargs)
    return decorator

def authorize_host(function):
    @functools.wraps(function)
    def authorize_host_decorator(*args, **kwargs):
        try:
            pattern = re.compile(r'^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$')
            token = pattern.findall(flask.request.headers['Authorization'])[0]
            headers = jwt.get_unverified_header(token)
            jwk = [k for k in JWKS['keys'] if k['kid'] == headers['kid']][0]
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            flask.g.identity = {
                'headers': headers,
                'claims': jwt.decode(token, key, algorithms='RS256', audience=CONFIG['uri'])
            }
        except Exception:
            flask.abort(401)
        return function(*args, **kwargs)
    return authorize_host_decorator

@APP.route('/rotate', methods=['POST'])
@authorize_admin
def rotate():
    generate_keypair(ID_JWKS_PATH, ID_PEM_PATH, ID_KID_PATH)
    JWKS, PEM, KID = load_key_data(ID_JWKS_PATH, ID_PEM_PATH, ID_KID_PATH)
    return KID

@APP.route('/issue', methods=['POST'])
@authorize_admin
def issue():
    if flask.request.headers.get('Authorization', '') != 'Bearer {}'.format(CONFIG['key']):
        app.logger.info('method=register code=401 reason=authorization')
        flask.abort(401)
    try:
        content = flask.request.get_json()
    except Exception as e:
        app.logger.info('method=register code=400 reason=invalid_json')
        flask.abort(400)
    tags = content['tags']
    return generate_token(tags, PEM, KID, CONFIG['uri'])

@APP.route('/', methods=['GET'])
@authorize_host
def poll():
    id = flask.g.identity['claims']['jti']
    tags = flask.g.identity['claims']['scope'].split(' ')
    HOSTS[id] = {
        'tags': tags,
        'ip': flask.request.remote_addr,
        'time': int(time.time())
    }
    return json.dumps(select_rules(CONFIG, HOSTS, tags))

if __name__=='__main__':
    HOSTS = {}
    configure_logger(APP)
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=4444)
    parser.add_argument('--cert')
    parser.add_argument('--key')
    args = parser.parse_args()
    sslconfig = (args.cert, args.key) if args.cert and args.key else None
    CONFIG = load_config(CONFIG_PATH)
    JWKS, PEM, KID = load_key_data(ID_JWKS_PATH, ID_PEM_PATH, ID_KID_PATH)
    APP.run(host='0.0.0.0', port=args.port, ssl_context=sslconfig)
