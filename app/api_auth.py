import random
import string
import arrow
from base64 import b64decode, b64encode
from datetime import datetime, timedelta
from functools import wraps

from flask import request, abort
from pyblake2 import blake2b

# hard-coded private key
privateKey = 'eb886203-0876-44f0-871d-6dd02fee3abb'


# The actual decorator function
def require_api_key(view_function):
    @wraps(view_function)
    # the new, post-decoration function. Note *args and **kwargs here.
    def decorated_function(*args, **kwargs):
        # Timedelta and now
        delta_time = timedelta(seconds=2)
        now_time = datetime.utcnow()
        if request.headers.get('x-api-claim') and request.headers.get('x-api-mac'):
            uri, api_key, timestamp, nonce = decode_header_claim(request.headers.get('x-api-claim'))
            actual_uri = request.script_root + request.path
            date = datetime.utcfromtimestamp(float(timestamp))
            signature = str(request.headers.get('x-api-mac'))

            # Check URI
            if uri != actual_uri:
                abort(401, 'claim URI does not match posted URI (actual: "%s", expected: "%s"' % (uri, actual_uri))
            # Check timestamp
            elif now_time + delta_time < date or now_time - delta_time > date:
                abort(401, 'claim timestamp outside of time-range (+/- 2 seconds)')
            # Check MAC signature
            elif not verify_mac_signature(signature, uri, api_key, timestamp, nonce):
                abort(401, 'claim MAC signature does not match claim data')
            else:
                return view_function(*args, **kwargs)
        else:
            abort(401)
    return decorated_function


def decode_header_claim(claim_text):
    claim = _decode(claim_text)
    claim_body, timestamp = claim.split('|')
    api_key, uri, nonce = claim_body.split(':')
    return uri, api_key, timestamp, nonce


def encode_header_claim(uri, api_key, timestamp, nonce):
    red_text = '{}:{}:{}|{}'.format(api_key, uri, nonce, str(timestamp))
    return _encode(red_text)


def sign_request_full(uri, api_key, timestamp, nonce, private_key):
    claim_text = encode_header_claim(uri, api_key, timestamp, nonce)
    signature = create_mac_signature(uri, api_key, timestamp, nonce, private_key)
    return claim_text, _encode(signature)


def sign_request(uri, api_key, private_key):
    nonce = ''.join(random.choice(string.ascii_lowercase) for _ in xrange(24))
    timestamp = arrow.get(datetime.utcnow()).timestamp
    return sign_request_full(uri, api_key, timestamp, nonce, private_key)


def verify_mac_signature(signature, uri, api_key, timestamp, nonce):
    actual_signature = _decode(signature)
    server_signature = create_mac_signature(uri, api_key, timestamp, nonce, privateKey)
    return server_signature == actual_signature


def create_mac_signature(uri, api_key, timestamp, nonce, private_key):
    red_text = '{}:{}:{}|{}'.format(api_key, uri, nonce, str(timestamp))
    h = blake2b(key=private_key, digest_size=32)
    h.update(red_text)
    black_text = h.digest()
    return black_text


def _encode(text):
    return b64encode(text).decode('utf-8')


def _decode(text):
    return b64decode(text)

