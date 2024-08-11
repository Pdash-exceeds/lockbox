# Don't change it lightly!  Existing tokens might depend on this!
JWT_ISSUER_LOCKBOX = "lockbox"

import dataclasses
import logging
import os
import sys
import time
import uuid
from typing import Any

import jwt
from flask import Flask, request, make_response,Response, stream_with_context
import requests
from requests.auth import HTTPBasicAuth

from lockbox import JWT_ISSUER_LOCKBOX
from lockbox.audit_log import get_audit_log_provider, Event
from lockbox.config import (
    load_config,
    BasicAuthCredentialConfig,
    BearerTokenCredentialConfig,
    HeadersCredentialConfig,
)

import re
import gzip
import io

def compress_in_memory(data):
    # Create an in-memory bytes buffer
    buffer = io.BytesIO()
    
    # Create a GzipFile object with the buffer as the file object
    with gzip.GzipFile(fileobj=buffer, mode='wb') as gzip_file:
        # Write the data to the gzip file object
        if isinstance(data, str):
            gzip_file.write(data.encode('utf-8'))
        else:
            gzip_file.write(data)
    
    # Get the compressed data from the buffer
    compressed_data = buffer.getvalue()
    
    return compressed_data
class PathPattern:
    def __init__(self, pattern):
        self.pattern = pattern
        self.regex = self._generate_regex()

    def _generate_regex(self):
        # Replace :parameter with named capturing group (?P<parameter>[^/]+)
        regex_pattern = re.sub(r':(\w+)', r'(?P<\1>[^/]+)', self.pattern)
        # Ensure the regex matches the entire string
        regex_pattern = f'^{regex_pattern}$'
        return re.compile(regex_pattern)

    def match(self, path):
        # Match the provided path against the generated regex
        return self.regex.match(path)

    def extract_parameters(self, path):
        match = self.match(path)
        if match:
            return match.groupdict()
        return None
    
app = Flask(__name__)

# Setup logging ASAP
# Credit: https://trstringer.com/logging-flask-gunicorn-the-manageable-way/
if __name__ != "__main__":
    gunicorn_logger = logging.getLogger("gunicorn.error")
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

try:
    config = load_config(os.environ["LOCKBOX_CONFIG_PATH"])
except KeyError as ke:
    app.logger.error(f"Please set LOCKBOX_CONFIG_PATH env var")
    sys.exit(1)
except Exception as e:
    app.logger.error(f"Error loading config: {e}")
    sys.exit(1)

if config.audit_log:
    audit_log_provider = get_audit_log_provider(config.audit_log)
else:
    audit_log_provider = None


@dataclasses.dataclass
class ValidateServiceTokenResult:
    error_message: str | None = None
    error_status_code: int | None = None
    service_token_payload: dict[str, Any] | None = None


def validate_service_token(
    audiences: list[str] | None, service_name: str, service_token: str, signing_key: str
) -> ValidateServiceTokenResult:
    service_token_payload = None
    try:
        service_token_payload = jwt.decode(
            service_token,
            signing_key,
            algorithms=["HS256"],
            options={"verify_signature": False},
        )
        if service_token_payload["iss"] != JWT_ISSUER_LOCKBOX:
            return ValidateServiceTokenResult(
                error_message="Invalid service_name token (bad issuer)",
                error_status_code=401,
                service_token_payload=service_token_payload,
            )
        if service_token_payload["exp"] < time.time():
            return ValidateServiceTokenResult(
                error_message="Invalid service_name token (expired)",
                error_status_code=401,
                service_token_payload=service_token_payload,
            )
        if service_token_payload["service_name"] != service_name:
            return ValidateServiceTokenResult(
                error_message="Invalid service_name token (wrong service_name)",
                error_status_code=401,
                service_token_payload=service_token_payload,
            )
    except Exception as e:
        return ValidateServiceTokenResult(
            error_message="Invalid service_name token",
            error_status_code=401,
            service_token_payload=service_token_payload,
        )
    try:
        allowed_audiences = []
        if audiences is not None:
            allowed_audiences.extend(audiences)
        else:
            allowed_audiences.append(service_token_payload["aud"])
        # verify signature this time
        service_token_payload = jwt.decode(
            service_token, signing_key, algorithms=["HS256"], audience=allowed_audiences
        )
        return ValidateServiceTokenResult(service_token_payload=service_token_payload)
    except Exception as e:
        print(e)
        return ValidateServiceTokenResult(
            error_message="Invalid service_name token (bad audience)",
            error_status_code=401,
            service_token_payload=service_token_payload,
        )


_signing_key: str | None = None


def get_signing_key() -> str:
    global _signing_key
    if _signing_key is None:
        # Check the service_name token
        signing_key_file = os.getenv("LOCKBOX_SIGNING_KEY_FILE")
        if signing_key_file is None:
            raise Exception("Missing LOCKBOX_SIGNING_KEY_FILE environment variable")
        with open(signing_key_file) as f:
            _signing_key = f.read()
    return _signing_key


def _log_request() -> None:
    app.logger.debug(f"Request args = {request.args}")
    for k, v in request.headers.items():
        app.logger.debug(f"Request header: {k} => {v}")


@app.route("/healthz")
def healthz():
    return "OK"



@app.route("/s/<service_name>/", methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/s/<service_name>/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def service(service_name: str, subpath: str = ""):
    # TODO check: can subpath be empty or None?

    request_id = str(uuid.uuid4())

    def _make_event(event_name: str, payload):
        return Event(
            # i.e. request_to_lockbox, lockbox_auth_failure, request_to_service, response_from_service, response_from_lockbox, lockbox_internal_error
            ts=time.time(),
            event_name=event_name,
            service_name=service_name,
            request_id=request_id,
            payload=payload,
        )

    _log_request()
    if audit_log_provider:
        audit_log_provider.log_service_event(
            event=_make_event(
                event_name="request_to_lockbox",
                payload={
                    "request": {
                        "method": request.method,
                        "path": request.path,
                        "args": request.args,
                        "headers": dict(request.headers),
                        "data": request.data.decode("utf-8"),
                        "form": request.form,
                    }
                },
            )
        )

    service_config = config.get_service_config(service_name)
    if service_config is None:
        return f"Invalid service_name {service_name}", 404

    if service_config.requires_service_token:

        def _check_service_token() -> ValidateServiceTokenResult:
            if "Authorization" not in request.headers:
                return ValidateServiceTokenResult(
                    error_message="Missing Authorization header", error_status_code=401
                )
            auth_header = request.headers["Authorization"]
            if not auth_header.startswith("Bearer "):
                return ValidateServiceTokenResult(
                    error_message="Invalid Authorization header", error_status_code=401
                )
            service_token = auth_header[len("Bearer ") :]

            try:
                signing_key = get_signing_key()
            except Exception:
                return ValidateServiceTokenResult(
                    error_message="Could not determine Lockbox signing key",
                    error_status_code=500,
                )

            return validate_service_token(
                audiences=service_config.valid_audiences,
                service_name=service_name,
                service_token=service_token,
                signing_key=signing_key,
            )

        validation_result = _check_service_token()
        if validation_result.error_status_code is not None:
            if audit_log_provider:
                event = _make_event(
                    event_name="lockbox_auth_failure",
                    payload={
                        "error": validation_result.error_message,
                        "service_token_payload": validation_result.service_token_payload,
                    },
                )
                audit_log_provider.log_service_event(event)
                assert validation_result.error_message is not None
                assert validation_result.error_status_code is not None
            return str(validation_result.error_message), int(
                validation_result.error_status_code
            )
        else:
            if audit_log_provider:
                event = _make_event(
                    event_name="lockbox_auth_success",
                    payload={
                        "service_token_payload": validation_result.service_token_payload
                    },
                )
                audit_log_provider.log_service_event(event)

    service_request_url = f"{service_config.base_url}/{subpath}"

    service_headers = {}

    requests_auth = None
    if service_config.credential:
        if isinstance(service_config.credential, BasicAuthCredentialConfig):
            requests_auth = HTTPBasicAuth(
                service_config.credential.username, service_config.credential.password
            )
        elif isinstance(service_config.credential, BearerTokenCredentialConfig):
            service_headers[
                "Authorization"
            ] = f"Bearer {service_config.credential.token}"
        elif isinstance(service_config.credential, HeadersCredentialConfig):
            service_headers.update(service_config.credential.headers)
        else:
            event = _make_event(
                event_name="lockbox_internal_error",
                payload={
                    "error": f"Invalid credential type: {service_config.credential.type}",
                },
            )
            if audit_log_provider:
                audit_log_provider.log_service_event(event)
            return f"Invalid credential type: {service_config.credential.type}", 500
    if service_config.allowed_endpoints is not None:
        isAllowed = False
        for endpoint in service_config.allowed_endpoints:
            path_pattern = PathPattern(endpoint)
            s = "/" + request.path.replace(f"/s/{service_name}/", "")
            match = path_pattern.match(s)
            if match:
                isAllowed = True
                break
                
        if not isAllowed:
            return f"Method not allowed", 405
        
    if request.method == "GET":
        response = requests.get(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    elif request.method == "PUT":
        response = requests.put(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    elif request.method == "POST":
        response = requests.post(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    elif request.method == "DELETE":
        response = requests.delete(
            service_request_url,
            headers=service_headers,
            params=request.args,
            data=request.form or request.data,
            auth=requests_auth,
        )
    else:
        event = _make_event(
            event_name="lockbox_internal_error",
            payload={
                "error": f"Unsupported method: {request.method}",
            },
        )
        if audit_log_provider:
            audit_log_provider.log_service_event(event)
        return f"Unsupported method: {request.method}", 405

    should_compress = True
    if should_compress:
        lockbox_response = make_response(compress_in_memory(response.text))
    else:
        lockbox_response = make_response(response.text)
        
    skip_headers = ['Access-Control-Allow-Origin', "Vary", 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy', 'Content-Security-Policy', 'Access-Control-Expose-Headers', 'Transfer-Encoding', 'Content-Encoding']
    for k, v in response.headers.items():
        if  k not in skip_headers :
            lockbox_response.headers[k] = v
    lockbox_response.headers["Content-Encoding"] = "gzip" if should_compress else "identity"
    
    lockbox_response.status_code = response.status_code
    
    
    if audit_log_provider:
        audit_log_provider.log_service_event(
            event=_make_event(
                event_name="response_from_service",
                payload={
                    "response": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "data": response.text,
                    }
                },
            )
        )
    
    return lockbox_response


