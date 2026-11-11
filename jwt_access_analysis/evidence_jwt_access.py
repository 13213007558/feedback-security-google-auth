"""Offline evidence for always_use_jwt_access behavior (google-auth 2.48.0).

Generates a throwaway RSA key in memory, builds service-account credentials
in various configurations, and refreshes them against a recording mock
transport. No network access is performed: the mock stands in for the OAuth
token endpoint and simply logs what would have been POSTed.

Run:  .venv/bin/python jwt_access_analysis/evidence_jwt_access.py
"""

import json
import urllib.parse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from google.auth import jwt as auth_jwt
from google.auth import metrics
from google.auth.exceptions import RefreshError
from google.oauth2 import service_account

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
TOKEN_URI = "https://oauth2.googleapis.com/token"


def make_sa_info():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return {
        "type": "service_account",
        "project_id": "offline-demo",
        "private_key_id": "deadbeef",
        "private_key": pem,
        "client_email": "demo@offline-demo.iam.gserviceaccount.com",
        "token_uri": TOKEN_URI,
    }


SA_INFO = make_sa_info()


class RecordingRequest:
    """Stands in for google.auth.transport.Request; records every call."""

    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers=None, body=None, **kwargs):
        self.calls.append({"method": method, "url": url, "body": body})

        class Response:
            status = 200
            data = json.dumps(
                {
                    "access_token": "ya29.opaque-token-from-endpoint",
                    "expires_in": 3600,
                    "token_type": "Bearer",
                }
            ).encode()

        return Response()


def decode_unverified(token):
    try:
        return auth_jwt.decode(token, verify=False)
    except Exception:
        return None  # opaque token, not a JWT


def parse_assertion(body):
    """Pull the JWT assertion out of the urlencoded token-endpoint body."""
    params = urllib.parse.parse_qs(body.decode() if isinstance(body, bytes) else body)
    assertion = params.get("assertion", [None])[0]
    return decode_unverified(assertion) if assertion else None


def run_case(name, build, transport_audience=None):
    creds = build()
    # Simulate what transport adapters (requests/grpc/urllib3) do per AIP-4111:
    # offer the default host as audience before the first request.
    if transport_audience is not None:
        creds._create_self_signed_jwt(transport_audience)
    request = RecordingRequest()
    outcome = {}
    try:
        creds.refresh(request)
        outcome["error"] = None
    except RefreshError as exc:
        outcome["error"] = str(exc)
    token_claims = decode_unverified(creds.token) if creds.token else None
    exchange = [c for c in request.calls if c["url"] == creds._token_uri]
    outcome.update(
        {
            "name": name,
            "token_endpoint_called": bool(exchange),
            "assertion_claims": parse_assertion(exchange[0]["body"]) if exchange else None,
            "final_token_is_jwt": token_claims is not None,
            "final_token_claims": token_claims,
            "metric_cred_type": creds._metric_header_for_usage(),
        }
    )
    return outcome


def base(**kwargs):
    return service_account.Credentials.from_service_account_info(SA_INFO, **kwargs)


CASES = [
    ("S1 scopes + jwt_access=True",
     lambda: base(scopes=SCOPES, always_use_jwt_access=True), None),
    ("S2 scopes + jwt_access=False (default)",
     lambda: base(scopes=SCOPES), None),
    ("S3 default_scopes only + jwt_access=True",
     lambda: base(default_scopes=DEFAULT_SCOPES, always_use_jwt_access=True), None),
    ("S4 no scopes at all + jwt_access=True",
     lambda: base(always_use_jwt_access=True), None),
    ("S5 with_subject (DWD) + scopes + jwt_access=True",
     lambda: base(scopes=SCOPES, always_use_jwt_access=True).with_subject("user@example.com"), None),
    ("S6 non-default universe + scopes",
     lambda: base(scopes=SCOPES).with_universe_domain("example-universe.com"), None),
    ("S7 non-default universe + with_subject",
     lambda: base(scopes=SCOPES).with_universe_domain("example-universe.com").with_subject("user@example.com"), None),
    ("S8 no scopes + jwt_access=False + transport audience",
     lambda: base(), "https://pubsub.googleapis.com/"),
    ("S9 scopes + jwt_access=True + transport audience",
     lambda: base(scopes=SCOPES, always_use_jwt_access=True), "https://pubsub.googleapis.com/"),
]


def fmt_claims(claims):
    if claims is None:
        return "-"
    keep = {k: v for k, v in claims.items() if k in ("iss", "sub", "aud", "scope")}
    return json.dumps(keep, sort_keys=True)


def main():
    print(f"{'case':52} {'endpoint?':9} {'metric':14} final-token claims")
    print("-" * 130)
    results = []
    for name, build, aud in CASES:
        r = run_case(name, build, transport_audience=aud)
        results.append(r)
        if r["error"]:
            print(f"{name:52} {'n/a':9} {'-':14} RefreshError: {r['error']}")
            continue
        final = fmt_claims(r["final_token_claims"]) if r["final_token_is_jwt"] else "(opaque) ya29.opaque-token-from-endpoint"
        print(f"{name:52} {str(r['token_endpoint_called']):9} {r['metric_cred_type']:14} {final}")
        if r["assertion_claims"]:
            print(f"{'':52} {'':9} {'':14} assertion sent to endpoint: {fmt_claims(r['assertion_claims'])}")
    print("-" * 130)
    print(f"metric legend: {metrics.CRED_TYPE_SA_JWT!r} = self-signed JWT, "
          f"{metrics.CRED_TYPE_SA_ASSERTION!r} = OAuth assertion exchange")


if __name__ == "__main__":
    main()
