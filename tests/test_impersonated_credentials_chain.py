# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""End-to-end style verification of the delegation chain carried by the
three IAM Credentials API operations exposed by impersonated credentials:

* ``generateAccessToken`` (access token refresh)
* ``signBlob`` (``Credentials.sign_bytes``)
* ``generateIdToken`` (``IDTokenCredentials.refresh``)

Every test drives a single scripted, in-memory IAM transport and then asserts
on the *requests that were actually emitted*: the final target service account
encoded in the URL, the ordered ``delegates`` chain in the JSON body and the
operation-specific parameters (scopes/lifetime, audience/includeEmail, payload).

The same transport also answers the OAuth2 token endpoint so that scenarios
where the source credential needs refreshing exercise the real refresh path
rather than a mocked one.
"""

import base64
import datetime
import http.client as http_client
import json
from unittest import mock
from urllib.parse import parse_qs

import pytest

from google.auth import _helpers
from google.auth import exceptions
from google.auth import impersonated_credentials
from google.auth.impersonated_credentials import Credentials
from google.oauth2 import credentials as user_credentials

TOKEN_URI = "https://example.com/oauth2/token"

TARGET_PRINCIPAL = "target-account@target-project.iam.gserviceaccount.com"
DELEGATE_ONE = "delegate-one@proj.iam.gserviceaccount.com"
DELEGATE_TWO = "delegate-two@proj.iam.gserviceaccount.com"
DELEGATE_CHAIN = [DELEGATE_ONE, DELEGATE_TWO]
TARGET_SCOPES = ["https://www.googleapis.com/auth/devstorage.read_only"]
LIFETIME = 1800
QUOTA_PROJECT = "quota-project"
FAKE_UNIVERSE_DOMAIN = "universe.test"
TARGET_AUDIENCE = "https://my-service.example.com"
IAM_ENDPOINT_OVERRIDE = (
    "https://us-east1-iamcredentials.googleapis.com/v1/projects/-"
    "/serviceAccounts/{}:generateAccessToken".format(TARGET_PRINCIPAL)
)

GDU_HOST = "iamcredentials.googleapis.com"

GENERATE_ACCESS_TOKEN = ":generateAccessToken"
SIGN_BLOB = ":signBlob"
GENERATE_ID_TOKEN = ":generateIdToken"


class FakeResponse(object):
    """Minimal stand-in for a ``requests.Response``.

    AuthorizedSession reads ``status_code``/``content``/``json()`` while the
    google-auth Request adapter reads ``status``/``data``; expose both.
    """

    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.content = _helpers.to_bytes(json.dumps(payload))
        self.headers = {}

    @property
    def status(self):
        return self.status_code

    @property
    def data(self):
        return self.content

    def json(self):
        return json.loads(self.content.decode("utf-8"))


class FakeIAMTransport(object):
    """Scripted transport that records every outgoing request.

    It is installed by patching ``requests.Session.request`` (the single
    chokepoint used by both ``AuthorizedSession`` and the google-auth
    ``Request`` adapter), so access-token, signBlob and generateIdToken calls
    plus the OAuth2 source-credential refresh all flow through one recorder.

    Per-endpoint failure statuses can be queued through ``fail_next``; every
    call is appended to ``calls`` as a dict with ``url``, ``method``,
    ``headers`` and the parsed ``body``.
    """

    def __init__(self, fail_next=None):
        self.calls = []
        # Ordered list of (endpoint_suffix, status_code) failures to emit.
        self.fail_next = list(fail_next or [])
        self.source_refresh_count = 0

    def patch(self):
        """Returns a mock context manager routing Session.request here."""
        return mock.patch(
            "google.auth.transport.requests.requests.Session.request",
            side_effect=self.handle_session_request,
        )

    def handle_session_request(
        self, method, url, data=None, headers=None, json=None, **kwargs
    ):
        # AuthorizedSession.post(json=...) leaves the payload in the json kwarg.
        body = json if json is not None else data
        return self.route(method=method, url=url, body=body, headers=headers)

    def __call__(self, url, method="POST", headers=None, body=None, **kwargs):
        # Also usable directly as a google.auth.transport.Request callable.
        return self.route(method=method, url=url, body=body, headers=headers)

    def route(self, method, url, body, headers):
        parsed_body = self._parse_body(body)
        self.calls.append(
            {"url": url, "method": method,
             "headers": dict(headers or {}), "body": parsed_body}
        )

        if url == TOKEN_URI:
            self.source_refresh_count += 1
            return self._token_endpoint_response()

        for suffix, status in list(self.fail_next):
            if url.endswith(suffix):
                self.fail_next.remove((suffix, status))
                return FakeResponse(
                    status,
                    {"error": {"code": status, "message": "forced failure"}},
                )

        if url.endswith(GENERATE_ACCESS_TOKEN):
            expire_time = (
                _helpers.utcnow().replace(microsecond=0)
                + datetime.timedelta(seconds=LIFETIME)
            ).isoformat("T") + "Z"
            return FakeResponse(
                http_client.OK,
                {"accessToken": "impersonated-access-token",
                 "expireTime": expire_time},
            )

        if url.endswith(SIGN_BLOB):
            signed_blob = base64.b64encode(b"fake-signature").decode("utf-8")
            return FakeResponse(
                http_client.OK, {"keyId": "1", "signedBlob": signed_blob}
            )

        if url.endswith(GENERATE_ID_TOKEN):
            return FakeResponse(http_client.OK, {
                "token": self._id_token(
                    parsed_body.get("audience", TARGET_AUDIENCE)
                )
            })

        raise AssertionError("Unexpected request to {}".format(url))

    @staticmethod
    def _parse_body(body):
        if body is None:
            return None
        if hasattr(body, "decode"):
            body = body.decode("utf-8")
        if not isinstance(body, str):
            return body
        try:
            return json.loads(body)
        except ValueError:
            # OAuth2 token endpoints use application/x-www-form-urlencoded.
            form = parse_qs(body)
            return {key: values[0] for key, values in form.items()}

    @staticmethod
    def _token_endpoint_response():
        return FakeResponse(http_client.OK, {
            "access_token": "fresh-source-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        })

    @staticmethod
    def _id_token(audience):
        jwt_header = json.dumps({"alg": "RS256", "typ": "JWT"}).encode("utf-8")
        header = base64.urlsafe_b64encode(jwt_header).rstrip(b"=")
        jwt_payload = json.dumps({
            "aud": audience,
            "iss": "https://accounts.google.com",
            "exp": int(_helpers.datetime_to_secs(_helpers.utcnow())) + 3600,
            "email_verified": True,
        }).encode("utf-8")
        payload = base64.urlsafe_b64encode(jwt_payload).rstrip(b"=")
        signature = base64.urlsafe_b64encode(b"signature").rstrip(b"=")
        return b".".join([header, payload, signature]).decode("utf-8")

    def iam_calls(self, suffix):
        return [call for call in self.calls if call["url"].endswith(suffix)]

    def last_iam_call(self, suffix):
        matching = self.iam_calls(suffix)
        assert matching, "No request was sent to {}".format(suffix)
        return matching[-1]


def make_user_source(stale=False):
    creds = user_credentials.Credentials(
        token="stale-source-token" if stale else "source-token",
        refresh_token="refresh-token",
        token_uri=TOKEN_URI,
        client_id="client-id",
        client_secret="client-secret",
        quota_project_id=QUOTA_PROJECT,
    )
    if stale:
        creds.expiry = _helpers.utcnow() - datetime.timedelta(seconds=60)
    return creds


_UNSET = object()


def make_impersonated(source_credentials=None, delegates=_UNSET, **overrides):
    kwargs = {
        "source_credentials": source_credentials or make_user_source(),
        "target_principal": TARGET_PRINCIPAL,
        "target_scopes": TARGET_SCOPES,
        "delegates": DELEGATE_CHAIN if delegates is _UNSET else delegates,
        "lifetime": LIFETIME,
        "quota_project_id": QUOTA_PROJECT,
    }
    kwargs.update(overrides)
    return Credentials(**kwargs)


def expected_iam_url(suffix, universe_domain=None):
    host = GDU_HOST if universe_domain is None else "iamcredentials.{}".format(
        universe_domain
    )
    return (
        "https://{host}/v1/projects/-/serviceAccounts/"
        "{principal}{suffix}".format(
            host=host, principal=TARGET_PRINCIPAL, suffix=suffix
        )
    )


class TestAccessRefreshPath(object):
    def test_refresh_sends_target_chain_and_operation_params(self):
        transport = FakeIAMTransport()
        creds = make_impersonated()

        creds.refresh(transport)

        call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        assert call["url"] == expected_iam_url(GENERATE_ACCESS_TOKEN)
        # The delegate chain must arrive in the exact construction order.
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        # Scopes and lifetime belong only to the access-token operation.
        assert call["body"]["scope"] == TARGET_SCOPES
        assert call["body"]["lifetime"] == "{}s".format(LIFETIME)
        assert "audience" not in call["body"]
        assert "includeEmail" not in call["body"]
        assert "payload" not in call["body"]
        # The source credential authenticates the IAM call, so both the bearer
        # token and the quota-project header come from that source credential.
        assert call["headers"]["authorization"] == "Bearer source-token"
        assert call["headers"]["x-goog-user-project"] == QUOTA_PROJECT
        assert creds.token == "impersonated-access-token"

    def test_refresh_without_delegates_sends_null_chain(self):
        transport = FakeIAMTransport()
        creds = make_impersonated(delegates=None)

        creds.refresh(transport)

        call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        assert call["body"]["delegates"] is None

    def test_refresh_uses_non_default_universe_domain_endpoint(self):
        source = user_credentials.Credentials(
            token="source-token", universe_domain=FAKE_UNIVERSE_DOMAIN
        )
        transport = FakeIAMTransport()
        creds = make_impersonated(source_credentials=source)

        creds.refresh(transport)

        call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        assert call["url"] == expected_iam_url(
            GENERATE_ACCESS_TOKEN, FAKE_UNIVERSE_DOMAIN
        )
        assert creds.universe_domain == FAKE_UNIVERSE_DOMAIN
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_refresh_honors_iam_endpoint_override(self):
        transport = FakeIAMTransport()
        creds = make_impersonated(iam_endpoint_override=IAM_ENDPOINT_OVERRIDE)

        creds.refresh(transport)

        call = transport.calls[-1]
        assert call["url"] == IAM_ENDPOINT_OVERRIDE
        # Overriding the URL must not disturb the delegation chain.
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_refresh_stale_source_credential_refreshes_first(self):
        transport = FakeIAMTransport()
        stale_source = make_user_source(stale=True)
        creds = make_impersonated(source_credentials=stale_source)

        creds.refresh(transport)

        # The OAuth2 token endpoint is hit before the IAM impersonation call.
        assert transport.calls[0]["url"] == TOKEN_URI
        assert transport.source_refresh_count == 1
        iam_call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        assert (
            iam_call["headers"]["authorization"] == "Bearer fresh-source-token"
        )
        assert iam_call["body"]["delegates"] == DELEGATE_CHAIN

    def test_refresh_failure_raises_refresh_error_without_losing_chain(self):
        transport = FakeIAMTransport(
            fail_next=[(GENERATE_ACCESS_TOKEN, http_client.UNAUTHORIZED)]
        )
        creds = make_impersonated()

        with pytest.raises(exceptions.RefreshError) as excinfo:
            creds.refresh(transport)

        assert excinfo.match(impersonated_credentials._REFRESH_ERROR)
        call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        # The chain is still present in the rejected request.
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        assert not creds.valid


class TestSignBytesPath(object):
    def test_sign_bytes_uses_real_authorized_session(self):
        # AuthorizedSession builds its own internal Request; point that
        # Request at the scripted transport so the full session flow, including
        # source-credential before_request handling, is exercised end to end.
        transport = FakeIAMTransport()
        creds = make_impersonated()

        with transport.patch():
            signature = creds.sign_bytes(b"bytes-to-sign")

        call = transport.last_iam_call(SIGN_BLOB)
        assert call["url"] == expected_iam_url(SIGN_BLOB)
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        assert call["body"]["payload"] == base64.b64encode(
            b"bytes-to-sign"
        ).decode("utf-8")
        # signBlob has no scopes/lifetime/audience parameters.
        assert "scope" not in call["body"]
        assert "lifetime" not in call["body"]
        assert "audience" not in call["body"]
        assert signature == b"fake-signature"

    def test_sign_bytes_non_default_universe_domain(self):
        source = user_credentials.Credentials(
            token="source-token", universe_domain=FAKE_UNIVERSE_DOMAIN
        )
        transport = FakeIAMTransport()
        creds = make_impersonated(source_credentials=source)

        with transport.patch():
            creds.sign_bytes(b"hello")

        call = transport.last_iam_call(SIGN_BLOB)
        assert call["url"] == expected_iam_url(SIGN_BLOB, FAKE_UNIVERSE_DOMAIN)
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_sign_bytes_failure_raises_transport_error(self):
        transport = FakeIAMTransport(
            fail_next=[(SIGN_BLOB, http_client.FORBIDDEN)]
        )
        creds = make_impersonated()

        with transport.patch(), pytest.raises(exceptions.TransportError):
            creds.sign_bytes(b"hello")

        call = transport.last_iam_call(SIGN_BLOB)
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_sign_bytes_retryable_failure_preserves_chain(self):
        transport = FakeIAMTransport(
            fail_next=[
                (SIGN_BLOB, http_client.INTERNAL_SERVER_ERROR),
                (SIGN_BLOB, http_client.SERVICE_UNAVAILABLE),
            ]
        )
        creds = make_impersonated()

        with transport.patch(), mock.patch("time.sleep", return_value=None):
            signature = creds.sign_bytes(b"hello")

        attempts = transport.iam_calls(SIGN_BLOB)
        assert len(attempts) == 3
        assert all(
            call["body"]["delegates"] == DELEGATE_CHAIN for call in attempts
        )
        assert signature == b"fake-signature"

    def test_sign_bytes_ignores_endpoint_override(self):
        # Documented asymmetry: iam_endpoint_override only applies to the
        # access-token path. signBlob keeps the standard endpoint.
        transport = FakeIAMTransport()
        creds = make_impersonated(iam_endpoint_override=IAM_ENDPOINT_OVERRIDE)

        with transport.patch():
            creds.sign_bytes(b"hello")

        call = transport.last_iam_call(SIGN_BLOB)
        assert call["url"] == expected_iam_url(SIGN_BLOB)
        assert call["body"]["delegates"] == DELEGATE_CHAIN


class TestIdTokenPath(object):
    def _refresh_id_token(self, transport, target_creds, **id_kwargs):
        id_creds = impersonated_credentials.IDTokenCredentials(
            target_creds, **id_kwargs
        )
        with transport.patch():
            id_creds.refresh(transport)
        return id_creds

    def test_id_token_sends_target_chain_audience_and_email_flag(self):
        transport = FakeIAMTransport()
        target_creds = make_impersonated()

        id_creds = self._refresh_id_token(
            transport, target_creds,
            target_audience=TARGET_AUDIENCE, include_email=True,
        )

        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["url"] == expected_iam_url(GENERATE_ID_TOKEN)
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        assert call["body"]["audience"] == TARGET_AUDIENCE
        assert call["body"]["includeEmail"] is True
        # Access-token and signBlob parameters must not leak here.
        assert "scope" not in call["body"]
        assert "lifetime" not in call["body"]
        assert "payload" not in call["body"]
        assert id_creds.token

    def test_id_token_include_email_defaults_to_false(self):
        transport = FakeIAMTransport()
        target_creds = make_impersonated()

        self._refresh_id_token(
            transport, target_creds, target_audience=TARGET_AUDIENCE
        )

        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["body"]["includeEmail"] is False

    def test_id_token_non_default_universe_domain(self):
        source = user_credentials.Credentials(
            token="source-token", universe_domain=FAKE_UNIVERSE_DOMAIN
        )
        transport = FakeIAMTransport()
        target_creds = make_impersonated(source_credentials=source)

        self._refresh_id_token(
            transport, target_creds, target_audience=TARGET_AUDIENCE
        )

        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["url"] == expected_iam_url(
            GENERATE_ID_TOKEN, FAKE_UNIVERSE_DOMAIN
        )
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_id_token_stale_source_refreshes_first(self):
        transport = FakeIAMTransport()
        target_creds = make_impersonated(
            source_credentials=make_user_source(stale=True)
        )

        self._refresh_id_token(
            transport, target_creds, target_audience=TARGET_AUDIENCE
        )

        assert transport.calls[0]["url"] == TOKEN_URI
        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["headers"]["authorization"] == "Bearer fresh-source-token"
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_id_token_failure_raises_refresh_error(self):
        transport = FakeIAMTransport(
            fail_next=[(GENERATE_ID_TOKEN, http_client.FORBIDDEN)]
        )
        target_creds = make_impersonated()
        id_creds = impersonated_credentials.IDTokenCredentials(
            target_creds, target_audience=TARGET_AUDIENCE
        )

        with transport.patch(), pytest.raises(
            exceptions.RefreshError
        ) as excinfo:
            id_creds.refresh(transport)

        assert excinfo.match("Error getting ID token")
        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_id_token_ignores_endpoint_override(self):
        transport = FakeIAMTransport()
        target_creds = make_impersonated(
            iam_endpoint_override=IAM_ENDPOINT_OVERRIDE
        )

        self._refresh_id_token(
            transport, target_creds, target_audience=TARGET_AUDIENCE
        )

        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["url"] == expected_iam_url(GENERATE_ID_TOKEN)
        assert call["body"]["delegates"] == DELEGATE_CHAIN


class TestCopyInterfaces(object):
    def test_with_quota_project_copy_keeps_chain_on_all_paths(self):
        transport = FakeIAMTransport()
        original = make_impersonated()

        copied = original.with_quota_project("new-quota-project")

        assert copied is not original
        assert copied._quota_project_id == "new-quota-project"
        assert original._quota_project_id == QUOTA_PROJECT
        # Every chain-defining attribute must be carried over verbatim.
        assert copied._delegates == DELEGATE_CHAIN
        assert copied._target_principal == TARGET_PRINCIPAL
        assert copied._target_scopes == TARGET_SCOPES
        assert copied._lifetime == LIFETIME
        assert copied._iam_endpoint_override == original._iam_endpoint_override

        copied.refresh(transport)
        call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        # The IAM call is authenticated by the *source* credential, so its
        # quota-project header reflects the source, not the impersonated
        # credential's own quota project (which only affects downstream API
        # calls made with the impersonated token).
        assert call["headers"]["x-goog-user-project"] == QUOTA_PROJECT
        # The impersonated credential still exposes its own copied value.
        assert copied.quota_project_id == "new-quota-project"
        assert original.quota_project_id == QUOTA_PROJECT

    def test_with_scopes_copy_does_not_mutate_original_or_chain(self):
        original = make_impersonated()
        original_delegates = original._delegates

        new_scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        copied = original.with_scopes(new_scopes)

        assert copied is not original
        assert copied._target_scopes == new_scopes
        assert original._target_scopes == TARGET_SCOPES
        assert copied._delegates is original_delegates
        assert copied._delegates == DELEGATE_CHAIN
        assert copied._target_principal == TARGET_PRINCIPAL

        transport = FakeIAMTransport()
        copied.refresh(transport)
        call = transport.last_iam_call(GENERATE_ACCESS_TOKEN)
        assert call["body"]["scope"] == new_scopes
        assert call["body"]["delegates"] == DELEGATE_CHAIN

    def test_with_trust_boundary_copy_keeps_chain_and_target(self):
        original = make_impersonated()
        boundary = {"encodedLocations": "0xABCD", "locations": ["us-central1"]}

        copied = original.with_trust_boundary(boundary)

        assert copied is not original
        assert copied._trust_boundary == boundary
        assert original._trust_boundary is None
        assert copied._delegates == DELEGATE_CHAIN
        assert copied._target_principal == TARGET_PRINCIPAL
        assert copied._iam_endpoint_override == original._iam_endpoint_override

    def test_make_copy_carries_endpoint_override_and_quota_project(self):
        transport = FakeIAMTransport()
        original = make_impersonated(
            iam_endpoint_override=IAM_ENDPOINT_OVERRIDE,
            quota_project_id=QUOTA_PROJECT,
        )

        copied = original._make_copy()

        assert copied is not original
        assert copied._iam_endpoint_override == IAM_ENDPOINT_OVERRIDE
        assert copied._quota_project_id == QUOTA_PROJECT
        assert copied._delegates == DELEGATE_CHAIN
        assert copied._target_principal == TARGET_PRINCIPAL

        copied.refresh(transport)
        assert transport.calls[-1]["url"] == IAM_ENDPOINT_OVERRIDE
        assert transport.calls[-1]["body"]["delegates"] == DELEGATE_CHAIN

    def test_copy_shares_delegates_list_with_original(self):
        # Documented current behavior: ``_make_copy`` passes the delegates
        # sequence through without copying it, so the new credential and the
        # original reference the *same* list. The emitted wire order is still
        # correct; callers just must not mutate the shared list in place.
        original = make_impersonated()
        copied = original.with_quota_project("other")

        assert copied._delegates is original._delegates

        copied._delegates.append("mutated@proj.iam.gserviceaccount.com")
        assert original._delegates[-1] == "mutated@proj.iam.gserviceaccount.com"

        # Reassigning the attribute (rather than mutating in place) breaks
        # the shared reference and leaves the original untouched.
        copied._delegates = list(DELEGATE_CHAIN)
        assert copied._delegates is not original._delegates
        assert copied._delegates == DELEGATE_CHAIN
        assert "mutated@proj.iam.gserviceaccount.com" in original._delegates

    def test_subject_is_dropped_when_copying_dwd_credentials(self):
        # Documented current behavior: ``_make_copy`` does not forward the
        # ``subject`` argument, so a domain-wide-delegation credential loses
        # its impersonated user on any copy-based with_* call.
        original = make_impersonated(subject="user@example.com")
        assert original._subject == "user@example.com"

        copied = original.with_quota_project("other")

        assert copied._subject is None
        # The delegation chain itself is still preserved.
        assert copied._delegates == DELEGATE_CHAIN

    def test_id_token_copy_interfaces_preserve_chain_and_options(self):
        transport = FakeIAMTransport()
        target_creds = make_impersonated()
        id_creds = impersonated_credentials.IDTokenCredentials(
            target_creds,
            target_audience=TARGET_AUDIENCE,
            include_email=False,
            quota_project_id=QUOTA_PROJECT,
        )

        new_audience = id_creds.with_target_audience(
            "https://other.example.com"
        )
        new_email = id_creds.with_include_email(True)
        new_quota = id_creds.with_quota_project("id-quota-project")
        rebuilt = id_creds.from_credentials(target_creds)

        for copy_cred in (new_audience, new_email, new_quota, rebuilt):
            assert copy_cred is not id_creds
            assert copy_cred._target_credentials is target_creds

        assert new_audience._target_audience == "https://other.example.com"
        assert new_audience._include_email is False
        assert new_email._include_email is True
        assert new_email._target_audience == TARGET_AUDIENCE
        assert new_quota._quota_project_id == "id-quota-project"
        assert rebuilt._include_email is False
        assert rebuilt._quota_project_id == QUOTA_PROJECT

        # The underlying impersonated credential still drives the same chain.
        with transport.patch():
            new_audience.refresh(transport)
        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        assert call["body"]["audience"] == "https://other.example.com"

    def test_id_token_quota_project_is_separate_from_iam_header(self):
        transport = FakeIAMTransport()
        target_creds = make_impersonated()
        id_creds = impersonated_credentials.IDTokenCredentials(
            target_creds, target_audience=TARGET_AUDIENCE,
            quota_project_id="id-quota-project",
        )

        with transport.patch():
            id_creds.refresh(transport)

        call = transport.last_iam_call(GENERATE_ID_TOKEN)
        # The IAM request is authenticated by the underlying source
        # credential; the IDTokenCredentials quota project never reaches it.
        assert call["headers"]["x-goog-user-project"] == QUOTA_PROJECT
        assert call["body"]["delegates"] == DELEGATE_CHAIN
        # It is still stored on the ID token credential for downstream use.
        assert id_creds.quota_project_id == "id-quota-project"


class TestThreePathsConsistency(object):
    def test_same_chain_target_and_universe_across_all_operations(self):
        source = user_credentials.Credentials(
            token="source-token", universe_domain=FAKE_UNIVERSE_DOMAIN
        )
        transport = FakeIAMTransport()
        creds = make_impersonated(source_credentials=source)

        creds.refresh(transport)
        with transport.patch():
            creds.sign_bytes(b"abc")
        id_creds = impersonated_credentials.IDTokenCredentials(
            creds, target_audience=TARGET_AUDIENCE, include_email=True
        )
        with transport.patch():
            id_creds.refresh(transport)

        expectations = {
            GENERATE_ACCESS_TOKEN: {
                "scope": TARGET_SCOPES,
                "lifetime": "{}s".format(LIFETIME),
            },
            SIGN_BLOB: {
                "payload": base64.b64encode(b"abc").decode("utf-8"),
            },
            GENERATE_ID_TOKEN: {
                "audience": TARGET_AUDIENCE,
                "includeEmail": True,
            },
        }
        for suffix, operation_params in expectations.items():
            call = transport.last_iam_call(suffix)
            assert TARGET_PRINCIPAL in call["url"]
            assert FAKE_UNIVERSE_DOMAIN in call["url"]
            assert call["body"]["delegates"] == DELEGATE_CHAIN
            for key, value in operation_params.items():
                assert call["body"][key] == value
            # Operation-specific keys stay isolated from one another.
            if suffix != GENERATE_ACCESS_TOKEN:
                assert "scope" not in call["body"]
                assert "lifetime" not in call["body"]
            if suffix != SIGN_BLOB:
                assert "payload" not in call["body"]
            if suffix != GENERATE_ID_TOKEN:
                assert "audience" not in call["body"]
                assert "includeEmail" not in call["body"]

    def test_constructor_copies_source_credential(self):
        source = make_user_source()
        original_token = source.token
        creds = make_impersonated(source_credentials=source)

        # Mutating the source handed to the constructor must not affect the
        # internal copy (the constructor does copy.copy + with_scopes).
        source.token = "tampered-token"

        assert creds._source_credentials is not source
        assert creds._source_credentials.token == original_token
