import base64
import json
import urllib.parse

from src.config.constants import EmailServiceType, OPENAI_API_ENDPOINTS, OPENAI_PAGE_TYPES, generate_random_user_info
from src.core.http_client import OpenAIHTTPClient
from src.core.openai.oauth import OAuthStart
from src.core.register import RegistrationEngine, RegistrationResult
from src.services.base import BaseEmailService


class DummyResponse:
    def __init__(self, status_code=200, payload=None, text="", headers=None, on_return=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = headers or {}
        self.on_return = on_return

    def json(self):
        if self._payload is None:
            raise ValueError("no json payload")
        return self._payload


class QueueSession:
    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []
        self.cookies = {}

    def get(self, url, **kwargs):
        return self._request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._request(method.upper(), url, **kwargs)

    def close(self):
        return None

    def _request(self, method, url, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "kwargs": kwargs,
        })
        if not self.steps:
            raise AssertionError(f"unexpected request: {method} {url}")
        expected_method, expected_url, response = self.steps.pop(0)
        assert method == expected_method
        assert url == expected_url
        if callable(response):
            response = response(self)
        if response.on_return:
            response.on_return(self)
        return response


class FakeEmailService(BaseEmailService):
    def __init__(self, codes):
        super().__init__(EmailServiceType.TEMPMAIL)
        self.codes = list(codes)
        self.otp_requests = []

    def create_email(self, config=None):
        return {
            "email": "tester@example.com",
            "service_id": "mailbox-1",
        }

    def get_verification_code(self, email, email_id=None, timeout=120, pattern=r"(?<!\d)(\d{6})(?!\d)", otp_sent_at=None):
        self.otp_requests.append({
            "email": email,
            "email_id": email_id,
            "otp_sent_at": otp_sent_at,
        })
        if not self.codes:
            raise AssertionError("no verification code queued")
        return self.codes.pop(0)

    def list_emails(self, **kwargs):
        return []

    def delete_email(self, email_id):
        return True

    def check_health(self):
        return True


class FakeOAuthManager:
    def __init__(self):
        self.start_calls = 0
        self.callback_calls = []

    def start_oauth(self):
        self.start_calls += 1
        return OAuthStart(
            auth_url=f"https://auth.example.test/flow/{self.start_calls}",
            state=f"state-{self.start_calls}",
            code_verifier=f"verifier-{self.start_calls}",
            redirect_uri="http://localhost:1455/auth/callback",
        )

    def handle_callback(self, callback_url, expected_state, code_verifier):
        self.callback_calls.append({
            "callback_url": callback_url,
            "expected_state": expected_state,
            "code_verifier": code_verifier,
        })
        return {
            "account_id": "acct-1",
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "id_token": "id-1",
        }


class FakeOpenAIClient:
    def __init__(self, sessions, sentinel_tokens):
        self._sessions = list(sessions)
        self._session_index = 0
        self._session = self._sessions[0]
        self._sentinel_tokens = list(sentinel_tokens)

    @property
    def session(self):
        return self._session

    def check_ip_location(self):
        return True, "US"

    def check_sentinel(self, did, proxies=None, *, flow="authorize_continue", include_pow=True, return_payload=False):
        if not self._sentinel_tokens:
            raise AssertionError("no sentinel token queued")
        token = self._sentinel_tokens.pop(0)
        if isinstance(token, dict):
            payload = {
                "token": str(token.get("token") or "").strip(),
                "so_token": str(token.get("so_token") or "").strip(),
                "flow": flow,
            }
            return payload if return_payload else payload["token"]
        if return_payload:
            return {"token": str(token or "").strip(), "so_token": "", "flow": flow}
        return token

    def close(self):
        if self._session_index + 1 < len(self._sessions):
            self._session_index += 1
            self._session = self._sessions[self._session_index]


def _workspace_cookie(workspace_id):
    payload = base64.urlsafe_b64encode(
        json.dumps({"workspaces": [{"id": workspace_id}]}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    return f"{payload}.sig"


def _response_with_did(did):
    return DummyResponse(
        status_code=200,
        text="ok",
        on_return=lambda session: session.cookies.__setitem__("oai-did", did),
    )


def _response_with_login_cookies(workspace_id="ws-1", session_token="session-1"):
    def setter(session):
        session.cookies["oai-client-auth-session"] = _workspace_cookie(workspace_id)
        session.cookies["__Secure-next-auth.session-token"] = session_token

    return DummyResponse(status_code=200, payload={}, on_return=setter)


def test_check_sentinel_sends_non_empty_pow(monkeypatch):
    session = QueueSession([
        ("POST", OPENAI_API_ENDPOINTS["sentinel"], DummyResponse(payload={"token": "sentinel-token"})),
    ])
    client = OpenAIHTTPClient()
    client._session = session

    monkeypatch.setattr(
        "src.core.http_client.build_sentinel_pow_token",
        lambda user_agent: "gAAAAACpow-token",
    )

    token = client.check_sentinel("device-1")

    assert token == "sentinel-token"
    body = json.loads(session.calls[0]["kwargs"]["data"])
    assert body["id"] == "device-1"
    assert body["flow"] == "authorize_continue"
    assert body["p"] == "gAAAAACpow-token"


def test_check_sentinel_supports_custom_flow_without_pow():
    session = QueueSession([
        ("POST", OPENAI_API_ENDPOINTS["sentinel"], DummyResponse(payload={"token": "sentinel-token", "so_token": "so-token"})),
    ])
    client = OpenAIHTTPClient()
    client._session = session

    payload = client.check_sentinel(
        "device-2",
        flow="oauth_create_account",
        include_pow=False,
        return_payload=True,
    )

    assert payload == {
        "token": "sentinel-token",
        "so_token": "so-token",
        "flow": "oauth_create_account",
    }
    body = json.loads(session.calls[0]["kwargs"]["data"])
    assert body["id"] == "device-2"
    assert body["flow"] == "oauth_create_account"
    assert body["p"] == ""


def test_generate_random_user_info_returns_full_name():
    info = generate_random_user_info()
    first, last = info["name"].split(" ", 1)
    assert first
    assert last


def test_get_workspace_id_falls_back_to_auth_session_payload():
    session = QueueSession([
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"workspace_id": "org-auth-session"}}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    workspace_id = engine._get_workspace_id()

    assert workspace_id == "org-auth-session"


def test_get_workspace_id_falls_back_to_auth_session_account_id():
    session = QueueSession([
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"id": "acct-auth-session"}}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    workspace_id = engine._get_workspace_id()

    assert workspace_id == "acct-auth-session"


def test_get_workspace_id_parses_base64_auth_info_cookie(monkeypatch):
    auth_info_payload = base64.urlsafe_b64encode(
        json.dumps({"workspaces": [{"id": "ws-auth-info"}]}).encode("utf-8")
    ).decode("ascii").rstrip("=")
    session = QueueSession([])
    session.cookies["oai-client-auth-info"] = urllib.parse.quote(auth_info_payload)
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    monkeypatch.setattr(engine, "_fetch_auth_session_payload", lambda: {})

    workspace_id = engine._get_workspace_id()

    assert workspace_id == "ws-auth-info"


def test_select_workspace_uses_last_continue_url_as_referer():
    session = QueueSession([
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue"}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session
    engine._last_validate_otp_continue_url = "https://auth.openai.com/add-phone"

    continue_url = engine._select_workspace("org-123")

    assert continue_url == "https://auth.example.test/continue"
    assert session.calls[0]["kwargs"]["headers"]["referer"] == "https://auth.openai.com/add-phone"


def test_select_workspace_for_current_session_tries_fallback_candidates():
    session = QueueSession([
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                text='{"account_id":"acct-fallback"}',
            ),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"workspace_id": "org-primary", "id": "acct-fallback"}}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(status_code=400, text="workspace not allowed"),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-fallback"}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session
    engine._last_validate_otp_continue_url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"

    workspace_id, continue_url = engine._select_workspace_for_current_session(
        preferred_workspace_id="org-primary",
    )

    assert workspace_id == "acct-fallback"
    assert continue_url == "https://auth.example.test/continue-fallback"
    assert json.loads(session.calls[2]["kwargs"]["data"]) == {"workspace_id": "org-primary"}
    assert json.loads(session.calls[3]["kwargs"]["data"]) == {"workspace_id": "acct-fallback"}


def test_select_workspace_for_current_session_probes_default_consent_when_gate_continue_url():
    session = QueueSession([
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(
                text='{"account_id":"acct-consent"}',
            ),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-consent"}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session
    engine._last_validate_otp_continue_url = "https://auth.openai.com/add-phone"
    engine._create_account_continue_url = "https://auth.openai.com/add-phone"

    workspace_id, continue_url = engine._select_workspace_for_current_session()

    assert workspace_id == "acct-consent"
    assert continue_url == "https://auth.example.test/continue-consent"
    assert session.calls[0]["url"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    assert session.calls[2]["kwargs"]["headers"]["referer"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    assert json.loads(session.calls[2]["kwargs"]["data"]) == {"workspace_id": "acct-consent"}


def test_select_workspace_for_current_session_retries_until_candidates_appear(monkeypatch):
    session = QueueSession([
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(text="<html>consent-1</html>"),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={}),
        ),
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(text='{"account_id":"acct-retry"}'),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-retry"}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    monkeypatch.setattr("src.core.register.time.sleep", lambda seconds: None)

    workspace_id, continue_url = engine._select_workspace_for_current_session(
        referer_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
    )

    assert workspace_id == "acct-retry"
    assert continue_url == "https://auth.example.test/continue-retry"
    assert json.loads(session.calls[4]["kwargs"]["data"]) == {"workspace_id": "acct-retry"}


def test_extract_session_token_from_cookie_text_supports_authjs_name():
    token = RegistrationEngine._extract_session_token_from_cookie_text(
        "foo=bar; __Secure-authjs.session-token=authjs-token-value; path=/"
    )

    assert token == "authjs-token-value"


def test_extract_session_token_from_cookie_jar_supports_authjs_chunks():
    token = RegistrationEngine._extract_session_token_from_cookie_jar(
        {
            "__Secure-authjs.session-token.0": "chunk-a",
            "__Secure-authjs.session-token.1": "chunk-b",
        }
    )

    assert token == "chunk-achunk-b"


def test_visit_continue_url_for_session_keeps_chatgpt_callback():
    callback_url = "https://chatgpt.com/api/auth/callback/openai?code=abc&state=xyz"
    session = QueueSession([
        ("GET", callback_url, DummyResponse(status_code=200)),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    final_url = engine._visit_continue_url_for_session(callback_url)

    assert final_url == callback_url
    assert session.calls[0]["url"] == callback_url


def test_native_backup_uses_consent_probe_when_workspace_id_missing(monkeypatch):
    session = QueueSession([
        (
            "GET",
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            DummyResponse(text='{"account_id":"acct-consent"}'),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-consent"}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session
    engine.password = "pw-1"
    engine.device_id = "did-1"
    callback_url = "http://localhost:1455/auth/callback?code=code-2&state=state-2"

    def fake_verify_email_otp_with_retry(*args, **kwargs):
        engine._last_validate_otp_continue_url = "https://auth.openai.com/add-phone"
        engine._last_validate_otp_workspace_id = ""
        return True

    monkeypatch.setattr(engine, "_verify_email_otp_with_retry", fake_verify_email_otp_with_retry)
    monkeypatch.setattr(engine, "_send_verification_code", lambda referer=None: True)
    monkeypatch.setattr(engine, "_retrigger_login_otp", lambda: True)
    monkeypatch.setattr(engine, "_visit_continue_url_for_session", lambda continue_url, result=None: continue_url)
    monkeypatch.setattr(engine, "_get_workspace_id", lambda: "")
    monkeypatch.setattr(engine, "_follow_redirects", lambda start_url: (callback_url, callback_url))
    monkeypatch.setattr(
        engine,
        "_handle_oauth_callback",
        lambda callback: {
            "account_id": "acct-2",
            "access_token": "access-2",
            "refresh_token": "refresh-2",
            "id_token": "id-2",
        },
    )

    result = RegistrationResult(success=False, logs=engine.logs)
    ok = engine._complete_token_exchange_native_backup(result)

    assert ok is True
    assert result.workspace_id == "acct-consent"
    assert result.account_id == "acct-2"
    assert result.access_token == "access-2"
    assert session.calls[0]["url"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
    assert session.calls[2]["kwargs"]["headers"]["referer"] == "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"


def test_native_backup_does_not_resend_login_otp_after_failure(monkeypatch):
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)

    monkeypatch.setattr(engine, "_verify_email_otp_with_retry", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        engine,
        "_send_verification_code",
        lambda referer=None: (_ for _ in ()).throw(AssertionError("unexpected resend")),
    )
    monkeypatch.setattr(
        engine,
        "_retrigger_login_otp",
        lambda: (_ for _ in ()).throw(AssertionError("unexpected retrigger")),
    )
    monkeypatch.setattr(
        engine,
        "_restart_login_flow",
        lambda: (_ for _ in ()).throw(AssertionError("unexpected relogin")),
    )

    result = RegistrationResult(success=False, logs=engine.logs)

    ok = engine._complete_token_exchange_native_backup(result)

    assert ok is False
    assert result.error_message == "验证码校验失败"


def test_resume_oauth_context_from_authorize_can_continue_from_consent(monkeypatch):
    session = QueueSession([
        (
            "GET",
            "https://auth.example.test/authorize",
            DummyResponse(text='<html>consent_challenge=abc123</html>'),
        ),
        (
            "GET",
            "https://auth.openai.com/api/accounts/consent?consent_challenge=abc123",
            DummyResponse(text='{"account_id":"acct-resume"}'),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-resume"}),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session
    engine.password = "pw-1"
    engine.device_id = "did-1"
    engine.oauth_start = OAuthStart(
        auth_url="https://auth.example.test/authorize",
        state="state-1",
        code_verifier="verifier-1",
        redirect_uri="http://localhost:1455/auth/callback",
    )

    callback_url = "http://localhost:1455/auth/callback?code=code-1&state=state-1"
    monkeypatch.setattr(engine, "_follow_redirects", lambda start_url, referer=None: (callback_url, callback_url))
    monkeypatch.setattr(
        engine,
        "_handle_oauth_callback",
        lambda callback: {
            "account_id": "acct-token",
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "id_token": "id-token",
        },
    )

    result = RegistrationResult(success=False, logs=engine.logs)
    ok = engine._resume_oauth_context_from_authorize(
        result,
        label="当前登录后的已认证会话",
    )

    assert ok is True
    assert result.workspace_id == "acct-resume"
    assert result.account_id == "acct-token"
    assert result.access_token == "access-token"
    assert session.calls[1]["url"] == "https://auth.openai.com/api/accounts/consent?consent_challenge=abc123"


def test_bootstrap_chatgpt_then_resume_codex_prefers_chatgpt_web_session(monkeypatch):
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)

    chatgpt_calls = []
    monkeypatch.setattr(
        engine,
        "_bootstrap_chatgpt_web_session_direct",
        lambda result, allow_partial_success=False: (
            chatgpt_calls.append("direct"),
            setattr(result, "workspace_id", "ws-chatgpt"),
            True,
        )[2],
    )
    monkeypatch.setattr(
        engine,
        "_bootstrap_session_token_via_chatgpt_full_login",
        lambda result: (_ for _ in ()).throw(AssertionError("unexpected full login fallback")),
    )
    monkeypatch.setattr(
        engine,
        "_resume_oauth_context_from_authorize",
        lambda result, label: (chatgpt_calls.append(f"resume:{label}"), True)[1],
    )

    result = RegistrationResult(success=False, logs=engine.logs)
    ok = engine._bootstrap_chatgpt_then_resume_codex(
        result,
        label="当前登录后的已认证会话",
    )

    assert ok is True
    assert result.workspace_id == "ws-chatgpt"
    assert chatgpt_calls == [
        "direct",
        "resume:当前登录后的已认证会话（ChatGPT 预热后）",
    ]


def test_bootstrap_chatgpt_then_resume_codex_falls_back_to_full_login(monkeypatch):
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)

    chatgpt_calls = []
    monkeypatch.setattr(
        engine,
        "_bootstrap_chatgpt_web_session_direct",
        lambda result, allow_partial_success=False: (chatgpt_calls.append("direct"), False)[1],
    )
    monkeypatch.setattr(
        engine,
        "_bootstrap_session_token_via_chatgpt_full_login",
        lambda result: (chatgpt_calls.append("full"), setattr(result, "workspace_id", "ws-full"), True)[2],
    )
    monkeypatch.setattr(
        engine,
        "_resume_oauth_context_from_authorize",
        lambda result, label: (chatgpt_calls.append(f"resume:{label}"), True)[1],
    )

    result = RegistrationResult(success=False, logs=engine.logs)
    ok = engine._bootstrap_chatgpt_then_resume_codex(
        result,
        label="当前登录后的已认证会话",
    )

    assert ok is True
    assert result.workspace_id == "ws-full"
    assert chatgpt_calls == [
        "direct",
        "full",
        "resume:当前登录后的已认证会话（ChatGPT 预热后）",
    ]


def test_follow_redirects_can_continue_from_consent_challenge_html():
    start_url = "https://auth.example.test/continue"
    consent_url = "https://auth.openai.com/api/accounts/consent?consent_challenge=consent-1"
    callback_url = "http://localhost:1455/auth/callback?code=code-1&state=state-1"
    session = QueueSession([
        (
            "GET",
            start_url,
            DummyResponse(status_code=200, text='<html>consent_challenge=consent-1</html>'),
        ),
        (
            "GET",
            consent_url,
            DummyResponse(status_code=302, headers={"Location": callback_url}),
        ),
        (
            "GET",
            "https://chatgpt.com/",
            DummyResponse(status_code=200),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    resolved_callback, final_url = engine._follow_redirects(start_url)

    assert resolved_callback == callback_url
    assert final_url == callback_url


def test_follow_chatgpt_auth_redirects_can_continue_from_callback_html():
    start_url = "https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
    callback_url = "https://chatgpt.com/api/auth/callback/openai?code=cb-1&state=st-1"
    session = QueueSession([
        (
            "GET",
            start_url,
            DummyResponse(status_code=200, text=f'<html><a href="{callback_url}">continue</a></html>'),
        ),
        (
            "GET",
            callback_url,
            DummyResponse(status_code=302, headers={"Location": "https://chatgpt.com/"}),
        ),
        (
            "GET",
            "https://chatgpt.com/",
            DummyResponse(status_code=200),
        ),
    ])
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.session = session

    resolved_callback, final_url = engine._follow_chatgpt_auth_redirects(start_url)

    assert resolved_callback == callback_url
    assert final_url == "https://chatgpt.com/"


def test_bootstrap_chatgpt_web_session_direct_resumes_auth_chain_before_direct_login(monkeypatch):
    class TempSession:
        def __init__(self):
            self.cookies = {}
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append(("GET", url, kwargs))
            return DummyResponse(status_code=200)

    temp_session = TempSession()
    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.email = "tester@example.com"
    engine.password = "pw-1"

    def fake_temp_session(*args, **kwargs):
        return temp_session

    bridge_calls = []
    wait_results = iter([
        ({}, ""),
        (
            {
                "accessToken": "access-bridge",
                "user": {"id": "user-bridge"},
                "account": {"id": "acct-bridge", "workspace_id": "ws-bridge"},
            },
            "session-bridge",
        ),
    ])

    monkeypatch.setattr("src.core.register.cffi_requests.Session", fake_temp_session)
    monkeypatch.setattr(
        engine,
        "_run_chatgpt_nextauth_bridge",
        lambda session_obj, *, email, device_id, log_prefix: (
            "https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
            "https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
        ),
    )
    monkeypatch.setattr(
        engine,
        "_wait_for_chatgpt_web_session",
        lambda session_obj, timeout=12: next(wait_results),
    )

    def fake_follow(start_url):
        bridge_calls.append(start_url)
        return (
            "https://chatgpt.com/api/auth/callback/openai?code=cb-2&state=st-2",
            "https://chatgpt.com/",
        )

    monkeypatch.setattr(engine, "_follow_chatgpt_auth_redirects", fake_follow)
    monkeypatch.setattr(engine, "_complete_chatgpt_bridge_stage", lambda result, final_url, log_prefix: False)
    monkeypatch.setattr(
        engine,
        "_perform_chatgpt_direct_auth_login",
        lambda session_obj: (_ for _ in ()).throw(AssertionError("unexpected direct login fallback")),
    )

    result = RegistrationResult(success=False, logs=engine.logs)
    ok = engine._bootstrap_chatgpt_web_session_direct(result)

    assert ok is True
    assert result.session_token == "session-bridge"
    assert result.access_token == "access-bridge"
    assert result.workspace_id == "ws-bridge"
    assert bridge_calls == [
        "https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
    ]
    assert temp_session.calls[0][1] == "https://chatgpt.com/api/auth/callback/openai?code=cb-2&state=st-2"


def test_bootstrap_chatgpt_web_session_direct_accepts_partial_logged_in_payload_for_resume(monkeypatch):
    class TempSession:
        def __init__(self):
            self.cookies = {}

    email_service = FakeEmailService([])
    engine = RegistrationEngine(email_service)
    engine.email = "tester@example.com"
    engine.password = "pw-1"

    monkeypatch.setattr("src.core.register.cffi_requests.Session", lambda *args, **kwargs: TempSession())
    monkeypatch.setattr(
        engine,
        "_run_chatgpt_nextauth_bridge",
        lambda session_obj, *, email, device_id, log_prefix: (
            "https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
            "https://auth.openai.com/api/accounts/authorize?client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH",
        ),
    )
    monkeypatch.setattr(
        engine,
        "_wait_for_chatgpt_web_session",
        lambda session_obj, timeout=12: (
            {
                "accessToken": "access-partial",
                "user": {
                    "id": "user-partial",
                    "customIds": {
                        "account_id": "acct-partial",
                        "workspace_id": "ws-partial",
                    },
                },
            },
            "",
        ),
    )
    monkeypatch.setattr(
        engine,
        "_perform_chatgpt_direct_auth_login",
        lambda session_obj: (_ for _ in ()).throw(AssertionError("unexpected direct login fallback")),
    )

    result = RegistrationResult(success=False, logs=engine.logs)
    ok = engine._bootstrap_chatgpt_web_session_direct(result, allow_partial_success=True)

    assert ok is True
    assert result.session_token == ""
    assert result.access_token == "access-partial"
    assert result.account_id == "acct-partial"
    assert result.workspace_id == "ws-partial"


def test_run_registers_then_relogs_to_fetch_token():
    session_one = QueueSession([
        ("GET", "https://auth.example.test/flow/1", _response_with_did("did-1")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["PASSWORD_REGISTRATION"]}}),
        ),
        ("POST", OPENAI_API_ENDPOINTS["register"], DummyResponse(payload={})),
        ("GET", OPENAI_API_ENDPOINTS["send_otp"], DummyResponse(payload={})),
        ("POST", OPENAI_API_ENDPOINTS["validate_otp"], DummyResponse(payload={})),
        ("POST", OPENAI_API_ENDPOINTS["create_account"], DummyResponse(payload={})),
    ])
    session_two = QueueSession([
        ("GET", "https://auth.example.test/flow/2", _response_with_did("did-2")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["LOGIN_PASSWORD"]}}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["password_verify"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]}}),
        ),
        ("POST", OPENAI_API_ENDPOINTS["validate_otp"], _response_with_login_cookies()),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"workspace_id": "ws-1"}}),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"workspace_id": "ws-1"}}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue"}),
        ),
        (
            "GET",
            "https://auth.example.test/continue",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-2&state=state-2"},
            ),
        ),
    ])

    email_service = FakeEmailService(["123456", "654321"])
    engine = RegistrationEngine(email_service)
    fake_oauth = FakeOAuthManager()
    engine.http_client = FakeOpenAIClient(
        [session_one, session_two],
        ["sentinel-1", {"token": "sentinel-create", "so_token": "so-create"}, "sentinel-2"],
    )
    engine.oauth_manager = fake_oauth

    result = engine.run()

    assert result.success is True
    assert result.source == "register"
    assert result.workspace_id == "ws-1"
    assert result.session_token == "session-1"
    assert fake_oauth.start_calls == 2
    assert len(email_service.otp_requests) == 2
    assert all(item["otp_sent_at"] is not None for item in email_service.otp_requests)
    assert sum(1 for call in session_one.calls if call["url"] == OPENAI_API_ENDPOINTS["send_otp"]) == 1
    assert sum(1 for call in session_two.calls if call["url"] == OPENAI_API_ENDPOINTS["send_otp"]) == 0
    assert sum(1 for call in session_one.calls if call["url"] == OPENAI_API_ENDPOINTS["select_workspace"]) == 0
    assert sum(1 for call in session_two.calls if call["url"] == OPENAI_API_ENDPOINTS["select_workspace"]) == 1
    create_account_call = next(call for call in session_one.calls if call["url"] == OPENAI_API_ENDPOINTS["create_account"])
    create_account_headers = create_account_call["kwargs"]["headers"]
    assert create_account_headers["referer"] == "https://auth.openai.com/about-you"
    assert json.loads(create_account_headers["openai-sentinel-token"]) == {
        "p": "",
        "t": "",
        "c": "sentinel-create",
        "id": "did-1",
        "flow": "oauth_create_account",
    }
    assert json.loads(create_account_headers["openai-sentinel-so-token"]) == {
        "so": "so-create",
        "c": "sentinel-create",
        "id": "did-1",
        "flow": "oauth_create_account",
    }
    relogin_start_body = json.loads(session_two.calls[1]["kwargs"]["data"])
    assert relogin_start_body["screen_hint"] == "login"
    assert relogin_start_body["username"]["value"] == "tester@example.com"
    password_verify_body = json.loads(session_two.calls[2]["kwargs"]["data"])
    assert password_verify_body == {"password": result.password}
    assert result.metadata["token_acquired_via_relogin"] is True


def test_existing_account_login_uses_auto_sent_otp_without_manual_send():
    session = QueueSession([
        ("GET", "https://auth.example.test/flow/1", _response_with_did("did-1")),
        (
            "POST",
            OPENAI_API_ENDPOINTS["signup"],
            DummyResponse(payload={"page": {"type": OPENAI_PAGE_TYPES["EMAIL_OTP_VERIFICATION"]}}),
        ),
        ("POST", OPENAI_API_ENDPOINTS["validate_otp"], _response_with_login_cookies("ws-existing", "session-existing")),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"workspace_id": "ws-existing"}}),
        ),
        (
            "GET",
            "https://chatgpt.com/api/auth/session",
            DummyResponse(payload={"account": {"workspace_id": "ws-existing"}}),
        ),
        (
            "POST",
            OPENAI_API_ENDPOINTS["select_workspace"],
            DummyResponse(payload={"continue_url": "https://auth.example.test/continue-existing"}),
        ),
        (
            "GET",
            "https://auth.example.test/continue-existing",
            DummyResponse(
                status_code=302,
                headers={"Location": "http://localhost:1455/auth/callback?code=code-1&state=state-1"},
            ),
        ),
    ])

    email_service = FakeEmailService(["246810"])
    engine = RegistrationEngine(email_service)
    fake_oauth = FakeOAuthManager()
    engine.http_client = FakeOpenAIClient([session], ["sentinel-1"])
    engine.oauth_manager = fake_oauth

    result = engine.run()

    assert result.success is True
    assert result.source == "login"
    assert fake_oauth.start_calls == 1
    assert sum(1 for call in session.calls if call["url"] == OPENAI_API_ENDPOINTS["send_otp"]) == 0
    assert len(email_service.otp_requests) == 1
    assert email_service.otp_requests[0]["otp_sent_at"] is not None
    assert result.metadata["token_acquired_via_relogin"] is False
