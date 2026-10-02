"""
Notification dispatch internals: _send_email, _send_webhook, _dispatch,
notify() and notify_sync(). Everything here is a unit test against fakes/
mocks - no real SMTP server or HTTP endpoint is ever contacted, regardless
of what SMTP_HOST happens to be set to in this environment's real .env.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from app.services import notification_service
from app.core.config import settings


# ---------------------------------------------------------------------------
# _send_email
# ---------------------------------------------------------------------------

def test_send_email_skips_when_smtp_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "")
    smtp_mock = MagicMock()
    monkeypatch.setattr(notification_service.smtplib, "SMTP", smtp_mock)

    notification_service._send_email("someone@example.com", "Subject", "Body")

    smtp_mock.assert_not_called()


def test_send_email_sends_with_tls_and_login_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_PORT", 587)
    monkeypatch.setattr(settings, "SMTP_USER", "svc-account")
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "secret")
    monkeypatch.setattr(settings, "SMTP_FROM", "noreply@example.com")
    monkeypatch.setattr(settings, "SMTP_USE_TLS", True)

    server = MagicMock()
    server.__enter__.return_value = server
    smtp_mock = MagicMock(return_value=server)
    monkeypatch.setattr(notification_service.smtplib, "SMTP", smtp_mock)

    notification_service._send_email("someone@example.com", "Subject", "Body")

    smtp_mock.assert_called_once_with("smtp.example.com", 587, timeout=10)
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("svc-account", "secret")
    args, _ = server.sendmail.call_args
    assert args[0] == "noreply@example.com"
    assert args[1] == ["someone@example.com"]
    assert "Subject" in args[2]


def test_send_email_skips_login_when_no_smtp_user(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(settings, "SMTP_USER", "")
    monkeypatch.setattr(settings, "SMTP_USE_TLS", False)

    server = MagicMock()
    server.__enter__.return_value = server
    monkeypatch.setattr(
        notification_service.smtplib, "SMTP", MagicMock(return_value=server)
    )

    notification_service._send_email("someone@example.com", "Subject", "Body")

    server.login.assert_not_called()
    server.starttls.assert_not_called()
    server.sendmail.assert_called_once()


def test_send_email_swallows_smtp_exceptions(monkeypatch):
    monkeypatch.setattr(settings, "SMTP_HOST", "smtp.example.com")

    def _boom(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(notification_service.smtplib, "SMTP", _boom)

    # Must not raise - a bad SMTP config should not break the caller
    # (e.g. incident creation) that triggered the notification.
    notification_service._send_email("someone@example.com", "Subject", "Body")


# ---------------------------------------------------------------------------
# _send_webhook
# ---------------------------------------------------------------------------

def test_send_webhook_posts_subject_message_and_metadata(monkeypatch):
    captured = {}

    class _FakeHTTPClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, json):
            captured["url"] = url
            captured["json"] = json
            return httpx.Response(200)

    monkeypatch.setattr(notification_service, "_webhook_client", lambda: _FakeHTTPClient())

    notification_service._send_webhook(
        "https://example.com/hook", "Subject", "Body text", {"incident_id": 5}
    )

    assert captured["url"] == "https://example.com/hook"
    assert captured["json"] == {
        "subject": "Subject",
        "message": "Body text",
        "metadata": {"incident_id": 5},
    }


def test_send_webhook_swallows_http_errors(monkeypatch):
    class _FailingHTTPClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, json):
            raise httpx.ConnectError("boom")

    monkeypatch.setattr(notification_service, "_webhook_client", lambda: _FailingHTTPClient())

    # Must not raise.
    notification_service._send_webhook("https://example.com/hook", "s", "m", None)


def test_send_webhook_defaults_metadata_to_empty_dict(monkeypatch):
    captured = {}

    class _FakeHTTPClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def post(self, url, json):
            captured["json"] = json
            return httpx.Response(200)

    monkeypatch.setattr(notification_service, "_webhook_client", lambda: _FakeHTTPClient())

    notification_service._send_webhook("https://example.com/hook", "s", "m", None)
    assert captured["json"]["metadata"] == {}


# ---------------------------------------------------------------------------
# _dispatch
# ---------------------------------------------------------------------------

def test_dispatch_skips_disabled_channel(monkeypatch):
    def _should_not_be_called(*args):
        raise AssertionError("disabled channel must not be dispatched")

    monkeypatch.setattr(notification_service, "_send_email", _should_not_be_called)
    channel = SimpleNamespace(enabled=False, channel_type="email", target="a@b.com")
    notification_service._dispatch(channel, "s", "m", None)  # must not raise


def test_dispatch_routes_email_channel_to_send_email(monkeypatch):
    calls = []
    monkeypatch.setattr(
        notification_service, "_send_email", lambda target, s, m: calls.append(target)
    )
    channel = SimpleNamespace(enabled=True, channel_type="email", target="a@b.com")
    notification_service._dispatch(channel, "s", "m", None)
    assert calls == ["a@b.com"]


def test_dispatch_routes_webhook_channel_to_send_webhook(monkeypatch):
    calls = []
    monkeypatch.setattr(
        notification_service,
        "_send_webhook",
        lambda target, s, m, md: calls.append(target),
    )
    channel = SimpleNamespace(
        enabled=True, channel_type="webhook", target="https://x.com/hook"
    )
    notification_service._dispatch(channel, "s", "m", None)
    assert calls == ["https://x.com/hook"]


# ---------------------------------------------------------------------------
# notify() - async entry point, tested against a fake AsyncSession so the
# dedup/filter logic can be exercised without needing to violate the real
# DB's UniqueConstraint on (org_id, channel_type, target).
# ---------------------------------------------------------------------------

class _FakeScalars:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class _FakeResult:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        return _FakeScalars(self._items)


class _FakeAsyncDB:
    def __init__(self, items):
        self._items = items

    async def execute(self, query):
        return _FakeResult(self._items)


@pytest.mark.asyncio
async def test_notify_does_nothing_when_no_channels_exist():
    fake_db = _FakeAsyncDB([])
    # Must not raise even though nothing is configured.
    await notification_service.notify(fake_db, 1, "incident_created", "s", "m")


@pytest.mark.asyncio
async def test_notify_dedupes_identical_channel_target_pairs(monkeypatch):
    dispatched = []
    monkeypatch.setattr(
        notification_service,
        "_dispatch",
        lambda channel, s, m, md: dispatched.append(channel.target),
    )
    duplicate_a = SimpleNamespace(
        channel_type="webhook",
        target="https://x.com/hook",
        enabled=True,
        events_json=["incident_created"],
    )
    duplicate_b = SimpleNamespace(
        channel_type="webhook",
        target="https://x.com/hook",
        enabled=True,
        events_json=["incident_created"],
    )
    fake_db = _FakeAsyncDB([duplicate_a, duplicate_b])

    await notification_service.notify(fake_db, 1, "incident_created", "s", "m")

    assert dispatched == ["https://x.com/hook"]


@pytest.mark.asyncio
async def test_notify_only_dispatches_subscribed_event_types(monkeypatch):
    dispatched = []
    monkeypatch.setattr(
        notification_service,
        "_dispatch",
        lambda channel, s, m, md: dispatched.append(channel.target),
    )
    not_subscribed = SimpleNamespace(
        channel_type="email",
        target="a@b.com",
        enabled=True,
        events_json=["approval_pending"],
    )
    subscribed = SimpleNamespace(
        channel_type="email",
        target="c@d.com",
        enabled=True,
        events_json=["incident_created", "approval_pending"],
    )
    fake_db = _FakeAsyncDB([not_subscribed, subscribed])

    await notification_service.notify(fake_db, 1, "incident_created", "s", "m")

    assert dispatched == ["c@d.com"]


# ---------------------------------------------------------------------------
# notify_sync() - the Celery-worker counterpart, no event loop involved.
# ---------------------------------------------------------------------------

class _FakeQuery:
    def __init__(self, items):
        self._items = items

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return self._items


class _FakeSyncDB:
    def __init__(self, items):
        self._items = items

    def query(self, model):
        return _FakeQuery(self._items)


def test_notify_sync_dedupes_and_filters_like_the_async_version(monkeypatch):
    dispatched = []
    monkeypatch.setattr(
        notification_service,
        "_dispatch",
        lambda channel, s, m, md: dispatched.append(channel.target),
    )
    duplicate = SimpleNamespace(
        channel_type="email",
        target="ops@x.com",
        enabled=True,
        events_json=["training_completed"],
    )
    unsubscribed = SimpleNamespace(
        channel_type="email",
        target="other@x.com",
        enabled=True,
        events_json=["training_failed"],
    )
    fake_db = _FakeSyncDB([duplicate, duplicate, unsubscribed])

    notification_service.notify_sync(fake_db, 1, "training_completed", "s", "m")

    assert dispatched == ["ops@x.com"]
