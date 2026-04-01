import asyncio
from contextlib import contextmanager
from pathlib import Path

from src.database.models import Base, EmailService
from src.database.session import DatabaseSessionManager
from src.web.routes import email as email_routes
from src.web.routes import registration as registration_routes


class DummySettings:
    tempmail_enabled = False
    yyds_mail_enabled = False
    yyds_mail_api_key = None
    yyds_mail_default_domain = None
    custom_domain_base_url = ""
    custom_domain_api_key = None


def test_get_service_types_hides_luckmail_when_sdk_unavailable(monkeypatch):
    monkeypatch.setattr(email_routes, "is_luckmail_sdk_available", lambda: False)

    result = asyncio.run(email_routes.get_service_types())

    values = {item["value"] for item in result["types"]}
    assert "luckmail" not in values


def test_test_email_service_returns_friendly_message_when_luckmail_sdk_missing(monkeypatch):
    runtime_dir = Path("tests_runtime")
    runtime_dir.mkdir(exist_ok=True)
    db_path = runtime_dir / "luckmail_optional_email_routes.db"
    if db_path.exists():
        db_path.unlink()

    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)

    with manager.session_scope() as session:
        session.add(
            EmailService(
                service_type="luckmail",
                name="LuckMail 主服务",
                config={
                    "base_url": "https://mails.luckyous.com/",
                    "api_key": "lm_test_key",
                    "project_code": "openai",
                },
                enabled=True,
                priority=0,
            )
        )

    @contextmanager
    def fake_get_db():
        session = manager.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setattr(email_routes, "get_db", fake_get_db)
    monkeypatch.setattr(email_routes, "is_luckmail_sdk_available", lambda: False)

    result = asyncio.run(email_routes.test_email_service(1))

    assert result.success is False
    assert "未启用 LuckMail" in result.message


def test_registration_available_services_skips_luckmail_when_sdk_unavailable(monkeypatch):
    runtime_dir = Path("tests_runtime")
    runtime_dir.mkdir(exist_ok=True)
    db_path = runtime_dir / "luckmail_optional_registration_routes.db"
    if db_path.exists():
        db_path.unlink()

    manager = DatabaseSessionManager(f"sqlite:///{db_path}")
    Base.metadata.create_all(bind=manager.engine)

    with manager.session_scope() as session:
        session.add(
            EmailService(
                service_type="luckmail",
                name="LuckMail 主服务",
                config={
                    "base_url": "https://mails.luckyous.com/",
                    "api_key": "lm_test_key",
                    "project_code": "openai",
                },
                enabled=True,
                priority=0,
            )
        )

    @contextmanager
    def fake_get_db():
        session = manager.SessionLocal()
        try:
            yield session
        finally:
            session.close()

    monkeypatch.setattr(registration_routes, "get_db", fake_get_db)
    monkeypatch.setattr(registration_routes, "is_luckmail_sdk_available", lambda: False)

    import src.config.settings as settings_module

    monkeypatch.setattr(settings_module, "get_settings", lambda: DummySettings())

    result = asyncio.run(registration_routes.get_available_email_services())

    assert result["luckmail"]["available"] is False
    assert result["luckmail"]["count"] == 0
    assert result["luckmail"]["services"] == []
