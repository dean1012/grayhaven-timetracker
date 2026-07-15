"""Grayhaven Systems LLC Time Tracker application factory."""

from __future__ import annotations

import logging
import time
from datetime import timedelta
from typing import Any

from flask import Flask, Response, g, render_template, request
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

from .bootstrap import reconcile_initial_admin
from .config import (
    DEFAULT_CONTACT_URL,
    environment_config,
    validate_branding,
    validate_contact_url,
    validate_timezone,
)
from .database import init_app as init_database
from .database import rollback_request_session, session_scope
from .logging_config import configure_logging
from .routes import register_routes

csrf = CSRFProtect()


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create and fully initialize one application instance."""
    configure_logging()
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    if test_config is None:
        app.config.update(environment_config())
    else:
        app.config.update(test_config)
    app.config.setdefault("CONTACT_URL", DEFAULT_CONTACT_URL)
    validate_timezone(str(app.config["DISPLAY_TIMEZONE"]))
    validate_contact_url(str(app.config["CONTACT_URL"]))
    if not app.config.get("SKIP_BRANDING_VALIDATION"):
        validate_branding(str(app.config["BRANDING_PATH"]))
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
    app.config.setdefault("SESSION_COOKIE_HTTPONLY", True)
    app.config.setdefault("SESSION_COOKIE_NAME", "grayhaven_timetracker_session")
    app.config.setdefault("SESSION_COOKIE_SAMESITE", "Lax")
    app.config.setdefault("SESSION_COOKIE_SECURE", False)
    app.config.setdefault("MAX_CONTENT_LENGTH", 1024 * 1024)
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", 3600)
    app.config.setdefault("APP_VERSION", "0.1.0-dev")

    trusted_proxies = int(app.config.get("TRUSTED_PROXY_COUNT", 0))
    if trusted_proxies:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app,
            x_for=trusted_proxies,
            x_proto=trusted_proxies,
            x_host=trusted_proxies,
        )

    csrf.init_app(app)
    init_database(app)
    with session_scope(app) as database:
        reconcile_initial_admin(app, database)
    register_request_logging(app)
    register_routes(app)
    register_security_headers(app)
    register_error_handlers(app)
    return app


def register_request_logging(app: Flask) -> None:
    """Attach structured access logging while suppressing healthy probe noise."""
    access_logger = logging.getLogger("grayhaven_timetracker.access")

    @app.before_request
    def begin_request_timing() -> None:
        g.request_started_at = time.perf_counter()

    @app.after_request
    def log_request(response: Response) -> Response:
        if request.endpoint == "main.health" and response.status_code < 400:
            return response
        started_at = getattr(g, "request_started_at", time.perf_counter())
        user = getattr(g, "current_user", None)
        logged_path = (
            "/shared/reports/[redacted]"
            if request.endpoint == "main.shared_report"
            else request.path
        )
        access_logger.info(
            "HTTP request",
            extra={
                "event": "http_access",
                "method": request.method,
                "path": logged_path,
                "status": response.status_code,
                "duration_us": int((time.perf_counter() - started_at) * 1_000_000),
                "ip": request.remote_addr,
                "user_id": user.id if user else None,
                "user_agent": request.user_agent.string[:512],
            },
        )
        return response


def register_security_headers(app: Flask) -> None:
    """Attach browser security and response-cache controls."""

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; "
            "script-src 'self'; style-src 'self'; font-src 'self'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        if request.endpoint not in {"static", "main.branding_asset"}:
            response.headers["Cache-Control"] = "no-store"
        return response


def register_error_handlers(app: Flask) -> None:
    """Render stable public error pages without exposing internal details."""

    def error_page(status: int, message: str) -> tuple[str, int]:
        return (
            render_template("error.html", status=status, message=message),
            status,
        )

    app.register_error_handler(
        CSRFError,
        lambda _: error_page(400, "The form expired or could not be verified."),
    )
    app.register_error_handler(
        400, lambda _: error_page(400, "The request could not be processed.")
    )
    app.register_error_handler(
        403, lambda _: error_page(403, "You do not have permission to do that.")
    )
    app.register_error_handler(
        404, lambda _: error_page(404, "The requested page was not found.")
    )
    app.register_error_handler(
        405, lambda _: error_page(405, "That action is not available for this request.")
    )
    app.register_error_handler(
        409, lambda error: error_page(409, getattr(error, "description", "Conflict."))
    )
    app.register_error_handler(
        429,
        lambda _: error_page(
            429, "Too many access attempts. Try again in a few minutes."
        ),
    )
    app.register_error_handler(
        413, lambda _: error_page(413, "The request was larger than the allowed limit.")
    )

    def internal_server_error(_: Any) -> tuple[str, int]:
        # A database exception may leave the request session unusable. Roll it
        # back and suppress authenticated navigation so error rendering cannot
        # trigger a second database failure while resolving permissions.
        rollback_request_session()
        g.current_user = None
        return error_page(500, "An unexpected application error occurred.")

    app.register_error_handler(500, internal_server_error)
