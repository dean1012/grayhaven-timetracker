"""Server-rendered application routes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from typing import Any, cast

import pyotp
from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from .auth import (
    LoginLimiter,
    current_user,
    find_user_by_email,
    hash_password,
    load_current_user,
    login_required,
    normalize_email,
    password_error,
    password_hasher,
    provisioning_uri,
    qr_data_uri,
    required_text,
    safe_next_url,
    valid_totp_secret,
    verify_password,
    verify_password_constant_time,
    verify_totp,
)
from .database import get_session, health_check
from .models import Client, Contract, Subtask, Task, TimeEntry, User
from .permissions import (
    CLIENT_ADD,
    CLIENT_VIEW,
    CONTRACT_ADD,
    CONTRACT_VIEW,
    REPORT_GENERATE,
    REPORT_VIEW,
    TASK_ADD,
    TASK_DELETE,
    TASK_EDIT,
    TIMER_START,
    TIMER_STOP,
    USER_ADD,
    USER_EDIT,
    USER_VIEW,
    can,
    permission_required,
)
from .reports import (
    build_contract_report,
    build_pdf,
    duration_seconds,
    format_datetime,
    format_duration,
    format_money,
)

main = Blueprint("main", __name__)
logger = logging.getLogger("grayhaven_timetracker.audit")
login_limiter = LoginLimiter()
login_ip_limiter = LoginLimiter(limit=50)


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def audit(event: str, **fields: Any) -> None:
    logger.info(event.replace("_", " "), extra={"event": event, **fields})


def form_text(name: str, label: str, maximum: int) -> str:
    return required_text(request.form.get(name, ""), label, maximum=maximum)


def get_or_404(model: type[Any], identifier: int) -> Any:
    item = get_session().get(model, identifier)
    if item is None:
        abort(404)
    return item


def register_routes(app: Flask) -> None:
    app.before_request(load_current_user)
    app.register_blueprint(main)

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "app_version": app.config["APP_VERSION"],
            "can": can,
            "contact_url": app.config["CONTACT_URL"],
            "format_datetime": format_datetime,
            "format_duration": format_duration,
            "format_money": format_money,
            "logged_user": current_user(),
        }


@main.get("/branding/<path:filename>")
def branding_asset(filename: str) -> Any:
    branding_path = Path(cast(str, current_app.config["BRANDING_PATH"])).resolve()
    requested = (branding_path / filename).resolve()
    if branding_path not in requested.parents or not requested.is_file():
        abort(404)
    return send_from_directory(branding_path, filename, max_age=86400)


@main.get("/health")
def health() -> tuple[dict[str, str], int] | dict[str, str]:
    try:
        health_check(current_app)
    except Exception:
        current_app.logger.exception("health check failed")
        return {"status": "error"}, 503
    return {"status": "ok"}


@main.route("/login", methods=["GET", "POST"])
def login() -> Any:
    if current_user() is not None:
        return redirect(url_for("main.dashboard"))
    if request.method != "POST":
        return render_template("login.html")

    raw_email = request.form.get("email", "")
    try:
        email = normalize_email(raw_email)
    except ValueError:
        email = raw_email.strip().lower()[:255]
    ip = request.remote_addr or "unknown"
    rate_key = f"{ip}|{email}"
    if login_limiter.blocked(rate_key) or login_ip_limiter.blocked(ip):
        audit("login_rate_limited", email=email, ip=ip)
        abort(429)

    user = find_user_by_email(email)
    password_valid = verify_password_constant_time(
        user, request.form.get("password", "")
    )
    if user is None or not user.is_enabled or not password_valid:
        login_limiter.record_failure(rate_key)
        login_ip_limiter.record_failure(ip)
        reason = "disabled" if user is not None and not user.is_enabled else "credentials"
        audit("login_rejected", email=email, ip=ip, reason=reason)
        flash("The sign-in information was not accepted.", "error")
        return render_template("login.html"), 401

    if user.totp_secret and not verify_totp(
        user.totp_secret, request.form.get("totp", "")
    ):
        login_limiter.record_failure(rate_key)
        login_ip_limiter.record_failure(ip)
        audit("login_rejected", email=email, ip=ip, reason="totp")
        flash("The sign-in information was not accepted.", "error")
        return render_template("login.html"), 401

    if password_hasher.check_needs_rehash(user.password_hash):
        user.password_hash = password_hasher.hash(request.form.get("password", ""))
        get_session().commit()
    login_limiter.clear(rate_key)
    session.clear()
    session.permanent = True
    session["user_id"] = user.id
    session["session_version"] = user.session_version
    audit("login_succeeded", user_id=user.id, ip=ip)
    return redirect(safe_next_url(request.args.get("next")) or url_for("main.dashboard"))


@main.post("/logout")
@login_required
def logout() -> Any:
    user = current_user()
    audit("logout", user_id=user.id if user else None, ip=request.remote_addr)
    session.clear()
    return redirect(url_for("main.login"))


@main.get("/")
@permission_required(CLIENT_VIEW)
def dashboard() -> str:
    clients = get_session().scalars(
        select(Client)
        .options(selectinload(Client.contracts))
        .order_by(Client.name)
    ).all()
    active_entry = get_session().scalar(
        select(TimeEntry)
        .where(
            TimeEntry.user_id == cast(User, current_user()).id,
            TimeEntry.stopped_at.is_(None),
        )
        .options(
            selectinload(TimeEntry.task)
            .selectinload(Task.contract)
            .selectinload(Contract.client),
            selectinload(TimeEntry.subtask),
        )
    )
    return render_template(
        "dashboard.html",
        clients=clients,
        active_entry=active_entry,
        active_elapsed_seconds=(
            duration_seconds(active_entry.started_at, now_utc())
            if active_entry
            else 0
        ),
        current_contract_id=None,
    )


@main.get("/clients/<int:client_id>")
@permission_required(CLIENT_VIEW)
def client(client_id: int) -> str:
    item = get_session().scalar(
        select(Client)
        .where(Client.id == client_id)
        .options(selectinload(Client.contracts))
    )
    if item is None:
        abort(404)
    return render_template("client.html", client=item)


@main.route("/clients/new", methods=["GET", "POST"])
@permission_required(CLIENT_ADD)
def new_client() -> Any:
    if request.method != "POST":
        return render_template("client_form.html")
    try:
        item = Client(
            name=form_text("name", "Client name", 200),
            contact_name=form_text("contact_name", "Contact name", 200),
            contact_email=normalize_email(request.form.get("contact_email", "")),
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("client_form.html"), 400
    get_session().add(item)
    get_session().commit()
    audit("client_created", user_id=cast(User, current_user()).id)
    return redirect(url_for("main.client", client_id=item.id))


@main.route("/contracts/new/<int:client_id>", methods=["GET", "POST"])
@permission_required(CONTRACT_ADD)
def new_contract(client_id: int) -> Any:
    client_item = cast(Client, get_or_404(Client, client_id))
    if request.method != "POST":
        return render_template("contract_form.html", client=client_item)
    try:
        rate = Decimal(request.form.get("hourly_rate", "")).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if rate < 0 or rate > Decimal("1000000"):
            raise ValueError("Hourly rate must be between $0.00 and $1,000,000.00.")
        contract_item = Contract(
            client=client_item,
            name=form_text("name", "Contract name", 200),
            contact_name=form_text("contact_name", "Contact name", 200),
            contact_email=normalize_email(request.form.get("contact_email", "")),
            hourly_rate_cents=int(rate * 100),
        )
    except (InvalidOperation, ValueError) as exc:
        message = str(exc) or "Enter a valid hourly rate."
        flash(message, "error")
        return render_template("contract_form.html", client=client_item), 400
    get_session().add(contract_item)
    get_session().commit()
    audit("contract_created", user_id=cast(User, current_user()).id)
    return redirect(url_for("main.contract", contract_id=contract_item.id))


@main.get("/contracts/<int:contract_id>")
@permission_required(CONTRACT_VIEW)
def contract(contract_id: int) -> str:
    item = get_session().scalar(
        select(Contract)
        .where(Contract.id == contract_id)
        .options(
            selectinload(Contract.client),
            selectinload(Contract.tasks).selectinload(Task.subtasks),
            selectinload(Contract.tasks)
            .selectinload(Task.subtasks)
            .selectinload(Subtask.time_entries),
            selectinload(Contract.tasks).selectinload(Task.time_entries),
        )
    )
    if item is None:
        abort(404)
    active_entry = get_session().scalar(
        select(TimeEntry)
        .where(
            TimeEntry.user_id == cast(User, current_user()).id,
            TimeEntry.stopped_at.is_(None),
        )
        .options(
            selectinload(TimeEntry.task)
            .selectinload(Task.contract)
            .selectinload(Contract.client),
            selectinload(TimeEntry.subtask),
        )
    )
    return render_template(
        "contract.html",
        contract=item,
        active_entry=active_entry,
        active_elapsed_seconds=(
            duration_seconds(active_entry.started_at, now_utc())
            if active_entry
            else 0
        ),
        current_contract_id=item.id,
    )


@main.post("/tasks/<int:contract_id>/new")
@permission_required(TASK_ADD)
def new_task(contract_id: int) -> Any:
    contract_item = cast(Contract, get_or_404(Contract, contract_id))
    try:
        name = form_text("name", "Task name", 200)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        get_session().add(Task(contract=contract_item, name=name))
        get_session().commit()
    return redirect(url_for("main.contract", contract_id=contract_id))


@main.post("/subtasks/<int:task_id>/new")
@permission_required(TASK_ADD)
def new_subtask(task_id: int) -> Any:
    task = cast(Task, get_or_404(Task, task_id))
    try:
        name = form_text("name", "Subtask name", 200)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        get_session().add(Subtask(task=task, name=name))
        get_session().commit()
    return redirect(url_for("main.contract", contract_id=task.contract_id))


@main.post("/tasks/<int:task_id>/rename")
@permission_required(TASK_EDIT)
def rename_task(task_id: int) -> Any:
    task = cast(Task, get_or_404(Task, task_id))
    try:
        task.name = form_text("name", "Task name", 200)
        get_session().commit()
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("main.contract", contract_id=task.contract_id))


@main.post("/subtasks/<int:subtask_id>/rename")
@permission_required(TASK_EDIT)
def rename_subtask(subtask_id: int) -> Any:
    subtask = cast(Subtask, get_or_404(Subtask, subtask_id))
    try:
        subtask.name = form_text("name", "Subtask name", 200)
        get_session().commit()
    except ValueError as exc:
        flash(str(exc), "error")
    return redirect(url_for("main.contract", contract_id=subtask.task.contract_id))


@main.post("/tasks/<int:task_id>/delete")
@permission_required(TASK_DELETE)
def delete_task(task_id: int) -> Any:
    database = get_session()
    task = cast(Task, get_or_404(Task, task_id))
    has_time = database.scalar(
        select(func.count(TimeEntry.id)).where(TimeEntry.task_id == task.id)
    )
    if has_time:
        abort(409, "Tasks with recorded time cannot be deleted.")
    contract_id = task.contract_id
    database.delete(task)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "Tasks with recorded time cannot be deleted.")
    return redirect(url_for("main.contract", contract_id=contract_id))


@main.post("/subtasks/<int:subtask_id>/delete")
@permission_required(TASK_DELETE)
def delete_subtask(subtask_id: int) -> Any:
    database = get_session()
    subtask = cast(Subtask, get_or_404(Subtask, subtask_id))
    has_time = database.scalar(
        select(func.count(TimeEntry.id)).where(TimeEntry.subtask_id == subtask.id)
    )
    if has_time:
        abort(409, "Subtasks with recorded time cannot be deleted.")
    contract_id = subtask.task.contract_id
    database.delete(subtask)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "Subtasks with recorded time cannot be deleted.")
    return redirect(url_for("main.contract", contract_id=contract_id))


@main.post("/timer/start")
@permission_required(TIMER_START)
def start_timer() -> Any:
    database = get_session()
    user = cast(User, current_user())
    try:
        task_id = int(request.form.get("task_id", ""))
    except ValueError:
        abort(400)
    task = cast(Task, get_or_404(Task, task_id))
    subtask: Subtask | None = None
    raw_subtask_id = request.form.get("subtask_id", "")
    if raw_subtask_id:
        try:
            subtask = cast(Subtask, get_or_404(Subtask, int(raw_subtask_id)))
        except ValueError:
            abort(400)
        if subtask.task_id != task.id:
            abort(400, "The selected subtask does not belong to the selected task.")
    entry = TimeEntry(
        user=user,
        task=task,
        subtask=subtask,
        started_at=now_utc(),
        stopped_at=None,
    )
    database.add(entry)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        flash("Stop your active timer before starting another.", "error")
        return redirect(
            url_for("main.contract", contract_id=task.contract_id), code=303
        )
    audit("timer_started", user_id=user.id)
    return redirect(url_for("main.contract", contract_id=task.contract_id))


@main.post("/timer/stop/<int:entry_id>")
@permission_required(TIMER_STOP)
def stop_timer(entry_id: int) -> Any:
    database = get_session()
    entry = cast(TimeEntry, get_or_404(TimeEntry, entry_id))
    user = cast(User, current_user())
    if entry.user_id != user.id or entry.stopped_at is not None:
        abort(403)
    entry.stopped_at = max(now_utc(), entry.started_at)
    database.commit()
    audit("timer_stopped", user_id=user.id)
    destination = safe_next_url(request.form.get("next"))
    return redirect(
        destination or url_for("main.contract", contract_id=entry.task.contract_id)
    )


@main.get("/profile")
@login_required
def profile() -> str:
    return render_template("profile.html", user=cast(User, current_user()))


@main.post("/profile/name")
@login_required
def update_profile_name() -> Any:
    user = cast(User, current_user())
    try:
        user.first_name = form_text("first_name", "First name", 100)
        user.last_name = form_text("last_name", "Last name", 100)
    except ValueError as exc:
        flash(str(exc), "error")
    else:
        get_session().commit()
        flash("Profile updated.", "success")
    return redirect(url_for("main.profile"))


@main.post("/profile/password")
@login_required
def change_password() -> Any:
    user = cast(User, current_user())
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirmation = request.form.get("confirm_password", "")
    if not verify_password(user.password_hash, current_password):
        flash("The current password was not accepted.", "error")
    elif verify_password(user.password_hash, new_password):
        flash("The new password must differ from the current password.", "error")
    elif new_password != confirmation:
        flash("The new password confirmation does not match.", "error")
    elif error := password_error(new_password):
        flash(error, "error")
    else:
        user.password_hash = hash_password(new_password)
        user.session_version += 1
        get_session().commit()
        session["session_version"] = user.session_version
        audit("password_changed", user_id=user.id)
        flash("Password changed successfully.", "success")
    return redirect(url_for("main.profile"))


@main.post("/profile/totp/setup")
@login_required
def setup_totp() -> str:
    user = cast(User, current_user())
    user.pending_totp_secret = pyotp.random_base32()
    get_session().commit()
    uri = provisioning_uri(user, user.pending_totp_secret)
    return render_template(
        "totp_setup.html",
        user=user,
        secret=user.pending_totp_secret,
        qr_code=qr_data_uri(uri),
    )


@main.post("/profile/totp/confirm")
@login_required
def confirm_totp() -> Any:
    user = cast(User, current_user())
    secret = user.pending_totp_secret
    if not secret or not verify_totp(secret, request.form.get("totp", "")):
        flash("The verification code was not accepted. Setup was not enabled.", "error")
        return redirect(url_for("main.profile")), 400
    user.totp_secret = secret
    user.pending_totp_secret = None
    user.session_version += 1
    get_session().commit()
    session["session_version"] = user.session_version
    audit("totp_enabled", user_id=user.id)
    flash("Two-factor authentication has been enabled.", "success")
    return redirect(url_for("main.profile"))


@main.post("/profile/totp/disable")
@login_required
def disable_totp() -> Any:
    user = cast(User, current_user())
    if not user.totp_secret:
        return redirect(url_for("main.profile"))
    if not verify_password(
        user.password_hash, request.form.get("current_password", "")
    ) or not verify_totp(user.totp_secret, request.form.get("totp", "")):
        flash("The password or verification code was not accepted.", "error")
        return redirect(url_for("main.profile")), 400
    user.totp_secret = None
    user.pending_totp_secret = None
    user.session_version += 1
    get_session().commit()
    session["session_version"] = user.session_version
    audit("totp_disabled", user_id=user.id)
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("main.profile"))


@main.get("/users")
@permission_required(USER_VIEW)
def users() -> str:
    user_list = get_session().scalars(
        select(User).order_by(User.last_name, User.first_name)
    ).all()
    return render_template("users.html", users=user_list)


@main.route("/users/new", methods=["GET", "POST"])
@permission_required(USER_ADD)
def new_user() -> Any:
    if request.method != "POST":
        return render_template("user_form.html")
    try:
        email = normalize_email(request.form.get("email", ""))
        if find_user_by_email(email):
            raise ValueError("A user with that email already exists.")
        password = request.form.get("password", "")
        password_hash = hash_password(password)
        secret = pyotp.random_base32()
        user = User(
            email=email,
            first_name=form_text("first_name", "First name", 100),
            last_name=form_text("last_name", "Last name", 100),
            password_hash=password_hash,
            totp_secret=secret,
            pending_totp_secret=None,
            role="user",
            is_enabled=True,
            session_version=1,
            created_at=now_utc(),
        )
    except ValueError as exc:
        flash(str(exc), "error")
        return render_template("user_form.html"), 400
    get_session().add(user)
    try:
        get_session().commit()
    except IntegrityError:
        get_session().rollback()
        flash("A user with that email already exists.", "error")
        return render_template("user_form.html"), 409
    audit("user_created", user_id=user.id)
    uri = provisioning_uri(user, secret)
    return render_template(
        "user_created.html", user=user, secret=secret, qr_code=qr_data_uri(uri)
    )


@main.post("/users/<int:user_id>/toggle-enabled")
@permission_required(USER_EDIT)
def toggle_user_enabled(user_id: int) -> Any:
    database = get_session()
    actor = cast(User, current_user())
    user = cast(User, get_or_404(User, user_id))
    if user.id == actor.id:
        abort(409, "Administrators cannot disable their current account.")
    user.is_enabled = not user.is_enabled
    user.session_version += 1
    if not user.is_enabled:
        stopped_at = now_utc()
        for entry in database.scalars(
            select(TimeEntry).where(
                TimeEntry.user_id == user.id, TimeEntry.stopped_at.is_(None)
            )
        ):
            entry.stopped_at = max(stopped_at, entry.started_at)
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "At least one enabled administrator is required.")
    audit(
        "user_enabled" if user.is_enabled else "user_disabled",
        user_id=user.id,
    )
    return redirect(url_for("main.users"))


@main.post("/users/<int:user_id>/toggle-admin")
@permission_required(USER_EDIT)
def toggle_user_admin(user_id: int) -> Any:
    database = get_session()
    actor = cast(User, current_user())
    user = cast(User, get_or_404(User, user_id))
    if user.id == actor.id:
        abort(409, "Administrators cannot change their current role.")
    user.role = "user" if user.role == "admin" else "admin"
    try:
        database.commit()
    except IntegrityError:
        database.rollback()
        abort(409, "At least one enabled administrator is required.")
    audit("user_role_changed", user_id=user.id)
    return redirect(url_for("main.users"))


@main.get("/reports/<int:contract_id>")
@permission_required(REPORT_VIEW)
def report_view(contract_id: int) -> str:
    contract_item = get_session().scalar(
        select(Contract)
        .where(Contract.id == contract_id)
        .options(selectinload(Contract.client))
    )
    if contract_item is None:
        abort(404)
    report = build_contract_report(
        get_session(), contract_item, cast(str, current_app.config["DISPLAY_TIMEZONE"])
    )
    return render_template("report.html", report=report)


@main.get("/reports/<int:contract_id>.pdf")
@permission_required(REPORT_GENERATE)
def report_pdf(contract_id: int) -> Any:
    contract_item = get_session().scalar(
        select(Contract)
        .where(Contract.id == contract_id)
        .options(selectinload(Contract.client))
    )
    if contract_item is None:
        abort(404)
    report = build_contract_report(
        get_session(), contract_item, cast(str, current_app.config["DISPLAY_TIMEZONE"])
    )
    pdf = build_pdf(
        report,
        Path(cast(str, current_app.config["BRANDING_PATH"])),
        cast(str, current_app.config["CONTACT_URL"]),
    )
    filename = f"contract-time-report-{contract_id}.pdf"
    audit("report_generated", user_id=cast(User, current_user()).id)
    return send_file(
        pdf,
        as_attachment=True,
        download_name=filename,
        mimetype="application/pdf",
        max_age=0,
    )
