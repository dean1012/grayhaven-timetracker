"""Grayhaven Systems LLC time tracker alpha application."""

from __future__ import annotations

import io
import os
import secrets
from datetime import datetime, timezone
from decimal import Decimal
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

import pyotp
from argon2 import PasswordHasher
from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
                                PageBreak, KeepTogether)
from sqlalchemy import event, text
from werkzeug.middleware.proxy_fix import ProxyFix

db = SQLAlchemy()
password_hasher = PasswordHasher()

PERMISSIONS = {
    "admin": {"report:view", "report:generate", "client:add", "client:view", "contract:add", "contract:view", "task:add", "task:view", "task:edit", "task:delete", "timer:start", "timer:stop", "user:add", "user:view", "user:edit"},
    "user": {"client:view", "contract:view", "task:add", "task:view", "task:edit", "task:delete", "timer:start", "timer:stop"},
}


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_enabled = db.Column(db.Boolean, nullable=False, default=True)
    session_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    contact_name = db.Column(db.String(200), nullable=False)
    contact_email = db.Column(db.String(255), nullable=False)
    contracts = db.relationship("Contract", back_populates="client", cascade="all, delete-orphan")


class Contract(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey("client.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    contact_name = db.Column(db.String(200), nullable=False)
    contact_email = db.Column(db.String(255), nullable=False)
    hourly_rate_cents = db.Column(db.Integer, nullable=False)
    client = db.relationship("Client", back_populates="contracts")
    tasks = db.relationship("Task", back_populates="contract", cascade="all, delete-orphan")

    @property
    def hourly_rate(self):
        return Decimal(self.hourly_rate_cents) / 100


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    contract_id = db.Column(db.Integer, db.ForeignKey("contract.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    contract = db.relationship("Contract", back_populates="tasks")
    subtasks = db.relationship("Subtask", back_populates="task", cascade="all, delete-orphan")
    entries = db.relationship("TimeEntry", back_populates="task")


class Subtask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    task = db.relationship("Task", back_populates="subtasks")
    entries = db.relationship("TimeEntry", back_populates="subtask")


class TimeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    contract_id = db.Column(db.Integer, db.ForeignKey("contract.id"), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey("task.id"), nullable=False)
    subtask_id = db.Column(db.Integer, db.ForeignKey("subtask.id"), nullable=True)
    started_at = db.Column(db.DateTime, nullable=False)
    stopped_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship("User")
    contract = db.relationship("Contract")
    task = db.relationship("Task", back_populates="entries")
    subtask = db.relationship("Subtask", back_populates="entries")

    @property
    def effective_end(self):
        return self.stopped_at or now_utc()

    @property
    def seconds(self):
        return max(0, int((self.effective_end - self.started_at).total_seconds()))


db.Index("uq_active_timer_per_user", TimeEntry.user_id, unique=True, sqlite_where=text("stopped_at IS NULL"))


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.environ.get('DATABASE_PATH', Path(app.instance_path) / 'timetracker.sqlite3')}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        DISPLAY_TIMEZONE=os.environ.get("TZ", "America/Chicago"),
        BRANDING_PATH=os.environ.get("BRANDING_PATH", str(Path(app.root_path) / "branding")),
    )
    db.init_app(app)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    with app.app_context():
        engine = db.engine

        @event.listens_for(engine, "connect")
        def enable_sqlite(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

        db.create_all()
        bootstrap_admin()

    register_routes(app)
    return app


def bootstrap_admin():
    email = os.environ.get("INITIAL_ADMIN_EMAIL")
    if not email:
        return
    email = email.strip().lower()
    user = User.query.filter_by(email=email).first()
    password_hash = os.environ.get("INITIAL_ADMIN_PASSWORD_HASH")
    password = os.environ.get("INITIAL_ADMIN_PASSWORD")
    if user is None and not password_hash and not password:
        raise RuntimeError("An initial admin password or password hash is required")
    if user is None:
        user = User(email=email, password_hash=password_hash or password_hasher.hash(password), totp_secret=os.environ.get("INITIAL_ADMIN_TOTP_SECRET") or pyotp.random_base32())
        db.session.add(user)
    elif password_hash or password:
        user.password_hash = password_hash or (password if password.startswith("$argon2") else password_hasher.hash(password))
    user.first_name = os.environ.get("INITIAL_ADMIN_FIRST_NAME", "Admin")
    user.last_name = os.environ.get("INITIAL_ADMIN_LAST_NAME", "User")
    user.totp_secret = os.environ.get("INITIAL_ADMIN_TOTP_SECRET") or user.totp_secret or pyotp.random_base32()
    user.is_admin = True
    user.is_enabled = True
    db.session.commit()


def current_user():
    user_id = session.get("user_id")
    user = db.session.get(User, user_id) if user_id else None
    if not user or not user.is_enabled or session.get("session_version") != user.session_version:
        session.clear()
        return None
    return user


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login", next=request.path))
        if not user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def register_routes(app):
    @app.context_processor
    def inject_globals():
        return {"logged_user": current_user(), "app_version": os.environ.get("APP_VERSION", "0.1.0-dev"), "format_duration": format_duration, "format_datetime": format_datetime, "now_utc": now_utc}

    @app.get("/branding/<path:filename>")
    def branding_asset(filename):
        branding_path = Path(app.config["BRANDING_PATH"])
        requested = (branding_path / filename).resolve()
        if branding_path.resolve() not in requested.parents or not requested.is_file():
            abort(404)
        return send_from_directory(branding_path, filename)

    @app.get("/health")
    def health():
        try:
            db.session.execute(text("SELECT 1"))
            return {"status": "ok"}
        except Exception:
            app.logger.exception("health check failed")
            return {"status": "error"}, 503

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            user = User.query.filter_by(email=email).first()
            valid = False
            if user and user.is_enabled:
                try:
                    password_hasher.verify(user.password_hash, request.form.get("password", ""))
                    valid = True
                except Exception:
                    valid = False
            if not valid:
                app.logger.warning("login rejected email=%s ip=%s", email, request.remote_addr)
                flash("The email or password was not accepted.", "error")
                return render_template("login.html"), 401
            if user.totp_secret and not pyotp.TOTP(user.totp_secret).verify(request.form.get("totp", "")):
                app.logger.warning("login rejected reason=totp email=%s ip=%s", email, request.remote_addr)
                flash("The verification code was not accepted.", "error")
                return render_template("login.html"), 401
            session.clear()
            session["user_id"] = user.id
            session["session_version"] = user.session_version
            app.logger.info("login succeeded user_id=%s ip=%s", user.id, request.remote_addr)
            return redirect(request.args.get("next") or url_for("dashboard"))
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        user = current_user()
        app.logger.info("logout user_id=%s ip=%s", user.id, request.remote_addr)
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def dashboard():
        return render_template("dashboard.html", clients=Client.query.order_by(Client.name).all())

    @app.get("/users")
    @admin_required
    def users():
        return render_template("users.html", users=User.query.order_by(User.last_name, User.first_name).all())

    @app.route("/users/new", methods=["GET", "POST"])
    @admin_required
    def new_user():
        if request.method == "POST":
            email = request.form["email"].strip().lower()
            password = request.form["password"]
            if User.query.filter_by(email=email).first():
                flash("A user with that email already exists.", "error")
                return render_template("user_form.html")
            if len(password) < 32 or not (any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password) and any(not c.isalnum() for c in password)):
                flash("The password does not meet the 32-character complexity requirements.", "error")
                return render_template("user_form.html")
            user = User(email=email, first_name=request.form["first_name"].strip(), last_name=request.form["last_name"].strip(), password_hash=password_hasher.hash(password), totp_secret=pyotp.random_base32(), is_enabled=True, is_admin=False)
            db.session.add(user)
            db.session.commit()
            return render_template("user_created.html", user=user)
        return render_template("user_form.html")

    @app.post("/users/<int:user_id>/toggle-enabled")
    @admin_required
    def toggle_user_enabled(user_id):
        user = db.get_or_404(User, user_id)
        if user.id == current_user().id:
            abort(409, "Use your profile to manage your own account.")
        user.is_enabled = not user.is_enabled
        user.session_version += 1
        if not user.is_enabled:
            for entry in TimeEntry.query.filter_by(user_id=user.id, stopped_at=None).all():
                entry.stopped_at = now_utc()
        db.session.commit()
        return redirect(url_for("users"))

    @app.post("/users/<int:user_id>/toggle-admin")
    @admin_required
    def toggle_user_admin(user_id):
        user = db.get_or_404(User, user_id)
        if user.id != current_user().id:
            user.is_admin = not user.is_admin
            db.session.commit()
        return redirect(url_for("users"))

    @app.route("/clients/new", methods=["GET", "POST"])
    @admin_required
    def new_client():
        if request.method == "POST":
            client = Client(name=request.form["name"].strip(), contact_name=request.form["contact_name"].strip(), contact_email=request.form["contact_email"].strip())
            db.session.add(client)
            db.session.commit()
            return redirect(url_for("dashboard"))
        return render_template("client_form.html")

    @app.route("/contracts/new/<int:client_id>", methods=["GET", "POST"])
    @admin_required
    def new_contract(client_id):
        client = db.get_or_404(Client, client_id)
        if request.method == "POST":
            rate = Decimal(request.form["hourly_rate"]).quantize(Decimal("0.01"))
            contract = Contract(client=client, name=request.form["name"].strip(), contact_name=request.form["contact_name"].strip(), contact_email=request.form["contact_email"].strip(), hourly_rate_cents=int(rate * 100))
            db.session.add(contract)
            db.session.commit()
            return redirect(url_for("contract", contract_id=contract.id))
        return render_template("contract_form.html", client=client)

    @app.get("/contracts/<int:contract_id>")
    @login_required
    def contract(contract_id):
        item = db.get_or_404(Contract, contract_id)
        return render_template("contract.html", contract=item)

    @app.post("/tasks/<int:contract_id>/new")
    @login_required
    def new_task(contract_id):
        contract = db.get_or_404(Contract, contract_id)
        name = request.form.get("name", "").strip()
        if name:
            db.session.add(Task(contract=contract, name=name))
            db.session.commit()
        return redirect(url_for("contract", contract_id=contract.id))

    @app.post("/subtasks/<int:task_id>/new")
    @login_required
    def new_subtask(task_id):
        task = db.get_or_404(Task, task_id)
        name = request.form.get("name", "").strip()
        if name:
            db.session.add(Subtask(task=task, name=name))
            db.session.commit()
        return redirect(url_for("contract", contract_id=task.contract_id))

    @app.post("/tasks/<int:task_id>/rename")
    @login_required
    def rename_task(task_id):
        task = db.get_or_404(Task, task_id)
        task.name = request.form["name"].strip()
        db.session.commit()
        return redirect(url_for("contract", contract_id=task.contract_id))

    @app.post("/subtasks/<int:subtask_id>/rename")
    @login_required
    def rename_subtask(subtask_id):
        subtask = db.get_or_404(Subtask, subtask_id)
        subtask.name = request.form["name"].strip()
        db.session.commit()
        return redirect(url_for("contract", contract_id=subtask.task.contract_id))

    @app.post("/tasks/<int:task_id>/delete")
    @login_required
    def delete_task(task_id):
        task = db.get_or_404(Task, task_id)
        if any(entry for entry in task.entries) or any(sub.entries for sub in task.subtasks):
            abort(409)
        contract_id = task.contract_id
        db.session.delete(task)
        db.session.commit()
        return redirect(url_for("contract", contract_id=contract_id))

    @app.post("/subtasks/<int:subtask_id>/delete")
    @login_required
    def delete_subtask(subtask_id):
        subtask = db.get_or_404(Subtask, subtask_id)
        if subtask.entries:
            abort(409)
        contract_id = subtask.task.contract_id
        db.session.delete(subtask)
        db.session.commit()
        return redirect(url_for("contract", contract_id=contract_id))

    @app.post("/timer/start")
    @login_required
    def start_timer():
        user = current_user()
        if TimeEntry.query.filter_by(user_id=user.id, stopped_at=None).first():
            abort(409, "Stop the active timer before starting another.")
        task = db.get_or_404(Task, int(request.form["task_id"]))
        subtask_id = request.form.get("subtask_id") or None
        subtask = db.session.get(Subtask, int(subtask_id)) if subtask_id else None
        if subtask and subtask.task_id != task.id:
            abort(400)
        db.session.add(TimeEntry(user=user, contract=task.contract, task=task, subtask=subtask, started_at=now_utc()))
        db.session.commit()
        return redirect(url_for("contract", contract_id=task.contract_id))

    @app.post("/timer/stop/<int:entry_id>")
    @login_required
    def stop_timer(entry_id):
        entry = db.get_or_404(TimeEntry, entry_id)
        if entry.user_id != current_user().id or entry.stopped_at:
            abort(403)
        entry.stopped_at = now_utc()
        db.session.commit()
        return redirect(url_for("contract", contract_id=entry.contract_id))

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        user = current_user()
        if request.method == "POST":
            current = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            try:
                password_hasher.verify(user.password_hash, current)
            except Exception:
                flash("The current password was not accepted.", "error")
                return render_template("profile.html", user=user)
            if new == current or new != confirm or len(new) < 32 or not (any(c.isupper() for c in new) and any(c.islower() for c in new) and any(c.isdigit() for c in new) and any(not c.isalnum() for c in new)):
                flash("The new password must be different, confirmed, and meet the 32-character complexity requirements.", "error")
                return render_template("profile.html", user=user)
            user.password_hash = password_hasher.hash(new)
            db.session.commit()
            flash("Password changed successfully.", "success")
        return render_template("profile.html", user=user)

    @app.post("/profile/totp/enable")
    @login_required
    def enable_totp():
        user = current_user()
        user.totp_secret = pyotp.random_base32()
        db.session.commit()
        return render_template("totp_enabled.html", user=user)

    @app.post("/profile/totp/disable")
    @login_required
    def disable_totp():
        user = current_user()
        user.totp_secret = None
        db.session.commit()
        flash("Two-factor authentication has been disabled.", "success")
        return redirect(url_for("profile"))

    @app.get("/reports/<int:contract_id>")
    @admin_required
    def report_view(contract_id):
        return render_template("report.html", report=build_report(db.get_or_404(Contract, contract_id)))

    @app.get("/reports/<int:contract_id>.pdf")
    @admin_required
    def report_pdf(contract_id):
        report = build_report(db.get_or_404(Contract, contract_id))
        buffer = build_pdf(report)
        return send_file(buffer, as_attachment=True, download_name=f"contract-time-report-{contract_id}.pdf", mimetype="application/pdf")


def build_report(contract):
    entries = TimeEntry.query.filter_by(contract_id=contract.id).order_by(TimeEntry.started_at).all()
    grouped = {}
    total_seconds = 0
    for entry in entries:
        seconds = entry.seconds
        total_seconds += seconds
        label = f"{entry.task.name} / {entry.subtask.name}" if entry.subtask else entry.task.name
        grouped.setdefault(label, {"seconds": 0, "cost": Decimal("0.00")})
        grouped[label]["seconds"] += seconds
        grouped[label]["cost"] += Decimal(seconds * contract.hourly_rate_cents) / Decimal(360000)
    tz = ZoneInfo(os.environ.get("TZ", "America/Chicago"))
    return {"contract": contract, "entries": entries, "grouped": grouped, "total_seconds": total_seconds, "total_cost": Decimal(total_seconds * contract.hourly_rate_cents) / Decimal(360000), "timezone": tz}


def format_duration(seconds):
    hours, remainder = divmod(int(seconds), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


def format_datetime(value, tz):
    return value.replace(tzinfo=timezone.utc).astimezone(tz).strftime("%Y-%m-%d %I:%M:%S %p %Z")


def build_pdf(report):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=0.55 * inch, leftMargin=0.55 * inch, topMargin=0.5 * inch, bottomMargin=0.5 * inch)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#E6EAF0"), fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontName="Helvetica", fontSize=9, leading=12, textColor=colors.HexColor("#353B44")))
    story = [Paragraph("Grayhaven Systems LLC", styles["ReportTitle"]), Paragraph("Contract Time Report", styles["Heading1"]), Spacer(1, 0.12 * inch), Paragraph(f"Client: {report['contract'].client.name}<br/>Contract: {report['contract'].name}<br/>Generated: {format_datetime(now_utc(), report['timezone'])}", styles["Body"]), Spacer(1, 0.18 * inch)]
    summary = [["Task / Subtask", "Duration", "Equivalent cost"]]
    for label, data in report["grouped"].items():
        summary.append([label, format_duration(data["seconds"]), f"${data['cost']:,.2f}"])
    summary.append(["Total", format_duration(report["total_seconds"]), f"${report['total_cost']:,.2f}"])
    table = Table(summary, colWidths=[3.7 * inch, 1.15 * inch, 1.25 * inch], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2A2F36")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#E6EAF0")), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBC7D3")), ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#E6EAF0")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"), ("ALIGN", (1, 1), (-1, -1), "RIGHT"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    story += [table, PageBreak(), Paragraph("Detailed Session Log", styles["Heading1"]), Spacer(1, 0.12 * inch)]
    details = [["User", "Task / Subtask", "Start", "End", "Duration", "Cost"]]
    for entry in report["entries"]:
        label = f"{entry.task.name} / {entry.subtask.name}" if entry.subtask else entry.task.name
        cost = Decimal(entry.seconds * report["contract"].hourly_rate_cents) / Decimal(360000)
        details.append([entry.user.full_name, label, format_datetime(entry.started_at, report["timezone"]), format_datetime(entry.effective_end, report["timezone"]), format_duration(entry.seconds), f"${cost:,.2f}"])
    detail_table = Table(details, colWidths=[1.05 * inch, 1.35 * inch, 1.1 * inch, 1.1 * inch, 0.7 * inch, 0.7 * inch], repeatRows=1)
    detail_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2A2F36")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#E6EAF0")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBC7D3")), ("FONTSIZE", (0, 0), (-1, -1), 6), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(detail_table)
    doc.build(story)
    buffer.seek(0)
    return buffer
