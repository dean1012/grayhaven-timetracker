"""Administrator invoice previews, issuance, downloads, and payment actions."""

from __future__ import annotations

import secrets
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast
from zoneinfo import ZoneInfo

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import selectinload

from .audit import record_audit_event
from .auth import current_user
from .database import get_session
from .invoice_pdf import invoice_pdf_with_status
from .invoice_summary import worker_daily_summary_rows
from .invoices import (
    create_invoice,
    mark_invoice_paid,
    preview_invoice,
    refund_invoice,
    void_invoice,
)
from .models import Client, Contract, Invoice, InvoiceLine, User
from .permissions import INVOICE_MANAGE, permission_required
from .public_ids import find_client, find_contract
from .reports import format_money
from .routes import (
    clear_sensitive_action_authorization,
    consume_sensitive_action_authorization,
    correction_reason,
    datetime_local_value,
    local_datetime_to_utc,
    now_utc,
    require_sensitive_action_authorization,
)

invoices = Blueprint("invoices", __name__, url_prefix="/invoices")
PAGE_SIZE = 25


def human_duration(seconds: int) -> str:
    """Show precise elapsed time without hiding billable seconds."""
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    parts = []
    for value, unit in ((hours, "hour"), (minutes, "minute"), (seconds, "second")):
        if value:
            parts.append(f"{value} {unit}{'' if value == 1 else 's'}")
    return " ".join(parts) or "0 seconds"


@invoices.context_processor
def invoice_globals() -> dict[str, Any]:
    return {
        "invoice_money": lambda cents: format_money(Decimal(cents) / 100),
        "human_duration": human_duration,
    }


def range_context(draft: dict[str, Any] | None = None) -> dict[str, Any]:
    database = get_session()
    return {
        "clients": database.scalars(
            select(Client).where(Client.archived_at.is_(None)).order_by(Client.name)
        ).all(),
        "projects": database.scalars(
            select(Contract)
            .where(Contract.archived_at.is_(None))
            .order_by(Contract.name, Contract.id)
        ).all(),
        "draft": draft if draft is not None else session.get("invoice_draft", {}),
        "timezone_name": current_app.config["DISPLAY_TIMEZONE"],
    }


def get_invoice(invoice_id: int) -> Invoice:
    invoice = get_session().scalar(
        select(Invoice)
        .where(Invoice.id == invoice_id)
        .options(selectinload(Invoice.lines).selectinload(InvoiceLine.entry))
    )
    if invoice is None:
        abort(404)
    return invoice


def audit_invoice(event: str, invoice: Invoice, **details: Any) -> None:
    record_audit_event(
        get_session(),
        event,
        source="admin",
        actor=cast(User, current_user()),
        ip_address=request.remote_addr,
        method=request.method,
        path=request.path,
        details={
            "invoice_number": invoice.invoice_number,
            **details,
        },
    )


@invoices.get("")
@permission_required(INVOICE_MANAGE)
def index() -> Any:
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        abort(400)
    if page < 1:
        abort(400)
    database = get_session()
    total = int(database.scalar(select(func.count(Invoice.id))) or 0)
    page_count = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > page_count:
        return redirect(url_for("invoices.index", page=page_count))
    items = database.scalars(
        select(Invoice)
        .options(selectinload(Invoice.lines).selectinload(InvoiceLine.entry))
        .order_by(
            case(
                (Invoice.status == "UNPAID", 0),
                ((Invoice.status == "PAID") & (Invoice.refunded.is_(False)), 1),
                (Invoice.refunded.is_(True), 2),
                else_=3,
            ),
            Invoice.issued_at.desc(),
            Invoice.id.desc(),
        )
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    return render_template(
        "invoices.html",
        invoices=items,
        total=total,
        page=page,
        page_count=page_count,
        timezone_info=ZoneInfo(current_app.config["DISPLAY_TIMEZONE"]),
        **range_context(),
    )


@invoices.get("/new")
@permission_required(INVOICE_MANAGE)
def new() -> str:
    return render_template("invoice_range.html", **range_context())


@invoices.post("/preview")
@permission_required(INVOICE_MANAGE)
def preview() -> Any:
    clear_sensitive_action_authorization()
    draft: dict[str, Any] = {
        key: request.form.get(key, "")
        for key in ("client_id", "contract_id", "mode", "range_start", "range_end")
    }
    try:
        database = get_session()
        client = find_client(database, str(draft["client_id"]))
        contract = find_contract(database, str(draft["contract_id"]))
        if (
            client is None
            or contract is None
            or contract.client_id != client.id
            or contract.archived_at is not None
        ):
            raise ValueError(
                "Select an active project belonging to the selected client."
            )
        timezone_name = str(current_app.config["DISPLAY_TIMEZONE"])
        start: datetime | None
        end: datetime | None
        if draft["mode"] == "custom":
            start = local_datetime_to_utc(draft["range_start"], "Start", timezone_name)
            end = local_datetime_to_utc(draft["range_end"], "End", timezone_name)
        elif draft["mode"] == "since_last":
            start = end = None
        else:
            raise ValueError("Select a valid invoice range mode.")
        proposed = preview_invoice(
            database,
            contract_id=contract.id,
            range_start_utc=start,
            range_end_utc=end,
            timezone_name=timezone_name,
        )
        draft.update(
            client_id=client.display_number,
            contract_id=contract.public_ref,
            range_start=datetime_local_value(proposed.range_start_utc, timezone_name),
            range_end=datetime_local_value(proposed.range_end_utc, timezone_name),
            fingerprint=proposed.fingerprint,
            nonce=secrets.token_urlsafe(24),
            timezone_name=timezone_name,
        )
        draft["start_utc"] = proposed.range_start_utc.isoformat()
        draft["end_utc"] = proposed.range_end_utc.isoformat()
        session["invoice_draft"] = draft
        return render_template(
            "invoice_preview.html",
            preview=proposed,
            draft=draft,
            timezone_info=ZoneInfo(timezone_name),
        )
    except (ValueError, OverflowError) as exc:
        flash(str(exc) or "Select a valid client and project.", "error")
        return render_template("invoice_range.html", **range_context(draft)), 400


@invoices.route("/generate", methods=["GET", "POST"])
@permission_required(INVOICE_MANAGE)
def generate() -> Any:
    draft = session.get("invoice_draft")
    if not isinstance(draft, dict) or not draft.get("fingerprint"):
        flash("Preview the invoice before generating it.", "warning")
        return redirect(url_for("invoices.index"))
    if request.method == "POST" and request.form.get("nonce") != draft.get("nonce"):
        abort(409, "This preview was replaced. Preview the invoice again.")
    actor = cast(User, current_user())
    if response := require_sensitive_action_authorization(
        actor, url_for("invoices.index")
    ):
        return response
    database = get_session()
    try:
        contract = find_contract(database, str(draft["contract_id"]))
        if contract is None or contract.client.display_number != draft["client_id"]:
            raise ValueError("Select a valid client and contract.")
        timezone_name = draft["timezone_name"]
        start = datetime.fromisoformat(draft["start_utc"])
        end = datetime.fromisoformat(draft["end_utc"])
        if request.method == "GET":
            proposed = preview_invoice(
                database,
                contract_id=contract.id,
                range_start_utc=start,
                range_end_utc=end,
                timezone_name=timezone_name,
            )
            if proposed.fingerprint != draft["fingerprint"]:
                raise ValueError(
                    "Eligible entries or project details changed. Please preview again."
                )
            return render_template(
                "invoice_preview.html",
                preview=proposed,
                draft=draft,
                timezone_info=ZoneInfo(timezone_name),
            )
        branding = Path(current_app.config["BRANDING_PATH"])
        invoice = create_invoice(
            database,
            contract_id=contract.id,
            range_start_utc=start,
            range_end_utc=end,
            timezone_name=timezone_name,
            expected_fingerprint=draft["fingerprint"],
            logo_path=branding / "grayhaven-logo-wordmark-light.png",
            font_regular_path=branding / "fonts/inter-400.ttf",
            font_bold_path=branding / "fonts/inter-700.ttf",
        )
        audit_invoice(
            "invoice_created",
            invoice,
            entry_count=len(invoice.lines),
            total_seconds=invoice.total_seconds,
            total_cents=invoice.total_cents,
            range_start=start,
            range_end=end,
            due_date=invoice.due_date,
        )
        database.commit()
    except (ValueError, IntegrityError, OperationalError) as exc:
        database.rollback()
        clear_sensitive_action_authorization()
        flash(
            str(exc)
            if isinstance(exc, ValueError)
            else "Invoice data changed or is busy. Please preview again.",
            "error",
        )
        return redirect(url_for("invoices.new"))
    session.pop("invoice_draft", None)
    consume_sensitive_action_authorization()
    flash(f"Invoice {invoice.invoice_number} generated.", "success")
    return redirect(url_for("invoices.index"))


@invoices.get("/<invoicenum:invoice_id>")
@permission_required(INVOICE_MANAGE)
def detail(invoice_id: int) -> str:
    invoice = get_invoice(invoice_id)
    return render_template(
        "invoice_detail.html",
        invoice=invoice,
        worker_daily_totals=worker_daily_summary_rows(
            invoice, invoice.lines, ZoneInfo(invoice.timezone_name)
        ),
        timezone_info=ZoneInfo(invoice.timezone_name),
    )


@invoices.get("/<invoicenum:invoice_id>/download")
@permission_required(INVOICE_MANAGE)
def download(invoice_id: int) -> Response:
    invoice = get_invoice(invoice_id)
    branding = Path(current_app.config["BRANDING_PATH"])
    return Response(
        invoice_pdf_with_status(
            invoice.pdf_bytes,
            invoice.display_status,
            pdf_version=invoice.pdf_version,
            font_regular_path=branding / "fonts/inter-400.ttf",
            font_bold_path=branding / "fonts/inter-700.ttf",
        ),
        mimetype="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="invoice-{invoice.invoice_number}.pdf"'
            )
        },
    )


@invoices.route("/<invoicenum:invoice_id>/<action>", methods=["GET", "POST"])
@permission_required(INVOICE_MANAGE)
def action(invoice_id: int, action: str) -> Any:
    labels = {
        "paid": "Mark Paid",
        "refund": "Refund",
        "void": "Void",
    }
    if action not in labels:
        abort(404)
    invoice = get_invoice(invoice_id)
    if invoice.status == "VOID":
        abort(409, "Voiding is permanent. This invoice cannot be changed.")
    if (action in {"paid", "void"} and invoice.status != "UNPAID") or (
        action == "refund" and (invoice.status != "PAID" or invoice.refunded)
    ):
        abort(409, "That action is not available for the invoice's current status.")
    actor = cast(User, current_user())
    if response := require_sensitive_action_authorization(
        actor, url_for("invoices.detail", invoice_id=invoice.id)
    ):
        return response
    reason_required = action in {"refund", "void"}
    context = {
        "invoice": invoice,
        "action": action,
        "action_label": labels[action],
        "reason_required": reason_required,
        "today": now_utc()
        .replace(tzinfo=ZoneInfo("UTC"))
        .astimezone(ZoneInfo(invoice.timezone_name))
        .date(),
    }
    if request.method == "GET":
        return render_template("invoice_action.html", **context)
    database = get_session()
    try:
        reason = correction_reason() if reason_required else None
        prior = {"status": invoice.display_status, "paid_date": invoice.paid_date}
        if action == "paid":
            invoice = mark_invoice_paid(database, invoice_id)
        elif action == "refund":
            invoice = refund_invoice(database, invoice_id)
        elif action == "void":
            invoice = void_invoice(database, invoice_id)
        audit_invoice(
            "invoice_" + action,
            invoice,
            correction_reason=reason,
            previous=prior,
            status=invoice.display_status,
            paid_date=invoice.paid_date,
        )
        database.commit()
    except (ValueError, IntegrityError, OperationalError) as exc:
        database.rollback()
        flash(
            str(exc)
            if isinstance(exc, ValueError)
            else "Invoice data changed or is busy. Please reload and try again.",
            "error",
        )
        return render_template("invoice_action.html", **context), 409
    consume_sensitive_action_authorization()
    flash(f"Invoice {invoice.invoice_number}: {labels[action]} completed.", "success")
    return redirect(url_for("invoices.detail", invoice_id=invoice.id))
