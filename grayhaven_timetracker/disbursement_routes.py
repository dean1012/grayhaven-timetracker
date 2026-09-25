"""Administrator disbursement management and worker history."""

from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any, cast

from flask import (
    Blueprint,
    abort,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError

from .audit import record_audit_event
from .auth import current_user
from .database import get_session
from .disbursements import (
    create_disbursement,
    outstanding_cents,
)
from .models import Disbursement, User
from .permissions import (
    DISBURSEMENT_MANAGE,
    DISBURSEMENT_VIEW_OWN,
    permission_required,
)
from .routes import (
    consume_sensitive_action_authorization,
    require_sensitive_action_authorization,
    unchanged_live_page_response,
)

disbursement_pages = Blueprint("disbursements", __name__)
PAGE_SIZE = 25


def _page() -> int:
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        abort(400)
    if page < 1:
        abort(400)
    return page


def _money(cents: int) -> str:
    return f"${Decimal(cents) / 100:,.2f}"


@disbursement_pages.app_context_processor
def disbursement_globals() -> dict[str, Any]:
    return {"disbursement_money": _money}


def _user(user_id: int) -> User:
    user = get_session().get(User, user_id)
    if user is None:
        abort(404)
    return user


def _amount_cents(raw: str) -> int:
    try:
        value = Decimal(raw)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Enter a valid amount.") from exc
    if not value.is_finite() or value <= 0 or value != value.quantize(Decimal("0.01")):
        raise ValueError("Amount must be positive with no more than two decimals.")
    cents = int(value * 100)
    if cents > 1_000_000_000:
        raise ValueError("Amount is too large.")
    return cents


def _form_values() -> dict[str, Any]:
    try:
        date_value = date.fromisoformat(request.form.get("date", ""))
    except ValueError as exc:
        raise ValueError("Enter a valid date.") from exc
    return {
        "kind": request.form.get("type", ""),
        "date_value": date_value,
        "transaction_id": request.form.get("transaction_id"),
        "amount_cents": _amount_cents(request.form.get("amount", "")),
        "notes": request.form.get("notes"),
    }


def _audit(event: str, item: Disbursement, **details: Any) -> None:
    record_audit_event(
        get_session(),
        event,
        source="admin",
        actor=cast(User, current_user()),
        ip_address=request.remote_addr,
        method=request.method,
        path=request.path,
        details={"disbursement_id": item.id, "worker_id": item.user_id, **details},
    )


@disbursement_pages.get("/disbursements")
@permission_required(DISBURSEMENT_MANAGE)
def index() -> Any:
    page = _page()
    database = get_session()
    total = int(database.scalar(select(func.count(User.id))) or 0)
    page_count = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > page_count:
        return redirect(url_for("disbursements.index", page=page_count))
    users = database.scalars(select(User)).all()
    rows = [(user, outstanding_cents(database, user.id)) for user in users]
    rows.sort(key=lambda row: (-row[1], row[0].last_name, row[0].first_name, row[0].id))
    rows = rows[(page - 1) * PAGE_SIZE : page * PAGE_SIZE]
    return render_template(
        "disbursements.html", rows=rows, page=page, page_count=page_count
    )


@disbursement_pages.get("/disbursements/<int:user_id>")
@permission_required(DISBURSEMENT_MANAGE)
def detail(user_id: int) -> Any:
    return _history(user_id, admin=True)


@disbursement_pages.get("/my/disbursements")
@permission_required(DISBURSEMENT_VIEW_OWN)
def my_history() -> Any:
    return _history(cast(User, current_user()).id, admin=False)


def _history(user_id: int, *, admin: bool) -> Any:
    database = get_session()
    user = _user(user_id)
    if response := unchanged_live_page_response():
        return response
    page = _page()
    query = select(Disbursement).where(
        Disbursement.user_id == user_id, Disbursement.archived_at.is_(None)
    )
    total = int(
        database.scalar(
            select(func.count(Disbursement.id)).where(
                Disbursement.user_id == user_id, Disbursement.archived_at.is_(None)
            )
        )
        or 0
    )
    page_count = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if page > page_count:
        endpoint = "disbursements.detail" if admin else "disbursements.my_history"
        if admin:
            return redirect(url_for(endpoint, user_id=user_id, page=page_count))
        return redirect(url_for(endpoint, page=page_count))
    items = database.scalars(
        query.order_by(Disbursement.date.desc(), Disbursement.id.desc())
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    return render_template(
        "disbursement_detail.html",
        user=user,
        items=items,
        admin=admin,
        page=page,
        page_count=page_count,
        pending=outstanding_cents(database, user_id) if admin else None,
        live_page=True,
    )


@disbursement_pages.route("/disbursements/<int:user_id>/new", methods=["GET", "POST"])
@permission_required(DISBURSEMENT_MANAGE)
def new(user_id: int) -> Any:
    user = _user(user_id)
    if outstanding_cents(get_session(), user_id) <= 0:
        abort(404)
    actor = cast(User, current_user())
    if response := require_sensitive_action_authorization(
        actor, url_for("disbursements.detail", user_id=user_id)
    ):
        return response
    if request.method == "GET":
        return render_template(
            "disbursement_form.html",
            user=user,
            today=date.today(),
            pending=outstanding_cents(get_session(), user_id),
            form_values={},
        )
    database = get_session()
    try:
        item = create_disbursement(
            database, user_id=user_id, actor_id=actor.id, **_form_values()
        )
        _audit("disbursement_created", item, amount_cents=item.amount_cents)
        database.commit()
    except (ValueError, IntegrityError, OperationalError) as exc:
        database.rollback()
        message = (
            str(exc)
            if isinstance(exc, ValueError)
            else "Disbursement could not be saved."
        )
        flash(message, "error")
        return render_template(
            "disbursement_form.html",
            user=user,
            today=date.today(),
            pending=outstanding_cents(database, user_id),
            form_values=request.form,
        ), 409
    consume_sensitive_action_authorization()
    flash("Disbursement saved.", "success")
    return redirect(url_for("disbursements.detail", user_id=user_id))
