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
    archive_disbursement,
    create_disbursement,
    outstanding_cents,
    unarchive_disbursement,
    update_disbursement,
)
from .models import Disbursement, User
from .permissions import (
    DISBURSEMENT_MANAGE,
    DISBURSEMENT_VIEW_OWN,
    permission_required,
)
from .routes import (
    consume_sensitive_action_authorization,
    correction_reason,
    require_sensitive_action_authorization,
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
        raise ValueError("Enter a valid amount") from exc
    if not value.is_finite() or value <= 0 or value != value.quantize(Decimal("0.01")):
        raise ValueError("Amount must be positive with no more than two decimals")
    cents = int(value * 100)
    if cents > 1_000_000_000:
        raise ValueError("Amount is too large")
    return cents


def _form_values() -> dict[str, Any]:
    try:
        date_value = date.fromisoformat(request.form.get("date", ""))
    except ValueError as exc:
        raise ValueError("Enter a valid date") from exc
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
    users = database.scalars(
        select(User)
        .order_by(User.last_name, User.first_name, User.id)
        .offset((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
    ).all()
    rows = [(user, outstanding_cents(database, user.id)) for user in users]
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
    page = _page()
    archived = admin and request.args.get("view") == "archived"
    predicate = (
        Disbursement.archived_at.is_not(None)
        if archived
        else Disbursement.archived_at.is_(None)
    )
    query = select(Disbursement).where(Disbursement.user_id == user_id, predicate)
    total = int(
        database.scalar(
            select(func.count(Disbursement.id)).where(
                Disbursement.user_id == user_id, predicate
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
        archived=archived,
        page=page,
        page_count=page_count,
        pending=outstanding_cents(database, user_id) if admin else None,
    )


@disbursement_pages.route("/disbursements/<int:user_id>/new", methods=["GET", "POST"])
@permission_required(DISBURSEMENT_MANAGE)
def new(user_id: int) -> Any:
    user = _user(user_id)
    actor = cast(User, current_user())
    if response := require_sensitive_action_authorization(
        actor, url_for("disbursements.detail", user_id=user_id)
    ):
        return response
    if request.method == "GET":
        return render_template(
            "disbursement_form.html", user=user, item=None, today=date.today()
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
            "disbursement_form.html", user=user, item=None, today=date.today()
        ), 409
    consume_sensitive_action_authorization()
    flash("Disbursement saved.", "success")
    return redirect(url_for("disbursements.detail", user_id=user_id))


@disbursement_pages.route(
    "/disbursements/<int:item_id>/<action>", methods=["GET", "POST"]
)
@permission_required(DISBURSEMENT_MANAGE)
def action(item_id: int, action: str) -> Any:
    if action not in {"edit", "archive", "unarchive"}:
        abort(404)
    database = get_session()
    item = database.get(Disbursement, item_id)
    if item is None:
        abort(404)
    user = _user(item.user_id)
    if (action == "unarchive") != (item.archived_at is not None):
        abort(409, "That action is not available for this disbursement.")
    actor = cast(User, current_user())
    if response := require_sensitive_action_authorization(
        actor, url_for("disbursements.detail", user_id=user.id)
    ):
        return response
    if request.method == "GET":
        return render_template(
            "disbursement_form.html",
            user=user,
            item=item,
            action=action,
            today=date.today(),
        )
    try:
        reason = correction_reason()
        prior = {
            "type": item.type,
            "amount_cents": item.amount_cents,
            "archived": item.archived_at is not None,
        }
        if action == "edit":
            item = update_disbursement(database, item_id, **_form_values())
        elif action == "archive":
            item = archive_disbursement(database, item_id, actor_id=actor.id)
        else:
            item = unarchive_disbursement(database, item_id)
        _audit(
            "disbursement_" + action,
            item,
            correction_reason=reason,
            previous=prior,
            amount_cents=item.amount_cents,
        )
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
            item=item,
            action=action,
            today=date.today(),
        ), 409
    consume_sensitive_action_authorization()
    flash("Disbursement updated.", "success")
    return redirect(url_for("disbursements.detail", user_id=user.id))
