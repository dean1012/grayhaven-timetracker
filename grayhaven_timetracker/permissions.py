"""Stable internal permission identifiers and role mappings."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import ParamSpec, TypeVar, cast

from flask import abort, redirect, request, url_for

from .auth import current_user

AUDIT_VIEW = "audit:view"
REPORT_VIEW = "report:view"
REPORT_SHARE = "report:share"
CLIENT_ADD = "client:add"
CLIENT_VIEW = "client:view"
CLIENT_EDIT = "client:edit"
CLIENT_DELETE = "client:delete"
CONTRACT_ADD = "contract:add"
CONTRACT_VIEW = "contract:view"
CONTRACT_EDIT = "contract:edit"
CONTRACT_DELETE = "contract:delete"
TASK_ADD = "task:add"
TASK_VIEW = "task:view"
TASK_EDIT = "task:edit"
TASK_DELETE = "task:delete"
TIMER_START = "timer:start"
TIMER_STOP = "timer:stop"
TIME_ENTRY_VIEW_OWN = "time_entry:view_own"
TIME_ENTRY_VIEW_ANY = "time_entry:view_any"
TIME_ENTRY_ADD_OWN = "time_entry:add_own"
TIME_ENTRY_ADD_ANY = "time_entry:add_any"
TIME_ENTRY_EDIT_OWN = "time_entry:edit_own"
TIME_ENTRY_EDIT_ANY = "time_entry:edit_any"
TIME_ENTRY_DELETE_OWN = "time_entry:delete_own"
TIME_ENTRY_DELETE_ANY = "time_entry:delete_any"
USER_ADD = "user:add"
USER_VIEW = "user:view"
USER_EDIT = "user:edit"
USER_PASSWORD_RESET = "user:password_reset"  # noqa: S105

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {
            AUDIT_VIEW,
            REPORT_VIEW,
            REPORT_SHARE,
            CLIENT_ADD,
            CLIENT_VIEW,
            CLIENT_EDIT,
            CLIENT_DELETE,
            CONTRACT_ADD,
            CONTRACT_VIEW,
            CONTRACT_EDIT,
            CONTRACT_DELETE,
            TASK_ADD,
            TASK_VIEW,
            TASK_EDIT,
            TASK_DELETE,
            TIMER_START,
            TIMER_STOP,
            TIME_ENTRY_VIEW_OWN,
            TIME_ENTRY_VIEW_ANY,
            TIME_ENTRY_ADD_OWN,
            TIME_ENTRY_ADD_ANY,
            TIME_ENTRY_EDIT_OWN,
            TIME_ENTRY_EDIT_ANY,
            TIME_ENTRY_DELETE_OWN,
            TIME_ENTRY_DELETE_ANY,
            USER_ADD,
            USER_VIEW,
            USER_EDIT,
            USER_PASSWORD_RESET,
        }
    ),
    "user": frozenset(
        {
            CLIENT_VIEW,
            CONTRACT_VIEW,
            TASK_ADD,
            TASK_VIEW,
            TASK_EDIT,
            TASK_DELETE,
            TIMER_START,
            TIMER_STOP,
            TIME_ENTRY_VIEW_OWN,
            TIME_ENTRY_ADD_OWN,
            TIME_ENTRY_EDIT_OWN,
            TIME_ENTRY_DELETE_OWN,
        }
    ),
}

P = ParamSpec("P")
R = TypeVar("R")


def can(permission: str) -> bool:
    """Return whether the authenticated user has an internal permission."""
    user = current_user()
    return bool(user and permission in ROLE_PERMISSIONS.get(user.role, frozenset()))


def permission_required(permission: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Enforce authentication and one stable permission at the route boundary."""

    def decorator(view: Callable[P, R]) -> Callable[P, R]:
        @wraps(view)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            if current_user() is None:
                next_path = request.full_path.rstrip("?")
                return cast(R, redirect(url_for("main.login", next=next_path)))
            if not can(permission):
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
