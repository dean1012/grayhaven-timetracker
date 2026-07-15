"""Stable internal permission identifiers and role mappings."""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, ParamSpec, TypeVar, cast

from flask import abort, redirect, request, url_for

from .auth import current_user

REPORT_VIEW = "report:view"
REPORT_GENERATE = "report:generate"
CLIENT_ADD = "client:add"
CLIENT_VIEW = "client:view"
CONTRACT_ADD = "contract:add"
CONTRACT_VIEW = "contract:view"
TASK_ADD = "task:add"
TASK_VIEW = "task:view"
TASK_EDIT = "task:edit"
TASK_DELETE = "task:delete"
TIMER_START = "timer:start"
TIMER_STOP = "timer:stop"
USER_ADD = "user:add"
USER_VIEW = "user:view"
USER_EDIT = "user:edit"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset(
        {
            REPORT_VIEW,
            REPORT_GENERATE,
            CLIENT_ADD,
            CLIENT_VIEW,
            CONTRACT_ADD,
            CONTRACT_VIEW,
            TASK_ADD,
            TASK_VIEW,
            TASK_EDIT,
            TASK_DELETE,
            TIMER_START,
            TIMER_STOP,
            USER_ADD,
            USER_VIEW,
            USER_EDIT,
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

