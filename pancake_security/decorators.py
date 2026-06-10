"""安全装饰器 — @has_role, @has_permission, @secured, authenticated_user()"""

from aiohttp import web
from pancake_security.context import SecurityContextHolder


# ── 权限装饰器 ──────────────────────────────────────────


def has_role(*roles: str):
    """@has_role("ADMIN", "MODERATOR") — 需要任一角色"""
    def decorator(func):
        func._required_roles = roles
        return func
    return decorator


def has_permission(*permissions: str):
    """@has_permission("user:delete", "user:edit") — 需要任一权限"""
    def decorator(func):
        func._required_permissions = permissions
        return func
    return decorator


def secured(roles=None, permissions=None):
    """@secured(roles=["ADMIN"], permissions=["user:delete"]) — 组合"""
    def decorator(func):
        func._required_roles = roles or ()
        func._required_permissions = permissions or ()
        return func
    return decorator


# ── 参数绑定标记 ──────────────────────────────────────────


class _AuthenticatedUserMarker:
    """标记参数需要注入当前已认证用户"""
    pass


def authenticated_user():
    """authenticated_user() — 注入当前已认证用户到 handler 参数

    Usage:
        @get("/me")
        @has_role("USER")
        async def me(self, user: User = authenticated_user()):
            return {"username": user.username}
    """
    return _AuthenticatedUserMarker()
