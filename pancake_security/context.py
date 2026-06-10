"""SecurityContext — 协程级安全上下文"""

from contextvars import ContextVar
from typing import Any


class Authentication:
    """认证凭证/已认证对象"""

    def __init__(self, principal: Any = None, credentials: str = "",
                 authorities: list[str] = None, details: dict = None,
                 authenticated: bool = False, auth_type: str = ""):
        self.principal = principal
        self.credentials = credentials
        self.authorities = authorities or []
        self.details = details or {}
        self.authenticated = authenticated
        self.auth_type = auth_type

    def has_role(self, role_name: str) -> bool:
        return f"ROLE_{role_name}" in self.authorities

    def has_permission(self, perm_name: str) -> bool:
        return perm_name in self.authorities


class AuthenticationError(Exception):
    """认证失败异常"""
    pass


_security_context: ContextVar[Authentication | None] = ContextVar(
    'security_context', default=None
)


class SecurityContextHolder:
    """安全上下文持有者 — 协程级"""

    @staticmethod
    def get() -> Authentication | None:
        return _security_context.get()

    @staticmethod
    def set(auth: Authentication) -> None:
        _security_context.set(auth)

    @staticmethod
    def clear() -> None:
        _security_context.set(None)
