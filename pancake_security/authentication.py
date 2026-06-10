"""认证管理器 — 委托给多个 AuthenticationBackend"""

import logging
from abc import ABC, abstractmethod

from pancake_security.context import Authentication, AuthenticationError

logger = logging.getLogger(__name__)


class AuthenticationBackend(ABC):
    """可插拔认证后端接口"""

    @abstractmethod
    async def authenticate(self, token: Authentication) -> Authentication | None:
        """尝试认证，返回 None 表示不支持此类型"""

    @abstractmethod
    async def load_user(self, username: str) -> "User | None":
        """加载用户信息"""

    def supports(self, token: Authentication) -> bool:
        """是否支持此类型的认证"""
        return True


class AuthenticationManager:
    """认证管理器 — 依次尝试各 backend"""

    def __init__(self):
        self._backends: list[AuthenticationBackend] = []

    def add_backend(self, backend: AuthenticationBackend) -> None:
        self._backends.append(backend)

    async def authenticate(self, token: Authentication) -> Authentication:
        for backend in self._backends:
            if not backend.supports(token):
                continue
            try:
                result = await backend.authenticate(token)
                if result and result.authenticated:
                    logger.debug(f"认证成功: backend={backend.__class__.__name__}")
                    return result
            except Exception as e:
                logger.debug(f"Backend {backend.__class__.__name__} 认证失败: {e}")
                continue
        raise AuthenticationError("认证失败: 所有后端均未通过")
