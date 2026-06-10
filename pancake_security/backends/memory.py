"""内存认证后端 — 开发测试用"""

import logging

from pancake_security.authentication import AuthenticationBackend
from pancake_security.context import Authentication
from pancake_security.user import User, Role, Permission

logger = logging.getLogger(__name__)


class MemoryBackend(AuthenticationBackend):
    """内存认证后端

    用户数据从 YAML 配置加载，适合开发和测试。
    """

    def __init__(self, users: dict = None, password_encoder=None):
        self._users: dict[str, User] = {}
        self._password_encoder = password_encoder
        if users:
            for username, info in users.items():
                roles = []
                for role_name in info.get("roles", []):
                    perms = [Permission(name=p) for p in info.get("permissions", [])]
                    roles.append(Role(name=role_name, permissions=perms))
                self._users[username] = User(
                    username=username,
                    password=info.get("password", ""),
                    roles=roles,
                    enabled=info.get("enabled", True),
                )

    async def authenticate(self, token: Authentication) -> Authentication | None:
        if token.auth_type not in ("form", ""):
            return None

        username = token.principal
        password = token.credentials

        user = self._users.get(username)
        if not user:
            logger.debug(f"用户不存在: {username}")
            return None

        if not user.enabled:
            logger.debug(f"用户已禁用: {username}")
            return None

        # 验证密码
        if self._password_encoder:
            if not self._password_encoder.verify(password, user.password):
                return None
        elif user.password != password:
            return None

        return Authentication(
            principal=user,
            credentials="",
            authorities=user.get_authorities(),
            authenticated=True,
            auth_type="form",
        )

    async def load_user(self, username: str) -> User | None:
        return self._users.get(username)
