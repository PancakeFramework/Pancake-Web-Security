"""JWT Token 认证后端"""

import logging
import time

from pancake_security.authentication import AuthenticationBackend
from pancake_security.context import Authentication

logger = logging.getLogger(__name__)


class JwtBackend(AuthenticationBackend):
    """JWT Token 认证后端

    依赖 PyJWT 库: pip install PyJWT
    """

    def __init__(self, secret: str, expire: int = 3600,
                 header: str = "Authorization", prefix: str = "Bearer",
                 user_loader=None):
        self._secret = secret
        self._expire = expire
        self._header = header
        self._prefix = prefix
        self._user_loader = user_loader  # async callable(username) -> User

    def _extract_token(self, auth_header: str) -> str | None:
        if not auth_header:
            return None
        if self._prefix:
            if auth_header.startswith(f"{self._prefix} "):
                return auth_header[len(self._prefix) + 1:]
            return None
        return auth_header

    async def authenticate(self, token: Authentication) -> Authentication | None:
        """验证 JWT token"""
        if token.auth_type != "jwt" and token.auth_type != "":
            return None

        jwt_token = token.credentials
        if not jwt_token:
            return None

        try:
            import jwt
            payload = jwt.decode(jwt_token, self._secret, algorithms=["HS256"])
        except Exception as e:
            logger.debug(f"JWT 解码失败: {e}")
            return None

        username = payload.get("sub")
        if not username:
            return None

        # 加载用户
        user = None
        if self._user_loader:
            user = await self._user_loader(username)

        authorities = payload.get("authorities", [])
        if user:
            authorities = user.get_authorities()

        return Authentication(
            principal=user or username,
            credentials=jwt_token,
            authorities=authorities,
            authenticated=True,
            auth_type="jwt",
            details={"payload": payload},
        )

    async def load_user(self, username: str):
        if self._user_loader:
            return await self._user_loader(username)
        return None

    def generate_token(self, username: str, authorities: list[str] = None) -> str:
        """生成 JWT token"""
        import jwt
        payload = {
            "sub": username,
            "authorities": authorities or [],
            "iat": int(time.time()),
            "exp": int(time.time()) + self._expire,
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")

    def supports(self, token: Authentication) -> bool:
        return token.auth_type in ("jwt", "")
