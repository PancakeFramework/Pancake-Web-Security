"""认证过滤器 — 从请求中提取身份并设入 SecurityContext"""

import logging

from pancake_security.context import Authentication, SecurityContextHolder

logger = logging.getLogger(__name__)


class AuthFilter:
    """认证过滤器

    提取顺序: Session → JWT Header → 不设置（匿名）
    """

    def __init__(self, auth_manager, jwt_header: str = "Authorization",
                 jwt_prefix: str = "Bearer"):
        self._auth_manager = auth_manager
        self._jwt_header = jwt_header
        self._jwt_prefix = jwt_prefix

    def _extract_from_session(self, request) -> Authentication | None:
        """从 Session 提取已认证信息"""
        session = request.get("session")
        if not session:
            return None
        auth_data = session.get("security:auth")
        if not auth_data:
            return None
        if isinstance(auth_data, dict):
            return Authentication(
                principal=auth_data.get("principal"),
                authorities=auth_data.get("authorities", []),
                authenticated=auth_data.get("authenticated", False),
                auth_type=auth_data.get("auth_type", "session"),
            )
        return None

    def _extract_jwt_token(self, request) -> str | None:
        """从请求头提取 JWT token"""
        header = request.headers.get(self._jwt_header, "")
        if self._jwt_prefix and header.startswith(f"{self._jwt_prefix} "):
            return header[len(self._jwt_prefix) + 1:]
        elif not self._jwt_prefix and header:
            return header
        return None

    async def do_filter(self, request, handler):
        auth = None

        # 1. 尝试从 Session 提取
        auth = self._extract_from_session(request)

        # 2. 尝试从 JWT 提取
        if not auth:
            jwt_token = self._extract_jwt_token(request)
            if jwt_token:
                try:
                    token = Authentication(
                        credentials=jwt_token,
                        auth_type="jwt",
                    )
                    auth = await self._auth_manager.authenticate(token)
                except Exception as e:
                    logger.debug(f"JWT 认证失败: {e}")

        # 3. 设入 SecurityContext
        if auth:
            SecurityContextHolder.set(auth)

        try:
            return await handler(request)
        finally:
            SecurityContextHolder.clear()
