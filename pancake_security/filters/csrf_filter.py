"""CSRF 防护过滤器"""

import hashlib
import hmac
import logging
import secrets
import fnmatch

from aiohttp import web

logger = logging.getLogger(__name__)


class CsrfFilter:
    """CSRF 防护过滤器

    - GET/HEAD/OPTIONS 不检查
    - 豁免路径（如 /api/**）不检查
    - 验证请求中的 CSRF token 与 session 中的一致
    """

    def __init__(self, token_name: str = "_csrf",
                 header_name: str = "X-CSRF-Token",
                 exempt_paths: list[str] = None):
        self.token_name = token_name
        self.header_name = header_name
        self.exempt_paths = exempt_paths or ["/api/**"]

    def _is_exempt(self, path: str) -> bool:
        for pattern in self.exempt_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def generate_token(self) -> str:
        """生成 CSRF token"""
        return secrets.token_hex(32)

    def _verify_token(self, request, token: str | None) -> bool:
        """验证 CSRF token"""
        if not token:
            return False
        session = request.get("session") or {}
        expected = session.get("csrf_token")
        if not expected:
            # 无 session token，可能是首次请求，放行
            return True
        return hmac.compare_digest(token, expected)

    async def do_filter(self, request, handler):
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return await handler(request)

        if self._is_exempt(request.path):
            return await handler(request)

        # 从 header 或 body 获取 token
        token = request.headers.get(self.header_name)
        if not token:
            try:
                post = await request.post()
                token = post.get(self.token_name)
            except Exception:
                pass

        if not self._verify_token(request, token):
            logger.warning(f"CSRF token 验证失败: {request.method} {request.path}")
            raise web.HTTPForbidden(reason="CSRF token 验证失败")

        return await handler(request)
