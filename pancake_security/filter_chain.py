"""安全过滤器链 — aiohttp middleware"""

import logging

from aiohttp import web

from pancake_security.filters.header_filter import SecurityHeaderFilter
from pancake_security.filters.csrf_filter import CsrfFilter
from pancake_security.filters.auth_filter import AuthFilter
from pancake_security.filters.rate_limit_filter import RateLimitFilter

logger = logging.getLogger(__name__)


class SecurityFilterChain:
    """安全过滤器链 — 作为 aiohttp middleware 执行

    过滤器执行顺序:
    1. SecurityHeaderFilter — 添加安全响应头
    2. CsrfFilter — CSRF token 验证
    3. AuthFilter — 从 Session/JWT 提取认证信息
    4. RateLimitFilter — 登录限流
    """

    def __init__(self, auth_manager, config: dict = None):
        config = config or {}
        self._filters = []

        # 1. 安全响应头
        headers_config = config.get("headers", {})
        self._filters.append(SecurityHeaderFilter(headers_config))

        # 2. CSRF
        csrf_config = config.get("csrf", {})
        if csrf_config.get("enabled", True):
            self._filters.append(CsrfFilter(
                token_name=csrf_config.get("token_name", "_csrf"),
                header_name=csrf_config.get("header_name", "X-CSRF-Token"),
                exempt_paths=csrf_config.get("exempt_paths", ["/api/**"]),
            ))

        # 3. 认证
        auth_config = config.get("auth", {})
        jwt_config = auth_config.get("jwt", {})
        self._filters.append(AuthFilter(
            auth_manager=auth_manager,
            jwt_header=jwt_config.get("header", "Authorization"),
            jwt_prefix=jwt_config.get("prefix", "Bearer"),
        ))

        # 4. 限流
        rate_config = config.get("rate_limit", {})
        if rate_config.get("enabled", True):
            self._filters.append(RateLimitFilter(
                max_attempts=rate_config.get("max_attempts", 5),
                window=rate_config.get("window", 300),
                lockout_time=rate_config.get("lockout_time", 900),
            ))

    async def do_filter(self, request, handler):
        """链式执行过滤器"""
        chain = handler
        for f in reversed(self._filters):
            chain = self._wrap(f, chain)
        return await chain(request)

    def _wrap(self, filter_obj, next_handler):
        async def wrapped(request):
            return await filter_obj.do_filter(request, next_handler)
        return wrapped
