"""权限检查中间件"""

import logging

from aiohttp import web
from pancake_security.context import SecurityContextHolder

logger = logging.getLogger(__name__)


class AuthorizationMiddleware:
    """权限检查中间件 — 在认证之后、业务处理之前执行

    order=-50，确保在 SecurityFilterChain(order=-100) 之后执行。
    检查 handler 上的 _required_roles / _required_permissions 装饰器标记。
    """

    async def process(self, request, handler):
        # 从 aiohttp handler 上获取原始 handler 的装饰器标记
        original = getattr(handler, '_original_handler', None)
        if not original:
            return await handler(request)

        required_roles = getattr(original, '_required_roles', None)
        required_perms = getattr(original, '_required_permissions', None)

        if not required_roles and not required_perms:
            return await handler(request)

        auth = SecurityContextHolder.get()
        if not auth or not auth.authenticated:
            logger.warning(f"未认证访问受保护资源: {request.method} {request.path}")
            raise web.HTTPUnauthorized(reason="未认证")

        user = auth.principal
        if required_roles:
            # user 可能是 User 对象或字符串
            has_role = False
            if hasattr(user, 'has_role'):
                has_role = any(user.has_role(r) for r in required_roles)
            else:
                has_role = any(auth.has_role(r) for r in required_roles)
            if not has_role:
                logger.warning(f"权限不足(角色): {request.method} {request.path}, 需要 {required_roles}")
                raise web.HTTPForbidden(reason=f"需要角色: {required_roles}")

        if required_perms:
            has_perm = False
            if hasattr(user, 'has_permission'):
                has_perm = any(user.has_permission(p) for p in required_perms)
            else:
                has_perm = any(auth.has_permission(p) for p in required_perms)
            if not has_perm:
                logger.warning(f"权限不足(权限): {request.method} {request.path}, 需要 {required_perms}")
                raise web.HTTPForbidden(reason=f"需要权限: {required_perms}")

        return await handler(request)
