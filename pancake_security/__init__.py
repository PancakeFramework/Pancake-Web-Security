"""Pancake Security 插件 — Spring Security 风格的安全模块

提供认证、授权、CSRF 防护、登录限流、安全响应头、密码安全。
"""

import inspect
import logging

from aiohttp import web
from pancake.ovenware import InitAction

logger = logging.getLogger(__name__)


class Main(InitAction):
    """Security 插件入口

    init_order=52, 在 web(50) 和 web-template(51) 之后加载。
    """

    init_order = 52
    build_order = 0

    def __init__(self):
        from pancake.registry import export
        from pancake import settings

        # 读取配置
        from pancake_security.config import SecurityConfig
        raw_config = settings.get("security") or {}
        self.config = SecurityConfig(raw_config)

        if not self.config.enabled:
            logger.info("Security 插件已禁用")
            return

        # ── 创建密码加密器 ──────────────────────────
        from pancake_security.password import create_encoder
        self.password_encoder = create_encoder(
            self.config.password_encoder,
            rounds=self.config.bcrypt_rounds,
        )

        # ── 创建认证后端 ──────────────────────────
        from pancake_security.authentication import AuthenticationManager
        self.auth_manager = AuthenticationManager()

        # 根据配置添加后端
        auth_type = self.config.auth_type

        if auth_type in ("form", "both"):
            from pancake_security.backends.memory import MemoryBackend
            memory_backend = MemoryBackend(
                users=self.config.memory_users,
                password_encoder=self.password_encoder,
            )
            self.auth_manager.add_backend(memory_backend)

        if auth_type in ("jwt", "both"):
            from pancake_security.backends.jwt import JwtBackend
            jwt_config = self.config.jwt_config
            jwt_backend = JwtBackend(
                secret=jwt_config.get("secret", "change-me"),
                expire=jwt_config.get("expire", 3600),
                header=jwt_config.get("header", "Authorization"),
                prefix=jwt_config.get("prefix", "Bearer"),
            )
            self.auth_manager.add_backend(jwt_backend)

        # ── 创建过滤器链 ──────────────────────────
        from pancake_security.filter_chain import SecurityFilterChain
        self.filter_chain = SecurityFilterChain(
            auth_manager=self.auth_manager,
            config=self.config.to_dict(),
        )

        # ── 注册中间件 ──────────────────────────
        self._register_middlewares(export)

        # ── 导出装饰器和工具 ──────────────────────
        from pancake_security.decorators import (
            secured, has_role, has_permission, authenticated_user
        )
        export(secured)
        export(has_role)
        export(has_permission)
        export(authenticated_user)

        # ── 导出核心类 ──────────────────────────
        from pancake_security.context import Authentication, SecurityContextHolder
        from pancake_security.user import User, Role, Permission
        from pancake_security.authentication import AuthenticationManager, AuthenticationError
        from pancake_security.password import PasswordEncoder
        export(Authentication)
        export(SecurityContextHolder)
        export(User)
        export(Role)
        export(Permission)
        export(AuthenticationManager)
        export(AuthenticationError)
        export(PasswordEncoder)

        # ── 注册到 oven ──────────────────────────
        from pancake import oven
        oven.pancake_other["security_config"] = self.config
        oven.pancake_other["auth_manager"] = self.auth_manager
        oven.pancake_other["password_encoder"] = self.password_encoder

        # ── 猴子补丁: 扩展 resolve_handler_args ──
        self._patch_resolve_handler_args()

        logger.info("Security 插件已加载")

    def _register_middlewares(self, export):
        """注册安全中间件"""
        filter_chain = self.filter_chain
        auth_manager = self.auth_manager

        # SecurityFilterChain (order=-100)
        @export
        def security_filter_chain():
            pass

        # 通过 middleware 注册
        from pancake_web.middleware import _middleware_registry

        # SecurityFilterChain middleware
        _middleware_registry.append((-100, _SecurityFilterChainMiddleware(filter_chain)))

        # AuthorizationMiddleware
        from pancake_security.authorization import AuthorizationMiddleware
        _middleware_registry.append((-50, AuthorizationMiddleware()))

        logger.info("安全中间件已注册")

    def _patch_resolve_handler_args(self):
        """猴子补丁: 扩展 web 的 resolve_handler_args，支持 authenticated_user()"""
        import pancake_web.decorators as web_decorators
        from pancake_security.decorators import _AuthenticatedUserMarker
        from pancake_security.context import SecurityContextHolder

        _original_resolve = web_decorators.resolve_handler_args

        async def _patched_resolve(request, handler):
            kwargs = await _original_resolve(request, handler)
            sig = inspect.signature(handler)
            for pname, param in sig.parameters.items():
                if isinstance(param.default, _AuthenticatedUserMarker):
                    auth = SecurityContextHolder.get()
                    if not auth or not auth.authenticated:
                        raise web.HTTPUnauthorized(reason="未认证")
                    kwargs[pname] = auth.principal
            return kwargs

        web_decorators.resolve_handler_args = _patched_resolve
        logger.info("已扩展 resolve_handler_args (authenticated_user)")

    def check(self) -> bool:
        return True

    def build(self):
        logger.info("Security 插件构建完成")


class _SecurityFilterChainMiddleware:
    """包装 SecurityFilterChain 为 aiohttp middleware"""

    def __init__(self, filter_chain):
        self._filter_chain = filter_chain

    async def process(self, request, handler):
        return await self._filter_chain.do_filter(request, handler)
