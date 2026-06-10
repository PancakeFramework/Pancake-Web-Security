"""pancake-security 插件测试"""

import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_user_model():
    """测试 User/Role/Permission 模型"""
    from pancake_security.user import User, Role, Permission

    perm1 = Permission(name="user:delete", description="删除用户")
    perm2 = Permission(name="user:edit", description="编辑用户")
    admin_role = Role(name="ADMIN", permissions=[perm1, perm2])
    user_role = Role(name="USER", permissions=[])

    user = User(
        username="alice",
        password="hashed",
        roles=[admin_role, user_role],
        enabled=True,
    )

    assert user.has_role("ADMIN") is True
    assert user.has_role("USER") is True
    assert user.has_role("GUEST") is False
    assert user.has_permission("user:delete") is True
    assert user.has_permission("user:edit") is True
    assert user.has_permission("user:list") is False

    authorities = user.get_authorities()
    assert "ROLE_ADMIN" in authorities
    assert "ROLE_USER" in authorities
    assert "user:delete" in authorities
    assert "user:edit" in authorities

    print("[PASS] test_user_model")


def test_authentication():
    """测试 Authentication 对象"""
    from pancake_security.context import Authentication

    auth = Authentication(
        principal="alice",
        credentials="token123",
        authorities=["ROLE_ADMIN", "user:delete"],
        authenticated=True,
        auth_type="jwt",
    )

    assert auth.principal == "alice"
    assert auth.authenticated is True
    assert auth.has_role("ADMIN") is True
    assert auth.has_role("USER") is False
    assert auth.has_permission("user:delete") is True

    print("[PASS] test_authentication")


def test_security_context_holder():
    """测试 SecurityContextHolder"""
    from pancake_security.context import SecurityContextHolder, Authentication

    # 初始为空
    assert SecurityContextHolder.get() is None

    # 设置
    auth = Authentication(principal="bob", authenticated=True)
    SecurityContextHolder.set(auth)
    assert SecurityContextHolder.get() is not None
    assert SecurityContextHolder.get().principal == "bob"

    # 清除
    SecurityContextHolder.clear()
    assert SecurityContextHolder.get() is None

    print("[PASS] test_security_context_holder")


def test_decorators():
    """测试权限装饰器"""
    from pancake_security.decorators import has_role, has_permission, secured

    @has_role("ADMIN", "MODERATOR")
    def admin_handler():
        pass

    @has_permission("user:delete")
    def delete_handler():
        pass

    @secured(roles=["ADMIN"], permissions=["user:delete"])
    def secured_handler():
        pass

    assert hasattr(admin_handler, '_required_roles')
    assert "ADMIN" in admin_handler._required_roles
    assert "MODERATOR" in admin_handler._required_roles

    assert hasattr(delete_handler, '_required_permissions')
    assert "user:delete" in delete_handler._required_permissions

    assert hasattr(secured_handler, '_required_roles')
    assert hasattr(secured_handler, '_required_permissions')
    assert "ADMIN" in secured_handler._required_roles
    assert "user:delete" in secured_handler._required_permissions

    print("[PASS] test_decorators")


def test_authenticated_user_marker():
    """测试 authenticated_user 标记"""
    from pancake_security.decorators import authenticated_user, _AuthenticatedUserMarker

    marker = authenticated_user()
    assert isinstance(marker, _AuthenticatedUserMarker)

    print("[PASS] test_authenticated_user_marker")


def test_password_encoder_plain():
    """测试明文密码加密器"""
    from pancake_security.password import PlainEncoder

    encoder = PlainEncoder()
    encoded = encoder.encode("mypassword")
    assert encoded == "mypassword"
    assert encoder.verify("mypassword", encoded) is True
    assert encoder.verify("wrong", encoded) is False

    print("[PASS] test_password_encoder_plain")


def test_password_encoder_factory():
    """测试密码加密器工厂"""
    from pancake_security.password import create_encoder, BcryptEncoder, PlainEncoder

    encoder = create_encoder("plain")
    assert isinstance(encoder, PlainEncoder)

    try:
        encoder = create_encoder("bcrypt")
        assert isinstance(encoder, BcryptEncoder)
        print("[PASS] test_password_encoder_factory (with bcrypt)")
    except ImportError:
        print("[SKIP] test_password_encoder_factory (bcrypt not installed)")


def test_security_config():
    """测试 SecurityConfig"""
    from pancake_security.config import SecurityConfig

    config = SecurityConfig({
        "enabled": True,
        "auth": {"type": "jwt"},
        "csrf": {"enabled": False},
        "rate_limit": {"max_attempts": 3},
    })

    assert config.enabled is True
    assert config.auth_type == "jwt"
    assert config.csrf_enabled is False
    assert config.rate_limit_max == 3

    d = config.to_dict()
    assert d["auth"]["type"] == "jwt"
    assert d["csrf"]["enabled"] is False

    print("[PASS] test_security_config")


def test_memory_backend():
    """测试内存认证后端"""
    from pancake_security.backends.memory import MemoryBackend
    from pancake_security.context import Authentication

    backend = MemoryBackend(users={
        "alice": {"password": "pass123", "roles": ["ADMIN"]},
        "bob": {"password": "pass456", "roles": ["USER"]},
    })

    # 测试认证成功
    token = Authentication(principal="alice", credentials="pass123", auth_type="form")
    result = asyncio.run(backend.authenticate(token))
    assert result is not None
    assert result.authenticated is True
    assert result.principal.username == "alice"
    assert result.principal.has_role("ADMIN") is True

    # 测试密码错误
    token = Authentication(principal="alice", credentials="wrong", auth_type="form")
    result = asyncio.run(backend.authenticate(token))
    assert result is None

    # 测试用户不存在
    token = Authentication(principal="unknown", credentials="pass", auth_type="form")
    result = asyncio.run(backend.authenticate(token))
    assert result is None

    # 测试 load_user
    user = asyncio.run(backend.load_user("bob"))
    assert user is not None
    assert user.username == "bob"

    print("[PASS] test_memory_backend")


def test_jwt_backend():
    """测试 JWT 后端"""
    try:
        import jwt as pyjwt
    except ImportError:
        print("[SKIP] test_jwt_backend (PyJWT not installed)")
        return

    from pancake_security.backends.jwt import JwtBackend
    from pancake_security.context import Authentication

    backend = JwtBackend(secret="test-secret", expire=3600)

    # 生成 token
    token_str = backend.generate_token("alice", authorities=["ROLE_ADMIN"])
    assert token_str is not None

    # 验证 token
    token = Authentication(credentials=token_str, auth_type="jwt")
    result = asyncio.run(backend.authenticate(token))
    assert result is not None
    assert result.authenticated is True
    assert result.principal == "alice"

    # 验证无效 token
    token = Authentication(credentials="invalid-token", auth_type="jwt")
    result = asyncio.run(backend.authenticate(token))
    assert result is None

    print("[PASS] test_jwt_backend")


def test_rate_limit_filter():
    """测试登录限流"""
    from pancake_security.filters.rate_limit_filter import RateLimitFilter

    rl = RateLimitFilter(max_attempts=3, window=60, lockout_time=300)

    # 初始允许
    assert asyncio.run(rl.check_rate_limit("alice")) is True

    # 记录失败
    asyncio.run(rl.record_failure("alice"))
    assert asyncio.run(rl.check_rate_limit("alice")) is True

    asyncio.run(rl.record_failure("alice"))
    assert asyncio.run(rl.check_rate_limit("alice")) is True

    asyncio.run(rl.record_failure("alice"))
    # 第 3 次后锁定
    assert asyncio.run(rl.check_rate_limit("alice")) is False

    # 重置
    asyncio.run(rl.reset("alice"))
    assert asyncio.run(rl.check_rate_limit("alice")) is True

    print("[PASS] test_rate_limit_filter")


def test_csrf_filter():
    """测试 CSRF 过滤器"""
    from pancake_security.filters.csrf_filter import CsrfFilter

    csrf = CsrfFilter(exempt_paths=["/api/**"])

    assert csrf._is_exempt("/api/users") is True
    assert csrf._is_exempt("/api/v1/login") is True
    assert csrf._is_exempt("/login") is False
    assert csrf._is_exempt("/admin/settings") is False

    token = csrf.generate_token()
    assert len(token) == 64  # 32 bytes hex

    print("[PASS] test_csrf_filter")


if __name__ == "__main__":
    test_user_model()
    test_authentication()
    test_security_context_holder()
    test_decorators()
    test_authenticated_user_marker()
    test_password_encoder_plain()
    test_password_encoder_factory()
    test_security_config()
    test_memory_backend()
    test_jwt_backend()
    test_rate_limit_filter()
    test_csrf_filter()
    print("\n[OK] 全部测试通过")
