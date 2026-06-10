# pancake-security

Spring Security 风格的 Pancake Web 安全模块插件，基于 aiohttp。

## 功能

- **认证**: 表单登录 / JWT Token / 两者并存
- **授权**: RBAC 角色权限 + 细粒度权限控制
- **CSRF 防护**: 自动生成/验证 CSRF Token
- **登录限流**: 防暴力破解，可配置锁定策略
- **安全响应头**: X-Frame-Options、CSP、HSTS 等
- **密码安全**: bcrypt / argon2 加密
- **可插拔后端**: 内存、JWT，可扩展数据库/LDAP/OAuth2

## 安装

```bash
pip install pancake-security
```

可选依赖:

```bash
pip install pancake-security[bcrypt]   # bcrypt 密码加密
pip install pancake-security[argon2]   # argon2 密码加密
```

## 快速开始

### 1. 配置 YAML

`src/resource/yaml/security.yaml`:

```yaml
security:
  enabled: true
  auth:
    type: form
  password:
    encoder: bcrypt
    bcrypt_rounds: 12
  csrf:
    enabled: true
    exempt_paths:
      - "/api/**"
  rate_limit:
    enabled: true
    max_attempts: 5
    window: 300
  headers:
    x_frame_options: "DENY"
    content_security_policy: "default-src 'self'"
```

### 2. 使用装饰器保护路由

```python
from pancake_security import has_role, has_permission, secured, authenticated_user

@controller("/api/users")
class UserController:
    auth_manager: AuthenticationManager = inject()
    password_encoder: PasswordEncoder = inject()

    @post("/login")
    async def login(self, body: LoginForm = request_body()):
        auth = Authentication(
            principal=body.username,
            credentials=body.password,
            auth_type="form"
        )
        result = await self.auth_manager.authenticate(auth)
        SecurityContextHolder.set(result)
        return {"msg": "登录成功"}

    @get("/me")
    @has_role("USER")
    async def me(self, user: User = authenticated_user()):
        return {"username": user.username, "roles": [r.name for r in user.roles]}

    @delete("/{id}")
    @has_permission("user:delete")
    async def delete_user(self, id: int = path_variable()):
        # 删除用户...

@controller("/api/admin")
class AdminController:
    @get("/dashboard")
    @has_role("ADMIN")
    async def dashboard(self):
        return {"msg": "Admin Dashboard"}

    @get("/users")
    @secured(roles=["ADMIN"], permissions=["user:list"])
    async def list_users(self):
        return [...]
```

## 核心概念

| Spring Security | pancake-security | 说明 |
|---|---|---|
| `SecurityContext` | `SecurityContext` | 协程级安全上下文（contextvars） |
| `Authentication` | `Authentication` | 认证凭证/已认证对象 |
| `AuthenticationManager` | `AuthenticationManager` | 认证管理器，委托给多个 Backend |
| `UserDetailsService` | `AuthenticationBackend` | 可插拔认证后端接口 |
| `PasswordEncoder` | `PasswordEncoder` | bcrypt/argon2 密码加密 |
| `FilterChain` | `SecurityFilterChain` | 安全过滤器链 |
| `@PreAuthorize` | `@has_role` / `@has_permission` | 路由级权限装饰器 |

## 配置项

| 配置键 | 类型 | 缺省值 | 说明 |
|--------|------|--------|------|
| `security.enabled` | bool | `true` | 启用安全模块 |
| `security.auth.type` | str | `form` | 认证类型: form / jwt / both |
| `security.auth.jwt.secret` | str | - | JWT 签名密钥 |
| `security.auth.jwt.expire` | int | `3600` | JWT 过期时间（秒） |
| `security.password.encoder` | str | `bcrypt` | 密码加密器: bcrypt / argon2 / plain |
| `security.password.bcrypt_rounds` | int | `12` | bcrypt 加密轮数 |
| `security.csrf.enabled` | bool | `true` | 启用 CSRF 防护 |
| `security.csrf.token_name` | str | `_csrf` | CSRF token 参数名 |
| `security.csrf.header_name` | str | `X-CSRF-Token` | CSRF token 请求头 |
| `security.csrf.exempt_paths` | list | `["/api/**"]` | CSRF 豁免路径 |
| `security.rate_limit.enabled` | bool | `true` | 启用登录限流 |
| `security.rate_limit.max_attempts` | int | `5` | 最大失败尝试次数 |
| `security.rate_limit.window` | int | `300` | 统计窗口（秒） |
| `security.rate_limit.lockout_time` | int | `900` | 锁定时长（秒） |
| `security.headers.*` | str | - | 安全响应头覆盖 |

## 装饰器

| 装饰器 | 用途 |
|--------|------|
| `@has_role("ADMIN")` | 需要指定角色 |
| `@has_permission("user:delete")` | 需要指定权限 |
| `@secured(roles=[...], permissions=[...])` | 组合权限 |
| `authenticated_user()` | 参数绑定：注入当前已认证用户 |

## 过滤器链

请求处理顺序:

```
SecurityFilterChain (order=-100)
  -> SecurityHeaderFilter: 添加安全响应头
  -> CsrfFilter: CSRF token 验证
  -> AuthFilter: 从 Session/JWT 提取认证信息
  -> RateLimitFilter: 登录限流检查
AuthorizationMiddleware (order=-50)
  -> 检查 @has_role / @has_permission 装饰器标记
Route Handler
```

## 扩展认证后端

实现 `AuthenticationBackend` 接口即可:

```python
from pancake_security.authentication import AuthenticationBackend
from pancake_security.context import Authentication

class MyBackend(AuthenticationBackend):
    async def authenticate(self, token: Authentication) -> Authentication | None:
        # 验证逻辑...
        return Authentication(principal=user, authenticated=True, ...)

    async def load_user(self, username: str) -> User | None:
        # 加载用户...
        return user
```

## License

MIT
