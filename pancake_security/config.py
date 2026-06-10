"""SecurityConfig — 安全配置"""


class SecurityConfig:
    """安全配置 — 从 YAML 加载"""

    def __init__(self, raw_config: dict = None):
        config = raw_config or {}
        self.enabled = config.get("enabled", True)

        # Auth
        auth = config.get("auth", {})
        self.auth_type = auth.get("type", "form")
        self.form_config = auth.get("form", {})
        self.jwt_config = auth.get("jwt", {})

        # Password
        pwd = config.get("password", {})
        self.password_encoder = pwd.get("encoder", "bcrypt")
        self.bcrypt_rounds = pwd.get("bcrypt_rounds", 12)

        # CSRF
        csrf = config.get("csrf", {})
        self.csrf_enabled = csrf.get("enabled", True)
        self.csrf_token_name = csrf.get("token_name", "_csrf")
        self.csrf_header_name = csrf.get("header_name", "X-CSRF-Token")
        self.csrf_exempt_paths = csrf.get("exempt_paths", ["/api/**"])

        # Rate limit
        rl = config.get("rate_limit", {})
        self.rate_limit_enabled = rl.get("enabled", True)
        self.rate_limit_max = rl.get("max_attempts", 5)
        self.rate_limit_window = rl.get("window", 300)
        self.rate_limit_lockout = rl.get("lockout_time", 900)

        # Headers
        self.headers_config = config.get("headers", {})

        # OAuth2
        self.oauth2_config = config.get("oauth2", {})

        # LDAP
        self.ldap_config = config.get("ldap", {})

        # Memory users (for development)
        self.memory_users = config.get("users", {})

    def to_dict(self) -> dict:
        """导出为字典，供 FilterChain 使用"""
        return {
            "enabled": self.enabled,
            "auth": {
                "type": self.auth_type,
                "form": self.form_config,
                "jwt": self.jwt_config,
            },
            "password": {
                "encoder": self.password_encoder,
                "bcrypt_rounds": self.bcrypt_rounds,
            },
            "csrf": {
                "enabled": self.csrf_enabled,
                "token_name": self.csrf_token_name,
                "header_name": self.csrf_header_name,
                "exempt_paths": self.csrf_exempt_paths,
            },
            "rate_limit": {
                "enabled": self.rate_limit_enabled,
                "max_attempts": self.rate_limit_max,
                "window": self.rate_limit_window,
                "lockout_time": self.rate_limit_lockout,
            },
            "headers": self.headers_config,
        }
