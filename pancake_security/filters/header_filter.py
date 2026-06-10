"""安全响应头过滤器"""

import logging

logger = logging.getLogger(__name__)


class SecurityHeaderFilter:
    """安全响应头过滤器 — 最先执行"""

    DEFAULT_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }

    def __init__(self, config: dict = None):
        self.headers = dict(self.DEFAULT_HEADERS)
        if config:
            # 用户配置覆盖默认值
            for key, value in config.items():
                header_name = key.replace("_", "-").title().replace(" ", "-")
                # 特殊映射
                mapping = {
                    "X-Frame-Options": "X-Frame-Options",
                    "Content-Security-Policy": "Content-Security-Policy",
                    "X-Content-Type-Options": "X-Content-Type-Options",
                    "Strict-Transport-Security": "Strict-Transport-Security",
                }
                for k, v in mapping.items():
                    if k.lower().replace("-", "_") == key.lower().replace("-", "_"):
                        header_name = v
                        break
                self.headers[header_name] = value

    async def do_filter(self, request, handler):
        response = await handler(request)
        for name, value in self.headers.items():
            response.headers.setdefault(name, value)
        return response
