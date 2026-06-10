"""登录限流 / 防暴力破解"""

import logging
import time

logger = logging.getLogger(__name__)


class RateLimitFilter:
    """登录限流过滤器

    使用内存存储（可选 Redis），记录失败尝试次数。
    超过阈值后锁定一段时间。
    """

    def __init__(self, max_attempts: int = 5, window: int = 300,
                 lockout_time: int = 900, cache=None):
        self.max_attempts = max_attempts
        self.window = window
        self.lockout_time = lockout_time
        self._cache = cache  # 可选 Redis 客户端
        self._memory_store: dict[str, dict] = {}

    def _get_store(self, identifier: str) -> dict:
        if identifier not in self._memory_store:
            self._memory_store[identifier] = {"attempts": 0, "first_attempt": 0, "locked_until": 0}
        return self._memory_store[identifier]

    async def check_rate_limit(self, identifier: str) -> bool:
        """检查是否超过限流，返回 True 表示允许"""
        store = self._get_store(identifier)
        now = time.time()

        # 检查锁定
        if store["locked_until"] > now:
            remaining = int(store["locked_until"] - now)
            logger.warning(f"账号 {identifier} 已锁定，剩余 {remaining} 秒")
            return False

        # 窗口过期，重置
        if store["first_attempt"] and (now - store["first_attempt"]) > self.window:
            store["attempts"] = 0
            store["first_attempt"] = 0

        return store["attempts"] < self.max_attempts

    async def record_failure(self, identifier: str) -> None:
        """记录一次失败尝试"""
        store = self._get_store(identifier)
        now = time.time()

        if store["first_attempt"] == 0:
            store["first_attempt"] = now

        store["attempts"] += 1

        if store["attempts"] >= self.max_attempts:
            store["locked_until"] = now + self.lockout_time
            logger.warning(
                f"账号 {identifier} 已锁定 {self.lockout_time} 秒 "
                f"(连续 {store['attempts']} 次失败)"
            )

    async def reset(self, identifier: str) -> None:
        """登录成功后重置计数"""
        self._memory_store.pop(identifier, None)

    async def do_filter(self, request, handler):
        """过滤器入口 — 仅对登录路径生效"""
        # 限流检查在 AuthFilter 中按需调用，此处直接透传
        return await handler(request)
