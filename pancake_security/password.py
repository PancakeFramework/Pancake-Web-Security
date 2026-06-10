"""密码加密器 — bcrypt / argon2"""

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class PasswordEncoder(ABC):
    """密码加密器接口"""

    @abstractmethod
    def encode(self, raw_password: str) -> str:
        """加密密码"""

    @abstractmethod
    def verify(self, raw_password: str, encoded: str) -> bool:
        """验证密码"""


class BcryptEncoder(PasswordEncoder):
    """bcrypt 密码加密器"""

    def __init__(self, rounds: int = 12):
        self._rounds = rounds

    def encode(self, raw_password: str) -> str:
        import bcrypt
        return bcrypt.hashpw(
            raw_password.encode("utf-8"),
            bcrypt.gensalt(rounds=self._rounds)
        ).decode("utf-8")

    def verify(self, raw_password: str, encoded: str) -> bool:
        import bcrypt
        try:
            return bcrypt.checkpw(
                raw_password.encode("utf-8"),
                encoded.encode("utf-8")
            )
        except Exception:
            return False


class Argon2Encoder(PasswordEncoder):
    """argon2 密码加密器"""

    def encode(self, raw_password: str) -> str:
        from argon2 import PasswordHasher
        return PasswordHasher().hash(raw_password)

    def verify(self, raw_password: str, encoded: str) -> bool:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError
        try:
            return PasswordHasher().verify(encoded, raw_password)
        except (VerifyMismatchError, Exception):
            return False


class PlainEncoder(PasswordEncoder):
    """明文密码（仅用于开发测试，生产环境禁止使用）"""

    def encode(self, raw_password: str) -> str:
        logger.warning("使用明文密码存储，仅限开发环境!")
        return raw_password

    def verify(self, raw_password: str, encoded: str) -> bool:
        return raw_password == encoded


def create_encoder(encoder_type: str = "bcrypt", **kwargs) -> PasswordEncoder:
    """工厂方法: 根据类型创建密码加密器"""
    if encoder_type == "bcrypt":
        return BcryptEncoder(rounds=kwargs.get("rounds", 12))
    elif encoder_type == "argon2":
        return Argon2Encoder()
    elif encoder_type == "plain":
        return PlainEncoder()
    else:
        raise ValueError(f"不支持的密码加密器: {encoder_type}")
