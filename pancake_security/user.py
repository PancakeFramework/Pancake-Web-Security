"""用户、角色、权限模型"""

from dataclasses import dataclass, field


@dataclass
class Permission:
    name: str           # "user:delete"
    description: str = ""


@dataclass
class Role:
    name: str           # "ADMIN"
    permissions: list[Permission] = field(default_factory=list)


@dataclass
class User:
    username: str
    password: str = ""
    roles: list[Role] = field(default_factory=list)
    enabled: bool = True
    account_locked: bool = False
    extra: dict = field(default_factory=dict)

    def has_role(self, role_name: str) -> bool:
        return any(r.name == role_name for r in self.roles)

    def has_permission(self, perm_name: str) -> bool:
        for role in self.roles:
            if any(p.name == perm_name for p in role.permissions):
                return True
        return False

    def get_authorities(self) -> list[str]:
        """获取所有权限标识: ["ROLE_ADMIN", "user:delete", ...]"""
        authorities = []
        for role in self.roles:
            authorities.append(f"ROLE_{role.name}")
            for perm in role.permissions:
                authorities.append(perm.name)
        return authorities
