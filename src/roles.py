"""参与方角色与信息访问边界。

广告主、制作机构、平台审核、渠道运营只能处理职责内的信息。
角色到可见信息域的映射是领域规则，不依赖具体调用方。
"""

from __future__ import annotations

import enum


class Role(enum.Enum):
    ADVERTISER = "广告主"
    PRODUCER = "内容制作机构"
    PLATFORM_REVIEWER = "平台审核人员"
    CHANNEL_OPERATOR = "渠道运营人员"
    AUDITOR = "审计人员"


# 各角色在职责内可见的信息域
SCOPES: dict[Role, frozenset[str]] = {
    Role.ADVERTISER: frozenset(
        {
            "project",
            "qualification",
            "script",
            "review",
            "release",
            "provenance",
            "liability",
            "freeze",
        }
    ),
    Role.PRODUCER: frozenset({"project", "script", "avatar", "derivative", "review"}),
    Role.PLATFORM_REVIEWER: frozenset(
        {
            "project",
            "qualification",
            "script",
            "avatar",
            "derivative",
            "review",
            "release",
            "provenance",
            "liability",
            "freeze",
        }
    ),
    Role.CHANNEL_OPERATOR: frozenset({"project", "release", "traffic", "channel"}),
    Role.AUDITOR: frozenset(
        {
            "project",
            "qualification",
            "script",
            "avatar",
            "derivative",
            "review",
            "release",
            "traffic",
            "channel",
            "provenance",
            "liability",
            "freeze",
            "audit",
        }
    ),
}

# 信息域中文名，供越权报错使用
SCOPE_LABELS = {
    "project": "项目立项",
    "qualification": "产品资质",
    "script": "脚本",
    "avatar": "数字人身份",
    "derivative": "素材衍生版本",
    "review": "审核意见",
    "release": "放行决定",
    "traffic": "购买流量",
    "channel": "发布渠道",
    "provenance": "素材谱系",
    "liability": "责任归属",
    "freeze": "冻结状态",
    "audit": "审计重放",
}


class AccessDeniedError(PermissionError):
    """角色访问了职责之外的信息域。"""


def assert_can_access(role: Role, scope: str) -> None:
    """校验角色是否可访问某信息域。"""
    allowed = SCOPES.get(role, frozenset())
    if scope not in allowed:
        label = SCOPE_LABELS.get(scope, scope)
        raise AccessDeniedError(f"{role.value}无权访问{label}")
