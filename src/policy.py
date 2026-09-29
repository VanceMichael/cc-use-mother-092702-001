"""发布门禁策略：把素材状态归约为一组可追溯的核查结论。

结论按依赖基（basis）区分：
- 产品资质结论依赖资质登记；
- 身份授权结论依赖数字人版本；
- 商品事实结论依赖脚本版本与资质事实。

衍生版本与父版本依赖基一致的结论直接继承（保留来源结论序号与证据），
只有依赖基变化的结论需要重算，从而做到“只重算受影响的结论”。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .roles import Role

QUALIFICATION = "qualification_verified"
IDENTITY_AUTH = "identity_authorization_verified"
PROVABLE_FACTS = "provable_facts_verified"

SYSTEM_CODES = (QUALIFICATION, IDENTITY_AUTH, PROVABLE_FACTS)

# 结论依赖基：键为结论代码，值为受何种输入变化影响
# （换数字人只动身份授权；改脚本只动商品事实）
CODE_SCOPE_LABELS = {
    QUALIFICATION: "产品资质",
    IDENTITY_AUTH: "数字人身份授权",
    PROVABLE_FACTS: "可证明商品事实",
}


@dataclass(frozen=True)
class Check:
    code: str
    passed: bool
    detail: str
    basis: tuple[Any, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class GateResult:
    passed: bool
    failures: tuple[dict[str, str], ...]


def required_codes(project: dict[str, Any], material: dict[str, Any] | None = None) -> tuple[str, ...]:
    codes = [QUALIFICATION, PROVABLE_FACTS]
    uses_avatar = bool(material and material.get("avatar_version"))
    if project["medical"] or uses_avatar:
        codes.insert(1, IDENTITY_AUTH)
    return tuple(codes)


def _qualification_basis(state: dict[str, Any], project_id: str) -> tuple[Any, ...] | None:
    qualification = state["qualifications"].get(project_id)
    if qualification is None:
        return None
    return ("qualification", qualification["seq"])


def compute_check(
    code: str,
    state: dict[str, Any],
    project_id: str,
    material: dict[str, Any],
    now: float,
) -> Check:
    """计算单个系统核查结论。"""
    project = state["projects"][project_id]
    qualification = state["qualifications"].get(project_id)

    if code == QUALIFICATION:
        if qualification is None:
            return Check(code, False, "尚未登记产品资质", ("qualification",))
        facts = qualification["facts"]
        missing_proof = sorted(
            fact_id
            for fact_id, fact in facts.items()
            if not fact.get("proof_ref") or not fact.get("proof_hash")
        )
        if missing_proof:
            return Check(
                code,
                False,
                f"产品事实缺少证明材料: {','.join(missing_proof)}",
                ("qualification", qualification["seq"]),
            )
        return Check(code, True, f"已核验{len(facts)}项产品事实", ("qualification", qualification["seq"]))

    if code == IDENTITY_AUTH:
        avatar_version = material.get("avatar_version")
        avatar = None
        if avatar_version is not None:
            avatar = state["avatars"].get(project_id, {}).get(avatar_version)
        if avatar is None:
            return Check(code, False, "医疗内容缺少已登记的数字人版本", ("avatar", avatar_version))
        if not avatar["identity_subject"]:
            return Check(
                code, False, "数字人身份主体不明", ("avatar", avatar_version)
            )
        if not avatar["authorization_ref"]:
            return Check(
                code,
                False,
                f"数字人{avatar['identity_subject']}缺少身份授权文件",
                ("avatar", avatar_version),
            )
        valid_until = avatar.get("authorization_valid_until")
        if valid_until is None or valid_until <= now:
            return Check(
                code,
                False,
                f"数字人{avatar['identity_subject']}的身份授权已过期或未载明有效期",
                ("avatar", avatar_version),
            )
        return Check(
            code,
            True,
            f"数字人{avatar['identity_subject']}授权有效至{valid_until}",
            ("avatar", avatar_version),
        )

    if code == PROVABLE_FACTS:
        script = state["scripts"].get(project_id, {}).get(material["script_version"])
        if script is None:
            return Check(
                code,
                False,
                f"脚本版本{material['script_version']}不存在",
                ("script", material["script_version"]),
            )
        basis = ("script", material["script_version"], script["content_hash"], qualification["seq"] if qualification else None)
        if qualification is None:
            return Check(code, False, "尚未登记产品资质，无法核对商品事实", basis)
        claims = script.get("claims", [])
        unverifiable = sorted(
            claim["fact_id"] for claim in claims if claim["fact_id"] not in qualification["facts"]
        )
        if unverifiable:
            return Check(
                code,
                False,
                f"脚本宣称缺少可证明事实支撑: {','.join(unverifiable)}",
                basis,
            )
        if project["medical"] and not claims:
            return Check(code, False, "医疗脚本未声明任何可核对的商品事实", basis)
        return Check(code, True, f"脚本{len(claims)}项宣称均有事实支撑", basis)

    raise ValueError(f"未知核查结论: {code}")


def _opinions_for(state: dict[str, Any], project_id: str, scope: str, ref: str) -> list[dict[str, Any]]:
    return list(state["opinions"].get((project_id, scope, ref), []))


def _component_verdict(
    state: dict[str, Any],
    project_id: str,
    scope: str,
    ref: str,
    submitter: str,
    label: str,
) -> dict[str, str] | None:
    """返回 None 表示通过，否则返回失败说明。后出现的否决覆盖先出现的批准。"""
    opinions = _opinions_for(state, project_id, scope, ref)
    if not opinions:
        return {"category": "review", "code": f"{scope}_review", "detail": f"{label}缺少平台复核意见"}
    latest = opinions[-1]
    approvals = [o for o in opinions if o["opinion"] == "approve"]
    if latest["opinion"] != "approve" or not approvals:
        return {"category": "review", "code": f"{scope}_review", "detail": f"{label}最新意见为否决或退回"}
    approver = latest["reviewer"]
    if approver == submitter:
        return {
            "category": "review",
            "code": "self_approval",
            "detail": f"{label}提交者{submitter}不得批准自己的内容",
        }
    if latest["reviewer_role"] != Role.PLATFORM_REVIEWER.value:
        return {
            "category": "review",
            "code": "reviewer_role",
            "detail": f"{label}必须由平台审核人员复核",
        }
    return None


def evaluate_gate(state: dict[str, Any], project_id: str, material_version: str, now: float) -> GateResult:
    """对指定素材版本执行完整门禁归约。"""
    project = state["projects"].get(project_id)
    material = state["materials"].get(project_id, {}).get(material_version)
    failures: list[dict[str, str]] = []
    if project is None:
        return GateResult(False, ({"category": "project", "code": "project", "detail": "项目不存在"},))
    if material is None:
        return GateResult(False, ({"category": "material", "code": "material", "detail": "素材版本不存在"},))

    freeze = state["freezes"].get(project_id)
    if freeze is not None and freeze.get("active"):
        versions = freeze.get("versions") or []
        if not versions or material_version in versions:
            failures.append({"category": "freeze", "code": "frozen", "detail": f"素材谱系已因{freeze['reason']}冻结"})

    # 系统结论：必须有记录且通过；身份授权在放行时刻再校验一次有效期
    conclusions = state.get("conclusions", {}).get((project_id, material_version), {})
    for code in required_codes(project, material):
        recorded = conclusions.get(code)
        if recorded is None:
            failures.append(
                {"category": "evidence", "code": code, "detail": f"缺少结论:{CODE_SCOPE_LABELS[code]}"}
            )
            continue
        if not recorded["passed"]:
            failures.append(
                {"category": "evidence", "code": code, "detail": recorded["detail"]}
            )
            continue
        if code == IDENTITY_AUTH:
            check = compute_check(code, state, project_id, material, now)
            if not check.passed:
                failures.append({"category": "evidence", "code": code, "detail": check.detail})

    # 人工复核：按组件版本覆盖；衍生版本未改动的组件沿用既有复核
    script = state["scripts"].get(project_id, {}).get(material["script_version"])
    if script is not None:
        failure = _component_verdict(
            state, project_id, "script", material["script_version"], script["submitter"], "脚本"
        )
        if failure:
            failures.append(failure)
    if project["medical"] and material.get("avatar_version"):
        avatar = state["avatars"].get(project_id, {}).get(material["avatar_version"])
        if avatar is not None:
            failure = _component_verdict(
                state, project_id, "avatar", material["avatar_version"], avatar["submitter"], "数字人"
            )
            if failure:
                failures.append(failure)

    if (project_id, material_version) not in state.get("truth", {}):
        failures.append(
            {"category": "liability", "code": "truth_responsibility", "detail": "尚未声明内容真实性责任人"}
        )

    return GateResult(not failures, tuple(failures))
