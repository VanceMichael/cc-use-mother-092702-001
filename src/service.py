"""数字广告责任链与发布门禁应用服务。

所有命令先做角色信息边界校验，再产生只追加事件；
状态一律由事件投影得到，服务重启后自动恢复（含审批期限与待发通知）。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import policy
from .events import EventStore
from .policy import GateResult
from .roles import Role, assert_can_access
from .state import projection

DEFAULT_REVIEW_SLA_SECONDS = 7 * 24 * 3600


class DomainError(ValueError):
    """领域规则被违反。"""


class AccountabilityService:
    def __init__(self, store: EventStore | Path | str | None = None, *, clock=time.time):
        self._clock = clock
        if isinstance(store, EventStore):
            self.store = store
        else:
            self.store = EventStore(Path(store) if store is not None else None, clock=clock)
        self.state = projection(self.store)

    # ---- 内部工具 ----

    def _append(self, kind: str, payload: dict[str, Any], *, actor_id: str):
        event = self.store.append(kind, payload, source=actor_id)
        from .state import apply

        apply(self.state, event)
        return event

    def _actor_role(self, actor_id: str) -> Role:
        actor = self.state["actors"].get(actor_id)
        if actor is None:
            raise DomainError(f"参与方未登记: {actor_id}")
        return Role(actor["role"])

    def _authorize(self, actor_id: str, scope: str) -> Role:
        role = self._actor_role(actor_id)
        assert_can_access(role, scope)
        return role

    def _project(self) -> dict[str, Any]:
        return self.state

    def _material(self, project_id: str, version: str) -> dict[str, Any]:
        material = self.state["materials"].get(project_id, {}).get(version)
        if material is None:
            raise DomainError(f"素材版本不存在: {project_id}/{version}")
        return material

    def _ensure_lineage_open(self, project_id: str, version: str | None = None) -> None:
        freeze = self.state["freezes"].get(project_id)
        if freeze is None or not freeze.get("active"):
            return
        roots = freeze.get("versions") or []
        if not roots:
            # 全项目冻结：任何变更与发布都被禁止
            raise DomainError(f"素材谱系已因{freeze['reason']}冻结，禁止变更或发布")
        if version is None:
            return
        if version in self._lineage_closure(project_id, roots):
            raise DomainError(f"素材谱系已因{freeze['reason']}冻结，禁止变更或发布")

    def _lineage_closure(self, project_id: str, roots: list[str]) -> set[str]:
        """冻结根版本及其全部衍生后代（沿 parent 链接展开）。"""
        materials = self.state["materials"].get(project_id, {})
        children: dict[str, list[str]] = {}
        for version, material in materials.items():
            parent = material.get("parent")
            if parent is not None:
                children.setdefault(parent, []).append(version)
        result: set[str] = set()
        stack = list(roots)
        while stack:
            current = stack.pop()
            if current in result:
                continue
            result.add(current)
            stack.extend(children.get(current, ()))
        return result

    # ---- 参与方与立项 ----

    def register_actor(self, actor_id: str, name: str, role: Role, *, org: str = "") -> None:
        if actor_id in self.state["actors"]:
            raise DomainError(f"参与方已登记: {actor_id}")
        self.store.append(
            "actor_registered",
            {"actor_id": actor_id, "name": name, "role": role.value, "org": org},
            source=actor_id,
        )
        # 登记事件直接重放进状态（登记人可能尚未存在，故不经 _append）
        self.state = projection(self.store)

    def create_project(
        self,
        actor_id: str,
        project_id: str,
        name: str,
        *,
        medical: bool,
        required_approver_roles: list[str] | None = None,
    ) -> None:
        self._authorize(actor_id, "project")
        if project_id in self.state["projects"]:
            raise DomainError(f"项目已存在: {project_id}")
        self._append(
            "project_created",
            {
                "project_id": project_id,
                "name": name,
                "medical": medical,
                "required_approver_roles": required_approver_roles
                or [Role.PLATFORM_REVIEWER.value],
            },
            actor_id=actor_id,
        )

    def register_qualification(
        self, actor_id: str, project_id: str, facts: list[dict[str, Any]]
    ) -> None:
        """登记产品资质事实；每项事实须有编号、证明材料引用与证据指纹。"""
        self._authorize(actor_id, "qualification")
        role = self._actor_role(actor_id)
        if role is not Role.ADVERTISER:
            raise DomainError("只有广告主可以登记产品资质事实")
        if project_id not in self.state["projects"]:
            raise DomainError(f"项目不存在: {project_id}")
        for fact in facts:
            for key in ("fact_id", "proof_ref", "proof_hash"):
                if not fact.get(key):
                    raise DomainError(f"产品事实缺少{key}: {fact.get('fact_id', '?')}")
        self._append(
            "qualification_registered",
            {"project_id": project_id, "facts": facts},
            actor_id=actor_id,
        )

    # ---- 脚本、数字人与素材谱系 ----

    def submit_script(
        self,
        actor_id: str,
        project_id: str,
        version: str,
        content_hash: str,
        *,
        claims: list[dict[str, str]] | None = None,
        parent: str | None = None,
    ) -> None:
        role = self._authorize(actor_id, "script")
        if role is not Role.PRODUCER:
            raise DomainError("只有内容制作机构可以提交脚本")
        self._ensure_lineage_open(project_id)
        if project_id not in self.state["projects"]:
            raise DomainError(f"项目不存在: {project_id}")
        if version in self.state["scripts"].get(project_id, {}):
            raise DomainError(f"脚本版本已存在: {version}")
        self._append(
            "script_submitted",
            {
                "project_id": project_id,
                "version": version,
                "parent": parent,
                "content_hash": content_hash,
                "claims": claims or [],
                "submitter": actor_id,
            },
            actor_id=actor_id,
        )

    def register_avatar(
        self,
        actor_id: str,
        project_id: str,
        version: str,
        *,
        identity_subject: str,
        generator: str,
        authorization_ref: str = "",
        authorization_valid_until: float | None = None,
        parent: str | None = None,
    ) -> None:
        role = self._authorize(actor_id, "avatar")
        if role is not Role.PRODUCER:
            raise DomainError("只有内容制作机构可以登记数字人")
        self._ensure_lineage_open(project_id)
        if not identity_subject:
            raise DomainError("数字人必须载明身份主体")
        if version in self.state["avatars"].get(project_id, {}):
            raise DomainError(f"数字人版本已存在: {version}")
        self._append(
            "avatar_registered",
            {
                "project_id": project_id,
                "version": version,
                "parent": parent,
                "generator": generator,
                "identity_subject": identity_subject,
                "authorization_ref": authorization_ref,
                "authorization_valid_until": authorization_valid_until,
                "submitter": actor_id,
            },
            actor_id=actor_id,
        )

    def build_material(
        self,
        actor_id: str,
        project_id: str,
        version: str,
        content_hash: str,
        *,
        script_version: str,
        avatar_version: str | None = None,
        parent: str | None = None,
        review_due_at: float | None = None,
    ) -> dict[str, dict[str, Any]]:
        """生成素材衍生版本并增量计算核查结论。

        与父版本依赖基一致的结论直接继承（记录来源），只重算受影响的结论。
        """
        role = self._authorize(actor_id, "derivative")
        if role is not Role.PRODUCER:
            raise DomainError("只有内容制作机构可以生成素材衍生版本")
        self._ensure_lineage_open(project_id, parent)
        project = self.state["projects"].get(project_id)
        if project is None:
            raise DomainError(f"项目不存在: {project_id}")
        if script_version not in self.state["scripts"].get(project_id, {}):
            raise DomainError(f"脚本版本不存在: {script_version}")
        if version in self.state["materials"].get(project_id, {}):
            raise DomainError(f"素材版本已存在: {version}")
        due_at = review_due_at or (self._clock() + DEFAULT_REVIEW_SLA_SECONDS)
        self._append(
            "material_built",
            {
                "project_id": project_id,
                "version": version,
                "parent": parent,
                "script_version": script_version,
                "avatar_version": avatar_version,
                "content_hash": content_hash,
                "submitter": actor_id,
                "review_due_at": due_at,
            },
            actor_id=actor_id,
        )
        self._raise_review_notification(project_id, version, due_at)
        return self._record_conclusions(project_id, version, parent=parent, source="system")

    def _raise_review_notification(self, project_id: str, version: str, due_at: float) -> None:
        notification_id = f"review:{project_id}:{version}"
        self._append(
            "notification_raised",
            {
                "id": notification_id,
                "to_role": Role.PLATFORM_REVIEWER.value,
                "message": f"素材{project_id}/{version}待审核，期限{due_at}",
                "ref": {"project_id": project_id, "material_version": version},
                "due_at": due_at,
            },
            actor_id="system",
        )

    # ---- 核查结论（增量） ----

    def recompute_conclusions(
        self, actor_id: str, project_id: str, version: str
    ) -> dict[str, dict[str, Any]]:
        """平台审核在补正材料后手动重算结论。"""
        self._authorize(actor_id, "review")
        return self._record_conclusions(project_id, version, source=actor_id)

    def _record_conclusions(
        self, project_id: str, version: str, *, source: str, parent: str | None = None
    ) -> dict[str, dict[str, Any]]:
        """只重算依赖基发生变化的结论；未变化的结论自父版本继承。"""
        material = self._material(project_id, version)
        project = self.state["projects"][project_id]
        if parent is None:
            parent = material.get("parent")
        parent_conclusions = (
            self.state["conclusions"].get((project_id, parent), {}) if parent else {}
        )
        now = self._clock()
        results: dict[str, dict[str, Any]] = {}
        for code in policy.required_codes(project, material):
            check = policy.compute_check(code, self.state, project_id, material, now)
            inherited = parent_conclusions.get(code)
            if inherited is not None and tuple(inherited["basis"]) == check.basis and check.passed:
                payload = {
                    "project_id": project_id,
                    "material_version": version,
                    "code": code,
                    "passed": True,
                    "detail": inherited["detail"],
                    "basis": list(check.basis),
                    "inherited_from": {
                        "material_version": parent,
                        "seq": inherited["seq"],
                    },
                }
            else:
                payload = {
                    "project_id": project_id,
                    "material_version": version,
                    "code": code,
                    "passed": check.passed,
                    "detail": check.detail,
                    "basis": list(check.basis),
                    "inherited_from": None,
                }
            self._append("conclusion_recorded", payload, actor_id=source)
            results[code] = payload
        return results

    # ---- 人工复核与真实性责任 ----

    def submit_review_opinion(
        self,
        actor_id: str,
        project_id: str,
        scope: str,
        reviewed_ref: str,
        opinion: str,
        *,
        note: str = "",
    ) -> None:
        """平台复核脚本/数字人组件版本。提交者不得批准自己提交的内容。"""
        role = self._authorize(actor_id, "review")
        if role is not Role.PLATFORM_REVIEWER:
            raise DomainError("只有平台审核人员可以提交复核意见")
        if opinion not in ("approve", "reject"):
            raise DomainError("复核意见只能是 approve 或 reject")
        if scope == "script":
            component = self.state["scripts"].get(project_id, {}).get(reviewed_ref)
        elif scope == "avatar":
            component = self.state["avatars"].get(project_id, {}).get(reviewed_ref)
        else:
            raise DomainError(f"未知复核对象: {scope}")
        if component is None:
            raise DomainError(f"复核对象不存在: {scope}/{reviewed_ref}")
        if opinion == "approve" and component["submitter"] == actor_id:
            raise DomainError("提交者不得批准自己提交的内容")
        self._append(
            "review_opinion_submitted",
            {
                "project_id": project_id,
                "scope": scope,
                "reviewed_ref": reviewed_ref,
                "reviewer": actor_id,
                "reviewer_role": role.value,
                "opinion": opinion,
                "note": note,
            },
            actor_id=actor_id,
        )

    def declare_truth_responsibility(
        self, actor_id: str, project_id: str, material_version: str, responsible_actor: str
    ) -> None:
        """声明承担内容真实性责任的主体（广告主职责）。"""
        role = self._authorize(actor_id, "liability")
        if role is not Role.ADVERTISER:
            raise DomainError("只有广告主可以声明内容真实性责任")
        self._material(project_id, material_version)
        if responsible_actor not in self.state["actors"]:
            raise DomainError(f"责任主体未登记: {responsible_actor}")
        existing = self.state["truth"].get((project_id, material_version))
        self._append(
            "truth_responsibility_declared",
            {
                "project_id": project_id,
                "material_version": material_version,
                "responsible": responsible_actor,
                "supersedes": existing["seq"] if existing else None,
            },
            actor_id=actor_id,
        )

    # ---- 放行门禁与渠道发布 ----

    def evaluate(self, project_id: str, material_version: str) -> GateResult:
        return policy.evaluate_gate(self.state, project_id, material_version, self._clock())

    def grant_release(self, actor_id: str, project_id: str, material_version: str) -> dict[str, Any]:
        """平台审核放行；审核中的素材不能被渠道直接发布。

        放行事件固化当时的全部证据快照，后续脚本/数字人变更不影响历史版本。
        """
        role = self._authorize(actor_id, "release")
        if role is not Role.PLATFORM_REVIEWER:
            raise DomainError("只有平台审核人员可以作出放行决定")
        self._ensure_lineage_open(project_id, material_version)
        material = self._material(project_id, material_version)
        gate = policy.evaluate_gate(self.state, project_id, material_version, self._clock())
        if not gate.passed:
            self._append(
                "release_rejected",
                {
                    "project_id": project_id,
                    "material_version": material_version,
                    "decider": actor_id,
                    "failures": list(gate.failures),
                },
                actor_id=actor_id,
            )
            raise DomainError("; ".join(item["detail"] for item in gate.failures))
        evidence = self._evidence_snapshot(project_id, material_version)
        self._append(
            "release_granted",
            {
                "project_id": project_id,
                "material_version": material_version,
                "decider": actor_id,
                "gate": {
                    "passed": True,
                    "codes": list(
                        policy.required_codes(
                            self.state["projects"][project_id],
                            self.state["materials"][project_id][material_version],
                        )
                    ),
                },
                "evidence": evidence,
            },
            actor_id=actor_id,
        )
        notification_id = f"review:{project_id}:{material_version}"
        if notification_id in self.state["notifications"]:
            self._append(
                "notification_delivered", {"id": notification_id}, actor_id="system"
            )
        return evidence

    def _evidence_snapshot(self, project_id: str, material_version: str) -> dict[str, Any]:
        """固化放行时刻的证据：组件指纹、结论、复核、责任人。"""
        material = self.state["materials"][project_id][material_version]
        script = self.state["scripts"][project_id][material["script_version"]]
        snapshot: dict[str, Any] = {
            "material": dict(material),
            "script": dict(script),
            "conclusions": {
                code: dict(item)
                for code, item in self.state["conclusions"]
                .get((project_id, material_version), {})
                .items()
            },
            "opinions": {},
            "truth_responsible": self.state["truth"]
            .get((project_id, material_version), {})
            .get("responsible"),
        }
        avatar_version = material.get("avatar_version")
        if avatar_version is not None:
            avatar = self.state["avatars"].get(project_id, {}).get(avatar_version)
            if avatar is not None:
                snapshot["avatar"] = dict(avatar)
        for scope, ref in (
            ("script", material["script_version"]),
            ("avatar", avatar_version),
        ):
            if ref is None:
                continue
            snapshot["opinions"][scope] = [
                dict(item) for item in self.state["opinions"].get((project_id, scope, ref), [])
            ]
        qualification = self.state["qualifications"].get(project_id)
        if qualification is not None:
            snapshot["qualification_seq"] = qualification["seq"]
        return snapshot

    def register_publish(
        self,
        actor_id: str,
        project_id: str,
        material_version: str,
        channel_id: str,
        callback_id: str,
    ) -> dict[str, Any]:
        """渠道登记实际发布。无放行记录一律拒绝；重复回调不重复生成发布记录。"""
        self._authorize(actor_id, "channel")
        if self._actor_role(actor_id) is not Role.CHANNEL_OPERATOR:
            raise DomainError("只有渠道运营人员可以登记发布")
        if callback_id in self.state["callbacks"]:
            seen = self.state["callbacks"][callback_id]
            return {
                "deduplicated": True,
                "seq": seen["seq"],
                "channel_id": seen["channel_id"],
            }
        self._ensure_lineage_open(project_id, material_version)
        self._material(project_id, material_version)
        release = self.state["releases"].get((project_id, material_version))
        if release is None:
            raise DomainError("素材尚未通过放行门禁，渠道不得直接发布")
        existing = self.state["publishes"].get((project_id, material_version), {}).get(channel_id)
        if existing is not None:
            raise DomainError(f"渠道{channel_id}发布记录已存在，需以状态回调更新")
        self._append(
            "channel_publish_registered",
            {
                "project_id": project_id,
                "material_version": material_version,
                "channel_id": channel_id,
                "callback_id": callback_id,
                "operator": actor_id,
            },
            actor_id=actor_id,
        )
        return {"deduplicated": False}

    def channel_status_callback(
        self,
        actor_id: str,
        callback_id: str,
        status: str,
        *,
        project_id: str,
        material_version: str,
        channel_id: str,
    ) -> dict[str, Any]:
        """渠道状态回调（下架/撤回等）。

        同一 callback_id 重复投递一律丢弃，绝不追加第二条事件或重复生成发布记录；
        渠道侧状态变更应使用新的 callback_id 投递。
        """
        self._authorize(actor_id, "channel")
        if self._actor_role(actor_id) is not Role.CHANNEL_OPERATOR:
            raise DomainError("只有渠道运营人员可以接收渠道回调")
        if status not in ("live", "paused", "taken_down", "withdrawn"):
            raise DomainError(f"未知渠道状态: {status}")
        if callback_id in self.state["callbacks"]:
            seen = self.state["callbacks"][callback_id]
            publish = self.state["publishes"].get(
                (seen["project_id"], seen["material_version"]), {}
            ).get(seen["channel_id"])
            return {
                "deduplicated": True,
                "seq": seen["seq"],
                "status": publish["status"] if publish is not None else status,
            }
        event = self._append(
            "channel_status_callback",
            {
                "callback_id": callback_id,
                "status": status,
                "project_id": project_id,
                "material_version": material_version,
                "channel_id": channel_id,
            },
            actor_id=actor_id,
        )
        return {"deduplicated": False, "seq": event.seq, "status": status}

    def record_traffic_purchase(
        self,
        actor_id: str,
        project_id: str,
        material_version: str,
        channel_id: str,
        traffic_ref: str,
        *,
        spend: float | None = None,
    ) -> None:
        self._authorize(actor_id, "traffic")
        self._material(project_id, material_version)
        self._ensure_lineage_open(project_id, material_version)
        self._append(
            "traffic_purchase_recorded",
            {
                "project_id": project_id,
                "material_version": material_version,
                "channel_id": channel_id,
                "traffic_ref": traffic_ref,
                "spend": spend,
            },
            actor_id=actor_id,
        )

    # ---- 投诉/撤回/监管调查：冻结与报告 ----

    def issue_freeze(
        self,
        actor_id: str,
        project_id: str,
        reason: str,
        *,
        versions: list[str] | None = None,
        note: str = "",
    ) -> None:
        """冻结素材谱系：投诉/撤回由广告主发起，监管调查由平台审核发起。

        冻结范围内（含衍生后代）禁止新衍生、放行与发布。
        """
        role = self._actor_role(actor_id)
        assert_can_access(role, "freeze")
        if project_id not in self.state["projects"]:
            raise DomainError(f"项目不存在: {project_id}")
        if reason not in ("投诉", "撤回", "监管调查"):
            raise DomainError("冻结原因只能是投诉、撤回或监管调查")
        allowed = (
            Role.ADVERTISER if reason in ("投诉", "撤回") else Role.PLATFORM_REVIEWER
        )
        if role is not allowed:
            who = "广告主" if allowed is Role.ADVERTISER else "平台审核人员"
            raise DomainError(f"{reason}冻结只能由{who}发起")
        self._append(
            "freeze_issued",
            {
                "project_id": project_id,
                "reason": reason,
                "versions": versions or [],
                "note": note,
            },
            actor_id=actor_id,
        )

    def release_freeze(self, actor_id: str, project_id: str) -> None:
        role = self._actor_role(actor_id)
        assert_can_access(role, "freeze")
        freeze = self.state["freezes"].get(project_id)
        if freeze is None or not freeze.get("active"):
            raise DomainError("项目不存在生效中的冻结")
        allowed = (
            Role.ADVERTISER
            if freeze["reason"] in ("投诉", "撤回")
            else Role.PLATFORM_REVIEWER
        )
        if role is not allowed:
            who = "广告主" if allowed is Role.ADVERTISER else "平台审核人员"
            raise DomainError(f"{freeze['reason']}冻结只能由{who}解除")
        self._append("freeze_released", {"project_id": project_id}, actor_id=actor_id)

    def freeze_report(self, actor_id: str, project_id: str) -> dict[str, Any]:
        """给出仍在传播的渠道、待补材料与责任缺口。"""
        self._authorize(actor_id, "freeze")
        if project_id not in self.state["projects"]:
            raise DomainError(f"项目不存在: {project_id}")
        freeze = self.state["freezes"].get(project_id)
        live_channels: list[dict[str, Any]] = []
        pending_materials: list[dict[str, Any]] = []
        liability_gaps: list[dict[str, Any]] = []
        materials = self.state["materials"].get(project_id, {})
        if freeze is not None and freeze.get("versions"):
            scoped_versions = self._lineage_closure(project_id, freeze["versions"])
        else:
            scoped_versions = set(materials)
        for version, material in materials.items():
            if version not in scoped_versions:
                continue
            for channel_id, publish in self.state["publishes"].get((project_id, version), {}).items():
                if publish["status"] == "live":
                    live_channels.append(
                        {
                            "material_version": version,
                            "channel_id": channel_id,
                            "operator": publish["operator"],
                            "since": publish["ts"],
                        }
                    )
            gate = policy.evaluate_gate(self.state, project_id, version, self._clock())
            missing = [item["detail"] for item in gate.failures if item["category"] != "freeze"]
            if missing:
                pending_materials.append(
                    {
                        "material_version": version,
                        "missing": missing,
                    }
                )
            truth = self.state["truth"].get((project_id, version))
            if truth is None:
                liability_gaps.append(
                    {"material_version": version, "gap": "未声明内容真实性责任人"}
                )
            release = self.state["releases"].get((project_id, version))
            if release is not None and truth is not None:
                evidence = release["evidence"]
                if not evidence.get("truth_responsible"):
                    liability_gaps.append(
                        {"material_version": version, "gap": "放行快照缺少真实性责任人"}
                    )
        return {
            "project_id": project_id,
            "freeze": None
            if freeze is None
            else {
                "reason": freeze["reason"],
                "active": freeze["active"],
                "versions": freeze.get("versions", []),
                "issued_at": freeze["ts"],
            },
            "live_channels": live_channels,
            "pending_materials": pending_materials,
            "liability_gaps": liability_gaps,
        }

    # ---- 期限与通知（重启后按原期限继续） ----

    def due_items(self, actor_id: str, *, now: float | None = None) -> dict[str, list[dict[str, Any]]]:
        """查询当前未完成的审批与未送达通知，期限沿用事件中记录的原始期限。"""
        role = self._actor_role(actor_id)
        if role not in (Role.PLATFORM_REVIEWER, Role.AUDITOR):
            from .roles import AccessDeniedError

            raise AccessDeniedError("只有平台审核人员与审计人员可以查看审批期限")
        moment = now if now is not None else self._clock()
        overdue_reviews: list[dict[str, Any]] = []
        for (project_id, version), task in self.state["review_tasks"].items():
            if task.get("status") == "pending" and task.get("due_at", float("inf")) <= moment:
                overdue_reviews.append(
                    {"project_id": project_id, "material_version": version, "due_at": task["due_at"]}
                )
        pending_notifications: list[dict[str, Any]] = []
        for notification_id, item in self.state["notifications"].items():
            if not item["delivered"]:
                pending_notifications.append(
                    {
                        "id": notification_id,
                        "to_role": item["to_role"],
                        "due_at": item["due_at"],
                        "overdue": item["due_at"] <= moment,
                        "message": item["message"],
                    }
                )
        return {
            "overdue_reviews": overdue_reviews,
            "pending_notifications": pending_notifications,
        }

    def deliver_notification(self, actor_id: str, notification_id: str) -> None:
        role = self._actor_role(actor_id)
        if notification_id not in self.state["notifications"]:
            raise DomainError(f"通知不存在: {notification_id}")
        target_role = self.state["notifications"][notification_id]["to_role"]
        if role is not Role.AUDITOR and role.value != target_role:
            raise DomainError("只能由通知对象本人或审计人员确认送达")
        if self.state["notifications"][notification_id]["delivered"]:
            return
        self._append(
            "notification_delivered", {"id": notification_id}, actor_id=actor_id
        )

    # ---- 审计：历史时点重放 ----

    def replay_release_decision(
        self, actor_id: str, project_id: str, material_version: str, at_time: float
    ) -> dict[str, Any]:
        """审计人员按历史时点只用当时已存在的事件重现一次放行决定。"""
        role = self._actor_role(actor_id)
        assert_can_access(role, "audit")
        historical = projection(self.store, at_time=at_time)
        gate = policy.evaluate_gate(historical, project_id, material_version, at_time)
        release = historical["releases"].get((project_id, material_version))
        recorded_now = self.state["releases"].get((project_id, material_version))
        return {
            "at_time": at_time,
            "gate_passed_at_point": gate.passed,
            "failures_at_point": [dict(item) for item in gate.failures],
            "release_existed_at_point": release is not None,
            "recorded_release": None
            if release is None
            else {
                "decider": release["decider"],
                "seq": release["seq"],
                "ts": release["ts"],
                "evidence_fingerprints": {
                    "material_hash": release["evidence"].get("material", {}).get("content_hash"),
                    "script_hash": release["evidence"].get("script", {}).get("content_hash"),
                },
            },
            "still_matches_current": release is not None
            and recorded_now is not None
            and release["seq"] == recorded_now["seq"],
        }
