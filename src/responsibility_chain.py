"""数字广告责任链与发布门禁的领域服务。

以事件溯源保存广告项目从立项到发布、投诉、冻结的完整责任链：
产品资质、脚本、数字人身份、素材衍生版本、审核意见、流量购买与发布渠道，
每个版本都记录提交人、复核人与内容真实性责任人。

事件流只增不改（哈希链防篡改），结论按事件重放得到；修改脚本或更换数字人时
只重算受影响的结论；服务重启后未完成的审批与通知按原期限继续；
审计人员可按历史时点重现任意一次放行决定。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable


# ---------------------------------------------------------------------------
# 角色与职责
# ---------------------------------------------------------------------------

class Role(str, Enum):
    ADVERTISER = "广告主"            # 承担内容真实性责任、购买流量
    PRODUCER = "内容制作机构"        # 撰写脚本、生成数字人、提交素材
    PLATFORM_REVIEWER = "平台审核"  # 复核内容、医疗内容前置核验
    CHANNEL_OPERATOR = "渠道运营"    # 只能发布已放行版本
    AUDITOR = "审计人员"             # 只读、历史重放
    REGULATOR = "监管人员"           # 只读、发起调查


# 各角色可读取的信息域；越权访问由 view_as 在投影层拦截。
SCOPES: dict[Role, frozenset[str]] = {
    Role.ADVERTISER: frozenset({
        "project", "qualification", "asset", "review", "traffic",
        "publish", "freeze", "gap",
    }),
    Role.PRODUCER: frozenset({"project", "asset", "review"}),
    Role.PLATFORM_REVIEWER: frozenset({
        "project", "qualification", "asset", "identity", "review", "publish",
    }),
    Role.CHANNEL_OPERATOR: frozenset({"project", "asset", "publish", "traffic", "freeze"}),
    Role.AUDITOR: frozenset({
        "project", "qualification", "asset", "identity", "review",
        "traffic", "publish", "freeze", "gap", "audit",
    }),
    Role.REGULATOR: frozenset({
        "project", "qualification", "asset", "identity", "review",
        "traffic", "publish", "freeze", "gap",
    }),
}

MEDICAL_CATEGORIES = frozenset({"药品", "医疗器械", "医疗服务"})
GENESIS_HASH = "0" * 64


# ---------------------------------------------------------------------------
# 事件
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Event:
    """不可变领域事件。``prev_hash`` 与 ``hash`` 构成防篡改哈希链。"""

    seq: int
    kind: str
    at: str                      # ISO8601，单调时钟由聚合根保证
    actor_id: str
    payload: dict[str, Any]
    idempotency_key: str | None = None
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    @staticmethod
    def digest(kind: str, at: str, actor_id: str, payload: dict[str, Any],
               idempotency_key: str | None, prev_hash: str) -> str:
        encoded = json.dumps(
            [kind, at, actor_id, payload, idempotency_key, prev_hash],
            ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "kind": self.kind,
            "at": self.at,
            "actor_id": self.actor_id,
            "payload": self.payload,
            "idempotency_key": self.idempotency_key,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }

    @staticmethod
    def from_dict(value: dict[str, Any]) -> "Event":
        return Event(
            seq=int(value["seq"]),
            kind=value["kind"],
            at=value["at"],
            actor_id=value["actor_id"],
            payload=value["payload"],
            idempotency_key=value.get("idempotency_key"),
            prev_hash=value["prev_hash"],
            hash=value["hash"],
        )


def _parse_at(at: str) -> datetime:
    return datetime.fromisoformat(at)


# ---------------------------------------------------------------------------
# 领域异常
# ----------------------------------------------------------------i-------

class DomainError(Exception):
    """所有业务规则违规的基类。"""


class AuthorizationError(DomainError):
    """角色无权执行该操作或读取该信息域。"""


class SeparationError(DomainError):
    """违反职责分离：提交者不得批准自己的内容。"""


class GateError(DomainError):
    """发布门禁未通过，渠道不得发布。"""


class MedicalGateError(GateError):
    """医疗内容前置核验未完成：身份授权或可证明的商品事实缺失。"""


class FreezeError(DomainError):
    """素材谱系已冻结，禁止任何变更。"""


class DeadlineError(DomainError):
    """审批超过规定期限。"""


# ---------------------------------------------------------------------------
# 快照（投影结果）
# ---------------------------------------------------------------------------

@dataclass
class VersionState:
    version_id: str
    asset_id: str
    asset_kind: str
    parent_version: str | None
    derived_from: tuple[str, ...]
    submitted_by: str
    reviewed_by: str | None = None
    truth_owner: str | None = None          # 内容真实性责任人
    changed_facts: frozenset[str] = frozenset()
    medical: bool = False
    qualification_id: str | None = None
    human_id: str | None = None
    identity_authorized: bool = False
    product_facts_verified: bool = False
    identity_verdict: str | None = None     # 身份授权核验结论
    facts_verdict: str | None = None        # 商品事实核验结论
    review_verdicts: dict[str, str] = field(default_factory=dict)
    release_decision_id: str | None = None
    released_at: str | None = None
    superseded_at: str | None = None        # 被新版本取代的时间；旧版证据保留


@dataclass
class PendingItem:
    key: tuple[str, ...]
    kind: str
    version_id: str
    opened_at: str
    deadline: str
    note: str

    def overdue(self, now: datetime) -> bool:
        return _parse_at(self.deadline) < now


@dataclass
class Snapshot:
    project_id: str | None = None
    frozen: bool = False
    frozen_reason: str | None = None
    frozen_at: str | None = None
    frozen_versions: frozenset[str] = frozenset()
    events: int = 0
    tip_hash: str = GENESIS_HASH
    clock: str | None = None
    scope_verdict: dict[str, frozenset[str]] = field(default_factory=dict)
    qualifications: dict[str, dict[str, Any]] = field(default_factory=dict)
    digital_humans: dict[str, dict[str, Any]] = field(default_factory=dict)
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)
    versions: dict[str, VersionState] = field(default_factory=dict)
    heads: dict[str, str] = field(default_factory=dict)            # asset_id -> 当前版本
    reviews: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    releases: dict[str, dict[str, Any]] = field(default_factory=dict)
    publishes: list[dict[str, Any]] = field(default_factory=list)
    traffic_purchases: dict[str, dict[str, Any]] = field(default_factory=dict)
    channels: dict[str, dict[str, Any]] = field(default_factory=dict)
    pending: dict[tuple[str, ...], PendingItem] = field(default_factory=dict)
    notifications: list[dict[str, Any]] = field(default_factory=list)
    freeze_scope: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# 投影：把事件流折叠为快照
# ---------------------------------------------------------------------------

class Projector:
    def __init__(self) -> None:
        self.s = Snapshot()

    def apply(self, event: Event) -> Snapshot:
        s = self.s
        kind, p = event.kind, event.payload
        s.events = event.seq
        s.tip_hash = event.hash
        s.clock = event.at

        if kind == "ProjectInitiated":
            s.project_id = p["project_id"]
            if p.get("medical"):
                s.scope_verdict.setdefault("__project__", frozenset())

        elif kind == "QualificationRegistered":
            s.qualifications[p["qualification_id"]] = {
                **p, "registered_by": event.actor_id,
            }

        elif kind == "DigitalHumanRegistered":
            s.digital_humans[p["human_id"]] = {
                **p, "registered_by": event.actor_id,
            }

        elif kind == "AssetCreated":
            s.assets[p["asset_id"]] = {**p, "created_by": event.actor_id}

        elif kind == "VersionSubmitted":
            medical = bool(p.get("medical"))
            changed = frozenset(p.get("changed_facts", ()))
            version = VersionState(
                version_id=p["version_id"],
                asset_id=p["asset_id"],
                asset_kind=p["asset_kind"],
                parent_version=p.get("parent_version"),
                derived_from=tuple(p.get("derived_from", ())),
                submitted_by=event.actor_id,
                truth_owner=p.get("truth_owner") or event.actor_id,
                changed_facts=changed,
                medical=medical,
                qualification_id=p.get("qualification_id"),
                human_id=p.get("human_id"),
                identity_authorized=not medical,
                product_facts_verified=not medical,
            )
            s.versions[p["version_id"]] = version
            s.heads[p["asset_id"]] = p["version_id"]
            # 新版本提交后，旧版标记为被取代，但证据与责任永久保留。
            if p.get("parent_version"):
                parent = s.versions.get(p["parent_version"])
                if parent is not None and parent.superseded_at is None:
                    parent.superseded_at = event.at
            # 打开待办：医疗内容必须先完成两项前置核验，然后进入复核。
            if medical:
                self._open(("medical-identity", p["version_id"]), "医疗身份授权核验",
                           p["version_id"], event, p.get("review_deadline_hours", 48))
                self._open(("medical-facts", p["version_id"]), "医疗商品事实核验",
                           p["version_id"], event, p.get("review_deadline_hours", 48))
            self._open(("review", p["version_id"]), "发布前复核",
                       p["version_id"], event, p.get("review_deadline_hours", 72))
            self._notify(event, f"版本 {p['version_id']} 已提交，等待复核",
                         p.get("reviewer_hint"))

        elif kind == "MedicalIdentityChecked":
            v = s.versions[p["version_id"]]
            v.identity_authorized = bool(p["authorized"])
            v.identity_verdict = p["verdict"]
            s.pending.pop(("medical-identity", p["version_id"]), None)

        elif kind == "ProductFactsVerified":
            v = s.versions[p["version_id"]]
            v.product_facts_verified = bool(p["verified"])
            v.facts_verdict = p["verdict"]
            s.pending.pop(("medical-facts", p["version_id"]), None)

        elif kind == "ReviewConcluded":
            v = s.versions[p["version_id"]]
            v.reviewed_by = event.actor_id
            v.review_verdicts[p["scope"]] = p["decision"]
            s.reviews[(p["version_id"], p["scope"])] = {
                **p, "reviewer": event.actor_id, "at": event.at, "seq": event.seq,
            }
            if p["scope"] == "release":
                # 复核驳回/要求修改即关闭待办；通过则保留待办，直到放行决定出具。
                if p["decision"] in ("rejected", "changes_requested"):
                    s.pending.pop(("review", p["version_id"]), None)
            self._notify(event, f"版本 {p['version_id']} 复核结论：{p['decision']}",
                         v.submitted_by)

        elif kind == "ReleaseApproved":
            v = s.versions[p["version_id"]]
            v.release_decision_id = p["decision_id"]
            v.released_at = event.at
            s.pending.pop(("review", p["version_id"]), None)
            s.releases[p["decision_id"]] = {
                **p, "version_id": p["version_id"], "approver": event.actor_id,
                "at": event.at,
                "basis_event_seq": event.seq,   # 历史重放的定位点
            }

        elif kind == "TrafficPurchased":
            s.traffic_purchases[p["order_id"]] = {
                **p, "purchased_by": event.actor_id, "at": event.at,
            }

        elif kind == "ChannelPrepared":
            s.channels[p["channel"]] = {**p, "prepared_by": event.actor_id}

        elif kind == "Published":
            v = s.versions[p["version_id"]]
            record = {
                **p, "published_by": event.actor_id, "at": event.at,
                "release_decision_id": v.release_decision_id,
            }
            s.publishes.append(record)
            s.channels.setdefault(p["channel"], {"channel": p["channel"]})
            s.channels[p["channel"]].setdefault("publishes", [])
            s.channels[p["channel"]]["publishes"].append(record)

        elif kind == "PublishRejected":
            s.publishes.append({
                **p, "rejected": True, "by": event.actor_id, "at": event.at,
            })

        elif kind == "ComplaintFiled" or kind == "WithdrawalRequested" or kind == "InvestigationOpened":
            s.notifications.append({
                "type": kind, "at": event.at, "detail": p, "actor": event.actor_id,
            })

        elif kind == "LineageFrozen":
            s.frozen = True
            s.frozen_reason = p["reason"]
            s.frozen_at = event.at
            s.frozen_versions = frozenset(p["versions"])
            s.freeze_scope = p
            for key in list(s.pending):
                if key[1] in s.frozen_versions:
                    s.pending.pop(key, None)
            self._notify(event, f"责任链冻结：{p['reason']}", None)

        return s

    def _open(self, key: tuple[str, ...], kind: str, version_id: str,
              event: Event, deadline_hours: int) -> None:
        opened = _parse_at(event.at)
        self.s.pending[key] = PendingItem(
            key=key, kind=kind, version_id=version_id, opened_at=event.at,
            deadline=(opened + timedelta(hours=deadline_hours)).isoformat(),
            note=f"{kind}须在 {deadline_hours} 小时内完成",
        )

    def _notify(self, event: Event, message: str, to: str | None) -> None:
        self.s.notifications.append({
            "type": "notification", "at": event.at, "message": message,
            "to": to, "trigger_event": event.seq,
        })


def fold(events: Iterable[Event], upto_seq: int | None = None) -> Snapshot:
    """把事件流折叠为快照；``upto_seq`` 用于历史时点重放。"""
    projector = Projector()
    snapshot = projector.s
    for event in events:
        if upto_seq is not None and event.seq > upto_seq:
            break
        snapshot = projector.apply(event)
    return snapshot


# ---------------------------------------------------------------------------
# 聚合根：责任链服务
# ---------------------------------------------------------------------------

class ResponsibilityChainService:
    """命令侧：校验业务规则并把事实写成只增事件。"""

    def __init__(self, project_id: str | None = None, *, clock: Callable[[], datetime] | None = None):
        self.project_id = project_id
        self._events: list[Event] = []
        self._idempotency: dict[str, int] = {}   # 回调键 -> 已生成事件序号
        self._clock = clock or datetime.now
        self._projector = Projector()
        self._snapshot = self._projector.s

    # -- 基础设施 --------------------------------------------------------

    @property
    def events(self) -> list[Event]:
        return list(self._events)

    @property
    def snapshot(self) -> Snapshot:
        return self._snapshot

    def now(self) -> datetime:
        return self._clock()

    def _raise_if_frozen(self, version_id: str | None = None, *, any_change: bool = False) -> None:
        s = self._snapshot
        if not s.frozen:
            return
        if any_change or (version_id is not None and version_id in s.frozen_versions):
            raise FreezeError(f"素材谱系已因「{s.frozen_reason}」冻结，禁止变更")

    def _record(self, kind: str, actor_id: str, payload: dict[str, Any],
                *, idempotency_key: str | None = None) -> Event:
        """追加事件；相同幂等键的重复回调直接返回首次事件，不重复生成记录。"""
        if idempotency_key is not None:
            first_seq = self._idempotency.get(idempotency_key)
            if first_seq is not None:
                return self._events[first_seq - 1]
        at = self._tick()
        seq = len(self._events) + 1
        prev = self._events[-1].hash if self._events else GENESIS_HASH
        digest = Event.digest(kind, at, actor_id, payload, idempotency_key, prev)
        event = Event(seq, kind, at, actor_id, payload, idempotency_key, prev, digest)
        self._events.append(event)
        self._snapshot = self._projector.apply(event)
        if idempotency_key is not None:
            self._idempotency[idempotency_key] = seq
        return event

    def _tick(self) -> str:
        """单调时钟：外部时钟回拨时不允许时间倒流。"""
        now = self._clock().replace(microsecond=0)
        if self._snapshot.clock is not None:
            last = _parse_at(self._snapshot.clock)
            if now <= last:
                now = last + timedelta(seconds=1)
        return now.isoformat()

    # -- 命令 ------------------------------------------------------------

    def initiate_project(self, actor_id: str, project_id: str, brand: str,
                         category: str, medical: bool = False,
                         *, roles: dict[str, Role] | None = None) -> Event:
        if self._events:
            raise DomainError("项目已立项")
        event = self._record("ProjectInitiated", actor_id, {
            "project_id": project_id, "brand": brand,
            "category": category, "medical": medical,
        })
        self.project_id = project_id
        return event

    def register_qualification(self, actor_id: str, qualification_id: str,
                               product: str, doc_ref: str, valid_until: str,
                               proven_facts: list[str]) -> Event:
        return self._record("QualificationRegistered", actor_id, {
            "qualification_id": qualification_id, "product": product,
            "doc_ref": doc_ref, "valid_until": valid_until,
            "proven_facts": list(proven_facts),
        })

    def register_digital_human(self, actor_id: str, human_id: str,
                               provider: str, real_person: str,
                               authorization_ref: str,
                               authorization_valid_until: str) -> Event:
        return self._record("DigitalHumanRegistered", actor_id, {
            "human_id": human_id, "provider": provider,
            "real_person": real_person,
            "authorization_ref": authorization_ref,
            "authorization_valid_until": authorization_valid_until,
        })

    def create_asset(self, actor_id: str, asset_id: str, asset_kind: str,
                     title: str, qualification_id: str | None = None,
                     human_id: str | None = None) -> Event:
        return self._record("AssetCreated", actor_id, {
            "asset_id": asset_id, "asset_kind": asset_kind, "title": title,
            "qualification_id": qualification_id, "human_id": human_id,
        })

    def submit_version(self, actor_id: str, version_id: str, asset_id: str,
                       asset_kind: str, *, parent_version: str | None = None,
                       derived_from: list[str] | None = None,
                       human_id: str | None = None,
                       qualification_id: str | None = None,
                       claimed_facts: list[str] | None = None,
                       changed_facts: list[str] | None = None,
                       medical: bool = False, truth_owner: str | None = None,
                       reviewer_hint: str | None = None,
                       review_deadline_hours: int = 72,
                       content_hash: str = "") -> Event:
        self._raise_if_frozen(parent_version)
        if asset_id not in self._snapshot.assets:
            raise DomainError(f"素材 {asset_id} 不存在，请先建档")
        if version_id in self._snapshot.versions:
            raise DomainError(f"版本 {version_id} 已存在")
        if parent_version and parent_version not in self._snapshot.versions:
            raise DomainError("父版本不存在，素材衍生谱系断裂")
        for source in derived_from or ():
            if source not in self._snapshot.versions:
                raise DomainError(f"衍生来源版本 {source} 不存在")
        if medical and not (human_id and qualification_id):
            raise MedicalGateError("医疗素材必须绑定数字人身份与产品资质")
        return self._record("VersionSubmitted", actor_id, {
            "version_id": version_id, "asset_id": asset_id,
            "asset_kind": asset_kind, "parent_version": parent_version,
            "derived_from": list(derived_from or ()), "human_id": human_id,
            "qualification_id": qualification_id,
            "claimed_facts": list(claimed_facts or ()),
            "changed_facts": list(changed_facts or ()),
            "medical": medical, "content_hash": content_hash,
            "truth_owner": truth_owner, "reviewer_hint": reviewer_hint,
            "review_deadline_hours": review_deadline_hours,
        })

    def check_medical_identity(self, actor_id: str, version_id: str,
                               authorized: bool, verdict: str,
                               evidence_refs: list[str]) -> Event:
        """医疗前置核验之一：核对数字人身份授权（肖像/声音/名义授权在有效期内）。"""
        self._require_version(version_id)
        self._raise_if_frozen(version_id)
        return self._record("MedicalIdentityChecked", actor_id, {
            "version_id": version_id, "authorized": authorized,
            "verdict": verdict, "evidence_refs": list(evidence_refs),
        })

    def verify_product_facts(self, actor_id: str, version_id: str,
                             verified: bool, verdict: str,
                             matched_facts: list[str],
                             unmatched_facts: list[str]) -> Event:
        """医疗前置核验之二：脚本宣称与可证明的商品事实逐条比对。"""
        version = self._require_version(version_id)
        self._raise_if_frozen(version_id)
        qualification = self._snapshot.qualifications.get(
            version.qualification_id
            or self._snapshot.assets[version.asset_id].get("qualification_id")
            or "")
        if qualification is None:
            raise MedicalGateError("缺少产品资质，无法核对可证明的商品事实")
        if verified and unmatched_facts:
            raise MedicalGateError("存在无法证明的宣称，不得核验通过")
        return self._record("ProductFactsVerified", actor_id, {
            "version_id": version_id, "verified": verified, "verdict": verdict,
            "matched_facts": list(matched_facts),
            "unmatched_facts": list(unmatched_facts),
        })

    def conclude_review(self, actor_id: str, version_id: str, scope: str,
                        decision: str, comment: str, *,
                        roles: dict[str, Role] | None = None,
                        as_role: Role | None = None) -> Event:
        """登记复核意见。提交者不得批准自己的内容（职责分离）。"""
        version = self._require_version(version_id)
        self._raise_if_frozen(version_id)
        if decision not in {"approved", "rejected", "changes_requested"}:
            raise DomainError("复核结论无效")
        if actor_id == version.submitted_by and decision == "approved":
            raise SeparationError("提交者不得批准自己提交的内容")
        role = as_role or (roles or {}).get(actor_id)
        if role is not Role.PLATFORM_REVIEWER:
            raise AuthorizationError("只有平台审核可以出具复核结论")
        if decision == "approved" and version.medical:
            if not (version.identity_authorized and version.product_facts_verified):
                raise MedicalGateError("医疗内容必须先通过身份授权与商品事实前置核验")
        return self._record("ReviewConcluded", actor_id, {
            "version_id": version_id, "scope": scope,
            "decision": decision, "comment": comment,
        })

    def approve_release(self, actor_id: str, version_id: str,
                        decision_id: str, *, roles: dict[str, Role] | None = None,
                        as_role: Role | None = None,
                        enforce_deadline: bool = True) -> Event:
        """放行决定：门禁全绿才能生成；复核人与提交人不得为同一人。"""
        version = self._require_version(version_id)
        self._raise_if_frozen(version_id)
        if actor_id == version.submitted_by:
            raise SeparationError("提交者不得批准自己的内容")
        role = as_role or (roles or {}).get(actor_id)
        if role is not Role.PLATFORM_REVIEWER:
            raise AuthorizationError("只有平台审核可以放行")
        if version.reviewed_by is None or "release" not in version.review_verdicts:
            raise GateError("缺少发布前复核意见")
        if version.review_verdicts.get("release") != "approved":
            raise GateError("复核未通过，不得放行")
        if version.medical and not (version.identity_authorized
                                   and version.product_facts_verified):
            raise MedicalGateError("医疗前置核验未全部通过")
        pending = self._snapshot.pending.get(("review", version_id))
        if enforce_deadline and pending is not None and pending.overdue(self.now()):
            raise DeadlineError(f"复核已超过期限 {pending.deadline}，需重新发起审批")
        return self._record("ReleaseApproved", actor_id, {
            "decision_id": decision_id, "version_id": version_id,
            "medical": version.medical,
            "identity_authorized": version.identity_authorized,
            "product_facts_verified": version.product_facts_verified,
            "review_event_seqs": [
                self._snapshot.reviews[(version_id, scope)]["seq"]
                for scope in version.review_verdicts
                if (version_id, scope) in self._snapshot.reviews
            ],
        })

    def purchase_traffic(self, actor_id: str, order_id: str, version_id: str,
                         channel: str, budget: int, *,
                         roles: dict[str, Role] | None = None,
                         as_role: Role | None = None) -> Event:
        self._require_version(version_id)
        role = as_role or (roles or {}).get(actor_id)
        if role is not Role.ADVERTISER:
            raise AuthorizationError("只有广告主可以购买流量")
        if self._snapshot.versions[version_id].release_decision_id is None:
            raise GateError("未放行版本不得购买流量")
        return self._record("TrafficPurchased", actor_id, {
            "order_id": order_id, "version_id": version_id,
            "channel": channel, "budget": budget,
        })

    def prepare_channel(self, actor_id: str, channel: str,
                        operator_company: str) -> Event:
        return self._record("ChannelPrepared", actor_id, {
            "channel": channel, "operator_company": operator_company,
        })

    def publish(self, actor_id: str, publish_id: str, channel: str,
                version_id: str, callback_key: str | None = None, *,
                roles: dict[str, Role] | None = None,
                as_role: Role | None = None) -> Event:
        """渠道发布：审核中的素材一律拒绝；回调按幂等键去重。"""
        version = self._require_version(version_id)
        role = as_role or (roles or {}).get(actor_id)
        if role is not Role.CHANNEL_OPERATOR:
            raise AuthorizationError("只有渠道运营可以执行发布")
        if self._snapshot.frozen and version_id in self._snapshot.frozen_versions:
            raise FreezeError("素材谱系已冻结，渠道必须撤回并停止传播")
        if version.release_decision_id is None:
            self._record("PublishRejected", actor_id, {
                "publish_id": publish_id, "channel": channel,
                "version_id": version_id,
                "reason": "素材尚未通过发布门禁，渠道不得直接发布",
            }, idempotency_key=f"reject:{callback_key}" if callback_key else None)
            raise GateError("审核中的素材不能被渠道直接发布")
        return self._record("Published", actor_id, {
            "publish_id": publish_id, "channel": channel,
            "version_id": version_id,
        }, idempotency_key=callback_key)

    # -- 投诉 / 撤回 / 调查 ----------------------------------------------

    def file_complaint(self, actor_id: str, complaint_id: str,
                       version_ids: list[str], summary: str) -> Event:
        return self._record("ComplaintFiled", actor_id, {
            "complaint_id": complaint_id, "versions": list(version_ids),
            "summary": summary,
        })

    def request_withdrawal(self, actor_id: str, request_id: str,
                           version_ids: list[str], reason: str) -> Event:
        return self._record("WithdrawalRequested", actor_id, {
            "request_id": request_id, "versions": list(version_ids),
            "reason": reason,
        })

    def open_investigation(self, actor_id: str, case_id: str,
                           version_ids: list[str], *,
                           roles: dict[str, Role] | None = None,
                           as_role: Role | None = None) -> Event:
        role = as_role or (roles or {}).get(actor_id)
        if role is not Role.REGULATOR and role is not Role.AUDITOR:
            raise AuthorizationError("只有监管或审计可以发起调查")
        return self._record("InvestigationOpened", actor_id, {
            "case_id": case_id, "versions": list(version_ids),
        })

    def freeze_lineage(self, actor_id: str, reason: str,
                       trigger_kind: str, trigger_ref: str,
                       *, roles: dict[str, Role] | None = None,
                       as_role: Role | None = None) -> Event:
        """冻结相关素材谱系：确定波及的全部版本（含衍生后代）并关闭其待办。"""
        role = as_role or (roles or {}).get(actor_id)
        if role not in (Role.AUDITOR, Role.REGULATOR, Role.PLATFORM_REVIEWER):
            raise AuthorizationError("审计、监管或平台审核才能冻结责任链")
        versions = self._collect_frozen_versions(trigger_kind, trigger_ref)
        if not versions:
            raise DomainError("冻结范围为空，找不到对应素材")
        return self._record("LineageFrozen", actor_id, {
            "reason": reason, "trigger_kind": trigger_kind,
            "trigger_ref": trigger_ref, "versions": sorted(versions),
        })

    def _collect_frozen_versions(self, trigger_kind: str, trigger_ref: str) -> set[str]:
        s = self._snapshot
        seeds: set[str] = set()
        if trigger_kind == "complaint":
            for event in self._events:
                if event.kind == "ComplaintFiled" and event.payload["complaint_id"] == trigger_ref:
                    seeds.update(event.payload["versions"])
        elif trigger_kind == "withdrawal":
            for event in self._events:
                if event.kind == "WithdrawalRequested" and event.payload["request_id"] == trigger_ref:
                    seeds.update(event.payload["versions"])
        elif trigger_kind == "investigation":
            for event in self._events:
                if event.kind == "InvestigationOpened" and event.payload["case_id"] == trigger_ref:
                    seeds.update(event.payload["versions"])
        elif trigger_kind == "version":
            seeds.add(trigger_ref)
        # 沿 derived_from / parent_version 向上找根，再向下收集整棵衍生子树。
        roots = set(seeds)
        changed = True
        while changed:
            changed = False
            for vid in list(roots):
                parent = s.versions[vid].parent_version
                if parent and parent not in roots:
                    roots.add(parent)
                    changed = True
        frozen: set[str] = set()
        stack = list(roots)
        while stack:
            vid = stack.pop()
            if vid in frozen:
                continue
            frozen.add(vid)
            for other in s.versions.values():
                if other.parent_version == vid or vid in other.derived_from:
                    stack.append(other.version_id)
        return frozen

    # -- 查询 ------------------------------------------------------------

    def freeze_report(self) -> dict[str, Any]:
        """冻结后给出：仍在传播的渠道、待补材料、责任缺口。"""
        s = self._snapshot
        if not s.frozen:
            raise DomainError("责任链尚未冻结")
        frozen = s.frozen_versions
        active_channels: dict[str, list[str]] = {}
        for record in s.publishes:
            if record.get("rejected"):
                continue
            if record["version_id"] in frozen:
                active_channels.setdefault(record["channel"], []).append(
                    record["version_id"])
        missing: list[str] = []
        responsibility_gaps: list[str] = []
        for vid in sorted(frozen):
            v = s.versions[vid]
            asset = s.assets.get(v.asset_id, {})
            bound_qualification = v.qualification_id or asset.get("qualification_id")
            bound_human = v.human_id or asset.get("human_id")
            if v.medical:
                if not v.identity_authorized:
                    missing.append(f"{vid}: 数字人身份授权证据缺失或未核验")
                if not v.product_facts_verified:
                    missing.append(f"{vid}: 可证明商品事实核对缺失")
            if not bound_qualification:
                missing.append(f"{vid}: 未绑定产品资质")
            if v.asset_kind == "数字人视频" and not bound_human:
                missing.append(f"{vid}: 未登记数字人身份来源")
            if v.reviewed_by is None:
                responsibility_gaps.append(f"{vid}: 无复核人，内容真实性责任悬空")
            elif v.truth_owner is None:
                responsibility_gaps.append(f"{vid}: 未指定内容真实性责任人")
            if v.release_decision_id is None and _published(s, vid):
                responsibility_gaps.append(
                    f"{vid}: 无放行决定却存在发布记录，门禁被绕过")
        return {
            "reason": s.frozen_reason,
            "frozen_at": s.frozen_at,
            "frozen_versions": sorted(frozen),
            "still_propagating": {
                channel: sorted(set(vids)) for channel, vids in active_channels.items()
            },
            "pending_materials": sorted(set(missing)),
            "responsibility_gaps": sorted(set(responsibility_gaps)),
        }

    def pending_on_restart(self) -> list[dict[str, Any]]:
        """服务重启后：未完成审批与通知按原期限继续（直接来自重放后的待办表）。"""
        now = self.now()
        items = []
        for item in self._snapshot.pending.values():
            items.append({
                "kind": item.kind, "version_id": item.version_id,
                "opened_at": item.opened_at, "deadline": item.deadline,
                "overdue": item.overdue(now), "note": item.note,
            })
        return sorted(items, key=lambda x: x["deadline"])

    def replay_release_at(self, version_id: str, *, at_seq: int | None = None,
                          at_time: str | None = None) -> dict[str, Any]:
        """审计能力：按历史时点重现一次放行决定，复算当时门禁所依据的证据。"""
        target_seq = at_seq
        if at_time is not None:
            target_seq = 0
            for event in self._events:
                if event.at <= at_time:
                    target_seq = event.seq
        if target_seq is None:
            approvals = [e for e in self._events
                         if e.kind == "ReleaseApproved"
                         and e.payload["version_id"] == version_id]
            if not approvals:
                raise DomainError("该版本没有放行决定可重放")
            target_seq = approvals[0].seq
        historical = fold(self._events, target_seq)
        version = historical.versions.get(version_id)
        if version is None:
            raise DomainError("该时点版本尚不存在")
        decision = None
        if version.release_decision_id:
            decision = historical.releases.get(version.release_decision_id)
        evidence = {
            "version": version.version_id,
            "submitted_by": version.submitted_by,
            "reviewed_by": version.reviewed_by,
            "truth_owner": version.truth_owner,
            "medical": version.medical,
            "identity_authorized": version.identity_authorized,
            "product_facts_verified": version.product_facts_verified,
            "review_verdicts": dict(version.review_verdicts),
            "lineage": self._lineage_as_of(historical, version_id),
        }
        checks = {
            "放行决定已存在": version.release_decision_id is not None,
            "复核存在且通过": version.review_verdicts.get("release") == "approved",
            "提交与复核分离": (version.reviewed_by is not None
                          and version.reviewed_by != version.submitted_by),
        }
        if version.medical:
            checks["身份授权已核验"] = version.identity_authorized
            checks["商品事实已证明"] = version.product_facts_verified
        return {
            "as_of_event_seq": target_seq,
            "as_of_time": self._events[target_seq - 1].at if target_seq else None,
            "release_decision": decision,
            "evidence": evidence,
            "gate_checks": checks,
            "would_release_now": all(checks.values()),
        }

    def affected_versions_on_change(self, changed_version: str) -> dict[str, Any]:
        """修改脚本或更换数字人时，只重算受影响结论：下游衍生版本及其失效项。"""
        s = self._snapshot
        if changed_version not in s.versions:
            raise DomainError("版本不存在")
        impacted: set[str] = set()
        stack = [changed_version]
        while stack:
            vid = stack.pop()
            for other in s.versions.values():
                if other.parent_version == vid or vid in other.derived_from:
                    if other.version_id not in impacted:
                        impacted.add(other.version_id)
                        stack.append(other.version_id)
        result = {}
        for vid in sorted(impacted | {changed_version}):
            v = s.versions[vid]
            stale = []
            if v.medical and not v.identity_authorized:
                stale.append("身份授权结论")
            if v.medical and not v.product_facts_verified:
                stale.append("商品事实结论")
            if changed_version != vid and v.release_decision_id is not None:
                stale.append("放行决定需基于新证据重新出具")
            result[vid] = {
                "needs_recheck": bool(stale) or vid in impacted,
                "invalidated_conclusions": stale,
                "published": _published(s, vid),
                "evidence_retained": True,   # 已上线版本保留当时证据与责任
            }
        return result

    def view_as(self, role: Role) -> dict[str, Any]:
        """职责内信息视图：角色只能看到授权范围内的信息域。"""
        allowed = SCOPES[role]
        s = self._snapshot

        def gated(name: str, value: Any) -> dict[str, Any]:
            return {name: value} if name in allowed else {}

        view: dict[str, Any] = {"role": role.value, "project_id": s.project_id}
        view.update(gated("project", {"frozen": s.frozen, "clock": s.clock}))
        view.update(gated("qualification", list(s.qualifications.values())))
        view.update(gated("identity", list(s.digital_humans.values())))
        view.update(gated("asset", [
            {"asset_id": a["asset_id"], "kind": a["asset_kind"],
             "head_version": s.heads.get(a["asset_id"])}
            for a in s.assets.values()
        ]))
        if "review" in allowed:
            view["versions"] = [self._version_view(v) for v in s.versions.values()]
        view.update(gated("traffic", list(s.traffic_purchases.values())))
        view.update(gated("publish", s.publishes))
        view.update(gated("freeze", {
            "frozen": s.frozen, "reason": s.frozen_reason,
            "versions": sorted(s.frozen_versions),
        }))
        if "gap" in allowed and s.frozen:
            view["gap_report"] = self.freeze_report()
        if "audit" in allowed:
            view["audit"] = {
                "event_count": s.events, "tip_hash": s.tip_hash,
                "pending": self.pending_on_restart(),
            }
        return view

    def _version_view(self, v: VersionState) -> dict[str, Any]:
        return {
            "version_id": v.version_id, "asset_id": v.asset_id,
            "parent_version": v.parent_version,
            "derived_from": list(v.derived_from),
            "submitted_by": v.submitted_by, "reviewed_by": v.reviewed_by,
            "truth_owner": v.truth_owner, "medical": v.medical,
            "identity_authorized": v.identity_authorized,
            "product_facts_verified": v.product_facts_verified,
            "release_decision_id": v.release_decision_id,
            "released_at": v.released_at, "superseded_at": v.superseded_at,
            "verdicts": dict(v.review_verdicts),
        }

    # -- 持久化与重放 ----------------------------------------------------

    def save(self, path: str | Path) -> None:
        """把事件流落盘；重启后用 load 重建全部状态与期限。"""
        data = {
            "project_id": self.project_id,
            "events": [e.to_dict() for e in self._events],
        }
        Path(path).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, *, clock: Callable[[], datetime] | None = None) -> "ResponsibilityChainService":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        service = cls(data.get("project_id"), clock=clock)
        for raw in data["events"]:
            event = Event.from_dict(raw)
            expected = Event.digest(
                event.kind, event.at, event.actor_id, event.payload,
                event.idempotency_key, event.prev_hash)
            if event.hash != expected:
                raise DomainError(f"事件 {event.seq} 摘要不匹配，事件流可能被篡改")
            prev = service._events[-1].hash if service._events else GENESIS_HASH
            if event.prev_hash != prev:
                raise DomainError(f"事件 {event.seq} 哈希链断裂")
            service._events.append(event)
            service._snapshot = service._projector.apply(event)
            if event.idempotency_key is not None:
                service._idempotency[event.idempotency_key] = event.seq
        return service

    # -- 内部工具 --------------------------------------------------------

    def _require_version(self, version_id: str) -> VersionState:
        version = self._snapshot.versions.get(version_id)
        if version is None:
            raise DomainError(f"版本 {version_id} 不存在")
        return version

    def _lineage_as_of(self, snapshot: Snapshot, version_id: str) -> list[str]:
        chain: list[str] = []
        current: str | None = version_id
        while current:
            chain.append(current)
            current = snapshot.versions[current].parent_version
        chain.reverse()
        return chain


def _published(snapshot: Snapshot, version_id: str) -> bool:
    return any(not r.get("rejected") and r["version_id"] == version_id
               for r in snapshot.publishes)
