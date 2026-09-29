"""事件投影：把只追加事件归约为责任链当前状态。

每个素材版本独立保留提交者、复核者、真实性责任人与证据指纹；
已放行版本在放行事件里固化当时的证据快照，后续改动不会回写历史。
"""

from __future__ import annotations

from typing import Any, Callable

from .events import Event


def _blank_state() -> dict[str, Any]:
    return {
        "projects": {},
        "actors": {},
        "qualifications": {},
        "scripts": {},
        "avatars": {},
        "materials": {},
        "opinions": {},
        "conclusions": {},
        "truth": {},
        "releases": {},
        "publishes": {},
        "callbacks": {},
        "traffic": [],
        "freezes": {},
        "review_tasks": {},
        "notifications": {},
    }


def apply(state: dict[str, Any], event: Event) -> dict[str, Any]:
    """归约单个事件；未知事件忽略以保证向前兼容。"""
    if not state:
        state.update(_blank_state())
    kind = event.kind
    p = event.payload
    if kind == "actor_registered":
        state["actors"][p["actor_id"]] = {
            "name": p["name"],
            "role": p["role"],
            "org": p.get("org", ""),
            "seq": event.seq,
        }
    elif kind == "project_created":
        state["projects"][p["project_id"]] = {
            "name": p["name"],
            "medical": p["medical"],
            "required_approver_roles": list(p.get("required_approver_roles", ["平台审核人员"])),
            "created_seq": event.seq,
            "created_ts": event.timestamp,
        }
    elif kind == "qualification_registered":
        state["qualifications"][p["project_id"]] = {
            "facts": {f["fact_id"]: f for f in p["facts"]},
            "registered_by": event.source,
            "seq": event.seq,
        }
    elif kind == "script_submitted":
        state["scripts"].setdefault(p["project_id"], {})[p["version"]] = {
            "parent": p.get("parent"),
            "content_hash": p["content_hash"],
            "claims": list(p.get("claims", [])),
            "submitter": p["submitter"],
            "seq": event.seq,
            "ts": event.timestamp,
        }
    elif kind == "avatar_registered":
        state["avatars"].setdefault(p["project_id"], {})[p["version"]] = {
            "parent": p.get("parent"),
            "generator": p["generator"],
            "identity_subject": p["identity_subject"],
            "authorization_ref": p.get("authorization_ref", ""),
            "authorization_valid_until": p.get("authorization_valid_until"),
            "submitter": p["submitter"],
            "seq": event.seq,
            "ts": event.timestamp,
        }
    elif kind == "material_built":
        state["materials"].setdefault(p["project_id"], {})[p["version"]] = {
            "parent": p.get("parent"),
            "script_version": p["script_version"],
            "avatar_version": p.get("avatar_version"),
            "content_hash": p["content_hash"],
            "submitter": p["submitter"],
            "seq": event.seq,
            "ts": event.timestamp,
        }
        state["review_tasks"][(p["project_id"], p["version"])] = {
            "submitted_at": event.timestamp,
            "due_at": p["review_due_at"],
            "status": "pending",
        }
    elif kind == "review_opinion_submitted":
        key = (p["project_id"], p["scope"], p["reviewed_ref"])
        state["opinions"].setdefault(key, []).append(
            {
                "reviewer": p["reviewer"],
                "reviewer_role": p["reviewer_role"],
                "opinion": p["opinion"],
                "note": p.get("note", ""),
                "seq": event.seq,
                "ts": event.timestamp,
            }
        )
    elif kind == "conclusion_recorded":
        key = (p["project_id"], p["material_version"])
        state["conclusions"].setdefault(key, {})[p["code"]] = {
            "passed": p["passed"],
            "detail": p["detail"],
            "basis": list(p["basis"]),
            "inherited_from": p.get("inherited_from"),
            "seq": event.seq,
            "ts": event.timestamp,
        }
    elif kind == "truth_responsibility_declared":
        state["truth"][(p["project_id"], p["material_version"])] = {
            "responsible": p["responsible"],
            "seq": event.seq,
            "ts": event.timestamp,
        }
    elif kind == "release_granted":
        key = (p["project_id"], p["material_version"])
        state["releases"][key] = {
            "gate": dict(p["gate"]),
            "evidence": dict(p["evidence"]),
            "decider": p["decider"],
            "seq": event.seq,
            "ts": event.timestamp,
        }
        task = state["review_tasks"].get(key)
        if task is not None:
            task["status"] = "done"
    elif kind == "release_rejected":
        key = (p["project_id"], p["material_version"])
        # 拒绝尝试只作证据记录，待审任务保持 pending，补正后按原期限继续
        task = state["review_tasks"].setdefault(
            key, {"submitted_at": event.timestamp, "due_at": None, "status": "pending"}
        )
        task["last_rejection_seq"] = event.seq
        task["last_rejection"] = list(p.get("failures", []))
    elif kind == "channel_publish_registered":
        key = (p["project_id"], p["material_version"])
        state["publishes"].setdefault(key, {})[p["channel_id"]] = {
            "callback_id": p["callback_id"],
            "operator": p["operator"],
            "status": "live",
            "seq": event.seq,
            "ts": event.timestamp,
        }
        state["callbacks"][p["callback_id"]] = {
            "project_id": p["project_id"],
            "material_version": p["material_version"],
            "channel_id": p["channel_id"],
            "seq": event.seq,
        }
    elif kind == "channel_status_callback":
        publish = state["publishes"].get(
            (p["project_id"], p["material_version"]), {}
        ).get(p["channel_id"])
        if publish is not None:
            publish["status"] = p["status"]
            publish["status_ts"] = event.timestamp
        state["callbacks"][p["callback_id"]] = {
            "project_id": p["project_id"],
            "material_version": p["material_version"],
            "channel_id": p["channel_id"],
            "seq": event.seq,
        }
    elif kind == "traffic_purchase_recorded":
        state["traffic"].append(
            {
                "project_id": p["project_id"],
                "material_version": p["material_version"],
                "channel_id": p["channel_id"],
                "traffic_ref": p["traffic_ref"],
                "spend": p.get("spend"),
                "seq": event.seq,
                "ts": event.timestamp,
            }
        )
    elif kind == "freeze_issued":
        state["freezes"][p["project_id"]] = {
            "reason": p["reason"],
            "versions": list(p.get("versions", [])),
            "note": p.get("note", ""),
            "seq": event.seq,
            "ts": event.timestamp,
            "active": True,
        }
    elif kind == "freeze_released":
        freeze = state["freezes"].get(p["project_id"])
        if freeze is not None:
            freeze["active"] = False
    elif kind == "notification_raised":
        state["notifications"][p["id"]] = {
            "to_role": p["to_role"],
            "to_actor": p.get("to_actor"),
            "message": p["message"],
            "ref": p.get("ref"),
            "due_at": p["due_at"],
            "delivered": False,
            "created_ts": event.timestamp,
            "seq": event.seq,
        }
    elif kind == "notification_delivered":
        notification = state["notifications"].get(p["id"])
        if notification is not None:
            notification["delivered"] = True
            notification["delivered_ts"] = event.timestamp
    return state


def projection(store, *, at_time: float | None = None) -> dict[str, Any]:
    """从事件存储重放得到状态；可截到某历史时点。"""
    return store.replay(apply, at_time=at_time, initial=_blank_state())
