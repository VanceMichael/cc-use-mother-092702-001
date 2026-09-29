"""数字广告责任链与发布门禁的端到端领域测试。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.events import EventStore
from src.roles import AccessDeniedError, Role
from src.service import AccountabilityService, DomainError

NOW = 1_000_000.0
DAY = 86400.0


class Clock:
    def __init__(self, value: float = NOW):
        self.value = value

    def __call__(self) -> float:
        return self.value


class ServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.svc = AccountabilityService(clock=self.clock)
        self._register_actors()

    def _register_actors(self) -> None:
        self.svc.register_actor("adv", "品牌广告主", Role.ADVERTISER, org="健康品牌")
        self.svc.register_actor("outsource", "外包脚本团队", Role.PRODUCER, org="制作公司")
        self.svc.register_actor("reviewer", "平台审核员甲", Role.PLATFORM_REVIEWER)
        self.svc.register_actor("operator", "渠道代运营", Role.CHANNEL_OPERATOR)
        self.svc.register_actor("auditor", "审计员", Role.AUDITOR)

    def _medical_project_ready(self, *, auth_until: float = NOW + 365 * DAY) -> str:
        """搭好一个医疗项目，素材 v1 已放行、已发布。"""
        svc = self.svc
        svc.create_project("adv", "P1", "保健饮品广告", medical=True)
        svc.register_qualification(
            "adv",
            "P1",
            [
                {
                    "fact_id": "F1",
                    "text": "每瓶含维生素C 100mg",
                    "proof_ref": "doc://F1.pdf",
                    "proof_hash": "h-f1",
                }
            ],
        )
        svc.submit_script(
            "outsource",
            "P1",
            "s1",
            "hash-script-s1",
            claims=[{"fact_id": "F1", "claim": "补充每日维生素C"}],
        )
        svc.register_avatar(
            "outsource",
            "P1",
            "a1",
            identity_subject="张医生",
            generator="数字人公司A",
            authorization_ref="doc://auth-zhang.pdf",
            authorization_valid_until=auth_until,
        )
        svc.build_material(
            "outsource",
            "P1",
            "v1",
            "hash-v1",
            script_version="s1",
            avatar_version="a1",
            review_due_at=NOW + 7 * DAY,
        )
        svc.submit_review_opinion("reviewer", "P1", "script", "s1", "approve")
        svc.submit_review_opinion("reviewer", "P1", "avatar", "a1", "approve")
        svc.declare_truth_responsibility("adv", "P1", "v1", "adv")
        svc.grant_release("reviewer", "P1", "v1")
        svc.register_publish("operator", "P1", "v1", "channel-x", "cb-1")
        svc.record_traffic_purchase("operator", "P1", "v1", "channel-x", "traffic-1", spend=5000)
        return "P1"

    # ---- 放行门禁 ----

    def test_full_medical_chain_releases_and_publishes(self) -> None:
        self._medical_project_ready()
        release = self.svc.state["releases"][("P1", "v1")]
        self.assertEqual(release["decider"], "reviewer")
        self.assertEqual(release["evidence"]["script"]["content_hash"], "hash-script-s1")
        self.assertEqual(release["evidence"]["avatar"]["generator"], "数字人公司A")
        self.assertEqual(release["evidence"]["truth_responsible"], "adv")
        publish = self.svc.state["publishes"][("P1", "v1")]["channel-x"]
        self.assertEqual(publish["status"], "live")

    def test_channel_cannot_publish_unreleased_material(self) -> None:
        self.svc.create_project("adv", "P2", "普通食品广告", medical=False)
        self.svc.register_qualification(
            "adv",
            "P2",
            [{"fact_id": "F1", "text": "事实", "proof_ref": "d", "proof_hash": "h"}],
        )
        self.svc.submit_script("outsource", "P2", "s1", "hs", claims=[{"fact_id": "F1"}])
        self.svc.build_material("outsource", "P2", "v1", "hv", script_version="s1")
        with self.assertRaisesRegex(DomainError, "尚未通过放行"):
            self.svc.register_publish("operator", "P2", "v1", "ch", "cb")

    def test_medical_requires_identity_authorization_and_provable_facts(self) -> None:
        self.svc.create_project("adv", "M", "医疗器械广告", medical=True)
        self.svc.register_qualification(
            "adv",
            "M",
            [{"fact_id": "F1", "text": "t", "proof_ref": "d", "proof_hash": "h"}],
        )
        self.svc.submit_script("outsource", "M", "s1", "hs", claims=[{"fact_id": "F1"}])
        self.svc.register_avatar(
            "outsource",
            "M",
            "a1",
            identity_subject="李医生",
            generator="数字人公司B",
        )
        self.svc.build_material("outsource", "M", "v1", "hv", script_version="s1", avatar_version="a1")
        gate = self.svc.evaluate("M", "v1")
        self.assertFalse(gate.passed)
        details = [f["detail"] for f in gate.failures]
        self.assertTrue(any("身份授权文件" in d for d in details), details)
        # 补授权后仍需复核与真实性声明；授权过期同样拦截
        self.svc.register_avatar(
            "outsource",
            "M",
            "a2",
            identity_subject="李医生",
            generator="数字人公司B",
            authorization_ref="doc://auth-li.pdf",
            authorization_valid_until=NOW - DAY,
        )
        self.svc.build_material(
            "outsource", "M", "v2", "hv2", script_version="s1", avatar_version="a2", parent="v1"
        )
        conclusions = self.svc.state["conclusions"][("M", "v2")]
        self.assertFalse(conclusions["identity_authorization_verified"]["passed"])

    def test_script_claims_without_proof_fact_are_rejected(self) -> None:
        self.svc.create_project("adv", "M2", "药品广告", medical=True)
        self.svc.register_qualification(
            "adv",
            "M2",
            [{"fact_id": "F1", "text": "t", "proof_ref": "d", "proof_hash": "h"}],
        )
        self.svc.submit_script(
            "outsource", "M2", "s1", "hs", claims=[{"fact_id": "F9", "claim": "包治百病"}]
        )
        self.svc.register_avatar(
            "outsource",
            "M2",
            "a1",
            identity_subject="王医生",
            generator="G",
            authorization_ref="d",
            authorization_valid_until=NOW + DAY,
        )
        self.svc.build_material("outsource", "M2", "v1", "hv", script_version="s1", avatar_version="a1")
        conclusion = self.svc.state["conclusions"][("M2", "v1")]["provable_facts_verified"]
        self.assertFalse(conclusion["passed"])
        self.assertIn("F9", conclusion["detail"])

    def test_submitter_cannot_approve_own_content(self) -> None:
        from src.policy import _component_verdict
        from src.state import _blank_state, apply
        from src.events import Event

        self.svc.create_project("adv", "P3", "广告", medical=False)
        self.svc.submit_script("outsource", "P3", "s1", "hs")
        # 制作方根本无权提交复核意见（角色分离先拦截）
        with self.assertRaises(DomainError):
            self.svc.submit_review_opinion("outsource", "P3", "script", "s1", "approve")
        # 即使同一账号同时具备提交与复核身份，策略层仍拒绝自批
        state = _blank_state()
        apply(
            state,
            Event(
                seq=1,
                timestamp=NOW,
                kind="review_opinion_submitted",
                payload={
                    "project_id": "P3",
                    "scope": "script",
                    "reviewed_ref": "s1",
                    "reviewer": "dual-user",
                    "reviewer_role": Role.PLATFORM_REVIEWER.value,
                    "opinion": "approve",
                },
            ),
        )
        failure = _component_verdict(state, "P3", "script", "s1", "dual-user", "脚本")
        self.assertIsNotNone(failure)
        self.assertEqual(failure["code"], "self_approval")

    def test_conclusion_failure_can_be_recomputed_after_remedy(self) -> None:
        self.svc.create_project("adv", "P4", "食品广告", medical=False)
        self.svc.submit_script(
            "outsource", "P4", "s1", "hs", claims=[{"fact_id": "F1"}]
        )
        self.svc.build_material("outsource", "P4", "v1", "hv", script_version="s1")
        self.assertFalse(self.svc.state["conclusions"][("P4", "v1")]["qualification_verified"]["passed"])
        self.svc.register_qualification(
            "adv",
            "P4",
            [{"fact_id": "F1", "text": "t", "proof_ref": "d", "proof_hash": "h"}],
        )
        results = self.svc.recompute_conclusions("reviewer", "P4", "v1")
        self.assertTrue(results["qualification_verified"]["passed"])
        self.assertTrue(results["provable_facts_verified"]["passed"])

    # ---- 增量结论与历史固化 ----

    def test_script_change_only_recomputes_facts_avatar_change_only_identity(self) -> None:
        self._medical_project_ready()
        svc = self.svc
        # 改脚本：商品事实重算，身份授权自 v1 继承
        svc.submit_script(
            "outsource",
            "P1",
            "s2",
            "hash-script-s2",
            parent="s1",
            claims=[{"fact_id": "F1", "claim": "新表述"}],
        )
        svc.build_material(
            "outsource", "P1", "v2", "hash-v2", script_version="s2", avatar_version="a1", parent="v1"
        )
        v2 = svc.state["conclusions"][("P1", "v2")]
        # 身份授权在 a1 未变时直接继承自 v1（basis 相同）
        inherited = v2["identity_authorization_verified"]["inherited_from"]
        self.assertIsNotNone(inherited)
        self.assertEqual(inherited["material_version"], "v1")
        # 脚本已换 s2，商品事实必须重算，不得继承
        self.assertIsNone(v2["provable_facts_verified"]["inherited_from"])
        # 产品资质同样未变，自 v1 继承
        self.assertEqual(v2["qualification_verified"]["inherited_from"]["material_version"], "v1")
        # 脚本复核按组件版本覆盖：s2 尚未复核，v2 门禁不通过；a1 的复核沿用
        svc.submit_review_opinion("reviewer", "P1", "script", "s2", "approve")
        svc.declare_truth_responsibility("adv", "P1", "v2", "adv")
        gate = svc.grant_release("reviewer", "P1", "v2")
        self.assertEqual(gate["script"]["content_hash"], "hash-script-s2")

        # 换数字人：身份授权重算，商品事实因脚本未变而继承
        svc.register_avatar(
            "outsource",
            "P1",
            "a2",
            identity_subject="赵医生",
            generator="数字人公司C",
            authorization_ref="doc://auth-zhao.pdf",
            authorization_valid_until=NOW + 30 * DAY,
            parent="a1",
        )
        svc.build_material(
            "outsource", "P1", "v3", "hash-v3", script_version="s2", avatar_version="a2", parent="v2"
        )
        v3 = svc.state["conclusions"][("P1", "v3")]
        self.assertIsNone(v3["identity_authorization_verified"]["inherited_from"])
        self.assertEqual(
            v3["provable_facts_verified"]["inherited_from"]["material_version"], "v2"
        )

    def test_released_version_keeps_evidence_after_later_changes(self) -> None:
        self._medical_project_ready()
        self.svc.submit_script("outsource", "P1", "s2", "hash-script-s2", parent="s1", claims=[])
        self.svc.build_material(
            "outsource", "P1", "v2", "hash-v2", script_version="s2", avatar_version="a1", parent="v1"
        )
        v1_release = self.svc.state["releases"][("P1", "v1")]
        self.assertEqual(v1_release["evidence"]["script"]["content_hash"], "hash-script-s1")
        self.assertEqual(v1_release["evidence"]["material"]["content_hash"], "hash-v1")

    # ---- 幂等回调 ----

    def test_duplicate_callbacks_do_not_duplicate_publish_records(self) -> None:
        self._medical_project_ready()
        before = len(self.svc.store.events)
        first = self.svc.register_publish("operator", "P1", "v1", "channel-y", "cb-dup")
        self.assertFalse(first["deduplicated"])
        second = self.svc.register_publish("operator", "P1", "v1", "channel-y", "cb-dup")
        self.assertTrue(second["deduplicated"])
        after = len(self.svc.store.events)
        self.assertEqual(after - before, 1)

        result = self.svc.channel_status_callback(
            "operator",
            "cb-status-1",
            "taken_down",
            project_id="P1",
            material_version="v1",
            channel_id="channel-x",
        )
        self.assertFalse(result["deduplicated"])
        repeat = self.svc.channel_status_callback(
            "operator",
            "cb-status-1",
            "taken_down",
            project_id="P1",
            material_version="v1",
            channel_id="channel-x",
        )
        self.assertTrue(repeat["deduplicated"])
        self.assertEqual(
            self.svc.state["publishes"][("P1", "v1")]["channel-x"]["status"], "taken_down"
        )

    # ---- 冻结与责任报告 ----

    def test_freeze_blocks_lineage_and_reports_live_channels_and_gaps(self) -> None:
        self._medical_project_ready()
        svc = self.svc
        # 再加一个缺少真实性责任人的版本，制造责任缺口
        svc.submit_script(
            "outsource", "P1", "s9", "hash-s9", parent="s1", claims=[{"fact_id": "F1"}]
        )
        svc.build_material(
            "outsource", "P1", "v9", "hash-v9", script_version="s9", avatar_version="a1", parent="v1"
        )
        svc.issue_freeze("reviewer", "P1", "监管调查", note="接到监管问询")
        with self.assertRaisesRegex(DomainError, "冻结"):
            svc.submit_script("outsource", "P1", "s10", "hash-s10")
        with self.assertRaisesRegex(DomainError, "冻结"):
            svc.register_publish("operator", "P1", "v1", "channel-z", "cb-z")

        report = svc.freeze_report("reviewer", "P1")
        self.assertTrue(report["freeze"]["active"])
        self.assertEqual(report["freeze"]["reason"], "监管调查")
        live = {(c["material_version"], c["channel_id"]) for c in report["live_channels"]}
        self.assertIn(("v1", "channel-x"), live)
        gap_versions = {g["material_version"] for g in report["liability_gaps"]}
        self.assertIn("v9", gap_versions)
        pending_versions = {m["material_version"] for m in report["pending_materials"]}
        self.assertIn("v9", pending_versions)

        # 冻结期间仍允许渠道状态回调（配合撤回下架），解除后恢复发布
        svc.channel_status_callback(
            "operator",
            "cb-down-x",
            "taken_down",
            project_id="P1",
            material_version="v1",
            channel_id="channel-x",
        )
        svc.release_freeze("reviewer", "P1")
        svc.register_publish("operator", "P1", "v1", "channel-z", "cb-z")

    def test_complaint_freeze_is_advertiser_only_and_covers_descendants(self) -> None:
        self._medical_project_ready()
        svc = self.svc
        # v2 是 v1 的衍生版本；只冻结 v1 也应覆盖 v2
        svc.submit_script(
            "outsource", "P1", "s2", "hash-s2", parent="s1", claims=[{"fact_id": "F1"}]
        )
        svc.build_material(
            "outsource", "P1", "v2", "hash-v2", script_version="s2", avatar_version="a1", parent="v1"
        )
        with self.assertRaisesRegex(DomainError, "广告主"):
            svc.issue_freeze("reviewer", "P1", "投诉")
        svc.issue_freeze("adv", "P1", "投诉", versions=["v1"])
        report = svc.freeze_report("adv", "P1")
        live = {c["material_version"] for c in report["live_channels"]}
        pending = {m["material_version"] for m in report["pending_materials"]}
        self.assertIn("v1", live)
        self.assertIn("v2", pending)
        with self.assertRaisesRegex(DomainError, "冻结"):
            svc.register_publish("operator", "P1", "v2", "ch-new", "cb-new")
        with self.assertRaisesRegex(DomainError, "广告主"):
            svc.release_freeze("reviewer", "P1")
        svc.release_freeze("adv", "P1")

    # ---- 角色信息边界 ----

    def test_roles_only_access_their_scopes(self) -> None:
        self._medical_project_ready()
        with self.assertRaises(AccessDeniedError):
            self.svc.register_qualification(
                "operator",
                "P1",
                [{"fact_id": "F", "proof_ref": "d", "proof_hash": "h"}],
            )
        with self.assertRaises(AccessDeniedError):
            self.svc.issue_freeze("operator", "P1", "投诉")
        with self.assertRaises(AccessDeniedError):
            self.svc.register_publish("adv", "P1", "v1", "ch", "cb-x")
        with self.assertRaises(AccessDeniedError):
            self.svc.replay_release_decision("reviewer", "P1", "v1", at_time=NOW)
        # 制作机构看不到购买流量
        with self.assertRaises(AccessDeniedError):
            self.svc.record_traffic_purchase("outsource", "P1", "v1", "ch", "t")

    # ---- 重启恢复与审计重放 ----

    def test_restart_keeps_original_deadlines_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            svc = AccountabilityService(path, clock=self.clock)
            svc2_actors(svc)
            svc.create_project("adv", "R1", "广告", medical=False)
            svc.register_qualification(
                "adv",
                "R1",
                [{"fact_id": "F1", "text": "t", "proof_ref": "d", "proof_hash": "h"}],
            )
            svc.submit_script("outsource", "R1", "s1", "hs", claims=[{"fact_id": "F1"}])
            svc.build_material(
                "outsource", "R1", "v1", "hv", script_version="s1", review_due_at=NOW + 2 * DAY
            )
            # 服务重启，时钟推进到期限之后
            self.clock.value = NOW + 10 * DAY
            restarted = AccountabilityService(path, clock=self.clock)
            self.assertIn("R1", restarted.state["projects"])
            due = restarted.due_items("reviewer")
            self.assertEqual(len(due["overdue_reviews"]), 1)
            self.assertEqual(due["overdue_reviews"][0]["due_at"], NOW + 2 * DAY)
            self.assertTrue(due["pending_notifications"][0]["overdue"])
            # 完成审批后通知消失
            restarted.submit_review_opinion("reviewer", "R1", "script", "s1", "approve")
            restarted.declare_truth_responsibility("adv", "R1", "v1", "adv")
            restarted.grant_release("reviewer", "R1", "v1")
            self.assertEqual(restarted.due_items("reviewer")["overdue_reviews"], [])

    def test_auditor_replays_release_at_historical_point(self) -> None:
        self._medical_project_ready()
        # 放行发生在 NOW；在放行前的时点重放，决定不存在且门禁缺复核/责任
        before = self.svc.replay_release_decision("auditor", "P1", "v1", at_time=NOW - 1)
        self.assertFalse(before["release_existed_at_point"])
        self.assertFalse(before["gate_passed_at_point"])
        # 放行后的时点重放：决定存在、证据指纹与当前一致
        after = self.svc.replay_release_decision("auditor", "P1", "v1", at_time=NOW + 1)
        self.assertTrue(after["release_existed_at_point"])
        self.assertTrue(after["gate_passed_at_point"])
        self.assertTrue(after["still_matches_current"])
        self.assertEqual(after["recorded_release"]["evidence_fingerprints"]["material_hash"], "hash-v1")

    def test_non_medical_material_without_avatar_skips_identity_check(self) -> None:
        self.svc.create_project("adv", "N1", "矿泉水广告", medical=False)
        self.svc.register_qualification(
            "adv",
            "N1",
            [{"fact_id": "F1", "text": "t", "proof_ref": "d", "proof_hash": "h"}],
        )
        self.svc.submit_script("outsource", "N1", "s1", "hs", claims=[{"fact_id": "F1"}])
        self.svc.build_material("outsource", "N1", "v1", "hv", script_version="s1")
        self.assertNotIn(
            "identity_authorization_verified", self.svc.state["conclusions"][("N1", "v1")]
        )
        self.svc.submit_review_opinion("reviewer", "N1", "script", "s1", "approve")
        self.svc.declare_truth_responsibility("adv", "N1", "v1", "adv")
        self.svc.grant_release("reviewer", "N1", "v1")


def svc2_actors(svc: AccountabilityService) -> None:
    svc.register_actor("adv", "品牌广告主", Role.ADVERTISER)
    svc.register_actor("outsource", "制作", Role.PRODUCER)
    svc.register_actor("reviewer", "审核", Role.PLATFORM_REVIEWER)
    svc.register_actor("operator", "渠道", Role.CHANNEL_OPERATOR)
    svc.register_actor("auditor", "审计", Role.AUDITOR)


if __name__ == "__main__":
    unittest.main()
