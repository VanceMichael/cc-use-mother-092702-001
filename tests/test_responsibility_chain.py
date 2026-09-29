"""数字广告责任链与发布门禁的领域服务测试。"""

import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from src.responsibility_chain import (
    AuthorizationError,
    DeadlineError,
    DomainError,
    FreezeError,
    GateError,
    MedicalGateError,
    Role,
    SeparationError,
    ResponsibilityChainService,
    fold,
)

# 参与方：广告主、外包制作、数字人供应商、平台审核、渠道代运营、审计/监管
ADVERTISER = "brand-compliance"
PRODUCER = "outsource-script"
HUMAN_PROVIDER = "avatar-vendor"
REVIEWER = "platform-reviewer-a"
REVIEWER_B = "platform-reviewer-b"
OPERATOR = "channel-operator"
AUDITOR = "auditor-1"
REGULATOR = "regulator-1"

ROLES = {
    ADVERTISER: Role.ADVERTISER,
    PRODUCER: Role.PRODUCER,
    HUMAN_PROVIDER: Role.PRODUCER,
    REVIEWER: Role.PLATFORM_REVIEWER,
    REVIEWER_B: Role.PLATFORM_REVIEWER,
    OPERATOR: Role.CHANNEL_OPERATOR,
    AUDITOR: Role.AUDITOR,
    REGULATOR: Role.REGULATOR,
}

BASE = datetime(2026, 9, 1, 9, 0, 0)


class Clock:
    def __init__(self, start=BASE):
        self.t = start

    def now(self):
        return self.t

    def advance(self, **kwargs):
        self.t += timedelta(**kwargs)
        return self.t


class Scenario:
    """搭建一个已完成医疗前置核验、复核与放行的健康品牌项目。"""

    def __init__(self):
        self.clock = Clock()
        self.svc = ResponsibilityChainService(clock=self.clock.now)

    def build(self, *, medical=True, approve=True, release=True,
              publish=True, changed_facts=None, medical_checks=True):
        svc = self.svc
        svc.initiate_project(ADVERTISER, "P-1001", "康馨健康",
                             "医疗器械" if medical else "保健食品", medical)
        svc.register_qualification(
            ADVERTISER, "Q-1", "血压仪 X100", "资质档案://Q-1",
            "2027-12-31", ["经过临床验证", "适用于家庭血压监测"])
        svc.register_digital_human(
            HUMAN_PROVIDER, "H-1", "数字人生成公司", "张某某（本人授权）",
            "授权书://H-1", "2027-06-30")
        svc.create_asset(PRODUCER, "A-1", "数字人视频", "血压仪科普短片",
                         qualification_id="Q-1", human_id="H-1")
        svc.submit_version(
            PRODUCER, "V-1", "A-1", "数字人视频", human_id="H-1",
            qualification_id="Q-1",
            claimed_facts=["经过临床验证", "适用于家庭血压监测"],
            changed_facts=changed_facts or ["脚本初稿", "数字人 H-1"],
            medical=medical, truth_owner=ADVERTISER,
            reviewer_hint=REVIEWER, review_deadline_hours=48,
            content_hash="hash-v1")
        if medical and medical_checks:
            svc.check_medical_identity(
                REVIEWER, "V-1", True, "授权书在有效期内，肖像与声音授权齐全",
                ["授权书://H-1"])
            svc.verify_product_facts(
                REVIEWER, "V-1", True, "宣称与注册备案事实一致",
                ["经过临床验证", "适用于家庭血压监测"], [])
        if approve:
            svc.conclude_review(REVIEWER, "V-1", "release", "approved",
                                "内容与资质一致，准予发布", roles=ROLES)
        if release:
            svc.approve_release(REVIEWER, "V-1", "D-1", roles=ROLES)
        svc.prepare_channel(OPERATOR, "短视频平台", "渠道代运营公司")
        if publish:
            svc.purchase_traffic(ADVERTISER, "T-1", "V-1", "短视频平台",
                                 50000, roles=ROLES)
            svc.publish(OPERATOR, "P-1", "短视频平台", "V-1",
                        callback_key="cbk-p-1", roles=ROLES)
        return svc


class HappyPathTest(unittest.TestCase):
    def test_full_chain_records_submitter_reviewer_truth_owner(self):
        svc = Scenario().build()
        v = svc.snapshot.versions["V-1"]
        self.assertEqual(v.submitted_by, PRODUCER)
        self.assertEqual(v.reviewed_by, REVIEWER)
        self.assertEqual(v.truth_owner, ADVERTISER)
        self.assertEqual(v.release_decision_id, "D-1")
        kinds = [e.kind for e in svc.events]
        self.assertIn("Published", kinds)
        self.assertEqual(len(svc.events), 12)

    def test_event_stream_is_hash_chained(self):
        svc = Scenario().build()
        prev = "0" * 64
        for event in svc.events:
            self.assertEqual(event.prev_hash, prev)
            prev = event.hash


class GateTest(unittest.TestCase):
    def test_under_review_asset_cannot_be_published_directly(self):
        sc = Scenario()
        svc = sc.build(approve=False, release=False, publish=False)
        with self.assertRaises(GateError):
            svc.publish(OPERATOR, "P-x", "短视频平台", "V-1", roles=ROLES)
        # 拒绝本身也留痕，但不生成发布记录。
        self.assertTrue(all(e.kind != "Published" for e in svc.events))
        self.assertIn("PublishRejected", [e.kind for e in svc.events])

    def test_traffic_purchase_requires_release(self):
        sc = Scenario()
        svc = sc.build(release=False, publish=False)
        with self.assertRaises(GateError):
            svc.purchase_traffic(ADVERTISER, "T-x", "V-1", "短视频平台",
                                 100, roles=ROLES)

    def test_medical_requires_identity_and_facts_before_review_approval(self):
        sc = Scenario()
        svc = sc.build(medical=True, approve=False, release=False,
                       publish=False, medical_checks=False)
        with self.assertRaises(MedicalGateError):
            svc.conclude_review(REVIEWER, "V-1", "release", "approved",
                                "前置核验未做", roles=ROLES)

    def test_medical_submission_requires_identity_and_qualification_binding(self):
        svc = ResponsibilityChainService()
        svc.initiate_project(ADVERTISER, "P", "品牌", "药品", True)
        svc.create_asset(PRODUCER, "A", "数字人视频", "标题")
        with self.assertRaises(MedicalGateError):
            svc.submit_version(PRODUCER, "V", "A", "数字人视频", medical=True)

    def test_unprovable_claim_cannot_pass_fact_verification(self):
        sc = Scenario()
        svc = sc.build(medical=True, approve=False, release=False, publish=False)
        # V-1 的商品事实核验在 build 中已通过；构造一个新宣称无法证明的版本。
        svc.submit_version(
            PRODUCER, "V-1b", "A-1", "数字人视频", parent_version="V-1",
            human_id="H-1", qualification_id="Q-1",
            claimed_facts=["根治高血压"], medical=True,
            truth_owner=ADVERTISER, review_deadline_hours=48)
        with self.assertRaises(MedicalGateError):
            svc.verify_product_facts(
                REVIEWER, "V-1b", True, "宣称无证据", [], ["根治高血压"])


class SeparationAndAccessTest(unittest.TestCase):
    def test_submitter_cannot_approve_own_content(self):
        sc = Scenario()
        svc = sc.build(approve=False, release=False, publish=False)
        with self.assertRaises(SeparationError):
            svc.conclude_review(PRODUCER, "V-1", "release", "approved",
                                "自我批准", roles=ROLES)
        with self.assertRaises(SeparationError):
            svc.approve_release(PRODUCER, "V-1", "D-x", roles=ROLES)

    def test_roles_cannot_execute_others_commands(self):
        svc = Scenario().build()
        with self.assertRaises(AuthorizationError):
            svc.conclude_review(OPERATOR, "V-1", "release", "approved",
                                "渠道无权审核", roles=ROLES)
        with self.assertRaises(AuthorizationError):
            svc.publish(REVIEWER, "P-x", "短视频平台", "V-1", roles=ROLES)
        with self.assertRaises(AuthorizationError):
            svc.purchase_traffic(PRODUCER, "T-x", "V-1", "短视频平台",
                                 10, roles=ROLES)

    def test_role_views_only_contain_in_scope_information(self):
        svc = Scenario().build()
        producer_view = svc.view_as(Role.PRODUCER)
        self.assertNotIn("traffic", producer_view)
        self.assertNotIn("publish", producer_view)
        self.assertNotIn("qualification", producer_view)
        operator_view = svc.view_as(Role.CHANNEL_OPERATOR)
        self.assertNotIn("versions", operator_view)   # 审核意见对渠道不可见
        self.assertIn("publish", operator_view)
        auditor_view = svc.view_as(Role.AUDITOR)
        self.assertIn("versions", auditor_view)
        self.assertIn("audit", auditor_view)


class IdempotencyTest(unittest.TestCase):
    def test_duplicate_callback_does_not_duplicate_publish_record(self):
        svc = Scenario().build(publish=False)
        first = svc.publish(OPERATOR, "P-1", "短视频平台", "V-1",
                            callback_key="cbk-1", roles=ROLES)
        second = svc.publish(OPERATOR, "P-1", "短视频平台", "V-1",
                             callback_key="cbk-1", roles=ROLES)
        self.assertEqual(first.seq, second.seq)
        publishes = [e for e in svc.events if e.kind == "Published"]
        self.assertEqual(len(publishes), 1)


class IncrementalRecomputeTest(unittest.TestCase):
    def test_script_change_only_recomputes_descendant_conclusions(self):
        sc = Scenario()
        svc = sc.build()
        # 基于 V-1 剪辑出 V-2（仅换字幕，无医疗宣称变化），并放行发布。
        svc.submit_version(
            PRODUCER, "V-2", "A-1", "数字人视频", parent_version="V-1",
            derived_from=["V-1"], human_id="H-1", qualification_id="Q-1",
            medical=True, truth_owner=ADVERTISER, review_deadline_hours=48)
        svc.check_medical_identity(REVIEWER, "V-2", True, "授权沿用", ["授权书://H-1"])
        svc.verify_product_facts(REVIEWER, "V-2", True, "事实一致",
                                 ["经过临床验证"], [])
        svc.conclude_review(REVIEWER_B, "V-2", "release", "approved",
                            "字幕修改不影响事实", roles=ROLES)
        svc.approve_release(REVIEWER_B, "V-2", "D-2", roles=ROLES)
        svc.publish(OPERATOR, "P-2", "短视频平台", "V-2", roles=ROLES)

        affected = svc.affected_versions_on_change("V-1")
        # 已上线的 V-1 是不可变历史版本：当时证据与责任保留，不重算其旧结论；
        # 只有下游衍生版本 V-2 的结论受影响。
        self.assertFalse(affected["V-1"]["needs_recheck"])
        self.assertTrue(affected["V-2"]["needs_recheck"])
        self.assertIn("放行决定需基于新证据重新出具",
                      affected["V-2"]["invalidated_conclusions"])
        # 已上线版本当时的证据与责任仍保留。
        self.assertTrue(affected["V-1"]["evidence_retained"])
        self.assertEqual(svc.snapshot.versions["V-1"].release_decision_id, "D-1")
        self.assertIsNotNone(svc.snapshot.versions["V-1"].superseded_at)

    def test_human_swap_invalidates_identity_only_for_medical_chain(self):
        sc = Scenario()
        svc = sc.build(medical=False)
        affected = svc.affected_versions_on_change("V-1")
        self.assertNotIn("身份授权结论", affected["V-1"]["invalidated_conclusions"])


class FreezeReportTest(unittest.TestCase):
    def test_freeze_freezes_lineage_and_reports_channels_gaps_materials(self):
        sc = Scenario()
        svc = sc.build()
        # 另一个缺少复核的版本被违规登记（模拟责任缺口）。
        svc.submit_version(
            PRODUCER, "V-9", "A-1", "数字人视频", parent_version="V-1",
            human_id="H-1", qualification_id="Q-1", medical=True,
            truth_owner=None, review_deadline_hours=48)
        svc.file_complaint(ADVERTISER, "C-1", ["V-9"], "消费者称疗效虚假")
        svc.freeze_lineage(REGULATOR, "监管调查：疗效投诉", "complaint",
                           "C-1", roles=ROLES)
        # 冻结范围沿谱系扩展：V-1 与 V-9 都在冻结集合内。
        self.assertEqual(svc.snapshot.frozen_versions, {"V-1", "V-9"})
        with self.assertRaises(FreezeError):
            svc.check_medical_identity(REVIEWER, "V-9", True, "补证", [])
        with self.assertRaises(FreezeError):
            svc.publish(OPERATOR, "P-3", "短视频平台", "V-1", roles=ROLES)
        report = svc.freeze_report()
        self.assertEqual(report["still_propagating"],
                         {"短视频平台": ["V-1"]})
        self.assertTrue(any("身份授权证据缺失" in m for m in report["pending_materials"]))
        self.assertTrue(any("无复核人" in g for g in report["responsibility_gaps"]))
        # 冻结关闭了相关待办审批。
        self.assertFalse(any(k[1] == "V-9" for k in svc.snapshot.pending))

    def test_withdrawal_triggers_freeze_without_regulator(self):
        svc = Scenario().build()
        svc.request_withdrawal(ADVERTISER, "W-1", ["V-1"], "主动撤回")
        svc.freeze_lineage(REVIEWER, "主动撤回，冻结传播", "withdrawal",
                           "W-1", roles=ROLES)
        self.assertTrue(svc.snapshot.frozen)


class RestartAndReplayTest(unittest.TestCase):
    def test_pending_approvals_keep_original_deadline_after_restart(self):
        sc = Scenario()
        # 复核已通过，但放行决定尚未出具：审批仍未完成。
        svc = sc.build(approve=True, release=False, publish=False)
        pending_before = svc.pending_on_restart()
        # 身份、事实两项前置核验已完成关闭，只剩待出具的放行决定。
        self.assertEqual(len(pending_before), 1)
        kinds = {item["kind"] for item in pending_before}
        self.assertEqual(kinds, {"发布前复核"})

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chain.json"
            svc.save(path)
            future_clock = Clock(BASE + timedelta(hours=49))
            restored = ResponsibilityChainService.load(path, clock=future_clock.now)
            pending_after = restored.pending_on_restart()
            self.assertEqual(len(pending_after), 1)
            self.assertEqual(pending_after[0]["deadline"],
                             pending_before[0]["deadline"])
            self.assertTrue(pending_after[0]["overdue"])
            # 超期放行被拒绝，需要重新发起审批。
            with self.assertRaises(DeadlineError):
                restored.approve_release(REVIEWER, "V-1", "D-late", roles=ROLES)
            # 重启后幂等表恢复，重复回调不会产生第二条发布记录（此前已发布场景）。

    def test_loaded_stream_detects_tampering(self):
        sc = Scenario()
        svc = sc.build()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "chain.json"
            svc.save(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            data["events"][3]["payload"]["real_person"] = "李某某（伪造）"
            path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(DomainError):
                ResponsibilityChainService.load(path)

    def test_auditor_replays_release_decision_at_historical_point(self):
        sc = Scenario()
        svc = sc.build()
        replay = svc.replay_release_at("V-1")
        self.assertTrue(replay["gate_checks"]["复核存在且通过"])
        self.assertTrue(replay["gate_checks"]["提交与复核分离"])
        self.assertTrue(replay["gate_checks"]["身份授权已核验"])
        self.assertTrue(replay["gate_checks"]["商品事实已证明"])
        self.assertEqual(replay["evidence"]["lineage"], ["V-1"])

        # 在放行事件之前的时点重放：当时门禁不会通过。
        approval_seq = next(e.seq for e in svc.events
                            if e.kind == "ReleaseApproved")
        before = svc.replay_release_at("V-1", at_seq=approval_seq - 1)
        self.assertFalse(before["would_release_now"])
        self.assertIsNone(before["release_decision"])

    def test_fold_rebuilds_snapshot_from_scratch(self):
        svc = Scenario().build()
        rebuilt = fold(svc.events)
        self.assertEqual(rebuilt.tip_hash, svc.snapshot.tip_hash)
        self.assertEqual(len(rebuilt.versions), 1)
        self.assertEqual(rebuilt.publishes[0]["release_decision_id"], "D-1")


if __name__ == "__main__":
    unittest.main()
