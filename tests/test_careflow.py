from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import unittest
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from careflow.api import create_handler
from careflow.clock import FrozenClock
from careflow.db import Database
from careflow.errors import Conflict, Forbidden, NotFound, Unauthorized, ValidationError
from careflow.service import Careflow


class CareflowCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self.temp.name) / "clinic.sqlite3")
        self.clock = FrozenClock(datetime(2026, 9, 27, 12, 0, tzinfo=UTC))
        self.app = Careflow(self.db, self.clock)
        initial = self.app.initialize_clinic("澄序门诊", "Asia/Shanghai", "诊所负责人", "LongPassphrase!2026")
        self.clinic = initial["clinic_id"]
        self.owner = initial["owner_id"]
        self.clinician = self.app.create_staff(self.clinic, "临床医生", "clinician", actor_id=self.owner)["id"]
        self.nurse = self.app.create_staff(self.clinic, "护理人员", "nurse", actor_id=self.owner)["id"]
        self.coordinator = self.app.create_staff(self.clinic, "运营协调员", "coordinator", actor_id=self.owner)["id"]
        self.patient = self.app.create_patient(self.clinic, self.coordinator, "case-017", "林女士")

    def tearDown(self):
        self.temp.cleanup()

    def consent(self, purpose="weight_program", revision=1, expires_at=None):
        digest = hashlib.sha256(f"{purpose}-r{revision}".encode()).hexdigest()
        return self.app.grant_consent(self.clinic, self.clinician, self.patient["id"], purpose,
                                      revision, digest, expires_at=expires_at)

    def plan(self, kind="weight"):
        consent = self.consent("weight_program" if kind == "weight" else "aesthetic_procedure")
        return self.app.create_plan(
            self.clinic, self.clinician, self.patient["id"], kind, self.clinician,
            {"description": "按门诊约定复核", "review_interval_days": 30},
            {"screening": "reviewed", "contraindications": [], "review_required": False},
            "2026-09-27", target_date="2026-12-27", consent_id=consent["id"])

    def appointment(self, key="visit-1"):
        return self.app.create_appointment(
            self.clinic, self.coordinator, self.patient["id"], "复诊",
            "2026-09-29T10:00:00+08:00", "2026-09-29T10:30:00+08:00", key, staff_id=self.clinician)

    def test_initialization_is_atomic_and_password_change_revokes_sessions(self):
        self.assertEqual(self.app.login(self.clinic, self.owner, "LongPassphrase!2026")["role"], "owner")
        token = self.app.login(self.clinic, self.owner, "LongPassphrase!2026")["access_token"]
        with self.assertRaises(Conflict):
            self.app.initialize_clinic("另一诊所", "UTC", "第二负责人", "AnotherPassphrase!2026")
        self.app.set_password(self.clinic, self.owner, self.owner, "NewPassphrase!2026")
        with self.assertRaises(Unauthorized):
            self.app.staff_for_token(self.clinic, token)
        self.assertTrue(self.app.login(self.clinic, self.owner, "NewPassphrase!2026")["access_token"])

    def test_clinic_boundary_and_role_permissions_hide_cross_clinic_records(self):
        other = self.app.create_clinic("另一诊所", "UTC")
        outsider = self.app.create_staff(other["id"], "负责人", "owner")
        with self.assertRaises(Unauthorized):
            self.app.get_patient(self.clinic, outsider["id"], self.patient["id"])
        with self.assertRaises(Forbidden):
            self.app.grant_consent(self.clinic, self.coordinator, self.patient["id"], "weight_program", 1, "a" * 64)
        self.assertNotIn("phone_ciphertext", self.app.get_patient(self.clinic, self.coordinator, self.patient["id"]))

    def test_withdrawal_preserves_consent_history_and_pauses_dependent_plan(self):
        plan = self.plan()
        self.app.transition_plan(self.clinic, self.clinician, plan["id"], 1, "propose")
        self.app.transition_plan(self.clinic, self.clinician, plan["id"], 2, "activate")
        consent = self.app.consent_history(self.clinic, self.clinician, self.patient["id"])[0]
        result = self.app.withdraw_consent(self.clinic, self.clinician, consent["id"], "患者提出撤回")
        self.assertEqual(result["state"], "withdrawn")
        self.assertEqual(self.app.plan_history(self.clinic, self.clinician, plan["id"])[-1]["snapshot"]["state"], "paused")
        self.assertEqual(len(self.app.consent_history(self.clinic, self.clinician, self.patient["id"])), 1)
        self.assertTrue(self.app.withdraw_consent(self.clinic, self.clinician, consent["id"], "重复请求")["replayed"])

    def test_plan_requires_signed_assessment_and_versioned_consent(self):
        consent = self.consent()
        assessment = self.app.create_assessment(self.clinic, self.clinician, self.patient["id"], "weight",
                                                {"weight_kg": "72.5", "waist_cm": 83}, {"sleep": "一般"})
        with self.assertRaises(Conflict):
            self.app.create_plan(self.clinic, self.clinician, self.patient["id"], "weight", self.clinician,
                                 {"description": "目标"}, {"review_required": True}, "2026-09-27",
                                 consent_id=consent["id"], assessment_id=assessment["id"])
        self.app.sign_assessment(self.clinic, self.clinician, assessment["id"], expected_version=1)
        plan = self.app.create_plan(self.clinic, self.clinician, self.patient["id"], "weight", self.clinician,
                                    {"description": "目标"}, {"review_required": True}, "2026-09-27",
                                    consent_id=consent["id"], assessment_id=assessment["id"])
        self.assertEqual(plan["state"], "draft")
        with self.assertRaises(Conflict):
            self.app.transition_plan(self.clinic, self.clinician, plan["id"], 1, "activate")

    def test_expired_consent_is_not_used_for_new_plan(self):
        consent = self.consent(expires_at="2026-09-27T12:01:00Z")
        self.clock.set(datetime(2026, 9, 27, 12, 2, tzinfo=UTC))
        with self.assertRaises(Conflict):
            self.app.create_plan(self.clinic, self.clinician, self.patient["id"], "weight", self.clinician,
                                 {"description": "目标"}, {}, "2026-09-27", consent_id=consent["id"])

    def test_appointment_hold_is_idempotent_and_expires_at_boundary(self):
        first = self.appointment()
        replay = self.appointment()
        self.assertEqual(first["id"], replay["id"])
        self.assertTrue(replay["replayed"])
        with self.assertRaises(Conflict):
            self.app.create_appointment(self.clinic, self.coordinator, self.patient["id"], "复诊",
                                        "2026-09-29T10:00:00+08:00", "2026-09-29T10:30:00+08:00", "visit-1",
                                        staff_id=self.clinician, plan_id="different")
        self.clock.set(datetime(2026, 9, 27, 12, 10, tzinfo=UTC))
        self.assertEqual(self.app.expire_holds(self.clinic)["expired"], 1)
        with self.assertRaises(Conflict):
            self.app.transition_appointment(self.clinic, self.coordinator, first["id"], 2, "book")

    def test_staff_overlap_is_rejected_but_adjacent_time_is_allowed(self):
        self.appointment("morning")
        with self.assertRaises(Conflict):
            self.app.create_appointment(self.clinic, self.coordinator, self.patient["id"], "复诊",
                                        "2026-09-29T10:15:00+08:00", "2026-09-29T10:45:00+08:00", "overlap",
                                        staff_id=self.clinician)
        adjacent = self.app.create_appointment(self.clinic, self.coordinator, self.patient["id"], "复诊",
                                              "2026-09-29T10:30:00+08:00", "2026-09-29T11:00:00+08:00", "adjacent",
                                              staff_id=self.clinician)
        self.assertEqual(adjacent["state"], "held")

    def test_observation_correction_is_append_only_and_report_uses_effective_value(self):
        original = self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 73.2,
                                              "2026-09-27T08:00:00+08:00")
        correction = self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 72.8,
                                                 "2026-09-27T08:00:00+08:00", correction_of=original["id"])
        series = self.app.reports.weight_series(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual([row["weight_kg"] for row in series["observations"]], [72.8])
        self.assertEqual(correction["correction_of"], original["id"])
        with self.assertRaises(Conflict):
            self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 72.1,
                                         "2026-09-27T08:00:00+08:00", correction_of=original["id"])

    def test_followup_lease_fencing_prevents_late_completion(self):
        followup = self.app.schedule_followup(self.clinic, self.clinician, self.patient["id"],
                                              "2026-09-27T11:00:00Z", "复诊反馈", "fup-1")
        first = self.app.claim_followups(self.clinic, self.nurse, lease_minutes=1)[0]
        self.clock.set(datetime(2026, 9, 27, 12, 2, tzinfo=UTC))
        second = self.app.claim_followups(self.clinic, self.coordinator, lease_minutes=3)[0]
        with self.assertRaises(Conflict):
            self.app.complete_followup(self.clinic, self.nurse, followup["id"], first["claim_token"], "迟到回写", first["version"])
        done = self.app.complete_followup(self.clinic, self.coordinator, followup["id"], second["claim_token"], "已联系", second["version"])
        self.assertEqual(done["state"], "done")

    def test_incident_history_is_versioned_and_replay_does_not_duplicate(self):
        incident = self.app.report_incident(self.clinic, self.nurse, self.patient["id"], "术后不适", "moderate",
                                            "2026-09-27T10:00:00+08:00", "患者报告局部红肿", "incident-1")
        replay = self.app.report_incident(self.clinic, self.nurse, self.patient["id"], "术后不适", "moderate",
                                          "2026-09-27T10:00:00+08:00", "患者报告局部红肿", "incident-1")
        self.assertEqual(replay["id"], incident["id"])
        self.app.transition_incident(self.clinic, self.clinician, incident["id"], "triage", "安排临床评估", 1)
        history = self.app.incident_history(self.clinic, self.clinician, incident["id"])
        self.assertEqual([item["type"] for item in history["events"]], ["reported", "triage"])

    def test_stop_flag_requires_clinician_review_and_diagnostic_reports_it(self):
        flag = self.app.clinical_flags.report(self.clinic, self.nurse, self.patient["id"], "prior_reaction", "stop", "既往材料待核实")
        report = self.app.run_diagnostics(self.clinic, self.owner)
        self.assertIn("clinical_flag.requires_review", {item["code"] for item in report["findings"]})
        with self.assertRaises(Forbidden):
            self.app.clinical_flags.review(self.clinic, self.nurse, flag["id"], 1, "confirm", "已核实")
        self.app.clinical_flags.review(self.clinic, self.clinician, flag["id"], 1, "confirm", "已复核原始材料")
        flags = self.app.clinical_flags.list_for_patient(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual(flags[0]["state"], "confirmed")

    def test_encounter_requires_sections_and_amendment_preserves_signed_note(self):
        appointment = self.appointment()
        self.app.transition_appointment(self.clinic, self.coordinator, appointment["id"], 1, "book")
        self.app.transition_appointment(self.clinic, self.coordinator, appointment["id"], 2, "arrive")
        self.clock.set(datetime(2026, 9, 29, 2, 0, tzinfo=UTC))
        self.app.transition_appointment(self.clinic, self.coordinator, appointment["id"], 3, "start")
        encounter = self.app.encounter_for_appointment(self.clinic, self.clinician, appointment["id"])
        with self.assertRaises(Conflict):
            self.app.sign_encounter(self.clinic, self.clinician, encounter["id"], 1)
        for section in ("chief_complaint", "assessment", "plan"):
            self.app.add_encounter_note(self.clinic, self.clinician, encounter["id"], section, f"记录-{section}",
                                        expected_version=encounter["version"])
            encounter = self.app.encounter_for_appointment(self.clinic, self.clinician, appointment["id"])
        self.app.sign_encounter(self.clinic, self.clinician, encounter["id"], encounter["version"])
        signed = self.app.encounter_notes(self.clinic, self.clinician, encounter["id"])
        first = next(item for item in signed["notes"] if item["section"] == "assessment")
        amended = self.app.add_encounter_note(self.clinic, self.clinician, encounter["id"], "assessment", "补充记录",
                                              expected_version=signed["version"], amendment_reason="补充化验时间")
        self.assertEqual(amended["state"], "amended")
        history = self.app.encounter_notes(self.clinic, self.clinician, encounter["id"])["notes"]
        self.assertTrue(any(item["id"] == first["id"] for item in history))

    def test_stock_uses_fefo_and_quarantine_blocks_consumption(self):
        product = self.app.supplies.register_product(self.clinic, self.owner, "无菌敷料", "consumable", "片")
        later = self.app.supplies.receive_lot(self.clinic, self.owner, product["id"], "s-1", "batch-later", 8,
                                              "receive-1", expires_on="2027-06-01")
        earlier = self.app.supplies.receive_lot(self.clinic, self.owner, product["id"], "s-1", "batch-earlier", 5,
                                                "receive-2", expires_on="2027-01-01")
        appointment = self.appointment()
        reserved = self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 7, "stock-reserve-1")
        self.assertEqual([row["lot_id"] for row in reserved["reservations"]], [earlier["id"], later["id"]])
        self.app.supplies.change_lot_state(self.clinic, self.owner, later["id"], "recall", "批次通知召回")
        with self.assertRaises(Conflict):
            self.app.supplies.consume_reservation(self.clinic, self.clinician, reserved["reservations"][1]["id"], expected_version=1)

    def test_stock_reservation_is_all_or_nothing_and_same_request_replays(self):
        product = self.app.supplies.register_product(self.clinic, self.owner, "一次性导管", "consumable", "支")
        self.app.supplies.receive_lot(self.clinic, self.owner, product["id"], "s-2", "lot-a", 2, "receive-a")
        appointment = self.appointment()
        with self.assertRaises(Conflict):
            self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 3, "reserve-too-many")
        balance = self.app.supplies.lot_balances(self.clinic, product["id"])[0]
        self.assertEqual(balance["available_quantity"], 2)
        first = self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 1, "reserve-one")
        replay = self.app.supplies.reserve(self.clinic, self.coordinator, appointment["id"], product["id"], 1, "reserve-one")
        self.assertEqual(first["reservations"], replay["reservations"])
        self.assertTrue(replay["replayed"])

    def test_milestone_defer_history_and_idempotent_creation(self):
        plan = self.plan()
        first = self.app.milestones.create(self.clinic, self.clinician, plan["id"], "review", "复核体重记录",
                                           "2026-10-10T09:00:00+08:00", "mile-1", assigned_to=self.nurse)
        again = self.app.milestones.create(self.clinic, self.clinician, plan["id"], "review", "复核体重记录",
                                           "2026-10-10T09:00:00+08:00", "mile-1", assigned_to=self.nurse)
        self.assertEqual(first["id"], again["id"])
        deferred = self.app.milestones.transition(self.clinic, self.nurse, first["id"], 1, "defer",
                                                 reason="患者改期", new_due_at="2026-10-12T09:00:00+08:00")
        self.assertEqual(deferred["state"], "pending")
        self.assertEqual(len(self.app.milestones.history(self.clinic, self.clinician, first["id"])), 2)

    def test_export_needs_consent_is_minimized_and_idempotent(self):
        with self.assertRaises(Conflict):
            self.app.exports.export(self.clinic, self.owner, self.patient["id"], ["profile"], "患者本人申请", "export-1")
        self.consent("data_export")
        first = self.app.exports.export(self.clinic, self.owner, self.patient["id"], ["profile", "observations"], "患者本人申请", "export-1")
        replay = self.app.exports.export(self.clinic, self.owner, self.patient["id"], ["observations", "profile"], "患者本人申请", "export-1")
        self.assertEqual(first["sha256"], replay["sha256"])
        self.assertTrue(replay["replayed"])
        self.assertNotIn("phone_ciphertext", json.dumps(first, ensure_ascii=False))

    def duplicate_patient(self, ref="case-017-dup"):
        """前台用第二个证件编号为同一位患者建立的重复档案。"""
        return self.app.create_patient(self.clinic, self.coordinator, ref, "林女士")

    def test_merge_preserves_history_visibility_with_provenance(self):
        source = self.duplicate_patient()
        # 护士把第一次体重测量记在了旧档案里，旧档案还有评估、授权、随访与安全关注项。
        first_weight = self.app.record_observation(self.clinic, self.nurse, source["id"], "weight_kg", 74.6,
                                                   "2026-09-26T09:30:00+08:00")
        assessment = self.app.create_assessment(self.clinic, self.clinician, source["id"], "weight",
                                                {"weight_kg": "74.6"}, {"sleep": "一般"})
        self.app.sign_assessment(self.clinic, self.clinician, assessment["id"], expected_version=1)
        digest = hashlib.sha256(b"weight_program-r1").hexdigest()
        self.app.grant_consent(self.clinic, self.clinician, source["id"], "weight_program", 1, digest)
        self.app.schedule_followup(self.clinic, self.clinician, source["id"],
                                   "2026-09-27T13:00:00Z", "首次复诊提醒", "fup-dup-1")
        self.app.clinical_flags.report(self.clinic, self.nurse, source["id"], "allergy", "caution", "青霉素过敏史")
        self.app.record_observation(self.clinic, self.clinician, self.patient["id"], "weight_kg", 74.1,
                                    "2026-09-27T08:00:00+08:00")
        before = self.app.patient_timeline(self.clinic, self.clinician, self.patient["id"])
        self.assertNotIn(first_weight["id"], json.dumps(before))

        result = self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                         expected_source=1, expected_target=1, reason="同一患者两个证件编号")
        self.assertEqual(result["state"], "merged")
        self.assertFalse(result["replayed"])
        self.assertTrue(result["merge_id"])

        # 保留档案时间线可见两侧事件，且每条事件保留最初所属档案编号。
        timeline = self.app.patient_timeline(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual(timeline["merged_from"], [source["id"]])
        by_action = {}
        for event in timeline["events"]:
            by_action.setdefault(event["action"], []).append(event)
        self.assertEqual(by_action["observation.recorded"][0]["patient_id"], source["id"])
        self.assertEqual(by_action["assessment.created"][0]["patient_id"], source["id"])
        self.assertEqual(by_action["followup.scheduled"][0]["patient_id"], source["id"])
        self.assertEqual(by_action["patient.merged"][0]["payload"]["source_id"], source["id"])
        # 第一次体重测量进入保留档案的测量序列，并标注来自旧档案。
        series = self.app.reports.weight_series(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual(series["merged_from"], [source["id"]])
        self.assertEqual([row["weight_kg"] for row in series["observations"]], [74.6, 74.1])
        self.assertEqual(series["observations"][0]["patient_id"], source["id"])
        observations = self.app.observation_series(self.clinic, self.clinician, self.patient["id"], "weight_kg")
        self.assertEqual({row["patient_id"] for row in observations}, {source["id"], self.patient["id"]})
        # 评估、授权、安全关注项同样可从保留档案追溯。
        assessments = self.app.list_assessments(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual(assessments[0]["patient_id"], source["id"])
        self.assertEqual(assessments[0]["status"], "signed")
        consents = self.app.consent_history(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual({row["patient_id"] for row in consents}, {source["id"]})
        flags = self.app.clinical_flags.list_for_patient(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual(flags[0]["patient_id"], source["id"])
        # 导出保留档案时两侧记录都在，且带有原始档案编号。
        self.consent("data_export")
        exported = self.app.exports.export(self.clinic, self.owner, self.patient["id"],
                                           ["observations", "assessments"], "患者本人申请", "export-merge-1")
        self.assertEqual(exported["data"]["merged_from"], [source["id"]])
        self.assertEqual({row["patient_id"] for row in exported["data"]["observations"]},
                         {source["id"], self.patient["id"]})
        self.assertEqual(exported["data"]["assessments"][0]["patient_id"], source["id"])

    def test_merged_source_queries_return_clear_result_without_leakage(self):
        source = self.duplicate_patient()
        merged = self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                         expected_source=1, expected_target=1, reason="重复建档")
        # 旧编号查询返回清楚的归并结果。
        retired = self.app.get_patient(self.clinic, self.coordinator, source["id"])
        self.assertEqual(retired["state"], "merged")
        self.assertEqual(retired["merged_into"], self.patient["id"])
        self.assertEqual(retired["merge"]["merge_id"], merged["merge_id"])
        self.assertEqual(retired["merge"]["reason"], "重复建档")
        self.assertEqual(retired["merge"]["merged_at"], merged["merged_at"])
        # 保留档案能看到并入了哪些旧编号。
        kept = self.app.get_patient(self.clinic, self.coordinator, self.patient["id"])
        self.assertEqual([item["patient_id"] for item in kept["merged_sources"]], [source["id"]])
        self.assertEqual(kept["merged_sources"][0]["external_ref"], "case-017-dup")
        # 旧编号时间线保留自身历史并标明去向。
        timeline = self.app.patient_timeline(self.clinic, self.clinician, source["id"])
        self.assertEqual(timeline["patient_state"], "merged")
        self.assertEqual(timeline["merged_into"], self.patient["id"])
        self.assertIn("patient.merged_away", {event["action"] for event in timeline["events"]})
        # 另一诊所查询该旧编号只得到"不存在"，不泄露归并去向。
        other = self.app.create_clinic("另一诊所", "UTC")
        outsider = self.app.create_staff(other["id"], "负责人", "owner")
        with self.assertRaises(NotFound):
            self.app.get_patient(other["id"], outsider["id"], source["id"])
        with self.assertRaises(NotFound):
            self.app.patient_timeline(other["id"], outsider["id"], source["id"])

    def test_merge_is_atomic_and_replay_does_not_reprocess_history(self):
        source = self.duplicate_patient()
        self.app.record_observation(self.clinic, self.nurse, source["id"], "weight_kg", 74.6,
                                    "2026-09-26T09:30:00+08:00")
        events_before = len(self.app.audit_history(self.clinic, self.owner))
        # 版本号过期（并发修改）导致合并失败：不留任何半套迁移。
        with self.assertRaises(Conflict):
            self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                    expected_source=9, expected_target=1, reason="重复建档")
        self.assertEqual(self.app.get_patient(self.clinic, self.owner, source["id"])["state"], "active")
        self.assertEqual(len(self.app.audit_history(self.clinic, self.owner)), events_before)
        with self.db.transaction(write=False) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM patient_merges").fetchone()[0], 0)
        # 正常合并后，同一请求重复提交返回首次结果，不重复处理既有历史。
        first = self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                        expected_source=1, expected_target=1, reason="重复建档")
        events_after_merge = len(self.app.audit_history(self.clinic, self.owner))
        replay = self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                         expected_source=1, expected_target=1, reason="重复建档")
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["merge_id"], first["merge_id"])
        self.assertEqual(replay["merged_at"], first["merged_at"])
        self.assertEqual(len(self.app.audit_history(self.clinic, self.owner)), events_after_merge)
        with self.db.transaction(write=False) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM patient_merges").fetchone()[0], 1)
        # 同一旧档案不能再并入其他保留档案，也不能反向合并。
        third = self.duplicate_patient("case-017-tri")
        with self.assertRaises(Conflict):
            self.app.merge_patients(self.clinic, self.owner, source["id"], third["id"],
                                    expected_source=2, expected_target=1, reason="改并入新档案")
        with self.assertRaises(Conflict):
            self.app.merge_patients(self.clinic, self.owner, self.patient["id"], source["id"],
                                    expected_source=1, expected_target=2, reason="反向合并")

    def test_concurrent_merge_requests_settle_exactly_once(self):
        source = self.duplicate_patient()
        results, errors = [], []

        def merge():
            try:
                results.append(self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                                       expected_source=1, expected_target=1, reason="重复建档"))
            except Exception as exc:  # noqa: BLE001 - 测试中收集并发结果
                errors.append(exc)

        threads = [threading.Thread(target=merge) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(1 for item in results if not item["replayed"]), 1)
        self.assertEqual(sum(1 for item in results if item["replayed"]), 1)
        self.assertEqual({item["merge_id"] for item in results}, {results[0]["merge_id"]})
        with self.db.transaction(write=False) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM patient_merges").fetchone()[0], 1)
        self.assertEqual(self.app.get_patient(self.clinic, self.owner, source["id"])["version"], 2)

    def test_merged_source_rejects_new_writes_but_stays_readable(self):
        source = self.duplicate_patient()
        assessment = self.app.create_assessment(self.clinic, self.clinician, source["id"], "weight",
                                                {"weight_kg": "74.6"}, {})
        self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                expected_source=1, expected_target=1, reason="重复建档")
        # 旧档案不再接受新记录，新数据只能写到保留档案。
        with self.assertRaises(Conflict):
            self.app.record_observation(self.clinic, self.nurse, source["id"], "weight_kg", 74.0,
                                        "2026-09-27T09:00:00+08:00")
        with self.assertRaises(Conflict):
            self.app.create_assessment(self.clinic, self.clinician, source["id"], "weight", {}, {})
        with self.assertRaises(Conflict):
            self.app.schedule_followup(self.clinic, self.clinician, source["id"],
                                       "2026-09-28T13:00:00Z", "随访", "fup-dup-2")
        with self.assertRaises(Conflict):
            self.app.grant_consent(self.clinic, self.clinician, source["id"], "weight_program", 1, "b" * 64)
        # 旧档案自身历史仍然可读，且只呈现它自己的记录。
        own = self.app.list_assessments(self.clinic, self.clinician, source["id"])
        self.assertEqual([row["id"] for row in own], [assessment["id"]])
        series = self.app.reports.weight_series(self.clinic, self.clinician, source["id"])
        self.assertEqual(series["patient_state"], "merged")
        self.assertNotIn("merged_from", series)

    def test_legacy_merged_patient_gains_lineage_reads_and_replay(self):
        # 模拟本次修复前已合并的档案：只有 patients 行被标记，没有合并登记。
        source = self.duplicate_patient()
        self.app.record_observation(self.clinic, self.nurse, source["id"], "weight_kg", 74.6,
                                    "2026-09-26T09:30:00+08:00")
        with self.db.transaction() as connection:
            connection.execute("UPDATE patients SET state='merged',merged_into=?,updated_at=?,version=version+1 WHERE id=?",
                               (self.patient["id"], self.app.now(), source["id"]))
        retired = self.app.get_patient(self.clinic, self.coordinator, source["id"])
        self.assertEqual(retired["merged_into"], self.patient["id"])
        self.assertIsNone(retired["merge"]["merge_id"])
        series = self.app.reports.weight_series(self.clinic, self.clinician, self.patient["id"])
        self.assertEqual([row["weight_kg"] for row in series["observations"]], [74.6])
        replay = self.app.merge_patients(self.clinic, self.owner, source["id"], self.patient["id"],
                                         expected_source=2, expected_target=1, reason="补登记")
        self.assertTrue(replay["replayed"])
        third = self.duplicate_patient("case-017-tri")
        with self.assertRaises(Conflict):
            self.app.merge_patients(self.clinic, self.owner, source["id"], third["id"],
                                    expected_source=2, expected_target=1, reason="改并入新档案")

    def test_daily_report_uses_clinic_calendar_day_and_dst_aware_bounds(self):
        clinic = self.app.create_clinic("北美诊所", "America/New_York")
        owner = self.app.create_staff(clinic["id"], "负责人", "owner")
        self.assertEqual(self.app.reports.daily_operations(clinic["id"], owner["id"], "2026-11-01")["window"]["ends_at"],
                         "2026-11-02T05:00:00Z")

    def test_audit_hash_chain_detects_tampering(self):
        self.app.audit_history(self.clinic, self.owner)
        self.assertTrue(self.app.verify_audit(self.clinic, self.owner)["ok"])
        with self.db.transaction() as connection:
            connection.execute("UPDATE audit_events SET action='tampered' WHERE sequence=1")
        self.assertFalse(self.app.verify_audit(self.clinic, self.owner)["ok"])

    def test_http_login_patient_creation_and_validation_error(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(self.app))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            request = Request(base + "/auth/token", data=json.dumps({"staff_id": self.owner,
                            "password": "LongPassphrase!2026"}).encode(), method="POST",
                              headers={"X-Clinic-ID": self.clinic, "Content-Type": "application/json"})
            with urlopen(request, timeout=3) as response:
                token = json.loads(response.read())["access_token"]
                self.assertEqual(response.status, 201)
            request = Request(base + "/patients", data=json.dumps({"external_ref": "http-1", "name": "周女士"}).encode(),
                              method="POST", headers={"X-Clinic-ID": self.clinic, "Authorization": f"Bearer {token}",
                                                       "Content-Type": "application/json"})
            with urlopen(request, timeout=3) as response:
                patient = json.loads(response.read())
                self.assertEqual(response.status, 201)
            request = Request(base + f"/patients/{patient['id']}", headers={"X-Clinic-ID": self.clinic,
                              "Authorization": "Bearer invalid"})
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 401)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
