"""重复档案合并后的读取范围与归并结果解析。

合并不改写历史业务行：评估、观察、随访等记录始终保留最初的患者编号，
审计事件因哈希链约束同样保持原样。保留档案的视图通过"档案范围"
（自身 + 已并入自身的源档案）把两侧历史并集呈现，行上的患者编号
即每条记录的来源追溯。
"""

from __future__ import annotations

from typing import Any


def placeholders(count: int) -> str:
    """生成 IN 子句的占位符串；调用方保证 count >= 1。"""
    return ",".join("?" for _ in range(count))


def scope_ids(connection, clinic_id: str, patient_id: str) -> list[str]:
    """档案读取范围：档案自身加上已并入它的源档案编号。

    合并要求两侧都是在诊档案，且已成为保留目标的档案不能再次作为源被合并，
    因此沿 patients.merged_into 展开一层即可覆盖全部既有历史，
    包括合并记录表建立之前完成的合并。
    """
    rows = connection.execute(
        "SELECT id FROM patients WHERE clinic_id=? AND merged_into=? AND state='merged' ORDER BY updated_at,id",
        (clinic_id, patient_id)).fetchall()
    return [patient_id, *[row["id"] for row in rows]]


def merge_outcome(connection, clinic_id: str, patient) -> dict[str, Any] | None:
    """已合并档案的归并结果；目标不在本诊所时不暴露去向，避免跨诊所泄露。"""
    if patient["state"] != "merged" or not patient["merged_into"]:
        return None
    target = connection.execute(
        "SELECT id,external_ref,state FROM patients WHERE id=? AND clinic_id=?",
        (patient["merged_into"], clinic_id)).fetchone()
    if target is None:
        return None
    record = connection.execute(
        "SELECT created_at FROM patient_merges WHERE clinic_id=? AND source_id=?",
        (clinic_id, patient["id"])).fetchone()
    merged_at = record["created_at"] if record else patient["updated_at"]
    return {"patient_id": target["id"], "external_ref": target["external_ref"],
            "state": target["state"], "merged_at": merged_at}
