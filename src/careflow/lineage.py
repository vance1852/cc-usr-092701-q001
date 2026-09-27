"""重复档案归并后的谱系解析。

合并不搬移任何业务数据行：源档案仅标记 state='merged' 并指向保留档案，
原始记录继续挂在最初录入的档案编号下。读取保留档案时，通过这里的递归
查询把"本档案 + 全部已并入它的来源档案"一并纳入，每条记录自带的
patient_id 即为溯源依据。所有解析都限定在单个诊所内，不会跨诊所展开。
"""

from __future__ import annotations


def merged_lineage(connection, clinic_id: str, patient_id: str) -> list[str]:
    """返回患者自身及全部（含间接）并入它的来源档案编号。

    merged_into 构成以在诊档案为根的森林；UNION 去重使异常成环的数据
    也不会造成无限递归。结果顺序为自根向来源的展开顺序，首元素恒为
    被查询档案自身（当它属于该诊所时）。
    """
    rows = connection.execute(
        "WITH RECURSIVE lineage(id) AS ("
        "SELECT id FROM patients WHERE id=? AND clinic_id=? "
        "UNION "
        "SELECT p.id FROM patients p JOIN lineage l ON p.merged_into=l.id AND p.clinic_id=?"
        ") SELECT id FROM lineage",
        (patient_id, clinic_id, clinic_id),
    ).fetchall()
    return [row["id"] for row in rows]


def direct_merge_sources(connection, clinic_id: str, patient_id: str) -> list[str]:
    """返回直接并入该档案的来源档案编号，按编号排序保证输出稳定。"""
    rows = connection.execute(
        "SELECT id FROM patients WHERE clinic_id=? AND merged_into=? ORDER BY id",
        (clinic_id, patient_id),
    ).fetchall()
    return [row["id"] for row in rows]


def placeholders(count: int) -> str:
    """生成 SQL IN 子句占位符；调用方保证 count>=1，集合来自谱系而非外部输入。"""
    return ",".join("?" for _ in range(count))
