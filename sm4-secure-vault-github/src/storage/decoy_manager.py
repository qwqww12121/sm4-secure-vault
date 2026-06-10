"""Decoy file-list and plaintext manager.

This module implements a small honey-view used when a non-real password is
entered. It never reads the real encrypted index or real encrypted objects.
"""

from __future__ import annotations

import json
from pathlib import Path

import config
from utils.path_utils import ensure_dir, get_filename, safe_join
from utils.security_utils import restrict_permissions


DECOY_CONTENTS: dict[str, str] = {
    "课程资料整理.txt": (
        "《密码学导论》课程资料整理\n"
        "\n"
        "1. 分组密码：重点关注 Feistel 结构、SPN 结构和工作模式。\n"
        "2. 散列函数：理解抗碰撞性、原像抗性和第二原像抗性。\n"
        "3. 消息认证：HMAC 可以用于检测数据是否被篡改。\n"
        "\n"
        "备注：本文档属于诱骗视图中的课程学习记录，不包含真实保密文件内容。\n"
    ),
    "实验记录.txt": (
        "实验记录\n"
        "\n"
        "日期：2026-06-10\n"
        "内容：测试本地文件加密库的命令行交互流程。\n"
        "结论：初始化、导入、列表、导出、删除命令均可正常执行。\n"
        "\n"
        "该文件是诱骗视图中的可读明文，用于避免错误口令直接暴露失败信号。\n"
    ),
    "日常备忘.csv": (
        "date,item,status\n"
        "2026-06-08,整理课程报告模板,done\n"
        "2026-06-09,补充测试截图,pending\n"
        "2026-06-10,检查 README 和 benchmark,pending\n"
        "# 说明：该 CSV 属于诱骗视图，不包含真实保密文件内容。\n"
    ),
}


def _make_decoy_content(filename: str) -> str:
    return (
        f"{filename} - 诱骗视图导出内容\n"
        "\n"
        "这是一份结构完整、语义合理的替代明文，用于诱骗模式演示。\n"
        "它并不是真实文件库中的明文内容，也不是由真实密文解密得到的结果。\n"
        "\n"
        "记录摘要：\n"
        "- 文件已在诱骗视图中登记。\n"
        "- 该导出操作不会访问真实 index.enc。\n"
        "- 该导出操作不会读取真实 vault_data/objects/*.enc。\n"
    )


def _load_dynamic_records() -> list[dict]:
    if not config.DECOY_INDEX_FILE.exists():
        return []
    try:
        data = json.loads(config.DECOY_INDEX_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    records = data.get("files", [])
    if not isinstance(records, list):
        return []
    return [record for record in records if isinstance(record, dict) and "filename" in record]


def _save_dynamic_records(records: list[dict]) -> None:
    config.VAULT_DIR.mkdir(parents=True, exist_ok=True)
    config.DECOY_INDEX_FILE.write_text(
        json.dumps({"version": "1.0", "files": records}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    restrict_permissions(config.DECOY_INDEX_FILE)


def _build_record(filename: str, content: str, index: int) -> dict:
    data = content.encode("utf-8")
    return {
        "filename": filename,
        "object_id": f"decoy-{index:03d}.enc",
        "size": len(data),
        "iv": "",
        "created_at": f"2026-06-{8 + index:02d} 09:30:00",
        "decoy": True,
    }


def list_decoy_files() -> list[dict]:
    """Return a plausible fake file list."""
    static_records = [
        _build_record(filename, content, index)
        for index, (filename, content) in enumerate(DECOY_CONTENTS.items(), start=1)
    ]
    dynamic_records = _load_dynamic_records()
    filenames = {record["filename"] for record in static_records}
    return static_records + [record for record in dynamic_records if record["filename"] not in filenames]


def extract_decoy_file(filename: str, output_dir: str) -> Path:
    """Write meaningful fake plaintext for a decoy filename."""
    content = DECOY_CONTENTS.get(filename)
    if content is None:
        dynamic_record = next(
            (record for record in _load_dynamic_records() if record["filename"] == filename),
            None,
        )
        content = _make_decoy_content(filename if dynamic_record is None else dynamic_record["filename"])
    output_path = safe_join(ensure_dir(output_dir), filename)
    output_path.write_bytes(content.encode("utf-8"))
    return output_path


def add_decoy_file(file_path: str) -> dict:
    """Pretend to add a file in decoy mode without touching real storage."""
    filename = get_filename(file_path)
    size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
    records = [record for record in _load_dynamic_records() if record["filename"] != filename]
    record = {
        "filename": filename,
        "object_id": f"decoy-upload-{len(records) + 1:03d}.enc",
        "size": size,
        "iv": "",
        "created_at": "2026-06-10 10:00:00",
        "decoy": True,
    }
    records.append(record)
    _save_dynamic_records(records)
    return record


def remove_decoy_file(filename: str) -> dict:
    """Pretend to remove a decoy file without touching real storage."""
    dynamic_records = _load_dynamic_records()
    for record in dynamic_records:
        if record["filename"] == filename:
            _save_dynamic_records([item for item in dynamic_records if item["filename"] != filename])
            return record
    for record in list_decoy_files():
        if record["filename"] == filename:
            return record
    return {
        "filename": filename,
        "object_id": "decoy-remove.enc",
        "size": 0,
        "iv": "",
        "created_at": "2026-06-10 10:05:00",
        "decoy": True,
    }
