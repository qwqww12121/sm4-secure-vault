"""Benchmark SM4-CBC encryption and decryption throughput."""

from __future__ import annotations

import csv
import secrets
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from crypto.random_utils import generate_iv
from crypto.sm4_modes import sm4_cbc_decrypt, sm4_cbc_encrypt
from utils.timer import time_function

BENCHMARK_DIR = ROOT / "benchmarks"
RESULT_CSV = BENCHMARK_DIR / "benchmark_result.csv"
REPORT_TABLE_CSV = ROOT / "report" / "tables" / "benchmark_result.csv"

SIZES = [
    (1024, "1KB"),
    (10 * 1024, "10KB"),
    (100 * 1024, "100KB"),
    (1024 * 1024, "1MB"),
    (10 * 1024 * 1024, "10MB"),
]


def _mb_per_sec(byte_count: int, seconds: float) -> float:
    if seconds <= 0:
        return 0.0
    return (byte_count / 1024 / 1024) / seconds


def _test_file_path(label: str) -> Path:
    return BENCHMARK_DIR / f"benchmark_{label}.tmp"


def _ensure_test_file(size: int, label: str) -> Path:
    path = _test_file_path(label)
    if not path.exists() or path.stat().st_size != size:
        path.write_bytes(secrets.token_bytes(size))
    return path


def run_benchmark() -> list[dict[str, str]]:
    """Run the benchmark and return CSV-ready rows."""
    key = secrets.token_bytes(16)
    rows: list[dict[str, str]] = []

    for size, label in SIZES:
        path = _ensure_test_file(size, label)
        plaintext = path.read_bytes()
        iv = generate_iv()

        ciphertext, encrypt_time = time_function(sm4_cbc_encrypt, plaintext, key, iv)
        decrypted, decrypt_time = time_function(sm4_cbc_decrypt, ciphertext, key, iv)
        if decrypted != plaintext:
            raise RuntimeError(f"decryption mismatch for {label}")

        rows.append(
            {
                "file_size_bytes": str(size),
                "file_size_label": label,
                "encrypt_time_sec": f"{encrypt_time:.6f}",
                "decrypt_time_sec": f"{decrypt_time:.6f}",
                "encrypt_speed_MBps": f"{_mb_per_sec(size, encrypt_time):.4f}",
                "decrypt_speed_MBps": f"{_mb_per_sec(size, decrypt_time):.4f}",
                "cipher_size_bytes": str(len(ciphertext)),
            }
        )
    return rows


def write_results(rows: list[dict[str, str]]) -> None:
    """Write benchmark rows to benchmark and report table CSV files."""
    RESULT_CSV.parent.mkdir(parents=True, exist_ok=True)
    REPORT_TABLE_CSV.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "file_size_bytes",
        "file_size_label",
        "encrypt_time_sec",
        "decrypt_time_sec",
        "encrypt_speed_MBps",
        "decrypt_speed_MBps",
        "cipher_size_bytes",
    ]
    with RESULT_CSV.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    shutil.copyfile(RESULT_CSV, REPORT_TABLE_CSV)


def main() -> None:
    """Run benchmark and print a short summary."""
    rows = run_benchmark()
    write_results(rows)
    print(f"Benchmark result written to {RESULT_CSV}")
    print(f"Report table copied to {REPORT_TABLE_CSV}")
    for row in rows:
        print(
            f"{row['file_size_label']:>5}: "
            f"enc {row['encrypt_time_sec']}s ({row['encrypt_speed_MBps']} MB/s), "
            f"dec {row['decrypt_time_sec']}s ({row['decrypt_speed_MBps']} MB/s)"
        )


if __name__ == "__main__":
    main()
