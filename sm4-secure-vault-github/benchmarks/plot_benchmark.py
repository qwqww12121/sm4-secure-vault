"""Plot benchmark CSV data when matplotlib is available."""

from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "benchmarks" / "benchmark_result.csv"
FIGURE_DIR = ROOT / "report" / "figures"


def _read_rows() -> list[dict[str, str]]:
    if not CSV_PATH.exists():
        raise FileNotFoundError("benchmark_result.csv not found; run benchmark_encrypt.py first")
    with CSV_PATH.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def main() -> None:
    """Create benchmark plots if matplotlib can be imported."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed; skip plotting. Core benchmark CSV is still usable.")
        return

    rows = _read_rows()
    labels = [row["file_size_label"] for row in rows]
    encrypt_time = [float(row["encrypt_time_sec"]) for row in rows]
    decrypt_time = [float(row["decrypt_time_sec"]) for row in rows]
    encrypt_speed = [float(row["encrypt_speed_MBps"]) for row in rows]
    decrypt_speed = [float(row["decrypt_speed_MBps"]) for row in rows]

    FIGURE_DIR.mkdir(parents=True, exist_ok=True)

    plt.figure()
    plt.plot(labels, encrypt_time, marker="o")
    plt.xlabel("File size")
    plt.ylabel("Time (s)")
    plt.title("SM4-CBC encryption time")
    plt.grid(True, alpha=0.3)
    plt.savefig(FIGURE_DIR / "encrypt_time.png", dpi=150, bbox_inches="tight")
    plt.close()

    plt.figure()
    plt.plot(labels, decrypt_time, marker="o")
    plt.xlabel("File size")
    plt.ylabel("Time (s)")
    plt.title("SM4-CBC decryption time")
    plt.grid(True, alpha=0.3)
    plt.savefig(FIGURE_DIR / "decrypt_time.png", dpi=150, bbox_inches="tight")
    plt.close()

    plt.figure()
    plt.plot(labels, encrypt_speed, marker="o", label="encrypt")
    plt.plot(labels, decrypt_speed, marker="s", label="decrypt")
    plt.xlabel("File size")
    plt.ylabel("Throughput (MB/s)")
    plt.title("SM4-CBC throughput")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.savefig(FIGURE_DIR / "throughput.png", dpi=150, bbox_inches="tight")
    plt.close()

    print(f"Figures written to {FIGURE_DIR}")


if __name__ == "__main__":
    main()
