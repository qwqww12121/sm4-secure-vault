"""Human-readable formatting helpers."""

from __future__ import annotations


def format_size(size: int) -> str:
    """Format a byte count as B/KB/MB/GB."""
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{size} B"


def format_file_table(records: list[dict]) -> str:
    """Format vault file records as a compact text table."""
    if not records:
        return "No files in vault."

    headers = ["Filename", "Size", "Imported At"]
    rows = [
        [record["filename"], format_size(int(record["size"])), record["created_at"]]
        for record in records
    ]
    widths = [
        max(len(str(row[col])) for row in [headers] + rows)
        for col in range(len(headers))
    ]

    def fmt(row: list[str]) -> str:
        return " | ".join(str(value).ljust(widths[i]) for i, value in enumerate(row))

    separator = "-+-".join("-" * width for width in widths)
    return "\n".join([fmt(headers), separator, *[fmt(row) for row in rows]])
