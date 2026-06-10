"""Command-line interface for the SM4 secure vault."""

from __future__ import annotations

import argparse
import getpass
import sys

import config
from exceptions import VaultError
from utils.format_utils import format_file_table
from vault_core import add_file, extract_file, init_vault, list_files, remove_file


def _prompt_password(
    prompt: str = "Master password: ",
    confirm: bool = False,
    confirm_prompt: str = "Confirm password: ",
    allow_empty: bool = False,
) -> str:
    password = getpass.getpass(prompt)
    if allow_empty and not password:
        return ""
    if confirm:
        again = getpass.getpass(confirm_prompt)
        if password != again:
            raise ValueError("passwords do not match")
    if not password:
        raise ValueError("password must not be empty")
    return password


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(description="Local SM4-CBC encrypted file vault")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="initialize a new vault")
    init_parser.add_argument(
        "--with-decoy",
        action="store_true",
        help="also configure a decoy password for plausible fake plaintext",
    )

    add_parser = subparsers.add_parser("add", help="import and encrypt a file")
    add_parser.add_argument("file_path")

    subparsers.add_parser("list", help="list files in the vault")

    extract_parser = subparsers.add_parser("extract", help="decrypt a file from the vault")
    extract_parser.add_argument("filename")
    extract_parser.add_argument("--out", required=True, help="output directory")

    remove_parser = subparsers.add_parser("remove", help="remove a file from the vault")
    remove_parser.add_argument("filename")

    subparsers.add_parser("benchmark", help="run encryption benchmark")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "benchmark":
            if str(config.PROJECT_ROOT) not in sys.path:
                sys.path.insert(0, str(config.PROJECT_ROOT))
            from benchmarks.benchmark_encrypt import main as benchmark_main

            benchmark_main()
            return 0

        if args.command == "init":
            password = _prompt_password(confirm=True)
            decoy_password = None
            if args.with_decoy:
                decoy_password = _prompt_password(
                    prompt="Decoy password: ",
                    confirm=True,
                    confirm_prompt="Confirm decoy password: ",
                )
            init_vault(password, decoy_password=decoy_password)
            print("Vault initialized.")
        elif args.command == "add":
            password = _prompt_password()
            record = add_file(args.file_path, password)
            print(f"Added: {record['filename']}")
        elif args.command == "list":
            password = _prompt_password()
            print(format_file_table(list_files(password)))
        elif args.command == "extract":
            password = _prompt_password()
            output_path = extract_file(args.filename, args.out, password)
            print(f"Extracted to: {output_path}")
        elif args.command == "remove":
            password = _prompt_password()
            record = remove_file(args.filename, password)
            print(f"Removed: {record['filename']}")
        return 0
    except (VaultError, ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
