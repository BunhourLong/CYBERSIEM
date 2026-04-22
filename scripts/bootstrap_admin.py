#!/usr/bin/env python3
"""
Bootstrap the first CyberSIEM admin account.

Usage (from project root):
    python -m scripts.bootstrap_admin --username admin
    python -m scripts.bootstrap_admin --username admin --role analyst

Password is read from the ADMIN_PASSWORD env var or prompted interactively.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.api.auth import hash_password
from src.security_engine.repository import SecurityRepository


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a CyberSIEM user account")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument(
        "--role",
        default="admin",
        choices=["readonly", "analyst", "admin"],
        help="Role to assign (default: admin)",
    )
    parser.add_argument(
        "--password",
        help="Password (uses ADMIN_PASSWORD env var if not given, then prompts)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Update role if user already exists (password unchanged)",
    )
    args = parser.parse_args()

    password = args.password or os.getenv("ADMIN_PASSWORD", "")
    if not password:
        try:
            password = getpass.getpass(f"Password for {args.username!r}: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.", file=sys.stderr)
            sys.exit(1)

    if not password:
        print("Error: password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    from src.api.auth import validate_password
    policy_err = validate_password(password)
    if policy_err:
        print(f"Error: {policy_err}", file=sys.stderr)
        sys.exit(1)

    repo = SecurityRepository()
    existing = repo.get_user_by_username(args.username)

    if existing:
        if not args.overwrite:
            print(
                f"User {args.username!r} already exists (role: {existing['role']}). "
                "Use --overwrite to update role."
            )
            sys.exit(0)
        updated = repo.update_user_role(args.username, args.role)
        if updated:
            repo.log_audit_event(
                actor="bootstrap_cli",
                action="role_changed",
                target=f"{args.username}→{args.role}",
                source_ip=None,
            )
            print(f"Updated {args.username!r} → role={args.role}")
        else:
            print("Update failed.", file=sys.stderr)
            sys.exit(1)
        return

    user = repo.create_user(args.username, hash_password(password), role=args.role)
    if user:
        repo.log_audit_event(
            actor="bootstrap_cli",
            action="user_created",
            target=args.username,
            source_ip=None,
        )
        print(f"Created {args.role} user: {args.username!r}")
    else:
        print("Failed to create user (conflict?).", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
