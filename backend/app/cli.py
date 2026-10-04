"""
Administrative commands. Run from the backend directory:

    python -m app.cli create-admin --email admin@example.com --full-name "Admin"
    python -m app.cli create-admin --email someone@example.com --promote

The password is prompted for (never passed as an argument, so it does not
end up in shell history). For automation, pipe it in with --password-stdin.
"""
import argparse
import getpass
import sys

from pydantic import ValidationError

from app.core.config import settings
from app.core.database import SessionLocal
from app.schemas.user import UserCreate
from app.services.user_service import UserService


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")

    password = getpass.getpass("Password: ")

    if getpass.getpass("Confirm password: ") != password:
        sys.exit("Passwords do not match.")

    return password


def create_admin(args: argparse.Namespace) -> None:
    db = SessionLocal()

    try:
        user = UserService.get_by_email(db, args.email)

        if user is not None:
            if not args.promote:
                sys.exit(
                    f"{args.email} already exists. "
                    "Use --promote to make it an active admin."
                )

            user.role = "admin"
            user.is_active = True
            db.commit()
            print(f"Promoted {args.email} to active admin.")
            return

        if not args.full_name:
            sys.exit("--full-name is required to create a new user.")

        try:
            user_data = UserCreate(
                email=args.email,
                full_name=args.full_name,
                password=_read_password(args.password_stdin),
            )
        except ValidationError as exc:
            sys.exit(
                "Invalid input:\n  - "
                + "\n  - ".join(error["msg"] for error in exc.errors())
            )

        UserService.create(db, user_data, role="admin")
        print(f"Created admin {args.email}.")
    finally:
        db.close()


def main() -> None:
    settings.validate()

    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)

    admin_parser = commands.add_parser(
        "create-admin",
        help="Create an admin account, or promote an existing user.",
    )
    admin_parser.add_argument("--email", required=True)
    admin_parser.add_argument("--full-name")
    admin_parser.add_argument(
        "--promote",
        action="store_true",
        help="Make an existing user an active admin.",
    )
    admin_parser.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the password from stdin instead of prompting.",
    )
    admin_parser.set_defaults(handler=create_admin)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
