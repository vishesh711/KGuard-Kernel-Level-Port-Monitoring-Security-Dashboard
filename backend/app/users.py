"""
Manage dashboard users from the command line (needs database access, not a login):

    python -m app.users create alice --role admin     # asks for the password
    echo "$PW" | python -m app.users create bob --password-stdin
    python -m app.users list
    python -m app.users set-password alice
    python -m app.users set-role bob admin
    python -m app.users disable bob | enable bob | delete bob

Changing a password, role or status ends that user's current logins.
"""

import argparse
import getpass
import sys

from .database import SessionLocal, init_db
from .models.user import ROLES, User
from .services.auth import MIN_PASSWORD_LENGTH, hash_password


def read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Again: ") != password:
            sys.exit("Passwords differ")
    if len(password) < MIN_PASSWORD_LENGTH:
        sys.exit(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    return password


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.users", description="Manage KGuard dashboard users")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("username")
    create.add_argument("--role", choices=ROLES, default="viewer")
    create.add_argument("--password-stdin", action="store_true")
    sub.add_parser("list")
    setpw = sub.add_parser("set-password")
    setpw.add_argument("username")
    setpw.add_argument("--password-stdin", action="store_true")
    role = sub.add_parser("set-role")
    role.add_argument("username")
    role.add_argument("role", choices=ROLES)
    for name in ("disable", "enable", "delete"):
        sub.add_parser(name).add_argument("username")
    args = parser.parse_args(argv)

    init_db()
    db = SessionLocal()
    try:
        if args.command == "list":
            for u in db.query(User).order_by(User.username):
                print(f"{u.username:24} {u.role:7} {'active' if u.is_active else 'disabled'}")
            return 0

        user = db.query(User).filter(User.username == args.username).first()
        if args.command == "create":
            if user:
                sys.exit(f"User {args.username} already exists")
            password_hash = hash_password(read_password(args.password_stdin))
            db.add(User(username=args.username, password_hash=password_hash,
                        role=args.role, is_active=True, token_version=0))
        else:
            if user is None:
                sys.exit(f"No user {args.username}")
            if args.command == "delete":
                db.delete(user)
            else:
                if args.command == "set-password":
                    user.password_hash = hash_password(read_password(args.password_stdin))
                elif args.command == "set-role":
                    user.role = args.role
                else:
                    user.is_active = args.command == "enable"
                user.token_version += 1
        db.commit()
        print(f"{args.command}: {args.username}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
