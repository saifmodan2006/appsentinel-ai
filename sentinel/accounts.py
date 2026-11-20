import argparse
import getpass
import time
from uuid import uuid4

from sqlalchemy import delete, select, update

from sentinel.auth import hasher
from sentinel.contracts import Credentials
from sentinel.db import audit, engine, migrate, sessions, users


def main():
    parser = argparse.ArgumentParser(
        description="Operator-managed Sentinel account recovery and provisioning"
    )
    parser.add_argument(
        "action", choices=["create-admin", "create-user", "reset-password"]
    )
    parser.add_argument("email")
    args = parser.parse_args()
    password = getpass.getpass("New password: ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords differ.")
    try:
        body = Credentials(email=args.email.casefold(), password=password)
    except ValueError:
        raise SystemExit(
            "Use a valid email and a password of 12 to 128 characters."
        ) from None
    migrate()
    with engine.begin() as conn:
        existing = conn.scalar(select(users.c.id).where(users.c.email == body.email))
        if args.action == "reset-password":
            if not existing:
                raise SystemExit("Account does not exist.")
            conn.execute(
                update(users)
                .where(users.c.id == existing)
                .values(password=hasher.hash(password))
            )
            conn.execute(delete(sessions).where(sessions.c.owner == existing))
        else:
            if existing:
                raise SystemExit("Account already exists.")
            existing = str(uuid4())
            conn.execute(
                users.insert().values(
                    id=existing,
                    email=body.email,
                    password=hasher.hash(password),
                    role="admin" if args.action == "create-admin" else "user",
                )
            )
        conn.execute(
            audit.insert().values(
                id=str(uuid4()),
                actor="local_operator",
                created=int(time.time()),
                record={"event": args.action, "account_id": existing},
            )
        )
    print("Account updated successfully.")


if __name__ == "__main__":
    main()
