from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    select,
    update,
)

from sentinel.config import DATABASE, ROOT, UPLOADS

ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
UPLOADS.mkdir(mode=0o700, exist_ok=True)
engine = create_engine(DATABASE, pool_pre_ping=True)

if engine.dialect.name == "sqlite":

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")


schema = MetaData()
users = Table(
    "users",
    schema,
    Column("id", String(36), primary_key=True),
    Column("email", String(254), unique=True, nullable=False),
    Column("password", String(256), nullable=False),
    Column("role", String(12), nullable=False),
)
sessions = Table(
    "sessions",
    schema,
    Column("digest", String(64), primary_key=True),
    Column(
        "owner", ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    ),
    Column("expires", BigInteger, nullable=False, index=True),
)
scans = Table(
    "scans",
    schema,
    Column("id", String(36), primary_key=True),
    Column("owner", ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("sha256", String(64), nullable=False),
    Column("filename", String(255), nullable=False),
    Column("bytes", BigInteger, nullable=False),
    Column("status", String(16), nullable=False),
    Column("created", BigInteger, nullable=False),
    Column("started", BigInteger),
    Column("finished", BigInteger),
    Column("error", String(300)),
    Column("report", JSON),
)
Index("scans_owner_created", scans.c.owner, scans.c.created)
Index("scans_owner_hash", scans.c.owner, scans.c.sha256)
Index("scans_status_created", scans.c.status, scans.c.created)
catalog = Table(
    "catalog",
    schema,
    Column("package", String(255), primary_key=True),
    Column("record", JSON, nullable=False),
)
audit = Table(
    "audit",
    schema,
    Column("id", String(36), primary_key=True),
    Column("actor", String(36), nullable=False),
    Column("created", BigInteger, nullable=False),
    Column("record", JSON, nullable=False),
)
state = Table(
    "system_state",
    schema,
    Column("key", String(40), primary_key=True),
    Column("value", BigInteger, nullable=False),
)
throttle = Table(
    "throttle",
    schema,
    Column("key", String(64), primary_key=True),
    Column("window", BigInteger, nullable=False, index=True),
    Column("count", Integer, nullable=False),
)


def queue_lock(conn):
    conn.execute(update(state).where(state.c.key == "admission").values(value=0))


def migrate():
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            conn.exec_driver_sql("SELECT pg_advisory_xact_lock(616594231)")
        else:
            conn.exec_driver_sql("BEGIN IMMEDIATE")
        schema.create_all(conn)
        version = conn.scalar(
            select(state.c.value).where(state.c.key == "schema_version")
        )
        if version is None:
            conn.execute(
                state.insert(),
                [
                    {"key": "schema_version", "value": 2},
                    {"key": "worker_heartbeat", "value": 0},
                    {"key": "admission", "value": 0},
                    {"key": "model_enabled", "value": 0},
                ],
            )
        elif version == 1:
            conn.execute(state.insert().values(key="model_enabled", value=0))
            conn.execute(
                update(state).where(state.c.key == "schema_version").values(value=2)
            )
        elif version != 2:
            raise RuntimeError("Unsupported database migration version")


if __name__ == "__main__":
    migrate()
