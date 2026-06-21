import csv
import os
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = Path(os.environ.get("IDENTITY_DATASET_DIR", ROOT / "dataset"))
if not DATASET_DIR.is_absolute():
    DATASET_DIR = ROOT / DATASET_DIR
DB_PATH = ROOT / "data" / "identity_sprawl.db"
SCHEMA_PATH = ROOT / "schema.sql"

TABLES = [
    "employees",
    "platform_accounts",
    "role_assignments",
    "group_membership",
    "audit_events",
    "employee_role_history",
    "api_tokens",
    "offboarding_records",
    "risk_findings",
]


def load_csv(conn, table_name):
    csv_path = DATASET_DIR / f"{table_name}.csv"
    with csv_path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        columns = reader.fieldnames or []
        placeholders = ",".join("?" for _ in columns)
        column_sql = ",".join(columns)
        rows = [[row[column] for column in columns] for row in reader]

    conn.executemany(
        f"INSERT INTO {table_name} ({column_sql}) VALUES ({placeholders})",
        rows,
    )
    return len(rows)


def build_database():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        counts = {table: load_csv(conn, table) for table in TABLES}
        conn.commit()
        return counts
    finally:
        conn.close()


if __name__ == "__main__":
    loaded = build_database()
    for table, count in loaded.items():
        print(f"{table}: {count} rows")
    print(f"database: {DB_PATH}")
