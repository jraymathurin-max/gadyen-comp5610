"""Storage layer (SQLite for the prototype; move to PostgreSQL with row-level
security before the pilot). Every function takes tenant_id explicitly, so data
from two practices can never be mixed by accident.

The evidence log is append-only and hash-chained: each row stores the hash of the
previous row, so any later modification is detectable with verify_chain()."""
import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, practice_name TEXT NOT NULL,
    language TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS domains (tenant_id TEXT NOT NULL, name TEXT NOT NULL,
    token TEXT NOT NULL, verified_at TEXT, PRIMARY KEY (tenant_id, name));
CREATE TABLE IF NOT EXISTS answers (tenant_id TEXT NOT NULL, question_id TEXT NOT NULL,
    value TEXT NOT NULL, answered_at TEXT NOT NULL, PRIMARY KEY (tenant_id, question_id));
CREATE TABLE IF NOT EXISTS endpoint_reports (id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL, report TEXT NOT NULL, uploaded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL, kind TEXT NOT NULL, tool TEXT, target TEXT,
    payload TEXT NOT NULL, created_at TEXT NOT NULL, prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL);
"""

GENESIS = "0" * 64


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _row_hash(prev_hash, tenant_id, kind, tool, target, payload, created_at) -> str:
    material = json.dumps([prev_hash, tenant_id, kind, tool, target, payload, created_at])
    return hashlib.sha256(material.encode()).hexdigest()


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---- tenants and domains -------------------------------------------------
    def create_tenant(self, practice_name: str, language: str) -> str:
        tenant_id = uuid.uuid4().hex
        self.db.execute("INSERT INTO tenants VALUES (?,?,?,?)",
                        (tenant_id, practice_name, language, now()))
        self.db.commit()
        return tenant_id

    def get_tenant(self, tenant_id: str) -> dict:
        row = self.db.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        if row is None:
            raise KeyError("unknown tenant")
        return dict(row)

    def add_domain(self, tenant_id: str, name: str) -> str:
        token = secrets.token_urlsafe(24)
        self.db.execute("INSERT OR REPLACE INTO domains VALUES (?,?,?,NULL)",
                        (tenant_id, name, token))
        self.db.commit()
        return token

    def domain_token(self, tenant_id: str, name: str) -> str:
        row = self.db.execute("SELECT token FROM domains WHERE tenant_id=? AND name=?",
                              (tenant_id, name)).fetchone()
        if row is None:
            raise KeyError("unknown domain")
        return row["token"]

    def mark_verified(self, tenant_id: str, name: str) -> None:
        self.db.execute("UPDATE domains SET verified_at=? WHERE tenant_id=? AND name=?",
                        (now(), tenant_id, name))
        self.db.commit()

    def verified_domains(self, tenant_id: str) -> set:
        rows = self.db.execute("SELECT name FROM domains WHERE tenant_id=? "
                               "AND verified_at IS NOT NULL", (tenant_id,)).fetchall()
        return {r["name"] for r in rows}

    # ---- questionnaire and endpoint reports -----------------------------------
    def save_answers(self, tenant_id: str, answers: dict) -> None:
        for qid, value in answers.items():
            self.db.execute("INSERT OR REPLACE INTO answers VALUES (?,?,?,?)",
                            (tenant_id, qid, json.dumps(value), now()))
        self.db.commit()

    def answers(self, tenant_id: str) -> dict:
        rows = self.db.execute("SELECT question_id, value FROM answers WHERE tenant_id=?",
                               (tenant_id,)).fetchall()
        return {r["question_id"]: json.loads(r["value"]) for r in rows}

    def add_endpoint_report(self, tenant_id: str, report: dict) -> None:
        self.db.execute("INSERT INTO endpoint_reports (tenant_id, report, uploaded_at) "
                        "VALUES (?,?,?)", (tenant_id, json.dumps(report), now()))
        self.db.commit()

    def endpoint_reports(self, tenant_id: str) -> list:
        rows = self.db.execute("SELECT report FROM endpoint_reports WHERE tenant_id=?",
                               (tenant_id,)).fetchall()
        return [json.loads(r["report"]) for r in rows]

    # ---- hash-chained evidence log -------------------------------------------
    def add_evidence(self, tenant_id: str, kind: str, payload, tool=None, target=None) -> str:
        last = self.db.execute("SELECT hash FROM evidence WHERE tenant_id=? "
                               "ORDER BY id DESC LIMIT 1", (tenant_id,)).fetchone()
        prev_hash = last["hash"] if last else GENESIS
        body = json.dumps(payload, sort_keys=True, default=str)
        created = now()
        digest = _row_hash(prev_hash, tenant_id, kind, tool, target, body, created)
        self.db.execute("INSERT INTO evidence (tenant_id, kind, tool, target, payload, "
                        "created_at, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?)",
                        (tenant_id, kind, tool, target, body, created, prev_hash, digest))
        self.db.commit()
        return digest

    def evidence(self, tenant_id: str, kind: str = None) -> list:
        sql = "SELECT * FROM evidence WHERE tenant_id=?"
        params = [tenant_id]
        if kind:
            sql += " AND kind=?"
            params.append(kind)
        rows = self.db.execute(sql + " ORDER BY id", params).fetchall()
        return [dict(r, payload=json.loads(r["payload"])) for r in rows]

    def verify_chain(self, tenant_id: str) -> bool:
        prev = GENESIS
        rows = self.db.execute("SELECT * FROM evidence WHERE tenant_id=? ORDER BY id",
                               (tenant_id,)).fetchall()
        for r in rows:
            expected = _row_hash(prev, r["tenant_id"], r["kind"], r["tool"], r["target"],
                                 r["payload"], r["created_at"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return False
            prev = r["hash"]
        return True
