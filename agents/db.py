import sqlite3
import json
import hashlib
from datetime import datetime
import uuid

DB_PATH = "guardian.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policy_baselines (
        id TEXT PRIMARY KEY,
        service_account TEXT NOT NULL,
        namespace TEXT NOT NULL,
        approved_yaml TEXT NOT NULL,
        canonical_hash TEXT NOT NULL,
        applied_at TEXT NOT NULL,
        status TEXT NOT NULL
    )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_hash ON policy_baselines(canonical_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sa_status ON policy_baselines(service_account, namespace, status)")
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS approval_queue (
        id TEXT PRIMARY KEY,
        baseline_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        risk_tier TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        resolved_by TEXT,
        resolved_at TEXT,
        FOREIGN KEY (baseline_id) REFERENCES policy_baselines(id)
    )
    """)
    conn.commit()
    conn.close()

def canonical_hash(permissions: list[dict]) -> str:
    """RFC 8785-style canonicalization + SHA-256."""
    normalized = sorted(
        [dict(sorted(p.items())) for p in permissions],
        key=lambda x: json.dumps(x, sort_keys=True)
    )
    canonical = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()

def check_broken_rollback(hash_val: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM policy_baselines WHERE canonical_hash = ? AND status = 'BROKEN_ROLLBACK'", (hash_val,))
    result = cursor.fetchone() is not None
    conn.close()
    return result

def get_active_baseline(sa: str, ns: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM policy_baselines WHERE service_account = ? AND namespace = ? AND status = 'ACTIVE'", (sa, ns))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def store_baseline(sa: str, ns: str, yaml_str: str, permissions: list[dict]) -> str:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Deprecate current ACTIVE
    cursor.execute(
        "UPDATE policy_baselines SET status = 'SUPERSEDED' WHERE service_account = ? AND namespace = ? AND status = 'ACTIVE'",
        (sa, ns)
    )
    
    baseline_id = str(uuid.uuid4())
    hash_val = canonical_hash(permissions)
    now = datetime.utcnow().isoformat() + "Z"
    
    cursor.execute("""
        INSERT INTO policy_baselines 
        (id, service_account, namespace, approved_yaml, canonical_hash, applied_at, status)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')
    """, (baseline_id, sa, ns, yaml_str, hash_val, now))
    
    conn.commit()
    conn.close()
    return baseline_id

def insert_approval_queue_entry(baseline_id: str, event_type: str, risk_tier: str):
    conn = sqlite3.connect(DB_PATH)
    entry_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat() + "Z"
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO approval_queue
        (id, baseline_id, event_type, risk_tier, status, created_at)
        VALUES (?, ?, ?, ?, 'pending', ?)
    """, (entry_id, baseline_id, event_type, risk_tier, now))
    conn.commit()
    conn.close()
