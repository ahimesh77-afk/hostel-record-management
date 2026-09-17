"""
HostelSync — backend API
Automated Student Hostel Leave & Attendance Management System

Stack: Flask + SQLite (stdlib only apart from Flask)
Run:   pip install flask
       python app.py
API:   http://127.0.0.1:5000/api/...
"""

import os
import sqlite3
import hashlib
import secrets
import datetime as dt
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hostelsync.db")
TOKEN_TTL_HOURS = 12

app = Flask(__name__, static_folder=None)


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS students (
    roll          TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    room          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS wardens (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    roll   TEXT NOT NULL REFERENCES students(roll) ON DELETE CASCADE,
    date   TEXT NOT NULL,                       -- YYYY-MM-DD
    status TEXT NOT NULL CHECK (status IN ('present','absent')),
    marked_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (roll, date)                         -- one record per student per day
);

CREATE TABLE IF NOT EXISTS leaves (
    id          TEXT PRIMARY KEY,
    roll        TEXT NOT NULL REFERENCES students(roll) ON DELETE CASCADE,
    from_date   TEXT NOT NULL,
    to_date     TEXT NOT NULL,
    reason      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','approved','rejected')),
    applied_on  TEXT NOT NULL,
    decided_by  TEXT,
    decided_on  TEXT
);

CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    user_type  TEXT NOT NULL CHECK (user_type IN ('student','warden')),
    user_id    TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_att_date  ON attendance(date);
CREATE INDEX IF NOT EXISTS idx_lv_status ON leaves(status);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()

    # seed demo accounts only on a fresh database
    if con.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0:
        demo_students = [
            ("S101", "Aarav Kumar", "B-204", "1234"),
            ("S102", "Divya Menon", "B-207", "1234"),
            ("S103", "Rohan Iyer", "B-210", "1234"),
        ]
        con.executemany(
            "INSERT INTO students (roll, name, room, password_hash) VALUES (?,?,?,?)",
            [(r, n, rm, hash_password(p)) for r, n, rm, p in demo_students],
        )
    if con.execute("SELECT COUNT(*) FROM wardens").fetchone()[0] == 0:
        con.execute(
            "INSERT INTO wardens (id, name, password_hash) VALUES (?,?,?)",
            ("W01", "Mrs. Lakshmi Priya", hash_password("admin")),
        )
    con.commit()
    con.close()


# --------------------------------------------------------------------------
# Passwords & tokens
# --------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000)
    return secrets.compare_digest(check.hex(), digest)


def issue_token(user_type: str, user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires = (dt.datetime.utcnow() + dt.timedelta(hours=TOKEN_TTL_HOURS)).isoformat()
    db = get_db()
    db.execute("DELETE FROM tokens WHERE expires_at < ?", (dt.datetime.utcnow().isoformat(),))
    db.execute(
        "INSERT INTO tokens (token, user_type, user_id, expires_at) VALUES (?,?,?,?)",
        (token, user_type, user_id, expires),
    )
    db.commit()
    return token


def current_user():
    """Resolve the bearer token into a user dict, or None."""
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else None
    if not token:
        return None
    row = get_db().execute(
        "SELECT * FROM tokens WHERE token = ? AND expires_at > ?",
        (token, dt.datetime.utcnow().isoformat()),
    ).fetchone()
    if not row:
        return None
    if row["user_type"] == "student":
        s = get_db().execute("SELECT * FROM students WHERE roll = ?", (row["user_id"],)).fetchone()
        if not s:
            return None
        return {"type": "student", "roll": s["roll"], "name": s["name"], "room": s["room"]}
    w = get_db().execute("SELECT * FROM wardens WHERE id = ?", (row["user_id"],)).fetchone()
    if not w:
        return None
    return {"type": "warden", "id": w["id"], "name": w["name"]}


def auth_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify(error="Not signed in or session expired"), 401
            if role and user["type"] != role:
                return jsonify(error="You are not allowed to do that"), 403
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def today_str():
    return dt.date.today().isoformat()


def parse_date(value):
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def body():
    return request.get_json(silent=True) or {}


def leave_json(row):
    """Shape a leave row the way the existing front-end expects."""
    return {
        "id": row["id"],
        "roll": row["roll"],
        "name": row["name"] if "name" in row.keys() else None,
        "from": row["from_date"],
        "to": row["to_date"],
        "reason": row["reason"],
        "status": row["status"],
        "appliedOn": row["applied_on"],
    }


@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    return resp


@app.route("/api/<path:_any>", methods=["OPTIONS"])
def cors_preflight(_any):
    return ("", 204)


# --------------------------------------------------------------------------
# Auth routes
# --------------------------------------------------------------------------

@app.post("/api/auth/register")
def register():
    d = body()
    name = (d.get("name") or "").strip()
    roll = (d.get("roll") or "").strip().upper()
    room = (d.get("room") or "").strip()
    password = d.get("password") or ""

    if not (name and roll and room and password):
        return jsonify(error="Please fill all fields"), 400
    if len(password) < 4:
        return jsonify(error="Password must be at least 4 characters"), 400

    db = get_db()
    if db.execute("SELECT 1 FROM students WHERE roll = ?", (roll,)).fetchone():
        return jsonify(error="Roll number already registered"), 409

    db.execute(
        "INSERT INTO students (roll, name, room, password_hash) VALUES (?,?,?,?)",
        (roll, name, room, hash_password(password)),
    )
    db.commit()
    return jsonify(message="Account created — please sign in", roll=roll), 201


@app.post("/api/auth/login")
def login():
    d = body()
    role = d.get("role")
    ident = (d.get("id") or "").strip().upper()
    password = d.get("password") or ""

    if role not in ("student", "warden"):
        return jsonify(error="Unknown role"), 400

    db = get_db()
    if role == "student":
        row = db.execute("SELECT * FROM students WHERE roll = ?", (ident,)).fetchone()
        bad = "Invalid roll number or password"
        key = "roll"
    else:
        row = db.execute("SELECT * FROM wardens WHERE id = ?", (ident,)).fetchone()
        bad = "Invalid warden ID or password"
        key = "id"

    if not row or not verify_password(password, row["password_hash"]):
        return jsonify(error=bad), 401

    token = issue_token(role, row[key])
    user = {"type": role, "name": row["name"], key: row[key]}
    if role == "student":
        user["room"] = row["room"]
    return jsonify(token=token, user=user)


@app.post("/api/auth/logout")
@auth_required()
def logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip()
    db = get_db()
    db.execute("DELETE FROM tokens WHERE token = ?", (token,))
    db.commit()
    return jsonify(message="Signed out")


@app.get("/api/me")
@auth_required()
def me():
    return jsonify(user=g.user)


# --------------------------------------------------------------------------
# Attendance
# --------------------------------------------------------------------------

@app.post("/api/attendance")
@auth_required("student")
def mark_attendance():
    status = (body().get("status") or "").lower()
    if status not in ("present", "absent"):
        return jsonify(error="Status must be 'present' or 'absent'"), 400

    roll, today = g.user["roll"], today_str()
    db = get_db()

    if db.execute("SELECT 1 FROM attendance WHERE roll=? AND date=?", (roll, today)).fetchone():
        return jsonify(error="Attendance for today is already marked"), 409

    approved = db.execute(
        """SELECT 1 FROM leaves
           WHERE roll=? AND status='approved' AND from_date <= ? AND to_date >= ?""",
        (roll, today, today),
    ).fetchone()
    if approved:
        return jsonify(error="You are on approved leave today"), 409

    db.execute("INSERT INTO attendance (roll, date, status) VALUES (?,?,?)", (roll, today, status))
    db.commit()
    return jsonify(message=f"Marked {status} for today", date=today, status=status), 201


@app.get("/api/attendance/me")
@auth_required("student")
def my_attendance():
    rows = get_db().execute(
        "SELECT date, status FROM attendance WHERE roll=? ORDER BY date DESC", (g.user["roll"],)
    ).fetchall()
    records = [dict(r) for r in rows]
    present = sum(1 for r in records if r["status"] == "present")
    total = len(records)
    return jsonify(
        records=records,
        summary={
            "total": total,
            "present": present,
            "absent": total - present,
            "percent": round(present / total * 100) if total else 0,
        },
    )


@app.get("/api/attendance/today")
@auth_required("warden")
def attendance_today():
    """Roster for a given date (?date=YYYY-MM-DD, defaults to today)."""
    date = request.args.get("date", today_str())
    if not parse_date(date):
        return jsonify(error="Invalid date"), 400

    rows = get_db().execute(
        """SELECT s.roll, s.name, s.room, a.status
           FROM students s
           LEFT JOIN attendance a ON a.roll = s.roll AND a.date = ?
           ORDER BY s.roll""",
        (date,),
    ).fetchall()
    roster = [dict(r) for r in rows]
    present = sum(1 for r in roster if r["status"] == "present")
    marked = sum(1 for r in roster if r["status"])
    pending = get_db().execute("SELECT COUNT(*) c FROM leaves WHERE status='pending'").fetchone()["c"]
    return jsonify(
        date=date,
        roster=roster,
        summary={
            "students": len(roster),
            "present": present,
            "absent": marked - present,
            "notMarked": len(roster) - marked,
            "pendingLeaves": pending,
        },
    )


# --------------------------------------------------------------------------
# Leaves
# --------------------------------------------------------------------------

@app.post("/api/leaves")
@auth_required("student")
def apply_leave():
    d = body()
    frm, to = parse_date(d.get("from")), parse_date(d.get("to"))
    reason = (d.get("reason") or "").strip()

    if not frm or not to or not reason:
        return jsonify(error="Please fill all fields"), 400
    if to < frm:
        return jsonify(error="To date cannot be before From date"), 400
    if frm < dt.date.today():
        return jsonify(error="Leave cannot start in the past"), 400
    if (to - frm).days > 30:
        return jsonify(error="Leave cannot exceed 30 days"), 400

    db = get_db()
    clash = db.execute(
        """SELECT 1 FROM leaves
           WHERE roll=? AND status IN ('pending','approved')
             AND from_date <= ? AND to_date >= ?""",
        (g.user["roll"], to.isoformat(), frm.isoformat()),
    ).fetchone()
    if clash:
        return jsonify(error="You already have a request covering these dates"), 409

    lid = "L" + secrets.token_hex(5)
    db.execute(
        """INSERT INTO leaves (id, roll, from_date, to_date, reason, status, applied_on)
           VALUES (?,?,?,?,?,'pending',?)""",
        (lid, g.user["roll"], frm.isoformat(), to.isoformat(), reason, today_str()),
    )
    db.commit()
    return jsonify(message="Leave request submitted", id=lid), 201


@app.get("/api/leaves/me")
@auth_required("student")
def my_leaves():
    rows = get_db().execute(
        "SELECT * FROM leaves WHERE roll=? ORDER BY applied_on DESC, id DESC", (g.user["roll"],)
    ).fetchall()
    return jsonify(leaves=[leave_json(r) for r in rows])


@app.get("/api/leaves")
@auth_required("warden")
def all_leaves():
    """Optional ?status=pending|approved|rejected"""
    status = request.args.get("status")
    sql = """SELECT l.*, s.name, s.room FROM leaves l
             JOIN students s ON s.roll = l.roll"""
    params = []
    if status:
        if status not in ("pending", "approved", "rejected"):
            return jsonify(error="Invalid status filter"), 400
        sql += " WHERE l.status = ?"
        params.append(status)
    sql += " ORDER BY (l.status='pending') DESC, l.applied_on DESC, l.id DESC"
    rows = get_db().execute(sql, params).fetchall()
    return jsonify(leaves=[leave_json(r) for r in rows])


@app.patch("/api/leaves/<leave_id>")
@auth_required("warden")
def decide_leave(leave_id):
    decision = (body().get("status") or "").lower()
    if decision not in ("approved", "rejected"):
        return jsonify(error="Decision must be 'approved' or 'rejected'"), 400

    db = get_db()
    row = db.execute("SELECT * FROM leaves WHERE id=?", (leave_id,)).fetchone()
    if not row:
        return jsonify(error="Leave request not found"), 404
    if row["status"] != "pending":
        return jsonify(error=f"This request was already {row['status']}"), 409

    db.execute(
        "UPDATE leaves SET status=?, decided_by=?, decided_on=? WHERE id=?",
        (decision, g.user["id"], today_str(), leave_id),
    )
    db.commit()
    return jsonify(message=f"Leave request {decision}", id=leave_id, status=decision)


# --------------------------------------------------------------------------
# Students (warden)
# --------------------------------------------------------------------------

@app.get("/api/students")
@auth_required("warden")
def list_students():
    rows = get_db().execute(
        """SELECT s.roll, s.name, s.room,
                  COUNT(a.id) AS total,
                  SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END) AS present
           FROM students s
           LEFT JOIN attendance a ON a.roll = s.roll
           GROUP BY s.roll ORDER BY s.roll"""
    ).fetchall()
    out = []
    for r in rows:
        total = r["total"] or 0
        present = r["present"] or 0
        out.append({
            "roll": r["roll"], "name": r["name"], "room": r["room"],
            "total": total, "present": present,
            "percent": round(present / total * 100) if total else 0,
        })
    return jsonify(students=out)


# --------------------------------------------------------------------------
# Bootstrap — one call that returns everything the current view needs
# --------------------------------------------------------------------------

@app.get("/api/bootstrap")
@auth_required()
def bootstrap():
    user = g.user
    db = get_db()
    data = {"user": user, "today": today_str()}

    if user["type"] == "student":
        att = db.execute(
            "SELECT date, status FROM attendance WHERE roll=? ORDER BY date DESC", (user["roll"],)
        ).fetchall()
        lv = db.execute(
            "SELECT * FROM leaves WHERE roll=? ORDER BY applied_on DESC, id DESC", (user["roll"],)
        ).fetchall()
        data["attendance"] = [dict(r) for r in att]
        data["leaves"] = [leave_json(r) for r in lv]
    else:
        data["students"] = list_students().get_json()["students"]
        data["todayAttendance"] = attendance_today().get_json()
        lv = db.execute(
            """SELECT l.*, s.name FROM leaves l JOIN students s ON s.roll=l.roll
               ORDER BY (l.status='pending') DESC, l.applied_on DESC, l.id DESC"""
        ).fetchall()
        data["leaves"] = [leave_json(r) for r in lv]
    return jsonify(data)


# --------------------------------------------------------------------------
# Serve the front-end (so everything runs on one origin)
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)


@app.errorhandler(404)
def not_found(_e):
    if request.path.startswith("/api/"):
        return jsonify(error="Endpoint not found"), 404
    return jsonify(error="Not found"), 404


if __name__ == "__main__":
    init_db()
    print(f"HostelSync API running — database at {DB_PATH}")
    app.run(debug=True, port=5000)
