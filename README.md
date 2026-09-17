# HostelSync — Backend

Flask + SQLite REST API for the Automated Student Hostel Leave & Attendance
Management System. The front-end (`index.html`) is the original UI with its
`localStorage` data layer swapped for `fetch` calls to this API.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 — Flask serves `index.html` from the same
folder, so keep both files together and there are no CORS issues.

`hostelsync.db` is created automatically on first run and seeded with the demo
accounts. Delete that file to reset everything.

| Role    | ID   | Password |
|---------|------|----------|
| Student | S101 | 1234     |
| Student | S102 | 1234     |
| Student | S103 | 1234     |
| Warden  | W01  | admin    |

## Endpoints

All routes except register/login need `Authorization: Bearer <token>`.

| Method | Path                     | Role    | Purpose                              |
|--------|--------------------------|---------|--------------------------------------|
| POST   | /api/auth/register       | public  | Student self-registration            |
| POST   | /api/auth/login          | public  | Returns a token valid for 12 hours   |
| POST   | /api/auth/logout         | any     | Invalidates the token                |
| GET    | /api/me                  | any     | Current user                         |
| GET    | /api/bootstrap           | any     | Everything the dashboard needs       |
| POST   | /api/attendance          | student | Mark today present/absent            |
| GET    | /api/attendance/me       | student | Own records + percentage             |
| GET    | /api/attendance/today    | warden  | Roster for a date (`?date=`)         |
| POST   | /api/leaves              | student | Apply for leave                      |
| GET    | /api/leaves/me           | student | Own requests                         |
| GET    | /api/leaves              | warden  | All requests (`?status=`)            |
| PATCH  | /api/leaves/{id}         | warden  | `{"status":"approved"/"rejected"}`   |
| GET    | /api/students            | warden  | Students with attendance %           |

## Rules enforced server-side

- Passwords stored as PBKDF2-SHA256 with a per-user salt, never in plain text.
- One attendance record per student per day (`UNIQUE(roll, date)`).
- Attendance cannot be marked on a day covered by an approved leave.
- Leave: `to >= from`, no start date in the past, max 30 days, and no overlap
  with an existing pending or approved request.
- A leave request can only be decided once, and only by a warden.
- Students cannot reach warden endpoints and vice versa (403).

## Notes for the report

Tokens live in a `tokens` table with an expiry, so sessions survive a server
restart and sign-out genuinely revokes access. If you deploy this beyond a
local demo, put it behind HTTPS and swap `app.run(debug=True)` for a real
WSGI server such as waitress or gunicorn.
