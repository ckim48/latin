import os, sqlite3, uuid, datetime
from functools import wraps
from flask import Flask, g, request, redirect, url_for, session, render_template, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

APP_NAME = "Latin Olympiad"
DB_PATH  = "app.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
CLASSMARKER_TEST_URL = os.environ.get("CLASSMARKER_TEST_URL", "https://www.classmarker.com/online-test/start/?quiz=ydk68c1692bdfd71")
# Map of test_key -> ClassMarker start URL and label
TESTS = {
    "lvl1_a": {"label": "Level 1 · Set A", "url": "https://www.classmarker.com/online-test/start/?quiz=ydk68c1692bdfd71"},
    "lvl1_b": {"label": "Level 1 · Set B", "url": "https://www.classmarker.com/online-test/start/?quiz=BBBB2222"},
    "lvl2_a": {"label": "Level 2 · Set A", "url": "https://www.classmarker.com/online-test/start/?quiz=CCCC3333"},
    "lvl2_b": {"label": "Level 2 · Set B", "url": "https://www.classmarker.com/online-test/start/?quiz=DDDD4444"},
    "lvl3_a": {"label": "Level 3 · Set A", "url": "https://www.classmarker.com/online-test/start/?quiz=EEEE5555"},
    "lvl3_b": {"label": "Level 3 · Set B", "url": "https://www.classmarker.com/online-test/start/?quiz=FFFF6666"},
    "lvl4_a": {"label": "Level 4 · Set A", "url": "https://www.classmarker.com/online-test/start/?quiz=GGGG7777"},
    "lvl4_b": {"label": "Level 4 · Set B", "url": "https://www.classmarker.com/online-test/start/?quiz=HHHH8888"},
    "lvl5_a": {"label": "Level 5 · Set A", "url": "https://www.classmarker.com/online-test/start/?quiz=IIII9999"},
    "lvl5_b": {"label": "Level 5 · Set B", "url": "https://www.classmarker.com/online-test/start/?quiz=JJJJ0000"},
    "open_a": {"label": "Open · Set A",   "url": "https://www.classmarker.com/online-test/start/?quiz=KKKK1212"},
    "open_b": {"label": "Open · Set B",   "url": "https://www.classmarker.com/online-test/start/?quiz=LLLL3434"},
}


# ---------- DB ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db
# ---------- Auth helpers ----------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

@app.teardown_appcontext
def close_db(_e=None):
    db = g.pop("db", None)
    if db:
        db.close()
def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attempts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            test_key TEXT NOT NULL,
            attempt_token TEXT UNIQUE,  -- used to match the exact attempt
            started_at TEXT NOT NULL,
            completed_at TEXT,
            source TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_attempts_user_test ON attempts(user_id, test_key);
        """
    )
    db.commit()

from flask import make_response
import secrets

@app.route("/start-test/<test_key>")
@login_required
def start_test(test_key):
    if test_key not in TESTS:
        flash("Unknown test.", "danger")
        return redirect(url_for("dashboard"))

    user = current_user()
    db = get_db()

    # If this specific test is already completed, prevent re-take
    done = db.execute(
        "SELECT 1 FROM attempts WHERE user_id=? AND test_key=? AND completed_at IS NOT NULL LIMIT 1",
        (user["id"], test_key)
    ).fetchone()
    if done:
        flash("You have already completed this test.", "info")
        return redirect(url_for("dashboard"))

    # Create attempt + token
    attempt_token = secrets.token_urlsafe(16)
    db.execute(
        "INSERT INTO attempts(user_id, test_key, attempt_token, started_at, source) VALUES(?,?,?,?,?)",
        (user["id"], test_key, attempt_token, datetime.datetime.utcnow().isoformat(), "start")
    )
    db.commit()

    # Build ClassMarker start link for this test
    base_url = TESTS[test_key]["url"]
    # Send both uid and our attempt token (if ClassMarker preserves query params, great)
    test_link = f"{base_url}&cm_uid={user['uid']}&aid={attempt_token}"
    return redirect(test_link)

import json, hmac, hashlib, base64
from flask import jsonify

CLASSMARKER_SECRET = os.environ.get("CLASSMARKER_SECRET", "")  # optional
@app.route("/classmarker/webhook", methods=["GET", "POST", "HEAD", "OPTIONS"])
def classmarker_webhook():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return jsonify({"ok": True}), 200

    if CLASSMARKER_SECRET:
        raw = request.get_data()
        sig_hdr = request.headers.get("X-Classmarker-Hmac-Sha256", "")
        mac = hmac.new(CLASSMARKER_SECRET.encode("utf-8"), raw, hashlib.sha256).digest()
        computed = base64.b64encode(mac).decode("ascii")
        if not hmac.compare_digest(sig_hdr, computed):
            return "invalid signature", 401

    payload = request.get_json(silent=True) or {}
    aid = (payload.get("aid") or payload.get("attempt_token") or "").strip() or None
    uid = (payload.get("cm_uid") or payload.get("uid") or "").strip().upper() or None

    # Flexible score extraction (adjust keys to your exact payload if needed)
    percent   = payload.get("percentage") or payload.get("percent") or None
    raw_score = payload.get("score") or payload.get("raw") or None
    max_score = payload.get("total") or payload.get("out_of") or None

    def _mark_completed_by_attempt(att_row_id):
        now = datetime.datetime.utcnow().isoformat()
        yr  = datetime.datetime.utcnow().year
        get_db().execute(
            """UPDATE attempts
               SET completed_at = COALESCE(completed_at, ?),
                   source       = 'webhook',
                   percent      = COALESCE(?, percent),
                   raw_score    = COALESCE(?, raw_score),
                   max_score    = COALESCE(?, max_score),
                   year         = COALESCE(?, year)
             WHERE id=?""",
            (now, percent, raw_score, max_score, yr, att_row_id)
        )
        get_db().commit()

    db = get_db()
    if aid:
        att = db.execute("SELECT * FROM attempts WHERE attempt_token=?", (aid,)).fetchone()
        if att and not att["completed_at"]:
            _mark_completed_by_attempt(att["id"])
            return jsonify({"ok": True}), 200

    if uid:
        user = db.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        if user:
            att = db.execute(
                "SELECT * FROM attempts WHERE user_id=? AND completed_at IS NULL ORDER BY id DESC LIMIT 1",
                (user["id"],)
            ).fetchone()
            if att:
                _mark_completed_by_attempt(att["id"])

    return jsonify({"ok": True}), 200
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    db = get_db()

    if request.method == "POST":
        action = request.form.get("action")

        # Update basic profile (name/email)
        if action == "update_profile":
            name  = request.form.get("name","").strip()
            email = request.form.get("email","").strip().lower()

            if not name or not email:
                flash("Name and Email are required.", "danger")
            else:
                # Ensure email uniqueness (except self)
                exists = db.execute(
                    "SELECT id FROM users WHERE email=? AND id<>?",
                    (email, user["id"])
                ).fetchone()
                if exists:
                    flash("That email is already in use.", "danger")
                else:
                    db.execute("UPDATE users SET name=?, email=? WHERE id=?", (name, email, user["id"]))
                    db.commit()
                    flash("Profile updated.", "success")

        # Change password
        elif action == "change_password":
            current_pw = request.form.get("current_password","")
            new_pw     = request.form.get("new_password","")
            confirm_pw = request.form.get("confirm_password","")

            if not check_password_hash(user["password_hash"], current_pw):
                flash("Current password is incorrect.", "danger")
            elif not new_pw or new_pw != confirm_pw:
                flash("New passwords do not match.", "danger")
            else:
                new_hash = generate_password_hash(new_pw)
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user["id"]))
                db.commit()
                flash("Password changed successfully.", "success")

        # refetch fresh user
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    # Stats for current year
    this_year = datetime.datetime.utcnow().year
    rows = db.execute(
        """SELECT a.*, COALESCE(a.year, strftime('%Y', a.started_at)) AS y
             FROM attempts a
            WHERE a.user_id=? AND (a.year=? OR strftime('%Y', a.started_at)=?)
            ORDER BY a.id DESC""",
        (user["id"], this_year, str(this_year))
    ).fetchall()

    # Aggregate: completed count, avg percent, best
    completed = [r for r in rows if r["completed_at"]]
    avg_percent = round(sum([r["percent"] for r in completed if r["percent"] is not None]) / max(1, len([r for r in completed if r["percent"] is not None])), 2) if completed else None
    best_percent = max([r["percent"] for r in completed if r["percent"] is not None], default=None)

    return render_template(
        "profile.html",
        app_name=APP_NAME,
        user=user,
        attempts=rows,
        this_year=this_year,
        avg_percent=avg_percent,
        best_percent=best_percent,
        completed_count=len(completed)
    )


@app.route("/classmarker/return", methods=["GET"])
def classmarker_return():
    db = get_db()
    raw_uid = request.args.get("uid", "") or ""
    uid = raw_uid.strip().upper() or None
    aid = (request.args.get("aid") or "").strip() or None

    # 1) Prefer attempt token (aid)
    if aid:
        att = db.execute(
            "SELECT * FROM attempts WHERE attempt_token=? AND completed_at IS NULL",
            (aid,)
        ).fetchone()
        if att:
            db.execute(
                "UPDATE attempts SET completed_at=?, source='return' WHERE id=?",
                (datetime.datetime.utcnow().isoformat(), att["id"])
            )
            db.commit()
            # ensure session has the user
            session["user_id"] = att["user_id"]
            flash("Your test is recorded as completed. Great job!", "success")
            return redirect(url_for("dashboard"))

    # 2) Else try uid
    if uid:
        user = db.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        if user:
            db.execute(
                """
                UPDATE attempts
                   SET completed_at=?, source='return'
                 WHERE user_id=? AND completed_at IS NULL
                 ORDER BY id DESC
                 LIMIT 1
                """,
                (datetime.datetime.utcnow().isoformat(), user["id"])
            )
            db.commit()
            session["user_id"] = user["id"]
            flash("Your test is recorded as completed. Great job!", "success")
            return redirect(url_for("dashboard"))

    # 3) Fallback to current session
    if "user_id" in session:
        db.execute(
            """
            UPDATE attempts
               SET completed_at=?, source='return'
             WHERE user_id=? AND completed_at IS NULL
             ORDER BY id DESC
             LIMIT 1
            """,
            (datetime.datetime.utcnow().isoformat(), session["user_id"])
        )
        db.commit()
        flash("Your test is recorded as completed. Great job!", "success")
        return redirect(url_for("dashboard"))

    flash("We could not verify your completion. Please log in.", "warning")
    return redirect(url_for("login"))

def _add_column_if_missing(table, col, decl):
    cols = {r[1] for r in get_db().execute(f"PRAGMA table_info({table})").fetchall()}
    if col not in cols:
        get_db().execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
        get_db().commit()

def migrate_schema():
    # attempts: add score fields (percent/raw/max) and year for quick filtering
    _add_column_if_missing("attempts", "percent", "REAL")
    _add_column_if_missing("attempts", "raw_score", "REAL")
    _add_column_if_missing("attempts", "max_score", "REAL")
    _add_column_if_missing("attempts", "year", "INTEGER")

@app.before_request
def _ensure_db():
    init_db()
    migrate_schema()

@app.before_request
def _ensure_db():
    init_db()


def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

# ---------- Routes ----------
@app.route("/")
def index():
    return render_template('index.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name  = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        pw    = request.form.get("password","")
        if not name or not email or not pw:
            flash("All fields are required.", "danger")
            return render_template("register.html", app_name=APP_NAME)
        uid = uuid.uuid4().hex[:10].upper()  # short unique ID for contestants
        pw_hash = generate_password_hash(pw)
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(uid,name,email,password_hash,created_at) VALUES(?,?,?,?,?)",
                (uid, name, email, pw_hash, datetime.datetime.utcnow().isoformat()),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Email already in use.", "danger")
            return render_template("register.html", app_name=APP_NAME)
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", app_name=APP_NAME)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        pw    = request.form.get("password","")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not user or not check_password_hash(user["password_hash"], pw):
            flash("Invalid email or password.", "danger")
            return render_template("login.html", app_name=APP_NAME)
        session["user_id"] = user["id"]
        flash("Welcome back!", "success")
        return redirect(request.args.get("next") or url_for("dashboard"))
    return render_template("login.html", app_name=APP_NAME)

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))
@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    db = get_db()

    # Which tests are done for this user?
    rows = db.execute(
        """
        SELECT test_key, MAX(CASE WHEN completed_at IS NOT NULL THEN 1 ELSE 0 END) AS done
          FROM attempts
         WHERE user_id=?
         GROUP BY test_key
        """,
        (user["id"],)
    ).fetchall()
    status = {r["test_key"]: bool(r["done"]) for r in rows}

    return render_template(
        "dashboard.html",
        app_name=APP_NAME,
        name=user["name"],
        uid=user["uid"],
        email=user["email"],
        tests=TESTS,      # <-- pass tests
        status=status     # <-- pass per-test completion
    )


if __name__ == "__main__":
    app.run(debug=True)
