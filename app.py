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

# ---------- DB ----------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

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
            started_at TEXT NOT NULL,
            completed_at TEXT,
            source TEXT,                     -- 'return' or 'webhook' (optional)
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()

from flask import make_response

@app.route("/start-test")
@login_required
def start_test():
    user = current_user()
    # If already completed, keep them here
    db = get_db()
    done = db.execute(
        "SELECT 1 FROM attempts WHERE user_id=? AND completed_at IS NOT NULL ORDER BY id DESC LIMIT 1",
        (user["id"],)
    ).fetchone()
    if done:
        flash("You’ve already completed the test.", "info")
        return redirect(url_for("dashboard"))

    # Record that they started
    db.execute(
        "INSERT INTO attempts(user_id, started_at, source) VALUES(?,?,?)",
        (user["id"], datetime.datetime.utcnow().isoformat(), "start")
    )
    db.commit()

    # Send them to ClassMarker with uid
    test_link = f"{CLASSMARKER_TEST_URL}&cm_uid={user['uid']}"
    return redirect(test_link)
@app.route("/classmarker/return")
def classmarker_return():
    """
    Students return here after finishing on ClassMarker.
    Prefer passing ?uid=<UID> back to us. If not present, we fall back to session.
    """
    uid = request.args.get("uid", "").strip().upper()

    db = get_db()
    if uid:
        user = db.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        if not user:
            flash("We could not match your UID. Please log in again.", "warning")
            return redirect(url_for("login"))
        # Mark last attempt as completed
        db.execute(
            """
            UPDATE attempts
            SET completed_at = ?
            WHERE user_id = ?
              AND completed_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (datetime.datetime.utcnow().isoformat(), user["id"])
        )
        db.commit()
        session["user_id"] = user["id"]  # ensure they are logged in
    else:
        # Fall back to session if uid isn't provided
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        db.execute(
            """
            UPDATE attempts
            SET completed_at = ?
            WHERE user_id = ?
              AND completed_at IS NULL
            ORDER BY id DESC
            LIMIT 1
            """,
            (datetime.datetime.utcnow().isoformat(), session["user_id"])
        )
        db.commit()

    flash("Your test is recorded as completed. Great job!", "success")
    return redirect(url_for("dashboard"))

@app.before_request
def _ensure_db():
    init_db()

# ---------- Auth helpers ----------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper

def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

# ---------- Routes ----------
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

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

    # Completed if there exists any attempt with completed_at not null
    completed = db.execute(
        "SELECT 1 FROM attempts WHERE user_id=? AND completed_at IS NOT NULL ORDER BY id DESC LIMIT 1",
        (user["id"],)
    ).fetchone() is not None

    return render_template(
        "dashboard.html",
        app_name=APP_NAME,
        name=user["name"],
        uid=user["uid"],
        email=user["email"],
        completed=completed,
        # We don't send test_link directly anymore; start through /start-test
    )


if __name__ == "__main__":
    app.run(debug=True)
