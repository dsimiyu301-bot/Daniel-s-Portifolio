import json
import os
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import click
from flask import (
    Flask, abort, flash, g, redirect, render_template,
    request, session, url_for
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
instance = Path(app.instance_path)
instance.mkdir(parents=True, exist_ok=True)

secret_path = instance / "secret.key"
if not secret_path.exists():
    try:
        with secret_path.open("x") as file:
            file.write(secrets.token_hex(32))
        secret_path.chmod(0o600)
    except FileExistsError:
        pass

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secret_path.read_text().strip(),
    MAX_CONTENT_LENGTH=64 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

CSRFProtect(app)

OWNER = {
    "name": "Daniel Wanjala Simiyu",
    "email": "dsimiyu301@gmail.com",
    "phone": "0727303107",
    "whatsapp": "254727303107",
    "location": "Kitale, Trans Nzoia County, Kenya",
}

CATEGORIES = [
    "Business", "E-commerce", "Education",
    "Portfolio", "Management Systems"
]


def db():
    if "db" not in g:
        connection = sqlite3.connect(instance / "portfolio.db")
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def initialize():
    db().executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL CHECK(price >= 0),
            days INTEGER NOT NULL CHECK(days > 0),
            image TEXT NOT NULL DEFAULT '',
            demo TEXT NOT NULL DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS enquiries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            message TEXT NOT NULL,
            items TEXT NOT NULL,
            total INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db().commit()


@app.cli.command("init-db")
def init_db_command():
    """Create database and add clearly labelled example projects."""
    initialize()

    if db().execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 0:
        examples = [
            (
                "Business Website — Example",
                "Business",
                "A sample package for a responsive company website, "
                "including service pages, an about page and a contact form.",
                18000, 7, "", ""
            ),
            (
                "Online Shop — Example",
                "E-commerce",
                "A sample online store package with product listings, "
                "a cart and order enquiries. Payment integrations are quoted separately.",
                45000, 21, "", ""
            ),
            (
                "School Website — Example",
                "Education",
                "A sample school website with information pages, "
                "announcements, an admissions section and contact details.",
                30000, 14, "", ""
            ),
            (
                "Personal Portfolio — Example",
                "Portfolio",
                "A sample portfolio package for showcasing skills, "
                "projects, services and contact information.",
                12000, 5, "", ""
            ),
            (
                "Inventory System — Example",
                "Management Systems",
                "A sample inventory application with stock records, "
                "an administrator dashboard and basic reports.",
                60000, 30, "", ""
            ),
        ]
        db().executemany("""
            INSERT INTO projects
            (title, category, description, price, days, image, demo)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, examples)
        db().commit()

    click.echo("Database ready. Example projects are available.")


@app.cli.command("set-admin")
@click.password_option(
    confirmation_prompt=True,
    help="Choose an admin password of at least 12 characters."
)
def set_admin(password):
    """Set or change the administrator password."""
    if len(password) < 12:
        raise click.ClickException("Use at least 12 characters.")

    initialize()
    db().execute("""
        INSERT INTO settings(key, value)
        VALUES ('admin_password', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
    """, (generate_password_hash(password),))
    db().commit()
    click.echo("Administrator password saved.")


@app.template_filter("kes")
def kes(value):
    return f"KSh {int(value):,}"


def cart_ids():
    result = []
    for value in session.get("cart", []):
        if isinstance(value, int) and value not in result:
            result.append(value)
    return result[:30]


def cart_projects():
    ids = cart_ids()
    if not ids:
        return []
    placeholders = ",".join("?" for _ in ids)
    return db().execute(
        f"SELECT * FROM projects WHERE id IN ({placeholders}) ORDER BY id",
        ids
    ).fetchall()


@app.context_processor
def shared():
    return {
        "owner": OWNER,
        "categories": CATEGORIES,
        "cart_count": len(cart_ids()),
    }


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' https:; "
        "style-src 'self'; "
        "script-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    if session.get("admin") or request.endpoint in {
        "login", "cart", "checkout", "thanks"
    }:
        response.headers["Cache-Control"] = "no-store"
    return response


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_project(project_id):
    project = db().execute(
        "SELECT * FROM projects WHERE id = ?", (project_id,)
    ).fetchone()
    if project is None:
        abort(404)
    return project


def valid_url(value):
    if not value:
        return True
    parsed = urlsplit(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


@app.get("/")
def index():
    query = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "")
    sort = request.args.get("sort", "newest")

    sql = "SELECT * FROM projects WHERE 1 = 1"
    args = []

    if query:
        sql += " AND (title LIKE ? OR description LIKE ?)"
        args.extend([f"%{query}%", f"%{query}%"])

    if category in CATEGORIES:
        sql += " AND category = ?"
        args.append(category)

    order = {
        "newest": "id DESC",
        "price-low": "price ASC",
        "price-high": "price DESC",
        "fastest": "days ASC",
    }.get(sort, "id DESC")

    projects = db().execute(sql + " ORDER BY " + order, args).fetchall()
    return render_template(
        "index.html", projects=projects, q=query,
        category=category, sort=sort
    )


@app.get("/projects/<int:project_id>")
def project(project_id):
    return render_template("project.html", project=get_project(project_id))


@app.post("/cart/add/<int:project_id>")
def add_to_cart(project_id):
    get_project(project_id)
    ids = cart_ids()

    if project_id not in ids:
        if len(ids) >= 30:
            flash("Your shortlist is full. Remove an item first.")
        else:
            ids.append(project_id)
            session["cart"] = ids
            flash("Project added to your shortlist.")
    else:
        flash("That project is already in your shortlist.")

    return redirect(url_for("cart"))


@app.post("/cart/remove/<int:project_id>")
def remove_from_cart(project_id):
    session["cart"] = [i for i in cart_ids() if i != project_id]
    return redirect(url_for("cart"))


@app.get("/cart")
def cart():
    projects = cart_projects()
    return render_template(
        "cart.html", projects=projects,
        total=sum(p["price"] for p in projects)
    )


@app.post("/checkout")
def checkout():
    projects = cart_projects()
    if not projects:
        flash("Select at least one project first.")
        return redirect(url_for("index"))

    limits = {"name": 100, "email": 254, "phone": 30, "message": 3000}
    fields = {}
    for key, limit in limits.items():
        value = request.form.get(key, "").strip()
        if not value or len(value) > limit:
            flash(f"Please provide a valid {key}, up to {limit} characters.")
            return redirect(url_for("cart"))
        fields[key] = value

    if (
        "@" not in fields["email"]
        or "." not in fields["email"].rsplit("@", 1)[-1]
        or any(c.isspace() for c in fields["email"])
    ):
        flash("Please enter a valid email address.")
        return redirect(url_for("cart"))

    if request.form.get("consent") != "yes":
        flash("Please agree to share your details for this enquiry.")
        return redirect(url_for("cart"))

    items = [
        {
            "id": p["id"],
            "title": p["title"],
            "price": p["price"],
            "days": p["days"],
        }
        for p in projects
    ]
    total = sum(item["price"] for item in items)
    reference = "DWS-" + secrets.token_hex(6).upper()

    db().execute("""
        INSERT INTO enquiries
        (reference, name, email, phone, message, items, total)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        reference, fields["name"], fields["email"], fields["phone"],
        fields["message"], json.dumps(items), total
    ))
    db().commit()

    session["cart"] = []
    session["last_reference"] = reference
    return redirect(url_for("thanks"))


@app.get("/thanks")
def thanks():
    reference = session.get("last_reference")
    if not reference:
        return redirect(url_for("index"))

    enquiry = db().execute(
        "SELECT * FROM enquiries WHERE reference = ?", (reference,)
    ).fetchone()
    if enquiry is None:
        abort(404)

    items = json.loads(enquiry["items"])
    lines = [
        f"Hello Daniel, I submitted enquiry {reference}.",
        "I would like a project similar to:",
    ]
    lines.extend(
        f"- {item['title']} ({kes(item['price'])}; {item['days']} days)"
        for item in items
    )
    lines.append("Please contact me to discuss the scope and final quote.")
    whatsapp = (
        f"https://wa.me/{OWNER['whatsapp']}?"
        + urlencode({"text": "\n".join(lines)})
    )
    return render_template(
        "thanks.html", enquiry=enquiry, whatsapp=whatsapp
    )


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if session.get("admin"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        setting = db().execute(
            "SELECT value FROM settings WHERE key = 'admin_password'"
        ).fetchone()
        password = request.form.get("password", "")

        if (
            setting
            and len(password) <= 1024
            and check_password_hash(setting["value"], password)
        ):
            session.clear()
            session["admin"] = True
            session.permanent = True
            return redirect(url_for("admin"))

        flash("Invalid login, or the administrator password has not been set.")

    return render_template("login.html")


@app.post("/admin/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.get("/admin")
@admin_required
def admin():
    edit_id = request.args.get("edit", type=int)
    editing = get_project(edit_id) if edit_id else None

    projects = db().execute(
        "SELECT * FROM projects ORDER BY id DESC"
    ).fetchall()

    enquiries = []
    for row in db().execute(
        "SELECT * FROM enquiries ORDER BY id DESC"
    ).fetchall():
        item = dict(row)
        item["projects"] = json.loads(item["items"])
        enquiries.append(item)

    return render_template(
        "admin.html", projects=projects,
        enquiries=enquiries, editing=editing
    )


@app.post("/admin/projects/save")
@admin_required
def save_project():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "")
    description = request.form.get("description", "").strip()
    image = request.form.get("image", "").strip()
    demo = request.form.get("demo", "").strip()

    try:
        price = int(request.form.get("price", ""))
        days = int(request.form.get("days", ""))
        project_id = int(request.form.get("project_id", "0"))
    except ValueError:
        flash("Price, delivery days and project ID must be whole numbers.")
        return redirect(url_for("admin"))

    valid = (
        1 <= len(title) <= 120
        and category in CATEGORIES
        and 10 <= len(description) <= 5000
        and 0 <= price <= 100000000
        and 1 <= days <= 3650
        and len(image) <= 1000
        and len(demo) <= 1000
        and valid_url(image)
        and valid_url(demo)
    )
    if not valid:
        flash("Check all fields. Optional links must use https://.")
        return redirect(url_for("admin"))

    values = (title, category, description, price, days, image, demo)
    if project_id:
        get_project(project_id)
        db().execute("""
            UPDATE projects
            SET title=?, category=?, description=?, price=?, days=?, image=?, demo=?
            WHERE id=?
        """, values + (project_id,))
    else:
        db().execute("""
            INSERT INTO projects
            (title, category, description, price, days, image, demo)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, values)

    db().commit()
    flash("Project saved.")
    return redirect(url_for("admin"))


@app.post("/admin/projects/<int:project_id>/delete")
@admin_required
def delete_project(project_id):
    get_project(project_id)
    db().execute("DELETE FROM projects WHERE id = ?", (project_id,))
    db().commit()
    flash("Project deleted. Existing enquiry records remain unchanged.")
    return redirect(url_for("admin"))


@app.post("/admin/enquiries/<int:enquiry_id>/status")
@admin_required
def enquiry_status(enquiry_id):
    status = request.form.get("status")
    if status not in {"New", "Contacted", "Completed"}:
        abort(400)

    db().execute(
        "UPDATE enquiries SET status = ? WHERE id = ?",
        (status, enquiry_id)
    )
    db().commit()
    flash("Enquiry status updated.")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)