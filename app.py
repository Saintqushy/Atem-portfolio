import os
import uuid
from functools import wraps
from pathlib import Path
from urllib.parse import quote

import click
import psycopg
from psycopg.rows import dict_row
from supabase import create_client

from dotenv import load_dotenv

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_talisman import Talisman

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from werkzeug.utils import secure_filename

from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
)

from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    NumberRange,
    Optional,
    URL,
)


# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

load_dotenv()


# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key-change-in-production"
)


# Safer session defaults.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "").lower() == "true"
    or os.environ.get("FLASK_ENV", "").lower() == "production"
)


# Prevent unexpectedly large uploads.
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


BASE_DIR = Path(__file__).resolve().parent




# ============================================================
# POSTGRESQL / NEON CONNECTION
# ============================================================
#
# This reads the DATABASE_URL stored inside your .env file.
#
# Example:
#
# DATABASE_URL=postgresql://...
#
# Never put the real password directly inside app.py.
#
# ============================================================

POSTGRES_URL = os.environ.get("DATABASE_URL")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_SECRET_KEY = os.environ.get("SUPABASE_SECRET_KEY")
SUPABASE_BUCKET = os.environ.get("SUPABASE_BUCKET", "portfolio-files")


def get_supabase_client():
    """
    Create a fresh Supabase client for each storage operation.

    This avoids reusing a stale long-lived HTTP connection while Flask
    is running in development/debug mode on Windows.
    """
    if not SUPABASE_URL or not SUPABASE_SECRET_KEY:
        raise RuntimeError(
            "Supabase Storage is not configured. "
            "Check SUPABASE_URL and SUPABASE_SECRET_KEY."
        )

    return create_client(
        SUPABASE_URL,
        SUPABASE_SECRET_KEY
    )


# ============================================================
# FILE STORAGE
# ============================================================

STATIC_DIR = BASE_DIR / "static"
UPLOADS_DIR = STATIC_DIR / "uploads"

PROJECT_STORAGE_PREFIX = "projects"
CERT_STORAGE_PREFIX = "certificates"
CV_STORAGE_PREFIX = "cv"


# ============================================================
# SECURITY HEADERS
# ============================================================

Talisman(
    app,

    content_security_policy={

        "default-src": [
            "'self'"
        ],

        "style-src": [
            "'self'",
            "https://fonts.googleapis.com"
        ],

        "font-src": [
            "'self'",
            "https://fonts.gstatic.com"
        ],

        "script-src": [
            "'self'"
        ],

        "img-src": [
            source
            for source in (
                "'self'",
                "data:",
                SUPABASE_URL or None
            )
            if source
        ],

        "object-src": [
            "'none'"
        ],

        "base-uri": [
            "'self'"
        ],

        "frame-ancestors": [
            "'self'"
        ],
    },

    force_https=(
        os.environ.get(
            "FORCE_HTTPS",
            ""
        ).lower() == "true"
    )
)


# ============================================================
# RATE LIMITING
# ============================================================

limiter = Limiter(

    key_func=get_remote_address,

    app=app,

    default_limits=[
        "60 per minute"
    ]
)


# ============================================================
# POSTGRESQL DATABASE CONNECTION
# ============================================================

def get_db_connection():

    if not POSTGRES_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured. Check your .env file."
        )

    return psycopg.connect(
        POSTGRES_URL,
        row_factory=dict_row
    )


# ============================================================
# SITE SETTINGS
# ============================================================

def get_setting(
    key,
    default=""
):

    with get_db_connection() as connection:

        row = connection.execute(
            """
            SELECT value
            FROM site_settings
            WHERE key = %s
            """,

            (key,),
        ).fetchone()


    return (
        row["value"]
        if row
        else default
    )


def set_setting(
    key,
    value
):

    with get_db_connection() as connection:

        connection.execute(
            """
            INSERT INTO site_settings (
                key,
                value
            )

            VALUES (%s, %s)

            ON CONFLICT(key)

            DO UPDATE
            SET value = excluded.value
            """,

            (
                key,
                value
            ),
        )

        connection.commit()


# ============================================================
# FILE HELPERS
# ============================================================

ALLOWED_UPLOAD_TYPES = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
}


def validate_upload_signature(file_storage, suffix):
    """
    Validate basic file signatures so a renamed executable or other file
    cannot be accepted merely because its filename ends in .jpg or .pdf.
    """
    file_storage.stream.seek(0)
    header = file_storage.stream.read(16)
    file_storage.stream.seek(0)

    if suffix in {".jpg", ".jpeg"}:
        return header.startswith(b"\xff\xd8\xff")

    if suffix == ".png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")

    if suffix == ".webp":
        return (
            len(header) >= 12
            and header[:4] == b"RIFF"
            and header[8:12] == b"WEBP"
        )

    if suffix == ".pdf":
        return header.startswith(b"%PDF-")

    return False


def save_upload(file_storage, storage_prefix):
    """
    Upload an approved file to the private backend-controlled Supabase
    client and return a portable storage reference for PostgreSQL.
    """
    if not file_storage or not file_storage.filename:
        return None

    storage_client = get_supabase_client()

    original_name = secure_filename(file_storage.filename)
    suffix = Path(original_name).suffix.lower()

    if suffix not in ALLOWED_UPLOAD_TYPES:
        raise ValueError("Unsupported upload file type.")

    if not validate_upload_signature(file_storage, suffix):
        raise ValueError(
            "The uploaded file contents do not match its file type."
        )

    unique_name = f"{uuid.uuid4().hex}{suffix}"
    object_path = f"{storage_prefix}/{unique_name}"
    content_type = ALLOWED_UPLOAD_TYPES[suffix]

    file_storage.stream.seek(0)
    file_bytes = file_storage.stream.read()
    file_storage.stream.seek(0)

    storage_client.storage.from_(SUPABASE_BUCKET).upload(
        path=object_path,
        file=file_bytes,
        file_options={
            "content-type": content_type,
            "upsert": "false",
        },
    )

    return f"supabase://{object_path}"


def supabase_public_url(storage_reference):
    if not storage_reference:
        return ""

    if storage_reference.startswith(("http://", "https://")):
        return storage_reference

    if not storage_reference.startswith("supabase://"):
        return ""

    object_path = storage_reference[len("supabase://"):]

    encoded_path = quote(
        object_path,
        safe="/"
    )

    return (
        f"{SUPABASE_URL}/storage/v1/object/public/"
        f"{SUPABASE_BUCKET}/{encoded_path}"
    )


def media_url(storage_reference):
    """
    Resolve both old local static paths and new Supabase references.
    This keeps existing migrated certificate/project records working.
    """
    if not storage_reference:
        return ""

    if storage_reference.startswith(("http://", "https://")):
        return storage_reference

    if storage_reference.startswith("supabase://"):
        return supabase_public_url(storage_reference)

    return url_for(
        "static",
        filename=storage_reference
    )


app.jinja_env.globals["media_url"] = media_url


def delete_managed_upload(storage_reference):
    """
    Delete only files managed by this portfolio.

    New files use supabase:// references.
    Old local uploads are retained for backward compatibility.
    """
    if not storage_reference:
        return

    if storage_reference.startswith("supabase://"):
        storage_client = get_supabase_client()

        object_path = storage_reference[len("supabase://"):]

        storage_client.storage.from_(
            SUPABASE_BUCKET
        ).remove(
            [object_path]
        )

        return

    if not storage_reference.startswith("uploads/"):
        return

    target = (
        STATIC_DIR
        / storage_reference
    ).resolve()

    try:
        uploads_root = UPLOADS_DIR.resolve()
        target.relative_to(uploads_root)
    except ValueError:
        return

    if target.is_file():
        target.unlink(
            missing_ok=True
        )


# ============================================================
# CONTACT FORM
# ============================================================

class ContactForm(FlaskForm):

    name = StringField(

        "Name",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=80
            )
        ]
    )


    email = StringField(

        "Email",

        validators=[
            DataRequired(),
            Email(),
            Length(
                max=120
            )
        ]
    )


    message = TextAreaField(

        "Message",

        validators=[
            DataRequired(),
            Length(
                min=5,
                max=2000
            )
        ]
    )


    submit = SubmitField(
        "Send Message"
    )


# ============================================================
# ADMIN LOGIN FORM
# ============================================================

class AdminLoginForm(FlaskForm):

    username = StringField(

        "Username",

        validators=[
            DataRequired(),
            Length(
                min=3,
                max=80
            )
        ]
    )


    password = PasswordField(

        "Password",

        validators=[
            DataRequired(),
            Length(
                min=8,
                max=200
            )
        ]
    )


    submit = SubmitField(
        "Sign In"
    )


# ============================================================
# PROJECT FORM
# ============================================================

class ProjectForm(FlaskForm):

    title = StringField(

        "Project title",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=120
            )
        ]
    )


    description = TextAreaField(

        "Description",

        validators=[
            DataRequired(),
            Length(
                min=10,
                max=1200
            )
        ]
    )


    tags = StringField(

        "Tags",

        validators=[
            Optional(),
            Length(
                max=300
            )
        ],

        description=(
            "Comma-separated, e.g. "
            "Flask, PostgreSQL, Security"
        )
    )


    project_url = StringField(

        "Project / case-study URL",

        validators=[
            Optional(),
            URL(),
            Length(
                max=500
            )
        ]
    )


    image = FileField(

        "Project image",

        validators=[

            FileAllowed(

                [
                    "jpg",
                    "jpeg",
                    "png",
                    "webp"
                ],

                "Images only: JPG, PNG or WEBP."
            )
        ]
    )


    display_order = IntegerField(

        "Display order",

        validators=[

            DataRequired(),

            NumberRange(
                min=0,
                max=999
            )
        ],

        default=0
    )


    is_published = BooleanField(
        "Show on portfolio",
        default=True
    )


    submit = SubmitField(
        "Save Project"
    )


# ============================================================
# CERTIFICATE FORM
# ============================================================

class CertificateForm(FlaskForm):

    issuer = StringField(

        "Issuer / category",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=80
            )
        ]
    )


    title = StringField(

        "Certificate title",

        validators=[
            DataRequired(),
            Length(
                min=2,
                max=140
            )
        ]
    )


    description = TextAreaField(

        "Description",

        validators=[
            DataRequired(),
            Length(
                min=5,
                max=600
            )
        ]
    )


    preview = FileField(

        "Preview image",

        validators=[

            FileAllowed(

                [
                    "jpg",
                    "jpeg",
                    "png",
                    "webp"
                ],

                "Preview must be JPG, PNG or WEBP."
            )
        ]
    )


    document = FileField(

        "Certificate PDF",

        validators=[

            FileAllowed(
                ["pdf"],
                "Certificate document must be PDF."
            )
        ]
    )


    display_order = IntegerField(

        "Display order",

        validators=[

            DataRequired(),

            NumberRange(
                min=0,
                max=999
            )
        ],

        default=0
    )


    is_published = BooleanField(
        "Show on portfolio",
        default=True
    )


    submit = SubmitField(
        "Save Certificate"
    )


# ============================================================
# CV FORM
# ============================================================

class CVForm(FlaskForm):

    cv_file = FileField(

        "CV PDF",

        validators=[

            DataRequired(),

            FileAllowed(
                ["pdf"],
                "Your CV must be a PDF."
            )
        ]
    )


    submit = SubmitField(
        "Upload CV"
    )


# ============================================================
# EMPTY FORM
# ============================================================

class EmptyForm(FlaskForm):

    submit = SubmitField(
        "Submit"
    )


# ============================================================
# ADMIN AUTHORIZATION DECORATOR
# ============================================================

def admin_required(view):

    @wraps(view)

    def wrapped_view(
        *args,
        **kwargs
    ):

        if not session.get(
            "admin_user_id"
        ):

            flash(
                "Please sign in to access the admin area.",
                "error"
            )

            return redirect(

                url_for(
                    "admin_login",
                    next=request.path
                )
            )


        return view(
            *args,
            **kwargs
        )


    return wrapped_view


# ============================================================
# CREATE ADMIN CLI COMMAND
# ============================================================

@app.cli.command(
    "create-admin"
)

@click.option(
    "--username",
    prompt=True
)

@click.password_option(
    "--password",
    prompt=True,
    confirmation_prompt=True
)

def create_admin(
    username,
    password
):

    """
    Create the first portfolio administrator
    or replace an administrator password.
    """


    username = (
        username.strip()
    )


    if len(username) < 3:

        raise click.ClickException(
            "Username must be at least 3 characters."
        )


    if len(password) < 10:

        raise click.ClickException(
            "Use a password of at least 10 characters."
        )


    with get_db_connection() as connection:

        existing = connection.execute(
            """
            SELECT id
            FROM admin_users
            WHERE username = %s
            """,

            (username,),
        ).fetchone()


        password_hash = (
            generate_password_hash(
                password
            )
        )


        if existing:

            connection.execute(
                """
                UPDATE admin_users

                SET password_hash = %s

                WHERE id = %s
                """,

                (
                    password_hash,
                    existing["id"]
                ),
            )


            click.echo(
                "Admin password updated."
            )


        else:

            connection.execute(
                """
                INSERT INTO admin_users (
                    username,
                    password_hash
                )

                VALUES (%s, %s)
                """,

                (
                    username,
                    password_hash
                ),
            )


            click.echo(
                "Admin user created."
            )


        connection.commit()


# ============================================================
# PUBLIC HOME
# ============================================================

@app.route("/")
def index():

    with get_db_connection() as connection:

        projects = connection.execute(
            """
            SELECT *

            FROM projects

            WHERE is_published = TRUE

            ORDER BY
                display_order ASC,
                id ASC
            """
        ).fetchall()


        certificates = connection.execute(
            """
            SELECT *

            FROM certificates

            WHERE is_published = TRUE

            ORDER BY
                display_order ASC,
                id ASC
            """
        ).fetchall()


    return render_template(

        "index.html",

        projects=projects,

        certificates=certificates,

        cv_available=bool(
            get_setting(
                "cv_path"
            )
        ),
    )


# ============================================================
# ABOUT REDIRECT
# ============================================================

@app.route("/about")
def about():

    return redirect(

        url_for(
            "index",
            _anchor="about"
        )
    )


# ============================================================
# PROJECTS REDIRECT
# ============================================================

@app.route("/projects")
def projects():

    return redirect(

        url_for(
            "index",
            _anchor="projects"
        )
    )


# ============================================================
# CV DOWNLOAD
# ============================================================

@app.route("/cv")
def download_cv():

    cv_path = get_setting(
        "cv_path"
    )

    if not cv_path:
        abort(
            404,
            description="CV has not been uploaded yet."
        )

    if cv_path.startswith(
        ("supabase://", "http://", "https://")
    ):
        target_url = media_url(cv_path)

        if not target_url:
            abort(404)

        return redirect(
            target_url,
            code=302
        )

    # Backward compatibility for any old local CV.
    file_path = (
        STATIC_DIR
        / cv_path
    ).resolve()

    try:
        file_path.relative_to(
            STATIC_DIR.resolve()
        )
    except ValueError:
        abort(404)

    if not file_path.is_file():
        abort(404)

    return send_file(
        file_path,
        as_attachment=True,
        download_name="Atem-Manyok-CV.pdf",
        mimetype="application/pdf",
    )


# ============================================================
# CONTACT
# ============================================================

@app.route(
    "/contact",
    methods=[
        "GET",
        "POST"
    ]
)

@limiter.limit(
    "3 per minute"
)

def contact():

    form = ContactForm()


    if form.validate_on_submit():

        try:

            with get_db_connection() as connection:

                connection.execute(
                    """
                    INSERT INTO messages (
                        name,
                        email,
                        message
                    )

                    VALUES (%s, %s, %s)
                    """,

                    (
                        form.name.data.strip(),

                        form.email.data
                        .strip()
                        .lower(),

                        form.message.data.strip(),
                    ),
                )


                connection.commit()


            flash(
                "Your message has been sent. "
                "I'll get back to you soon.",
                "success",
            )


            return redirect(
                url_for(
                    "contact"
                )
            )


        except psycopg.Error:

            app.logger.exception(
                "Database error while saving contact message."
            )


            flash(
                "Something went wrong while sending your message. "
                "Please try again.",
                "error",
            )


    return render_template(
        "contact.html",
        form=form
    )


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route(
    "/admin/login",
    methods=[
        "GET",
        "POST"
    ]
)

@limiter.limit(
    "5 per minute"
)

def admin_login():

    if session.get(
        "admin_user_id"
    ):

        return redirect(
            url_for(
                "admin_dashboard"
            )
        )


    form = AdminLoginForm()


    if form.validate_on_submit():

        with get_db_connection() as connection:

            user = connection.execute(
                """
                SELECT
                    id,
                    username,
                    password_hash

                FROM admin_users

                WHERE username = %s
                """,

                (
                    form.username.data.strip(),
                ),
            ).fetchone()


        if (
            user
            and check_password_hash(
                user["password_hash"],
                form.password.data
            )
        ):

            session.clear()

            session[
                "admin_user_id"
            ] = user["id"]

            session[
                "admin_username"
            ] = user["username"]


            next_url = request.args.get(
                "next",
                ""
            )


            if (
                next_url.startswith("/")
                and not next_url.startswith("//")
            ):

                return redirect(
                    next_url
                )


            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )


        flash(
            "Invalid username or password.",
            "error"
        )


    return render_template(
        "admin_login.html",
        form=form
    )


# ============================================================
# ADMIN LOGOUT
# ============================================================

@app.route(
    "/admin/logout",
    methods=["POST"]
)

@admin_required

def admin_logout():

    form = EmptyForm()


    if not form.validate_on_submit():

        abort(400)


    session.clear()


    flash(
        "You have been signed out.",
        "success"
    )


    return redirect(
        url_for(
            "admin_login"
        )
    )


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin")

@admin_required

def admin_dashboard():

    with get_db_connection() as connection:

        counts = {

            "messages":

                connection.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM messages
                    """
                ).fetchone()["n"],


            "unread_messages":

                connection.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM messages
                    WHERE is_read = FALSE
                    """
                ).fetchone()["n"],


            "projects":

                connection.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM projects
                    """
                ).fetchone()["n"],


            "certificates":

                connection.execute(
                    """
                    SELECT COUNT(*) AS n
                    FROM certificates
                    """
                ).fetchone()["n"],
        }


        recent_messages = connection.execute(
            """
            SELECT *

            FROM messages

            ORDER BY
                created_at DESC,
                id DESC

            LIMIT 5
            """
        ).fetchall()


    return render_template(

        "admin_dashboard.html",

        counts=counts,

        recent_messages=recent_messages,

        cv_path=get_setting(
            "cv_path"
        ),

        logout_form=EmptyForm(),
    )


# ============================================================
# ADMIN MESSAGES
# ============================================================

@app.route(
    "/admin/messages"
)

@admin_required

def admin_messages():

    with get_db_connection() as connection:

        messages = connection.execute(
            """
            SELECT *

            FROM messages

            ORDER BY
                created_at DESC,
                id DESC
            """
        ).fetchall()


    return render_template(

        "admin_messages.html",

        messages=messages,

        action_form=EmptyForm(),

        logout_form=EmptyForm(),
    )


@app.route(
    "/admin/messages/<int:message_id>/read",
    methods=["POST"]
)

@admin_required

def admin_message_read(
    message_id
):

    form = EmptyForm()


    if not form.validate_on_submit():

        abort(400)


    with get_db_connection() as connection:

        connection.execute(
            """
            UPDATE messages

            SET is_read = TRUE

            WHERE id = %s
            """,

            (message_id,),
        )


        connection.commit()


    return redirect(
        url_for(
            "admin_messages"
        )
    )


@app.route(
    "/admin/messages/<int:message_id>/delete",
    methods=["POST"]
)

@admin_required

def admin_message_delete(
    message_id
):

    form = EmptyForm()


    if not form.validate_on_submit():

        abort(400)


    with get_db_connection() as connection:

        connection.execute(
            """
            DELETE FROM messages

            WHERE id = %s
            """,

            (message_id,),
        )


        connection.commit()


    flash(
        "Message deleted.",
        "success"
    )


    return redirect(
        url_for(
            "admin_messages"
        )
    )


# ============================================================
# ADMIN PROJECTS
# ============================================================

@app.route(
    "/admin/projects"
)

@admin_required

def admin_projects():

    with get_db_connection() as connection:

        projects = connection.execute(
            """
            SELECT *

            FROM projects

            ORDER BY
                display_order ASC,
                id ASC
            """
        ).fetchall()


    return render_template(

        "admin_projects.html",

        projects=projects,

        action_form=EmptyForm(),

        logout_form=EmptyForm(),
    )


# ============================================================
# NEW PROJECT
# ============================================================

@app.route(
    "/admin/projects/new",
    methods=[
        "GET",
        "POST"
    ]
)

@admin_required

def admin_project_new():

    form = ProjectForm()


    if form.validate_on_submit():

        image_path = save_upload(
            form.image.data,
            PROJECT_STORAGE_PREFIX
        )


        with get_db_connection() as connection:

            connection.execute(
                """
                INSERT INTO projects (

                    title,
                    description,
                    tags,
                    image_path,
                    project_url,
                    is_published,
                    display_order

                )

                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,

                (
                    form.title.data.strip(),

                    form.description.data.strip(),

                    (
                        form.tags.data
                        or ""
                    ).strip(),

                    image_path,

                    (
                        form.project_url.data
                        or ""
                    ).strip(),

                    bool(
                        form.is_published.data
                    ),

                    form.display_order.data
                    or 0,
                ),
            )


            connection.commit()


        flash(
            "Project added.",
            "success"
        )


        return redirect(
            url_for(
                "admin_projects"
            )
        )


    return render_template(

        "admin_project_form.html",

        form=form,

        heading="Add Project",

        project=None,

        logout_form=EmptyForm(),
    )


# ============================================================
# EDIT PROJECT
# ============================================================

@app.route(
    "/admin/projects/<int:project_id>/edit",
    methods=[
        "GET",
        "POST"
    ]
)

@admin_required

def admin_project_edit(
    project_id
):

    with get_db_connection() as connection:

        project = connection.execute(
            """
            SELECT *

            FROM projects

            WHERE id = %s
            """,

            (project_id,),
        ).fetchone()


    if not project:

        abort(404)


    form = ProjectForm()


    if request.method == "GET":

        form.title.data = (
            project["title"]
        )

        form.description.data = (
            project["description"]
        )

        form.tags.data = (
            project["tags"]
        )

        form.project_url.data = (
            project["project_url"]
        )

        form.display_order.data = (
            project["display_order"]
        )

        form.is_published.data = bool(
            project["is_published"]
        )


    if form.validate_on_submit():

        new_image_path = (
            project["image_path"]
        )


        if (
            form.image.data
            and form.image.data.filename
        ):

            uploaded = save_upload(
                form.image.data,
                PROJECT_STORAGE_PREFIX
            )


            if uploaded:

                delete_managed_upload(
                    project["image_path"]
                )

                new_image_path = uploaded


        with get_db_connection() as connection:

            connection.execute(
                """
                UPDATE projects

                SET
                    title = %s,
                    description = %s,
                    tags = %s,
                    image_path = %s,
                    project_url = %s,
                    is_published = %s,
                    display_order = %s,
                    updated_at = CURRENT_TIMESTAMP

                WHERE id = %s
                """,

                (
                    form.title.data.strip(),

                    form.description.data.strip(),

                    (
                        form.tags.data
                        or ""
                    ).strip(),

                    new_image_path,

                    (
                        form.project_url.data
                        or ""
                    ).strip(),

                    bool(
                        form.is_published.data
                    ),

                    form.display_order.data
                    or 0,

                    project_id,
                ),
            )


            connection.commit()


        flash(
            "Project updated.",
            "success"
        )


        return redirect(
            url_for(
                "admin_projects"
            )
        )


    return render_template(

        "admin_project_form.html",

        form=form,

        heading="Edit Project",

        project=project,

        logout_form=EmptyForm(),
    )


# ============================================================
# DELETE PROJECT
# ============================================================

@app.route(
    "/admin/projects/<int:project_id>/delete",
    methods=["POST"]
)

@admin_required

def admin_project_delete(
    project_id
):

    form = EmptyForm()


    if not form.validate_on_submit():

        abort(400)


    with get_db_connection() as connection:

        project = connection.execute(
            """
            SELECT image_path

            FROM projects

            WHERE id = %s
            """,

            (project_id,),
        ).fetchone()


        if not project:

            abort(404)


        connection.execute(
            """
            DELETE FROM projects

            WHERE id = %s
            """,

            (project_id,),
        )


        connection.commit()


    delete_managed_upload(
        project["image_path"]
    )


    flash(
        "Project deleted.",
        "success"
    )


    return redirect(
        url_for(
            "admin_projects"
        )
    )


# ============================================================
# ADMIN CERTIFICATES
# ============================================================

@app.route(
    "/admin/certificates"
)

@admin_required

def admin_certificates():

    with get_db_connection() as connection:

        certificates = connection.execute(
            """
            SELECT *

            FROM certificates

            ORDER BY
                display_order ASC,
                id ASC
            """
        ).fetchall()


    return render_template(

        "admin_certificates.html",

        certificates=certificates,

        action_form=EmptyForm(),

        logout_form=EmptyForm(),
    )


# ============================================================
# NEW CERTIFICATE
# ============================================================

@app.route(
    "/admin/certificates/new",
    methods=[
        "GET",
        "POST"
    ]
)

@admin_required

def admin_certificate_new():

    form = CertificateForm()


    if form.validate_on_submit():

        preview_path = save_upload(
            form.preview.data,
            CERT_STORAGE_PREFIX
        )


        document_path = save_upload(
            form.document.data,
            CERT_STORAGE_PREFIX
        )


        with get_db_connection() as connection:

            connection.execute(
                """
                INSERT INTO certificates (

                    issuer,
                    title,
                    description,
                    preview_path,
                    document_path,
                    is_published,
                    display_order

                )

                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,

                (
                    form.issuer.data.strip(),

                    form.title.data.strip(),

                    form.description.data.strip(),

                    preview_path,

                    document_path,

                    bool(
                        form.is_published.data
                    ),

                    form.display_order.data
                    or 0,
                ),
            )


            connection.commit()


        flash(
            "Certificate added.",
            "success"
        )


        return redirect(
            url_for(
                "admin_certificates"
            )
        )


    return render_template(

        "admin_certificate_form.html",

        form=form,

        heading="Add Certificate",

        certificate=None,

        logout_form=EmptyForm(),
    )


# ============================================================
# EDIT CERTIFICATE
# ============================================================

@app.route(
    "/admin/certificates/<int:certificate_id>/edit",
    methods=[
        "GET",
        "POST"
    ]
)

@admin_required

def admin_certificate_edit(
    certificate_id
):

    with get_db_connection() as connection:

        certificate = connection.execute(
            """
            SELECT *

            FROM certificates

            WHERE id = %s
            """,

            (certificate_id,),
        ).fetchone()


    if not certificate:

        abort(404)


    form = CertificateForm()


    if request.method == "GET":

        form.issuer.data = (
            certificate["issuer"]
        )

        form.title.data = (
            certificate["title"]
        )

        form.description.data = (
            certificate["description"]
        )

        form.display_order.data = (
            certificate["display_order"]
        )

        form.is_published.data = bool(
            certificate["is_published"]
        )


    if form.validate_on_submit():

        preview_path = (
            certificate["preview_path"]
        )

        document_path = (
            certificate["document_path"]
        )


        if (
            form.preview.data
            and form.preview.data.filename
        ):

            uploaded = save_upload(
                form.preview.data,
                CERT_STORAGE_PREFIX
            )


            if uploaded:

                delete_managed_upload(
                    certificate["preview_path"]
                )

                preview_path = uploaded


        if (
            form.document.data
            and form.document.data.filename
        ):

            uploaded = save_upload(
                form.document.data,
                CERT_STORAGE_PREFIX
            )


            if uploaded:

                delete_managed_upload(
                    certificate["document_path"]
                )

                document_path = uploaded


        with get_db_connection() as connection:

            connection.execute(
                """
                UPDATE certificates

                SET
                    issuer = %s,
                    title = %s,
                    description = %s,
                    preview_path = %s,
                    document_path = %s,
                    is_published = %s,
                    display_order = %s,
                    updated_at = CURRENT_TIMESTAMP

                WHERE id = %s
                """,

                (
                    form.issuer.data.strip(),

                    form.title.data.strip(),

                    form.description.data.strip(),

                    preview_path,

                    document_path,

                    bool(
                        form.is_published.data
                    ),

                    form.display_order.data
                    or 0,

                    certificate_id,
                ),
            )


            connection.commit()


        flash(
            "Certificate updated.",
            "success"
        )


        return redirect(
            url_for(
                "admin_certificates"
            )
        )


    return render_template(

        "admin_certificate_form.html",

        form=form,

        heading="Edit Certificate",

        certificate=certificate,

        logout_form=EmptyForm(),
    )


# ============================================================
# DELETE CERTIFICATE
# ============================================================

@app.route(
    "/admin/certificates/<int:certificate_id>/delete",
    methods=["POST"]
)

@admin_required

def admin_certificate_delete(
    certificate_id
):

    form = EmptyForm()


    if not form.validate_on_submit():

        abort(400)


    with get_db_connection() as connection:

        certificate = connection.execute(
            """
            SELECT
                preview_path,
                document_path

            FROM certificates

            WHERE id = %s
            """,

            (certificate_id,),
        ).fetchone()


        if not certificate:

            abort(404)


        connection.execute(
            """
            DELETE FROM certificates

            WHERE id = %s
            """,

            (certificate_id,),
        )


        connection.commit()


    delete_managed_upload(
        certificate["preview_path"]
    )


    delete_managed_upload(
        certificate["document_path"]
    )


    flash(
        "Certificate deleted.",
        "success"
    )


    return redirect(
        url_for(
            "admin_certificates"
        )
    )


# ============================================================
# ADMIN CV
# ============================================================

@app.route(
    "/admin/cv",
    methods=[
        "GET",
        "POST"
    ]
)

@admin_required

def admin_cv():

    form = CVForm()


    current_cv = get_setting(
        "cv_path"
    )


    if form.validate_on_submit():

        new_path = save_upload(
            form.cv_file.data,
            CV_STORAGE_PREFIX
        )


        if new_path:

            set_setting(
                "cv_path",
                new_path
            )

            delete_managed_upload(
                current_cv
            )


            flash(
                "CV updated successfully.",
                "success"
            )


            return redirect(
                url_for(
                    "admin_cv"
                )
            )


    return render_template(

        "admin_cv.html",

        form=form,

        current_cv=current_cv,

        logout_form=EmptyForm(),
    )


# ============================================================
# ERROR HANDLER - LARGE UPLOAD
# ============================================================

@app.errorhandler(413)

def upload_too_large(
    _error
):

    flash(
        "That upload is too large. "
        "Maximum file size is 8 MB.",
        "error"
    )


    return redirect(

        request.referrer

        or url_for(
            "admin_dashboard"
        )
    )




# ============================================================
# RUN APP
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=(
            os.environ.get(
                "FLASK_ENV"
            )
            != "production"
        )
    )
