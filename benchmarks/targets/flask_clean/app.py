"""Hardened counterpart of flask_vuln, used to measure false positives.

Every finding reported on this file is a false positive. Two spots
(ALLOWED_HOSTS guard in /fetch) are deliberately guarded in a way a
single-function taint analysis cannot see; the AI triage stage is expected to
dismiss them. They are the reason the benchmark reports triage separately.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import subprocess
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import Flask, abort, jsonify, redirect, request, session
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"   # cookie sessions: block cross-site requests (CSRF)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.secret_key = os.environ["APP_SECRET_KEY"]

ALLOWED_HOSTS = {"api.example.org", "status.example.org"}
UPLOAD_DIR = os.path.abspath("uploads")
HOST_RE = re.compile(r"[A-Za-z0-9.-]{1,253}")


def db():
    return sqlite3.connect("users.db")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    salt_hex, digest_hex = stored.split(":")
    candidate = hash_password(password, bytes.fromhex(salt_hex)).split(":")[1]
    return hmac.compare_digest(candidate, digest_hex)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    conn = db()
    row = conn.execute("SELECT id, password, role FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if row and verify_password(password, row[1]):
        session["user_id"], session["role"] = row[0], row[2]
        return jsonify({"message": "Welcome"})
    return "Invalid credentials", 401


@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        abort(400)
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return escape(result.stdout)


@app.route("/read")
@login_required
def read_file():
    name = secure_filename(request.args.get("file", ""))
    path = os.path.join(UPLOAD_DIR, name)
    with open(path, "r") as handle:
        return escape(handle.read())


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    uploaded = request.files["file"]
    name = secure_filename(uploaded.filename)
    if not name.lower().endswith((".png", ".jpg", ".pdf")):
        abort(400)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    uploaded.save(os.path.join(UPLOAD_DIR, name))
    return "Uploaded"


@app.route("/fetch")
@login_required
def fetch():
    url = request.args.get("url", "")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        abort(400)
    response = requests.get(url, timeout=5, allow_redirects=False)
    return escape(response.text)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    return "<h1>Search results for: " + str(escape(query)) + "</h1>"


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    if user_id != session["user_id"] and session.get("role") != "admin":
        abort(403)
    conn = db()
    row = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return jsonify({"profile": row})


@app.route("/delete-user/<int:user_id>", methods=["DELETE"])
@login_required
@admin_required
def delete_user(user_id):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return "User deleted"


@app.route("/go")
def go():
    target = request.args.get("to", "/")
    if not target.startswith("/") or target.startswith("//"):
        target = "/"
    return redirect(target)


@app.route("/generate")
@login_required
def generate():
    count = min(int(request.args.get("count", 10)), 100)
    return str(sum(1 for _ in range(count)))


@app.errorhandler(Exception)
def handle_error(error):
    app.logger.exception("unhandled error")
    return "Internal error", 500


def new_token():
    return secrets.token_urlsafe(32)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
