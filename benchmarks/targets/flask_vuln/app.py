import os
import re
import json
import pickle
import random
import sqlite3
import hashlib
import subprocess
import urllib.request
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)


app.secret_key = "super-secret-production-key-123"
DATABASE_PASSWORD = "admin123"
API_KEY = "sk_test_123456789"


def connect_db():
    return sqlite3.connect("users.db")


def initialize_db():
    db = connect_db()
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    db.commit()
    db.close()


@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    db = connect_db()
    cursor = db.cursor()


    query = f"INSERT INTO users VALUES (NULL, '{username}', '{password}', 'user')"
    cursor.execute(query)

    db.commit()
    db.close()

    return "Registration successful"


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    db = connect_db()
    cursor = db.cursor()


    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    db.close()

    if user:
        return jsonify({"message": "Welcome", "role": user[3]})

    return "Invalid credentials", 401


def hash_password(password):

    return hashlib.sha256(password.encode()).hexdigest()


@app.route("/reset-password", methods=["POST"])
def reset_password():
    username = request.form["username"]
    new_password = request.form["password"]

    db = connect_db()
    cursor = db.cursor()


    cursor.execute(
        f"UPDATE users SET password='{new_password}' WHERE username='{username}'"
    )

    db.commit()
    db.close()

    return "Password changed"


@app.route("/ping")
def ping():
    host = request.args.get("host")


    command = "ping -c 1 " + host
    result = subprocess.getoutput(command)

    return result


@app.route("/read")
def read_file():
    filename = request.args.get("file")


    path = "./documents/" + filename

    with open(path, "r") as file:
        return file.read()


@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]


    filename = file.filename
    destination = os.path.join("uploads", filename)

    os.makedirs("uploads", exist_ok=True)
    file.save(destination)

    return "Uploaded"


@app.route("/fetch")
def fetch():
    url = request.args.get("url")


    response = urllib.request.urlopen(url)

    return response.read()


@app.route("/load-object", methods=["POST"])
def load_object():
    data = request.data


    obj = pickle.loads(data)

    return str(obj)


@app.route("/search")
def search():
    query = request.args.get("q")


    html = "<h1>Search results for: " + query + "</h1>"

    return render_template_string(html)


@app.route("/debug")
def debug():
    return jsonify({
        "secret": app.secret_key,
        "database_password": DATABASE_PASSWORD,
        "api_key": API_KEY,
        "environment": dict(os.environ)
    })


def generate_token():
    return str(random.randint(100000, 999999))


@app.route("/admin")
def admin():
    role = request.args.get("role")


    if role == "admin":
        return "Welcome administrator"

    return "Access denied", 403


@app.route("/profile/<int:user_id>")
def profile(user_id):
    db = connect_db()
    cursor = db.cursor()


    cursor.execute(
        "SELECT username, role FROM users WHERE id = ?",
        (user_id,)
    )

    user = cursor.fetchone()
    db.close()

    return jsonify({"profile": user})


@app.route("/redirect")
def redirect_user():
    from flask import redirect

    target = request.args.get("url")


    return redirect(target)


def validate_password(password):
    return len(password) >= 4


def log_login(username, password):

    with open("login.log", "a") as log:
        log.write(f"Login: {username}:{password}\n")


def download_data(url):
    import ssl


    context = ssl._create_unverified_context()

    return urllib.request.urlopen(
        url,
        context=context
    ).read()


@app.route("/process", methods=["POST"])
def process():
    data = request.get_json()


    command = data["command"]

    return jsonify({"received": command})


def validate_input(value):
    pattern = re.compile(r"^(a+)+$")
    return bool(pattern.match(value))


@app.route("/delete-user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    db = connect_db()
    cursor = db.cursor()


    cursor.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    db.commit()
    db.close()

    return "User deleted"


@app.route("/config")
def configuration():
    return jsonify({
        "database": "localhost",
        "username": "root",
        "password": "root123",
        "debug": True,
        "environment": "production"
    })


def create_temp_file(data):
    filename = "/tmp/application_data.txt"

    with open(filename, "w") as file:
        file.write(data)

    return filename


def save_sensitive_data(data):
    filename = "secrets.txt"

    with open(filename, "w") as file:
        file.write(data)

    os.chmod(filename, 0o777)


@app.route("/generate")
def generate():
    count = int(request.args.get("count", 100))


    result = []

    for i in range(count):
        result.append("A" * 10000)

    return str(len(result))


@app.route("/exception")
def exception():
    value = request.args.get("value")

    try:
        return str(100 / int(value))
    except Exception as error:

        return str(error), 500


if __name__ == "__main__":
    initialize_db()


    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
