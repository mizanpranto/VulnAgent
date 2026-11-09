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

# 1. Hardcoded secrets
app.secret_key = "super-secret-production-key-123"
DATABASE_PASSWORD = "admin123"
API_KEY = "sk_test_123456789"

# 2. Database connection
def connect_db():
    return sqlite3.connect("users.db")

# 3. Initialize database
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

# 4. Register user
@app.route("/register", methods=["POST"])
def register():
    username = request.form["username"]
    password = request.form["password"]

    db = connect_db()
    cursor = db.cursor()

    # SQL Injection
    query = f"INSERT INTO users VALUES (NULL, '{username}', '{password}', 'user')"
    cursor.execute(query)

    db.commit()
    db.close()

    return "Registration successful"

# 5. Login
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    db = connect_db()
    cursor = db.cursor()

    # SQL Injection + plaintext password
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    db.close()

    if user:
        return jsonify({"message": "Welcome", "role": user[3]})

    return "Invalid credentials", 401

# 6. Password hashing
def hash_password(password):
    # Weak password hashing: unsalted SHA256
    return hashlib.sha256(password.encode()).hexdigest()

# 7. Password reset
@app.route("/reset-password", methods=["POST"])
def reset_password():
    username = request.form["username"]
    new_password = request.form["password"]

    db = connect_db()
    cursor = db.cursor()

    # Missing identity verification
    cursor.execute(
        f"UPDATE users SET password='{new_password}' WHERE username='{username}'"
    )

    db.commit()
    db.close()

    return "Password changed"

# 8. Command execution
@app.route("/ping")
def ping():
    host = request.args.get("host")

    # Command injection
    command = "ping -c 1 " + host
    result = subprocess.getoutput(command)

    return result

# 9. File reader
@app.route("/read")
def read_file():
    filename = request.args.get("file")

    # Path traversal
    path = "./documents/" + filename

    with open(path, "r") as file:
        return file.read()

# 10. File upload
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]

    # No file content validation
    filename = file.filename
    destination = os.path.join("uploads", filename)

    os.makedirs("uploads", exist_ok=True)
    file.save(destination)

    return "Uploaded"

# 11. SSRF
@app.route("/fetch")
def fetch():
    url = request.args.get("url")

    # Server-side request forgery
    response = urllib.request.urlopen(url)

    return response.read()

# 12. Insecure deserialization
@app.route("/load-object", methods=["POST"])
def load_object():
    data = request.data

    # Unsafe pickle deserialization
    obj = pickle.loads(data)

    return str(obj)

# 13. Reflected XSS
@app.route("/search")
def search():
    query = request.args.get("q")

    # Unescaped user input
    html = "<h1>Search results for: " + query + "</h1>"

    return render_template_string(html)

# 14. Information disclosure
@app.route("/debug")
def debug():
    return jsonify({
        "secret": app.secret_key,
        "database_password": DATABASE_PASSWORD,
        "api_key": API_KEY,
        "environment": dict(os.environ)
    })

# 15. Weak random token
def generate_token():
    return str(random.randint(100000, 999999))

# 16. Insecure authorization
@app.route("/admin")
def admin():
    role = request.args.get("role")

    # Client-controlled authorization
    if role == "admin":
        return "Welcome administrator"

    return "Access denied", 403

# 17. IDOR
@app.route("/profile/<int:user_id>")
def profile(user_id):
    db = connect_db()
    cursor = db.cursor()

    # No ownership verification
    cursor.execute(
        "SELECT username, role FROM users WHERE id = ?",
        (user_id,)
    )

    user = cursor.fetchone()
    db.close()

    return jsonify({"profile": user})

# 18. Open redirect
@app.route("/redirect")
def redirect_user():
    from flask import redirect

    target = request.args.get("url")

    # Unvalidated redirect destination
    return redirect(target)

# 19. Weak password policy
def validate_password(password):
    return len(password) >= 4

# 20. Sensitive logging
def log_login(username, password):
    # Password exposed in logs
    with open("login.log", "a") as log:
        log.write(f"Login: {username}:{password}\n")

# 21. Insecure TLS verification
def download_data(url):
    import ssl

    # TLS certificate validation disabled
    context = ssl._create_unverified_context()

    return urllib.request.urlopen(
        url,
        context=context
    ).read()

# 22. Unsafe JSON handling
@app.route("/process", methods=["POST"])
def process():
    data = request.get_json()

    # No schema or input validation
    command = data["command"]

    return jsonify({"received": command})

# 23. Regular expression denial of service
def validate_input(value):
    pattern = re.compile(r"^(a+)+$")
    return bool(pattern.match(value))

# 24. Weak access control
@app.route("/delete-user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    db = connect_db()
    cursor = db.cursor()

    # Missing authorization check
    cursor.execute(
        "DELETE FROM users WHERE id = ?",
        (user_id,)
    )

    db.commit()
    db.close()

    return "User deleted"

# 25. Exposed internal configuration
@app.route("/config")
def configuration():
    return jsonify({
        "database": "localhost",
        "username": "root",
        "password": "root123",
        "debug": True,
        "environment": "production"
    })

# 26. Unsafe temporary file handling
def create_temp_file(data):
    filename = "/tmp/application_data.txt"

    with open(filename, "w") as file:
        file.write(data)

    return filename

# 27. Insecure file permissions
def save_sensitive_data(data):
    filename = "secrets.txt"

    with open(filename, "w") as file:
        file.write(data)

    os.chmod(filename, 0o777)

# 28. Unrestricted resource consumption
@app.route("/generate")
def generate():
    count = int(request.args.get("count", 100))

    # No upper limit
    result = []

    for i in range(count):
        result.append("A" * 10000)

    return str(len(result))

# 29. Debug information exposure
@app.route("/exception")
def exception():
    value = request.args.get("value")

    try:
        return str(100 / int(value))
    except Exception as error:
        # Internal exception details exposed
        return str(error), 500

# 30. Application startup
if __name__ == "__main__":
    initialize_db()

    # Debug server exposed to all interfaces
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )