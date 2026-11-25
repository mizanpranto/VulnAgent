import textwrap
import unittest

from vulnagent.taint import analyze_python


def scan(source):
    return analyze_python("t.py", textwrap.dedent(source))


def cwes(findings):
    return sorted(f.cwe for f in findings)


class InjectionSinks(unittest.TestCase):
    def test_sql_injection_via_fstring_variable(self):
        found = scan("""
            from flask import request
            def f(cursor):
                name = request.args.get("name")
                query = f"SELECT * FROM t WHERE n = '{name}'"
                cursor.execute(query)
        """)
        self.assertEqual(cwes(found), [89])
        self.assertEqual(found[0].line, 6)
        self.assertTrue(found[0].source.startswith("request.args.get"))
        self.assertIn("assigned to `query`", " ".join(found[0].data_flow))

    def test_parameterized_query_is_not_flagged(self):
        self.assertEqual(scan("""
            from flask import request
            def f(cursor):
                cursor.execute("SELECT * FROM t WHERE n = ?", (request.args["n"],))
        """), [])

    def test_int_cast_removes_injection_taint(self):
        found = scan("""
            from flask import request
            def f(cursor):
                n = int(request.args["n"])
                cursor.execute(f"SELECT * FROM t LIMIT {n}")
        """)
        self.assertEqual(found, [])

    def test_command_injection_and_list_form(self):
        bad = scan("""
            import subprocess
            from flask import request
            def f():
                host = request.args["h"]
                return subprocess.getoutput("ping " + host)
        """)
        self.assertEqual(cwes(bad), [78])
        good = scan("""
            import subprocess
            from flask import request
            def f():
                return subprocess.run(["ping", "-c", "1", request.args["h"]])
        """)
        self.assertEqual(good, [])

    def test_shlex_quote_sanitizes(self):
        self.assertEqual(scan("""
            import os, shlex
            from flask import request
            def f():
                os.system("ls " + shlex.quote(request.args["d"]))
        """), [])

    def test_path_traversal_vs_secure_filename(self):
        self.assertEqual(cwes(scan("""
            from flask import request
            def f():
                return open(request.args["file"]).read()
        """)), [22])
        self.assertEqual(scan("""
            from flask import request
            from werkzeug.utils import secure_filename
            def f():
                return open("/srv/" + secure_filename(request.args["file"])).read()
        """), [])

    def test_ssrf_and_open_redirect(self):
        found = scan("""
            import requests
            from flask import request, redirect
            def a():
                return requests.get(request.args["u"]).text
            def b():
                return redirect(request.args["next"])
        """)
        self.assertEqual(cwes(found), [601, 918])

    def test_template_injection_from_request_url(self):
        found = scan("""
            from flask import request, render_template_string
            def handler(e):
                template = "<h3>%s</h3>" % request.url
                return render_template_string(template), 404
        """)
        self.assertEqual(cwes(found), [1336])

    def test_deserialization_and_eval(self):
        found = scan("""
            import pickle
            from flask import request
            def a():
                return pickle.loads(request.data)
            def b():
                return eval(request.args["x"])
        """)
        self.assertEqual(cwes(found), [95, 502])
        self.assertTrue(all(f.severity == "critical" for f in found))

    def test_untainted_eval_is_low_confidence(self):
        found = scan("def f(expr):\n    return eval(expr)\n")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].confidence, "low")
        self.assertEqual(found[0].severity, "medium")

    def test_route_parameter_taint_depends_on_converter(self):
        text = scan("""
            @app.route("/u/<name>")
            def a(name):
                return render_template_string("<p>" + name)
            @app.route("/n/<int:count>")
            def b(count):
                return render_template_string("<p>" + str(count))
        """)
        self.assertEqual({f.line for f in text}, {4})  # only the unconverted <name>, not <int:count>


class ConfigurationChecks(unittest.TestCase):
    def test_hardcoded_secrets_in_all_shapes(self):
        found = scan("""
            import os
            app.secret_key = "super-secret-key-123"
            DATABASE_PASSWORD = "admin123"
            app.config["SECRET_KEY_HMAC"] = "s3cr3tvalue"
            settings = {"api_key": "sk_live_abcdef"}
            connect(password="hunter2hunter2")
            OK1 = os.environ["TOKEN"]
            OK2 = "short"
            PASSWORD_FIELD = "your-password-here"
        """)
        self.assertEqual(sorted(f.line for f in found), [3, 4, 5, 6, 7])
        self.assertTrue(all(f.cwe == 798 for f in found))

    def test_jwt_verify_false_is_not_a_tls_finding(self):
        jwt = scan("import jwt\ndef f(t):\n    return jwt.decode(t, verify=False)\n")
        self.assertEqual(cwes(jwt), [347])
        tls = scan("import requests\nrequests.get('https://x', verify=False)\n")
        self.assertEqual(cwes(tls), [295])

    def test_debug_chmod_and_temp_file(self):
        found = scan("""
            import os
            app.run(debug=True)
            os.chmod("secrets.txt", 0o777)
            open("/tmp/data.txt", "w")
        """)
        self.assertEqual(cwes(found), [377, 489, 732])
        self.assertEqual(scan("import os\nos.chmod('f', 0o600)\n"), [])

    def test_weak_random_only_in_security_context(self):
        found = scan("""
            import random
            def generate_token():
                return random.randint(1, 9)
            def roll_dice():
                return random.randint(1, 6)
        """)
        self.assertEqual([f.line for f in found], [4])

    def test_fast_hash_for_password(self):
        found = scan("""
            import hashlib
            def hash_password(password):
                return hashlib.sha256(password.encode()).hexdigest()
            def checksum(data):
                return hashlib.sha256(data).hexdigest()
        """)
        self.assertEqual(cwes(found), [916])

    def test_missing_authorization_on_write_route(self):
        bad = scan("""
            @app.route("/d/<int:user_id>", methods=["DELETE"])
            def delete(user_id):
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        """)
        self.assertIn(862, cwes(bad))
        ok = scan("""
            @app.route("/d/<int:user_id>", methods=["DELETE"])
            @login_required
            def delete(user_id):
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        """)
        self.assertEqual(ok, [])

    def test_exception_text_and_logging_secrets(self):
        found = scan("""
            def f(log, password):
                try:
                    run()
                except Exception as error:
                    return str(error)
                log.write(f"login {password}")
        """)
        self.assertEqual(cwes(found), [209, 532])


class Robustness(unittest.TestCase):
    def test_syntax_error_returns_empty(self):
        self.assertEqual(scan("def broken(:\n"), [])

    def test_deeply_nested_expression_does_not_crash(self):
        source = "x = " + "(" * 400 + "1" + ")" * 400 + "\n"
        try:
            scan(source)
        except RecursionError:
            self.fail("deeply nested input must not crash the analyzer")


if __name__ == "__main__":
    unittest.main()
