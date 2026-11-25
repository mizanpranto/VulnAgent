"""Smoke tests for the A01 access-control layer: one vulnerable and one safe fixture per headline rule.

This is NOT the full per-rule fixture suite from the roadmap; it exists so the layer is never shipped untested.
"""

import unittest

from vulnagent.a01 import analyze
from vulnagent.a01.extractors import js
from vulnagent.a01.registry import RULES


def rules_of(files):
    return {f.rule_id for f in analyze(files).findings}


EXPRESS_GUARD_OPEN = {
    "app.js": "const express=require('express');const app=express();app.use('/api',require('./r'));module.exports=app;",
    "r.js": "const router=require('express').Router();const {auth}=require('./mw');\n"
            "router.get('/me',auth,(req,res)=>res.json({ok:1}));module.exports=router;",
    "mw.js": "exports.auth=function(req,res,next){\n  if(!req.headers.authorization){ res.status(401).json({e:1}); }\n  next();\n}",
}
EXPRESS_GUARD_SAFE = dict(EXPRESS_GUARD_OPEN, **{
    "mw.js": "exports.auth=function(req,res,next){\n  if(!req.headers.authorization){ return res.status(401).json({e:1}); }\n  next();\n}"})

FLASK_ADMIN_AT_REGISTER = {"app.py": (
    "from flask import Flask, request, jsonify\napp = Flask(__name__)\n"
    "@app.route('/register', methods=['POST'])\ndef register():\n"
    "    u = User(name=request.json['name'], role='admin')\n    db.session.add(u)\n    return jsonify({'ok': 1})\n")}
FLASK_ADMIN_SAFE = {"app.py": FLASK_ADMIN_AT_REGISTER["app.py"].replace("role='admin'", "role='user'")}

FLASK_IDOR = {"app.py": (
    "from flask import Flask, jsonify\nfrom flask_login import login_required, current_user\napp = Flask(__name__)\n"
    "@app.route('/orders/<int:oid>')\n@login_required\ndef order(oid):\n    return jsonify(Order.query.filter_by(id=oid).first().to_dict())\n")}
FLASK_IDOR_SAFE = {"app.py": FLASK_IDOR["app.py"].replace("filter_by(id=oid)", "filter_by(id=oid, user_id=current_user.id)")}

FLASK_ABOVE_ROUTE = {"app.py": (
    "from flask import Flask, jsonify\nfrom flask_login import login_required\napp = Flask(__name__)\n"
    "@login_required\n@app.route('/secret')\ndef secret():\n    return jsonify({})\n")}
FLASK_BELOW_ROUTE = {"app.py": FLASK_ABOVE_ROUTE["app.py"].replace("@login_required\n@app.route('/secret')", "@app.route('/secret')\n@login_required")}


class RegistryTests(unittest.TestCase):
    def test_registry_is_consistent(self):
        self.assertGreaterEqual(len(RULES), 16)
        for rule in RULES.values():
            self.assertTrue(rule.fix_example.strip())
            self.assertEqual(rule.owasp, "A01")


@unittest.skipUnless(js.available(), "tree-sitter extra not installed")
class JavaScriptTests(unittest.TestCase):
    def test_fail_open_guard_detected_and_safe_version_clean(self):
        self.assertIn("A01-GUARD-FAIL-OPEN", rules_of(EXPRESS_GUARD_OPEN))
        self.assertNotIn("A01-GUARD-FAIL-OPEN", rules_of(EXPRESS_GUARD_SAFE))

    def test_router_mounted_in_another_file_gets_its_prefix(self):
        paths = [r["path"] for r in analyze(EXPRESS_GUARD_SAFE).report["matrix"]]
        self.assertEqual(paths, ["/api/me"])


class PythonTests(unittest.TestCase):
    def test_admin_granted_at_registration(self):
        found = {f.rule_id: f for f in analyze(FLASK_ADMIN_AT_REGISTER).findings}
        self.assertEqual(found["A01-PRIV-ASSIGN"].severity, "critical")
        self.assertNotIn("A01-PRIV-ASSIGN", rules_of(FLASK_ADMIN_SAFE))

    def test_idor_and_owner_scoped_safe_version(self):
        self.assertIn("A01-IDOR", rules_of(FLASK_IDOR))
        self.assertNotIn("A01-IDOR", rules_of(FLASK_IDOR_SAFE))

    def test_guard_decorator_above_route_is_ineffective(self):
        self.assertIn("A01-GUARD-COVERAGE", rules_of(FLASK_ABOVE_ROUTE))
        self.assertNotIn("A01-GUARD-COVERAGE", rules_of(FLASK_BELOW_ROUTE))

    def test_findings_take_cwe_and_severity_from_registry(self):
        for f in analyze(FLASK_IDOR).findings:
            rule = RULES[f.rule_id]
            self.assertIn(f.cwe, rule.cwes)
            self.assertEqual(f.owasp_scope, "A01")
            self.assertIn(f.status, ("confirmed", "likely", "needs-review"))
            if rule.evidence_kind == "absence":
                self.assertNotEqual(f.status, "confirmed")


class LimitationsTests(unittest.TestCase):
    def test_unsupported_and_partial_languages_are_listed(self):
        files = {"a.rs": "fn main(){}", "b.go": 'package main\nimport "net/http"\nfunc main(){}'}
        report = analyze(files, all_paths=list(files)).report
        self.assertIn("Rust", report["not_analysed"])
        self.assertIn("Go", report["not_analysed"])


if __name__ == "__main__":
    unittest.main()
