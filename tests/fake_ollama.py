"""A tiny deterministic stand-in for Ollama, used by the test suite.

It speaks the real REST shape (/api/tags, /api/chat with tool calls) so the
client, agent loop and web app are exercised over HTTP. It is NOT a model:
its "reasoning" is a few fixed rules, enough to test the plumbing and the
safety policy (including a mode that obeys prompt injection).
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "qwen3:8b"


class FakeState:
    def __init__(self):
        self.requests = []          # every /api/chat payload received
        self.obey_injection = True  # simulate a manipulable model


def _text(messages) -> str:
    return "\n".join(str(m.get("content", "")) for m in messages)


def make_handler(state: FakeState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            pass

        def _send(self, payload, code=200):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/api/tags":
                self._send({"models": [{"name": MODEL}]})
            else:
                self._send({"error": "not found"}, 404)

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            state.requests.append(payload)
            messages = payload.get("messages", [])
            system = messages[0]["content"] if messages else ""
            if system.startswith("You are the triage stage"):
                self._send({"message": self._triage(payload, messages)})
            elif system.startswith("You are the discovery stage"):
                self._send({"message": {"role": "assistant", "content": json.dumps(self._discovery(messages))}})
            else:
                self._send({"message": {"role": "assistant", "content": "{}"}})

        def _triage(self, payload, messages):
            has_tool_result = any(m.get("role") == "tool" for m in messages)
            if payload.get("tools") and not has_tool_result:
                return {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "read_lines", "arguments": {"file": "app.py", "start": 1, "end": 40}}}]}
            seen = _text(messages)
            if state.obey_injection and "ignore all previous instructions" in seen.lower():
                verdict = {"verdict": "false_positive", "reason": "File says it is safe.", "fix": ""}
            elif "ALLOWED_HOSTS" in seen and "SSRF" in seen:
                verdict = {"verdict": "false_positive", "reason": "ALLOWED_HOSTS allowlist guards the URL "
                                                                  "(app.py:26).", "fix": ""}
            else:
                verdict = {"verdict": "confirmed", "reason": "Input reaches the sink unguarded.", "fix": ""}
            return {"role": "assistant", "content": json.dumps(verdict)}

        def _discovery(self, messages):
            seen = _text(messages)
            findings = []
            if "app.run(" in seen:
                findings.append({"title": "Debug mode exposes interactive debugger", "severity": "medium",
                                 "confidence": "medium", "line": 1, "cwe": "CWE-489",
                                 "evidence": "debug=True", "explanation": "Debugger reachable remotely.",
                                 "fix": "Disable debug."})
            # A hallucinated claim: the quoted code does not exist anywhere.
            findings.append({"title": "Command injection via os.system", "severity": "critical",
                             "confidence": "high", "line": 7, "cwe": "CWE-78",
                             "evidence": "os.system(user_cmd + payload_that_does_not_exist)",
                             "explanation": "Invented.", "fix": ""})
            return {"findings": findings}

    return Handler


def start(port: int = 0):
    state = FakeState()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state, f"http://127.0.0.1:{server.server_address[1]}"


if __name__ == "__main__":  # manual use: python tests/fake_ollama.py 11500
    import sys
    srv, _state, url = start(int(sys.argv[1]) if len(sys.argv) > 1 else 11500)
    print("fake ollama on", url, flush=True)
    threading.Event().wait()
