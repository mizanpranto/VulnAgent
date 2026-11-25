"""Minimal Ollama REST client with tool-calling and robust JSON extraction."""

from __future__ import annotations

import json
import re

import requests


class OllamaError(RuntimeError):
    """Raised for any problem talking to Ollama (message is user-presentable)."""


def strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text or "", flags=re.DOTALL).strip()


def _balanced_objects(text: str):
    """Yield every top-level {...} substring, ignoring braces inside strings."""
    depth, start, in_str, escape = 0, None, False, False
    for index, char in enumerate(text):
        if in_str:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_str = False
            continue
        if char == '"':
            in_str = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                yield text[start:index + 1]
                start = None


def extract_json(response_text: str):
    """Parse a JSON object out of model output (think tags, fences, prose)."""
    text = strip_think(response_text)
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for candidate in _balanced_objects(text):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError("model did not return valid JSON")


class OllamaClient:
    def __init__(self, host="http://127.0.0.1:11434", model="qwen3:8b",
                 timeout=300, num_ctx=8192, session=None):
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.http = session or requests.Session()

    def check(self) -> None:
        """Raise OllamaError with an actionable message if the model is unavailable."""
        try:
            response = self.http.get(self.host + "/api/tags", timeout=10)
            response.raise_for_status()
        except requests.RequestException as error:
            raise OllamaError(
                f"Cannot reach Ollama at {self.host} ({error.__class__.__name__}). "
                "Start it with `ollama serve`.") from error
        names = {m.get("name", "") for m in response.json().get("models", [])}
        wanted = self.model if ":" in self.model else self.model + ":latest"
        if wanted not in names:
            raise OllamaError(f"Model {self.model!r} is not installed. Run: ollama pull {self.model}")

    def chat(self, messages, tools=None, json_mode=False, temperature=0.1) -> dict:
        payload = {
            "model": self.model,
            "stream": False,
            "messages": messages,
            "think": False,
            "options": {"temperature": temperature, "num_ctx": self.num_ctx},
        }
        if tools:
            payload["tools"] = tools
        elif json_mode:
            payload["format"] = "json"
        data = self._post(payload)
        message = data.get("message") or {}
        message["content"] = strip_think(message.get("content", ""))
        return message

    def _post(self, payload):
        url = self.host + "/api/chat"
        try:
            response = self.http.post(url, json=payload, timeout=self.timeout)
            if response.status_code == 400 and "think" in payload:
                # Older Ollama builds reject the `think` field.
                payload = {k: v for k, v in payload.items() if k != "think"}
                response = self.http.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.Timeout as error:
            raise OllamaError(f"Ollama timed out after {self.timeout}s") from error
        except requests.RequestException as error:
            raise OllamaError(f"Ollama request failed: {error}") from error
        except ValueError as error:
            raise OllamaError("Ollama returned a non-JSON response") from error
