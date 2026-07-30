from __future__ import annotations

import json

import httpx
import pytest

from app.integrations import claude_client
from app.integrations.claude_client import (
    ClaudeTaskItem,
    ClaudeTaskPayload,
    _call_claude,
    _extract_json,
    _normalize_task_item,
    _normalize_vuln_type,
    _parse_json_payload,
    _strip_heading_marks,
    _validate_tasks_payload,
    generate_frontend_tasks,
    generate_security_mentor_summary,
)


def task_item(is_vulnerable: bool = True, vuln_type: str = "XSS") -> ClaudeTaskItem:
    return ClaudeTaskItem(code="x", isVulnerable=is_vulnerable, vulnerabilityType=vuln_type)


class FakeResponse:
    def __init__(self, payload, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self):
        return self._payload


def fake_client(response=None, raises=None):
    """Build a stand-in for httpx.Client usable as a context manager."""

    class _Client:
        def __init__(self, *args, **kwargs):
            self.captured = {}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json=None, headers=None):
            _Client.last_url = url
            _Client.last_json = json
            _Client.last_headers = headers
            if raises is not None:
                raise raises
            return response

    return _Client


class TestExtractJson:
    def test_extracts_object_from_surrounding_prose(self):
        text = 'Sure! Here is the JSON:\n{"tasks": []}\nHope that helps.'
        assert _extract_json(text) == '{"tasks": []}'

    def test_extracts_object_from_a_markdown_fence(self):
        text = '```json\n{"tasks": [1]}\n```'
        assert _extract_json(text) == '{"tasks": [1]}'

    def test_extracts_a_bare_array(self):
        assert _extract_json("prefix [1, 2, 3] suffix") == "[1, 2, 3]"

    def test_handles_nested_structures(self):
        text = 'x {"tasks": [{"code": "a"}]} y'
        assert _extract_json(text) == '{"tasks": [{"code": "a"}]}'

    def test_handles_balanced_braces_inside_code_snippets(self):
        text = '{"code": "function f() { return 1; }"}'
        assert json.loads(_extract_json(text))["code"] == "function f() { return 1; }"

    def test_returns_only_the_first_complete_object(self):
        assert _extract_json('{"a": 1} {"b": 2}') == '{"a": 1}'

    def test_raises_when_no_json_present(self):
        with pytest.raises(ValueError, match="did not contain valid JSON"):
            _extract_json("I cannot help with that request.")

    def test_raises_on_an_unterminated_object(self):
        with pytest.raises(ValueError):
            _extract_json('{"tasks": [')


class TestParseJsonPayload:
    def test_parses_plain_json(self):
        text = '{"tasks": [{"code": "a", "isVulnerable": true, "vulnerabilityType": "XSS"}]}'

        payload = _parse_json_payload(text)

        assert len(payload.tasks) == 1
        assert payload.tasks[0].vulnerabilityType == "XSS"

    def test_recovers_from_a_markdown_fenced_response(self):
        text = (
            'Here you go:\n```json\n{"tasks": [{"code": "a", "isVulnerable": false, '
            '"vulnerabilityType": "SAFE"}]}\n```'
        )

        assert _parse_json_payload(text).tasks[0].isVulnerable is False

    def test_accepts_a_bare_top_level_array(self):
        text = '[{"code": "a", "isVulnerable": true, "vulnerabilityType": "RCE"}]'

        assert _parse_json_payload(text).tasks[0].vulnerabilityType == "RCE"

    def test_accepts_snippets_as_an_alias_for_tasks(self):
        text = '{"snippets": [{"code": "a", "isVulnerable": true, "vulnerabilityType": "SSRF"}]}'

        assert _parse_json_payload(text).tasks[0].vulnerabilityType == "SSRF"

    def test_invalid_shape_raises_value_error(self):
        with pytest.raises(ValueError, match="validation failed"):
            _parse_json_payload('{"tasks": [{"missing": "fields"}]}')

    def test_unknown_vulnerability_type_raises_value_error(self):
        text = '{"tasks": [{"code": "a", "isVulnerable": true, "vulnerabilityType": "TIME_TRAVEL"}]}'

        with pytest.raises(ValueError):
            _parse_json_payload(text)


class TestNormalizeTaskItem:
    def test_non_dict_items_become_empty(self):
        assert _normalize_task_item("nonsense") == {}
        assert _normalize_task_item(None) == {}

    def test_vulnerable_alias_is_mapped(self):
        assert _normalize_task_item({"vulnerable": True})["isVulnerable"] is True

    def test_type_alias_is_mapped(self):
        assert _normalize_task_item({"type": "SSRF"})["vulnerabilityType"] == "SSRF"

    def test_vulnerability_alias_is_mapped(self):
        assert _normalize_task_item({"vulnerability": "RCE"})["vulnerabilityType"] == "RCE"

    def test_safe_type_is_inferred_when_not_vulnerable(self):
        assert _normalize_task_item({"isVulnerable": False})["vulnerabilityType"] == "SAFE"

    def test_xss_is_assumed_when_vulnerable_but_untyped(self):
        assert _normalize_task_item({"isVulnerable": True})["vulnerabilityType"] == "XSS"

    def test_missing_hints_become_an_empty_list(self):
        assert _normalize_task_item({"code": "a"})["hints"] == []

    def test_scalar_hints_are_wrapped(self):
        assert _normalize_task_item({"hints": "just one"})["hints"] == ["just one"]

    def test_hints_are_capped_at_two(self):
        assert _normalize_task_item({"hints": ["a", "b", "c", "d"]})["hints"] == ["a", "b"]

    def test_hint_entries_are_coerced_to_strings(self):
        assert _normalize_task_item({"hints": [1, 2]})["hints"] == ["1", "2"]

    def test_original_item_is_not_mutated(self):
        original = {"code": "a"}
        _normalize_task_item(original)
        assert original == {"code": "a"}


class TestNormalizeVulnType:
    def test_safe_code_is_always_marked_safe(self):
        assert _normalize_vuln_type(False, "XSS") == "SAFE"

    def test_vulnerable_code_cannot_be_marked_safe(self):
        """A vulnerable snippet labelled SAFE would make the round unwinnable."""
        assert _normalize_vuln_type(True, "SAFE") == "XSS"

    def test_valid_pairings_pass_through(self):
        assert _normalize_vuln_type(True, "SQL_INJECTION") == "SQL_INJECTION"


class TestValidateTasksPayload:
    def test_accepts_a_matching_payload(self):
        payload = ClaudeTaskPayload(tasks=[task_item(True), task_item(False, "SAFE")])

        assert _validate_tasks_payload(payload, count=2, vuln_density=0.5) is payload

    def test_rejects_the_wrong_number_of_tasks(self):
        payload = ClaudeTaskPayload(tasks=[task_item()])

        with pytest.raises(ValueError, match="expected 3"):
            _validate_tasks_payload(payload, count=3, vuln_density=0.5)

    def test_rejects_the_wrong_vulnerable_count(self):
        payload = ClaudeTaskPayload(tasks=[task_item(True), task_item(True)])

        with pytest.raises(ValueError, match="unexpected vulnerable count"):
            _validate_tasks_payload(payload, count=2, vuln_density=0.5)

    def test_at_least_one_vulnerable_task_is_always_required(self):
        """max(1, ...) means even a zero density demands one vulnerable snippet."""
        payload = ClaudeTaskPayload(tasks=[task_item(False, "SAFE")])

        with pytest.raises(ValueError, match="expected 1"):
            _validate_tasks_payload(payload, count=1, vuln_density=0.0)


class TestStripHeadingMarks:
    def test_markdown_symbols_are_removed(self):
        assert _strip_heading_marks("## Summary **bold**") == "Summary bold"

    def test_whitespace_is_collapsed(self):
        assert _strip_heading_marks("a\n\n  b\tc") == "a b c"

    def test_sentence_punctuation_is_preserved(self):
        text = "Input is unescaped, so XSS is possible - fix it."
        assert _strip_heading_marks(text) == text

    def test_empty_input_is_handled(self):
        assert _strip_heading_marks("") == ""


class TestCallClaude:
    def _call(self):
        return _call_claude(
            api_key="k",
            model="m",
            version="v",
            system_prompt="s",
            user_prompt="u",
            max_tokens=10,
        )

    def test_concatenates_text_content_blocks(self, monkeypatch):
        response = FakeResponse({"content": [{"text": "part one"}, {"text": "part two"}]})
        monkeypatch.setattr(claude_client.httpx, "Client", fake_client(response))

        assert self._call() == "part one\npart two"

    def test_ignores_non_dict_content_blocks(self, monkeypatch):
        response = FakeResponse({"content": [{"text": "kept"}, "dropped"]})
        monkeypatch.setattr(claude_client.httpx, "Client", fake_client(response))

        assert self._call() == "kept"

    def test_unexpected_shape_is_returned_as_json(self, monkeypatch):
        monkeypatch.setattr(claude_client.httpx, "Client", fake_client(FakeResponse({"odd": 1})))

        assert json.loads(self._call()) == {"odd": 1}

    def test_sends_the_authentication_headers(self, monkeypatch):
        client_cls = fake_client(FakeResponse({"content": [{"text": "ok"}]}))
        monkeypatch.setattr(claude_client.httpx, "Client", client_cls)

        self._call()

        assert client_cls.last_headers["x-api-key"] == "k"
        assert client_cls.last_headers["anthropic-version"] == "v"
        assert client_cls.last_url == "https://api.anthropic.com/v1/messages"

    def test_timeout_becomes_a_runtime_error(self, monkeypatch):
        monkeypatch.setattr(
            claude_client.httpx, "Client", fake_client(raises=httpx.TimeoutException("slow"))
        )

        with pytest.raises(RuntimeError, match="timed out"):
            self._call()

    def test_http_error_becomes_a_runtime_error(self, monkeypatch):
        monkeypatch.setattr(claude_client.httpx, "Client", fake_client(FakeResponse({}, 429)))

        with pytest.raises(RuntimeError, match="429"):
            self._call()

    def test_connection_error_becomes_a_runtime_error(self, monkeypatch):
        monkeypatch.setattr(
            claude_client.httpx, "Client", fake_client(raises=httpx.ConnectError("no route"))
        )

        with pytest.raises(RuntimeError, match="connection failed"):
            self._call()


class TestGenerateFrontendTasks:
    def _generate(self, count=2, vuln_density=0.5):
        return generate_frontend_tasks(
            language="javascript",
            difficulty="EASY",
            complexity_level="basic",
            count=count,
            vuln_density=vuln_density,
        )

    def test_missing_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY is not configured"):
            self._generate()

    def test_assigns_unique_ids_and_the_requested_language(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        monkeypatch.setattr(
            claude_client,
            "_call_claude",
            lambda **kwargs: json.dumps(
                {
                    "tasks": [
                        {"code": "a", "isVulnerable": True, "vulnerabilityType": "XSS"},
                        {"code": "b", "isVulnerable": False, "vulnerabilityType": "SAFE"},
                    ]
                }
            ),
        )

        tasks = self._generate()

        assert len({task.id for task in tasks}) == 2
        assert all(task.language == "javascript" for task in tasks)

    def test_missing_system_names_are_filled_from_the_roster(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        monkeypatch.setattr(
            claude_client,
            "_call_claude",
            lambda **kwargs: json.dumps(
                {
                    "tasks": [
                        {"code": "a", "isVulnerable": True, "vulnerabilityType": "XSS"},
                        {"code": "b", "isVulnerable": False, "vulnerabilityType": "SAFE"},
                    ]
                }
            ),
        )

        tasks = self._generate()

        assert [task.systemName for task in tasks] == ["O2", "NAVIGATION"]

    def test_upstream_count_mismatch_surfaces_as_value_error(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        monkeypatch.setattr(
            claude_client,
            "_call_claude",
            lambda **kwargs: json.dumps(
                {"tasks": [{"code": "a", "isVulnerable": True, "vulnerabilityType": "XSS"}]}
            ),
        )

        with pytest.raises(ValueError, match="expected 2"):
            self._generate()


class TestGenerateSecurityMentorSummary:
    def test_no_failures_short_circuits_without_calling_the_api(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        summary = generate_security_mentor_summary(["log"], [])

        assert "No vulnerabilities were missed" in summary

    def test_missing_api_key_raises_when_there_is_work_to_do(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
            generate_security_mentor_summary(["log"], ["REACTOR: xss"])

    def test_scanner_noise_is_withheld_from_the_prompt(self, monkeypatch):
        """The mentor persona must not mention tooling, so those logs are filtered out."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        captured = {}

        def _call(**kwargs):
            captured.update(kwargs)
            return "Summary text."

        monkeypatch.setattr(claude_client, "_call_claude", _call)
        generate_security_mentor_summary(
            ["Hacktron scan failed: offline", "unescaped output sink"], ["REACTOR: xss"]
        )

        sent = json.loads(captured["user_prompt"])
        assert sent["hacktron_logs"] == ["unescaped output sink"]

    def test_response_is_stripped_of_markdown(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
        monkeypatch.setattr(claude_client, "_call_claude", lambda **kwargs: "## **Summary**")

        assert generate_security_mentor_summary(["log"], ["REACTOR: xss"]) == "Summary"
