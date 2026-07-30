from __future__ import annotations

import pytest

from app import main as main_module
from app import store as store_module


class TestHealth:
    def test_health_reports_ok(self, client):
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_elevenlabs_health_reports_error_without_a_key(self, client, monkeypatch):
        monkeypatch.setattr(
            main_module, "validate_api_key", lambda: (False, "ELEVENLABS_API_KEY not configured")
        )

        body = client.get("/health/elevenlabs").json()

        assert body["service"] == "elevenlabs"
        assert body["status"] == "error"

    def test_elevenlabs_health_reports_ok_with_a_valid_key(self, client, monkeypatch):
        monkeypatch.setattr(main_module, "validate_api_key", lambda: (True, "API key is valid"))

        assert client.get("/health/elevenlabs").json()["status"] == "ok"


class TestGenerate:
    def test_returns_generated_tasks(self, client, monkeypatch, make_frontend_task):
        monkeypatch.setattr(
            main_module, "generate_frontend_tasks", lambda **kwargs: [make_frontend_task("t1")]
        )

        response = client.post(
            "/generate",
            json={
                "language": "javascript",
                "difficulty": "EASY",
                "complexityLevel": "basic",
                "count": 1,
            },
        )

        assert response.status_code == 200
        assert [task["id"] for task in response.json()["tasks"]] == ["t1"]

    def test_difficulty_config_drives_vulnerability_density(
        self, client, monkeypatch, make_frontend_task
    ):
        captured = {}

        def _generate(**kwargs):
            captured.update(kwargs)
            return [make_frontend_task("t1")]

        monkeypatch.setattr(main_module, "generate_frontend_tasks", _generate)
        client.post(
            "/generate",
            json={
                "language": "python",
                "difficulty": "HARD",
                "complexityLevel": "advanced",
                "count": 2,
            },
        )

        assert captured["vuln_density"] == 0.8

    @pytest.mark.parametrize("difficulty", ["IMPOSSIBLE", "easy", ""])
    def test_invalid_difficulty_is_rejected_by_validation(self, client, difficulty):
        response = client.post(
            "/generate",
            json={
                "language": "javascript",
                "difficulty": difficulty,
                "complexityLevel": "basic",
                "count": 1,
            },
        )

        assert response.status_code == 422

    @pytest.mark.parametrize("count", [0, 11])
    def test_out_of_range_count_is_rejected_by_validation(self, client, count):
        response = client.post(
            "/generate",
            json={
                "language": "javascript",
                "difficulty": "EASY",
                "complexityLevel": "basic",
                "count": count,
            },
        )

        assert response.status_code == 422

    def test_upstream_failure_becomes_503(self, client, monkeypatch):
        def _explode(**kwargs):
            raise RuntimeError("Anthropic API unreachable")

        monkeypatch.setattr(main_module, "generate_frontend_tasks", _explode)

        response = client.post(
            "/generate",
            json={
                "language": "javascript",
                "difficulty": "EASY",
                "complexityLevel": "basic",
                "count": 1,
            },
        )

        assert response.status_code == 503
        assert "unreachable" in response.json()["detail"]

    def test_malformed_upstream_payload_becomes_400(self, client, monkeypatch):
        def _explode(**kwargs):
            raise ValueError("Claude returned no usable tasks")

        monkeypatch.setattr(main_module, "generate_frontend_tasks", _explode)

        response = client.post(
            "/generate",
            json={
                "language": "javascript",
                "difficulty": "EASY",
                "complexityLevel": "basic",
                "count": 1,
            },
        )

        assert response.status_code == 400

    def test_unexpected_failure_does_not_leak_internals(self, client, monkeypatch):
        def _explode(**kwargs):
            raise TypeError("secret internal detail")

        monkeypatch.setattr(main_module, "generate_frontend_tasks", _explode)

        response = client.post(
            "/generate",
            json={
                "language": "javascript",
                "difficulty": "EASY",
                "complexityLevel": "basic",
                "count": 1,
            },
        )

        assert response.status_code == 500
        assert "secret internal detail" not in response.text


class TestAudit:
    def _payload(self, task):
        return {"tasks": [task.model_dump()], "language": "javascript"}

    def test_empty_task_list_is_rejected(self, client):
        response = client.post("/audit", json={"tasks": [], "language": "javascript"})

        assert response.status_code == 400
        assert "No tasks provided" in response.json()["detail"]

    def test_returns_findings_and_summary(self, client, monkeypatch, make_frontend_task):
        monkeypatch.setattr(main_module, "scan_with_hacktron", lambda *a, **k: [("t1", "log")])
        monkeypatch.setattr(
            main_module, "generate_security_mentor_summary", lambda *a, **k: "mentor summary"
        )
        task = make_frontend_task("t1", vulnerability_type="SQL_INJECTION")

        report = client.post("/audit", json=self._payload(task)).json()["report"]

        assert report["summary"] == "mentor summary"
        assert report["findings"][0]["severity"] == "CRITICAL"

    def test_scanner_failure_still_returns_a_report(self, client, monkeypatch, make_frontend_task):
        def _explode(*args, **kwargs):
            raise RuntimeError("scanner offline")

        monkeypatch.setattr(main_module, "scan_with_hacktron", _explode)
        monkeypatch.setattr(
            main_module, "generate_security_mentor_summary", lambda *a, **k: "mentor summary"
        )

        response = client.post("/audit", json=self._payload(make_frontend_task("t1")))

        assert response.status_code == 200
        assert response.json()["report"]["findings"]

    def test_claude_failure_falls_back_to_the_local_summary(
        self, client, monkeypatch, make_frontend_task
    ):
        monkeypatch.setattr(main_module, "scan_with_hacktron", lambda *a, **k: [("t1", "log")])

        def _explode(*args, **kwargs):
            raise RuntimeError("claude offline")

        monkeypatch.setattr(main_module, "generate_security_mentor_summary", _explode)
        task = make_frontend_task("t1", vulnerability_type="XSS")

        summary = client.post("/audit", json=self._payload(task)).json()["report"]["summary"]

        assert "Security scan detected 1 vulnerability." in summary

    def test_both_providers_failing_still_returns_200(
        self, client, monkeypatch, make_frontend_task
    ):
        def _explode(*args, **kwargs):
            raise RuntimeError("offline")

        monkeypatch.setattr(main_module, "scan_with_hacktron", _explode)
        monkeypatch.setattr(main_module, "generate_security_mentor_summary", _explode)

        response = client.post("/audit", json=self._payload(make_frontend_task("t1")))

        assert response.status_code == 200

    def test_safe_tasks_produce_no_findings(self, client, monkeypatch, make_frontend_task):
        monkeypatch.setattr(main_module, "scan_with_hacktron", lambda *a, **k: [])
        monkeypatch.setattr(
            main_module, "generate_security_mentor_summary", lambda *a, **k: "all clear"
        )
        task = make_frontend_task("t1", is_vulnerable=False, vulnerability_type="SAFE")

        report = client.post("/audit", json=self._payload(task)).json()["report"]

        assert report["findings"] == []


class TestLandingPage:
    def test_serves_the_client_index_when_present(self, client, monkeypatch, tmp_path):
        index = tmp_path / "index.html"
        index.write_text("<html>game</html>", encoding="utf-8")
        monkeypatch.setattr(main_module, "CLIENT_INDEX_PATH", index)

        response = client.get("/")

        assert response.status_code == 200
        assert "game" in response.text

    def test_returns_404_when_the_client_is_not_built(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(main_module, "CLIENT_INDEX_PATH", tmp_path / "missing.html")

        assert client.get("/").status_code == 404


class TestTTS:
    def test_empty_text_is_rejected_by_validation(self, client):
        assert client.post("/tts", json={"text": ""}).status_code == 422

    def test_whitespace_only_text_is_rejected_by_the_handler(self, client):
        """min_length=1 lets "   " past validation, so the handler must catch it."""
        response = client.post("/tts", json={"text": "   "})

        assert response.status_code == 400
        assert "cannot be empty" in response.json()["detail"]

    def test_overlong_text_is_rejected_by_validation(self, client):
        assert client.post("/tts", json={"text": "a" * 5001}).status_code == 422

    def test_returns_audio_url_and_duration(self, client, monkeypatch):
        monkeypatch.setattr(
            main_module, "generate_speech", lambda text, voice_id: ("data:audio/mpeg;base64,AA", 1.2)
        )

        body = client.post("/tts", json={"text": "hello"}).json()

        assert body["audioUrl"].startswith("data:audio/mpeg;base64,")
        assert body["duration"] == 1.2

    def test_missing_api_key_becomes_503(self, client, monkeypatch):
        def _explode(text, voice_id):
            raise RuntimeError("ELEVENLABS_API_KEY not configured in environment")

        monkeypatch.setattr(main_module, "generate_speech", _explode)

        response = client.post("/tts", json={"text": "hello"})

        assert response.status_code == 503

    def test_unexpected_failure_does_not_leak_internals(self, client, monkeypatch):
        def _explode(text, voice_id):
            raise TypeError("internal detail")

        monkeypatch.setattr(main_module, "generate_speech", _explode)

        response = client.post("/tts", json={"text": "hello"})

        assert response.status_code == 500
        assert "internal detail" not in response.text


class TestSessionLifecycle:
    @pytest.fixture(autouse=True)
    def stub_providers(self, monkeypatch, make_frontend_task):
        monkeypatch.setattr(
            store_module,
            "generate_frontend_tasks",
            lambda **kwargs: [
                make_frontend_task("t1", is_vulnerable=True, vulnerability_type="XSS"),
                make_frontend_task("t2", is_vulnerable=False, vulnerability_type="SAFE"),
            ],
        )
        monkeypatch.setattr(store_module, "scan_with_hacktron", lambda payload, lang: [
            (task_id, "log") for task_id, _ in payload
        ])
        monkeypatch.setattr(
            store_module, "generate_security_mentor_summary", lambda *a, **k: "mentor summary"
        )

    def test_full_round_trip(self, client):
        created = client.post("/session", json={"difficulty": "easy", "task_count": 2})
        assert created.status_code == 201
        session_id = created.json()["session_id"]
        assert created.json()["config"]["base_time_seconds"] == 120

        tasks = client.get(f"/session/{session_id}/tasks").json()["tasks"]
        assert len(tasks) == 2
        assert "isVulnerable" not in tasks[0]

        submitted = client.post(
            f"/session/{session_id}/submit",
            json={
                "answers": [
                    {"task_id": "t1", "user_choice": "sabotaged"},
                    {"task_id": "t2", "user_choice": "sabotaged"},
                ]
            },
        ).json()
        assert submitted["correct"] == 1
        assert submitted["missed_task_ids"] == ["t2"]

        finished = client.post(f"/session/{session_id}/finish").json()
        assert finished["score"] == 1
        assert finished["mentor_report"]["summary"] == "mentor summary"

        results = client.get(f"/session/{session_id}/results").json()
        assert results == finished

    def test_unknown_session_returns_404(self, client):
        assert client.get("/session/missing/tasks").status_code == 404
        assert client.post("/session/missing/finish").status_code == 404
        assert client.get("/session/missing/results").status_code == 404

    def test_submitting_to_an_unknown_session_returns_404(self, client):
        response = client.post(
            "/session/missing/submit",
            json={"answers": [{"task_id": "t1", "user_choice": "clean"}]},
        )

        assert response.status_code == 404

    def test_results_are_served_from_cache_without_recomputing(self, client, monkeypatch):
        session_id = client.post(
            "/session", json={"difficulty": "easy", "task_count": 2}
        ).json()["session_id"]
        client.post(f"/session/{session_id}/finish")

        def _fail(*args, **kwargs):
            raise AssertionError("cached results should not trigger another scan")

        monkeypatch.setattr(store_module, "scan_with_hacktron", _fail)

        assert client.get(f"/session/{session_id}/results").status_code == 200

    def test_results_requested_before_finish_computes_them_on_demand(self, client):
        session_id = client.post(
            "/session", json={"difficulty": "easy", "task_count": 2}
        ).json()["session_id"]

        results = client.get(f"/session/{session_id}/results")

        assert results.status_code == 200
        assert results.json()["mentor_report"]["summary"] == "mentor summary"

    def test_task_generation_failure_becomes_503(self, client, monkeypatch):
        def _explode(**kwargs):
            raise RuntimeError("Anthropic API unreachable")

        monkeypatch.setattr(store_module, "generate_frontend_tasks", _explode)

        response = client.post("/session", json={"difficulty": "easy", "task_count": 2})

        assert response.status_code == 503
        assert "Failed to create session" in response.json()["detail"]

    def test_unknown_task_id_in_submission_returns_400(self, client):
        session_id = client.post(
            "/session", json={"difficulty": "easy", "task_count": 2}
        ).json()["session_id"]

        response = client.post(
            f"/session/{session_id}/submit",
            json={"answers": [{"task_id": "ghost", "user_choice": "clean"}]},
        )

        assert response.status_code == 400
        assert "Unknown task id" in response.json()["detail"]

    def test_duplicate_answers_return_400(self, client):
        session_id = client.post(
            "/session", json={"difficulty": "easy", "task_count": 2}
        ).json()["session_id"]

        response = client.post(
            f"/session/{session_id}/submit",
            json={
                "answers": [
                    {"task_id": "t1", "user_choice": "clean"},
                    {"task_id": "t1", "user_choice": "sabotaged"},
                ]
            },
        )

        assert response.status_code == 400
        assert "Duplicate answer" in response.json()["detail"]

    def test_out_of_range_task_count_is_rejected(self, client):
        assert client.post("/session", json={"difficulty": "easy", "task_count": 0}).status_code == 422
        assert client.post("/session", json={"difficulty": "easy", "task_count": 11}).status_code == 422
