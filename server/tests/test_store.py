from __future__ import annotations

from datetime import datetime

import pytest

from app import store as store_module
from app.schemas import AnswerSchema, TaskPublicSchema
from app.store import (
    InMemoryStore,
    SessionData,
    _map_complexity,
    _map_vuln_type,
    _to_frontend_difficulty,
    build_fallback_mentor_report,
    score_session,
)


def make_session(tasks, answers=None) -> SessionData:
    return SessionData(
        session_id="s1",
        difficulty="easy",
        created_at=datetime(2026, 1, 1),
        tasks=tasks,
        answers=answers or {},
    )


class TestScoring:
    def test_correctly_flagging_a_vulnerable_task_scores(self, make_task_schema):
        task = make_task_schema("t1", is_vulnerable=True)
        session = make_session([task], {"t1": AnswerSchema(task_id="t1", user_choice="sabotaged")})

        assert score_session(session) == (1, 0, [])

    def test_correctly_clearing_a_safe_task_scores(self, make_task_schema):
        task = make_task_schema("t1", is_vulnerable=False, vulnerability_type="none")
        session = make_session([task], {"t1": AnswerSchema(task_id="t1", user_choice="clean")})

        assert score_session(session) == (1, 0, [])

    def test_missing_a_vulnerability_is_counted_as_missed(self, make_task_schema):
        task = make_task_schema("t1", is_vulnerable=True)
        session = make_session([task], {"t1": AnswerSchema(task_id="t1", user_choice="clean")})

        assert score_session(session) == (0, 1, ["t1"])

    def test_false_positive_on_safe_code_is_counted_as_missed(self, make_task_schema):
        task = make_task_schema("t1", is_vulnerable=False, vulnerability_type="none")
        session = make_session([task], {"t1": AnswerSchema(task_id="t1", user_choice="sabotaged")})

        assert score_session(session) == (0, 1, ["t1"])

    def test_unanswered_tasks_count_as_missed(self, make_task_schema):
        session = make_session([make_task_schema("t1"), make_task_schema("t2")])

        assert score_session(session) == (0, 2, ["t1", "t2"])

    def test_mixed_round_scores_and_reports_missed_ids_in_task_order(self, make_task_schema):
        tasks = [
            make_task_schema("t1", is_vulnerable=True),
            make_task_schema("t2", is_vulnerable=False, vulnerability_type="none"),
            make_task_schema("t3", is_vulnerable=True),
        ]
        answers = {
            "t1": AnswerSchema(task_id="t1", user_choice="sabotaged"),
            "t2": AnswerSchema(task_id="t2", user_choice="sabotaged"),
            "t3": AnswerSchema(task_id="t3", user_choice="clean"),
        }

        assert score_session(make_session(tasks, answers)) == (1, 2, ["t2", "t3"])


class TestSessionLookup:
    def test_unknown_session_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown session"):
            InMemoryStore().get_session("nope")

    def test_create_session_registers_and_returns_it(self, monkeypatch, make_frontend_task):
        monkeypatch.setattr(
            store_module, "generate_frontend_tasks", lambda **kwargs: [make_frontend_task("t1")]
        )
        store = InMemoryStore()

        session = store.create_session("easy", 1)

        assert store.get_session(session.session_id) is session
        assert len(session.tasks) == 1

    def test_create_session_passes_difficulty_config_through(
        self, monkeypatch, make_frontend_task
    ):
        captured = {}

        def _generate(**kwargs):
            captured.update(kwargs)
            return [make_frontend_task("t1")]

        monkeypatch.setattr(store_module, "generate_frontend_tasks", _generate)
        InMemoryStore().create_session("hard", 3)

        assert captured["difficulty"] == "HARD"
        assert captured["complexity_level"] == "advanced"
        assert captured["count"] == 3
        assert captured["vuln_density"] == 0.8


class TestPublicTaskLeakage:
    def test_public_tasks_never_expose_the_answer(self, make_task_schema):
        """The whole game breaks if the client can read is_vulnerable."""
        store = InMemoryStore()
        store.sessions["s1"] = make_session(
            [make_task_schema("t1", is_vulnerable=True, vulnerability_type="sqli")]
        )

        public = store.list_public_tasks("s1")

        assert isinstance(public[0], TaskPublicSchema)
        serialised = public[0].model_dump()
        assert "is_vulnerable" not in serialised
        assert "vulnerability_type" not in serialised
        assert "vulnerability_line" not in serialised

    def test_public_tasks_still_carry_what_the_client_needs(self, make_task_schema):
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1", code="dangerous()")])

        public = store.list_public_tasks("s1")

        assert public[0].id == "t1"
        assert public[0].code == "dangerous()"
        assert public[0].difficulty == "easy"


class TestSubmitAnswers:
    def test_unknown_task_id_is_rejected(self, make_task_schema):
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1")])

        with pytest.raises(ValueError, match="Unknown task id"):
            store.submit_answers("s1", [AnswerSchema(task_id="ghost", user_choice="clean")])

    def test_duplicate_answers_are_rejected(self, make_task_schema):
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1")])
        answer = AnswerSchema(task_id="t1", user_choice="sabotaged")

        with pytest.raises(ValueError, match="Duplicate answer"):
            store.submit_answers("s1", [answer, answer])

    def test_valid_submission_returns_score(self, make_task_schema):
        store = InMemoryStore()
        store.sessions["s1"] = make_session(
            [make_task_schema("t1", is_vulnerable=True), make_task_schema("t2", is_vulnerable=True)]
        )

        result = store.submit_answers(
            "s1",
            [
                AnswerSchema(task_id="t1", user_choice="sabotaged"),
                AnswerSchema(task_id="t2", user_choice="clean"),
            ],
        )

        assert result.correct == 1
        assert result.incorrect == 1
        assert result.missed_task_ids == ["t2"]

    def test_rejected_submission_does_not_partially_apply(self, make_task_schema):
        """A batch containing one bad id should not leave the earlier answer stored."""
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1")])

        with pytest.raises(ValueError):
            store.submit_answers(
                "s1",
                [
                    AnswerSchema(task_id="t1", user_choice="sabotaged"),
                    AnswerSchema(task_id="ghost", user_choice="clean"),
                ],
            )

        assert store.sessions["s1"].answers == {}


class TestGracefulDegradation:
    def test_scanner_failure_is_recorded_per_missed_task(
        self, monkeypatch, make_task_schema
    ):
        def _explode(*args, **kwargs):
            raise RuntimeError("scanner offline")

        monkeypatch.setattr(store_module, "scan_with_hacktron", _explode)
        monkeypatch.setattr(
            store_module, "generate_security_mentor_summary", lambda *a, **k: "summary"
        )
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1", is_vulnerable=True)])

        result = store.finish_session("s1")

        assert result.missed_task_ids == ["t1"]
        assert "Audit failed" in result.audit_logs[0].raw_log

    def test_claude_failure_falls_back_to_a_static_report(self, monkeypatch, make_task_schema):
        monkeypatch.setattr(store_module, "scan_with_hacktron", lambda *a, **k: [("t1", "log")])

        def _explode(*args, **kwargs):
            raise RuntimeError("claude offline")

        monkeypatch.setattr(store_module, "generate_security_mentor_summary", _explode)
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1", is_vulnerable=True)])

        result = store.finish_session("s1")

        assert "missed at least one vulnerable system" in result.mentor_report.summary

    def test_finish_is_idempotent_and_does_not_rescan(self, monkeypatch, make_task_schema):
        calls = []

        def _scan(payload, language):
            calls.append(payload)
            return [(task_id, "log") for task_id, _ in payload]

        monkeypatch.setattr(store_module, "scan_with_hacktron", _scan)
        monkeypatch.setattr(
            store_module, "generate_security_mentor_summary", lambda *a, **k: "summary"
        )
        store = InMemoryStore()
        store.sessions["s1"] = make_session([make_task_schema("t1", is_vulnerable=True)])

        store.finish_session("s1")
        store.finish_session("s1")

        assert len(calls) == 1

    def test_perfect_round_produces_no_audit_logs(self, monkeypatch, make_task_schema):
        monkeypatch.setattr(
            store_module, "generate_security_mentor_summary", lambda *a, **k: "summary"
        )
        store = InMemoryStore()
        store.sessions["s1"] = make_session(
            [make_task_schema("t1", is_vulnerable=True)],
            {"t1": AnswerSchema(task_id="t1", user_choice="sabotaged")},
        )

        result = store.finish_session("s1")

        assert result.score == 1
        assert result.audit_logs == []


class TestFallbackReport:
    def test_clean_sweep_message(self):
        assert "Clean sweep" in build_fallback_mentor_report([]).summary

    def test_missed_tasks_message_mentions_remediation(self):
        summary = build_fallback_mentor_report(["t1"]).summary
        assert "parameterized queries" in summary


class TestMappings:
    @pytest.mark.parametrize(
        "frontend,internal",
        [
            ("XSS", "xss"),
            ("SQL_INJECTION", "sqli"),
            ("SSRF", "ssrf"),
            ("RCE", "rce"),
            ("PATH_TRAVERSAL", "path_traversal"),
            ("COMMAND_INJECTION", "command_injection"),
            ("INSECURE_DESERIALIZATION", "insecure_deserialization"),
            ("SAFE", "none"),
        ],
    )
    def test_vulnerability_types_map_to_internal_names(self, frontend, internal):
        assert _map_vuln_type(frontend) == internal

    def test_unrecognised_vulnerability_type_maps_to_none(self):
        assert _map_vuln_type("QUANTUM_INJECTION") == "none"

    @pytest.mark.parametrize(
        "tag,expected",
        [("low", "basic"), ("medium", "intermediate"), ("high", "advanced"), ("?", "basic")],
    )
    def test_complexity_tags_map_to_frontend_levels(self, tag, expected):
        assert _map_complexity(tag) == expected

    @pytest.mark.parametrize("difficulty", ["easy", "medium", "hard"])
    def test_difficulty_is_upper_cased_for_the_frontend(self, difficulty):
        assert _to_frontend_difficulty(difficulty) == difficulty.upper()
