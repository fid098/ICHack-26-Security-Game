from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.schemas import (
    DIFFICULTY_CONFIGS,
    AnswerSchema,
    GenerateSnippetsRequest,
    SessionCreateRequest,
    TTSRequest,
)


class TestSessionCreateRequest:
    @pytest.mark.parametrize("count", [1, 5, 10])
    def test_accepts_counts_in_range(self, count):
        assert SessionCreateRequest(difficulty="easy", task_count=count).task_count == count

    @pytest.mark.parametrize("count", [0, -1, 11, 100])
    def test_rejects_counts_out_of_range(self, count):
        with pytest.raises(ValidationError):
            SessionCreateRequest(difficulty="easy", task_count=count)

    def test_rejects_unknown_difficulty(self):
        with pytest.raises(ValidationError):
            SessionCreateRequest(difficulty="impossible", task_count=1)

    def test_difficulty_is_case_sensitive(self):
        """The internal difficulty literal is lower case; EASY belongs to the frontend."""
        with pytest.raises(ValidationError):
            SessionCreateRequest(difficulty="EASY", task_count=1)


class TestGenerateSnippetsRequest:
    def test_accepts_a_valid_request(self):
        request = GenerateSnippetsRequest(
            language="python", difficulty="HARD", complexityLevel="advanced", count=3
        )

        assert request.language == "python"
        assert request.difficulty == "HARD"

    @pytest.mark.parametrize("count", [0, 11])
    def test_rejects_counts_out_of_range(self, count):
        with pytest.raises(ValidationError):
            GenerateSnippetsRequest(
                language="python", difficulty="EASY", complexityLevel="basic", count=count
            )

    def test_rejects_unsupported_language(self):
        with pytest.raises(ValidationError):
            GenerateSnippetsRequest(
                language="cobol", difficulty="EASY", complexityLevel="basic", count=1
            )

    def test_rejects_unknown_complexity_level(self):
        with pytest.raises(ValidationError):
            GenerateSnippetsRequest(
                language="python", difficulty="EASY", complexityLevel="expert", count=1
            )


class TestAnswerSchema:
    @pytest.mark.parametrize("choice", ["clean", "sabotaged"])
    def test_accepts_the_two_valid_choices(self, choice):
        assert AnswerSchema(task_id="t1", user_choice=choice).user_choice == choice

    def test_rejects_any_other_choice(self):
        with pytest.raises(ValidationError):
            AnswerSchema(task_id="t1", user_choice="maybe")


class TestTTSRequest:
    def test_rejects_empty_text(self):
        with pytest.raises(ValidationError):
            TTSRequest(text="")

    def test_rejects_text_over_the_limit(self):
        with pytest.raises(ValidationError):
            TTSRequest(text="a" * 5001)

    def test_accepts_text_at_the_limit(self):
        assert len(TTSRequest(text="a" * 5000).text) == 5000

    def test_voice_id_is_optional(self):
        assert TTSRequest(text="hello").voiceId is None

    def test_rejects_overlong_voice_id(self):
        with pytest.raises(ValidationError):
            TTSRequest(text="hello", voiceId="v" * 101)


class TestDifficultyConfigs:
    def test_every_difficulty_is_configured(self):
        assert set(DIFFICULTY_CONFIGS) == {"easy", "medium", "hard"}

    def test_harder_difficulties_allow_less_time(self):
        times = [DIFFICULTY_CONFIGS[d].base_time_seconds for d in ("easy", "medium", "hard")]
        assert times == sorted(times, reverse=True)

    def test_harder_difficulties_carry_a_bigger_penalty(self):
        penalties = [DIFFICULTY_CONFIGS[d].penalty_seconds for d in ("easy", "medium", "hard")]
        assert penalties == sorted(penalties)

    def test_vulnerability_density_rises_with_difficulty(self):
        densities = [DIFFICULTY_CONFIGS[d].vuln_density for d in ("easy", "medium", "hard")]
        assert densities == sorted(densities)
        assert all(0.0 <= d <= 1.0 for d in densities)

    def test_hints_are_disabled_only_on_hard(self):
        assert DIFFICULTY_CONFIGS["easy"].hints_allowed
        assert DIFFICULTY_CONFIGS["medium"].hints_allowed
        assert not DIFFICULTY_CONFIGS["hard"].hints_allowed
