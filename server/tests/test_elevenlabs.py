from __future__ import annotations

import base64

import httpx
import pytest

from app.integrations import elevenlabs as elevenlabs_module
from app.integrations.elevenlabs import VOICE_IDS, generate_speech, validate_api_key


class FakeResponse:
    def __init__(self, status_code: int = 200, content: bytes = b"", text: str = ""):
        self.status_code = status_code
        self.content = content
        self.text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)


def fake_client(response=None, raises=None):
    class _Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def _handle(self, url, **kwargs):
            _Client.last_url = url
            _Client.last_headers = kwargs.get("headers")
            _Client.last_json = kwargs.get("json")
            if raises is not None:
                raise raises
            return response

        def get(self, url, **kwargs):
            return self._handle(url, **kwargs)

        def post(self, url, **kwargs):
            return self._handle(url, **kwargs)

    return _Client


@pytest.fixture(autouse=True)
def block_dotenv_fallback(monkeypatch):
    """_get_api_key falls back to loading the repo .env, which would leak a real key."""
    monkeypatch.setattr(elevenlabs_module, "load_dotenv", lambda *args, **kwargs: False)


class TestValidateApiKey:
    def test_missing_key_is_reported_without_a_request(self, monkeypatch):
        monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)

        is_valid, message = validate_api_key()

        assert is_valid is False
        assert "not configured" in message

    @pytest.mark.parametrize(
        "status,fragment",
        [
            (200, "valid"),
            (401, "invalid or expired"),
            (403, "lacks necessary permissions"),
            (429, "rate limit exceeded"),
            (500, "status 500"),
        ],
    )
    def test_status_codes_map_to_messages(self, monkeypatch, status, fragment):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        monkeypatch.setattr(
            elevenlabs_module.httpx, "Client", fake_client(FakeResponse(status_code=status))
        )

        is_valid, message = validate_api_key()

        assert is_valid is (status == 200)
        assert fragment in message

    def test_connection_failure_is_reported(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        monkeypatch.setattr(
            elevenlabs_module.httpx, "Client", fake_client(raises=httpx.ConnectError("down"))
        )

        is_valid, message = validate_api_key()

        assert is_valid is False
        assert "Cannot connect" in message

    def test_sends_the_api_key_header(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "secret")
        client_cls = fake_client(FakeResponse(status_code=200))
        monkeypatch.setattr(elevenlabs_module.httpx, "Client", client_cls)

        validate_api_key()

        assert client_cls.last_headers["xi-api-key"] == "secret"
        assert client_cls.last_url.endswith("/voices")


class TestGenerateSpeech:
    def test_missing_key_raises(self, monkeypatch):
        monkeypatch.delenv("ELEVENLABS_API_KEY", raising=False)

        with pytest.raises(RuntimeError, match="ELEVENLABS_API_KEY not configured"):
            generate_speech("hello")

    def test_returns_a_base64_data_url(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        monkeypatch.setattr(
            elevenlabs_module.httpx, "Client", fake_client(FakeResponse(content=b"audio-bytes"))
        )

        audio_url, _ = generate_speech("hello")

        assert audio_url.startswith("data:audio/mpeg;base64,")
        encoded = audio_url.split(",", 1)[1]
        assert base64.b64decode(encoded) == b"audio-bytes"

    def test_duration_is_estimated_from_word_count(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        monkeypatch.setattr(
            elevenlabs_module.httpx, "Client", fake_client(FakeResponse(content=b"a"))
        )

        _, duration = generate_speech("one two three")

        assert duration == pytest.approx(3 / 150 * 60)

    def test_named_preset_resolves_to_a_voice_id(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        client_cls = fake_client(FakeResponse(content=b"a"))
        monkeypatch.setattr(elevenlabs_module.httpx, "Client", client_cls)

        generate_speech("hello", voice_id="ship_computer")

        assert client_cls.last_url.endswith(VOICE_IDS["ship_computer"])

    def test_unknown_preset_falls_back_to_the_default_voice(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        client_cls = fake_client(FakeResponse(content=b"a"))
        monkeypatch.setattr(elevenlabs_module.httpx, "Client", client_cls)

        generate_speech("hello", voice_id="does-not-exist")

        assert client_cls.last_url.endswith(VOICE_IDS["default"])

    @pytest.mark.parametrize(
        "status,fragment",
        [
            (401, "invalid or expired"),
            (403, "access forbidden"),
            (429, "rate limit exceeded"),
            (500, "ElevenLabs API error: 500"),
        ],
    )
    def test_http_errors_map_to_readable_runtime_errors(self, monkeypatch, status, fragment):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        monkeypatch.setattr(
            elevenlabs_module.httpx,
            "Client",
            fake_client(FakeResponse(status_code=status, text="upstream detail")),
        )

        with pytest.raises(RuntimeError, match=fragment):
            generate_speech("hello")

    def test_connection_failure_raises(self, monkeypatch):
        monkeypatch.setenv("ELEVENLABS_API_KEY", "k")
        monkeypatch.setattr(
            elevenlabs_module.httpx, "Client", fake_client(raises=httpx.ConnectError("down"))
        )

        with pytest.raises(RuntimeError, match="Failed to connect"):
            generate_speech("hello")
