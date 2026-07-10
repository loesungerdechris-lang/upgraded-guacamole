from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
from pathlib import Path

import pytest

from sentinel_core.xai_voice import (
    ResponseCollector,
    VoiceResponse,
    VoiceSessionConfig,
    XaiVoiceClient,
    XaiVoiceConfigurationError,
    XaiVoiceProtocolError,
    XaiVoiceRemoteError,
    build_user_turn_events,
    create_pcm16_wav,
    parse_server_event,
    persist_voice_response,
    _safe_terminal_text,
)


def test_websocket_url_uses_documented_model_parameter() -> None:
    config = VoiceSessionConfig(model="grok-voice-think-fast-1.0")
    assert config.websocket_url() == (
        "wss://api.x.ai/v1/realtime?model=grok-voice-think-fast-1.0"
    )


def test_agent_id_fails_closed_without_explicit_opt_in() -> None:
    config = VoiceSessionConfig()
    with pytest.raises(XaiVoiceConfigurationError, match="undocumented"):
        config.websocket_url(agent_id="agent_TestAgent123456")


def test_agent_id_requires_valid_format_even_with_opt_in() -> None:
    config = VoiceSessionConfig()
    with pytest.raises(XaiVoiceConfigurationError, match="invalid format"):
        config.websocket_url(agent_id="https://attacker.example", allow_undocumented_agent_id=True)


def test_agent_id_can_be_explicitly_opted_in() -> None:
    config = VoiceSessionConfig()
    assert config.websocket_url(
        agent_id="agent_TestAgent123456",
        allow_undocumented_agent_id=True,
    ).endswith("model=grok-voice-latest&agent_id=agent_TestAgent123456")


def test_resumption_requires_valid_conversation_id_and_opt_in() -> None:
    with pytest.raises(XaiVoiceConfigurationError, match="resumption_enabled"):
        VoiceSessionConfig().websocket_url(conversation_id="conversation-1")

    config = VoiceSessionConfig(resumption_enabled=True)
    assert "conversation_id=conversation-1" in config.websocket_url(
        conversation_id="conversation-1"
    )
    with pytest.raises(XaiVoiceConfigurationError, match="invalid format"):
        config.websocket_url(conversation_id="../../escape")


def test_session_update_has_explicit_pcm_and_non_authoritative_instructions() -> None:
    event = VoiceSessionConfig(sample_rate=24000).session_update_event()
    session = event["session"]
    assert event["type"] == "session.update"
    assert session["audio"]["input"]["format"] == {
        "type": "audio/pcm",
        "rate": 24000,
    }
    assert session["audio"]["output"]["format"] == {
        "type": "audio/pcm",
        "rate": 24000,
    }
    assert "non-authoritative" in session["instructions"]
    assert session["reasoning"] == {"effort": "high"}


def test_build_user_turn_events() -> None:
    item, response = build_user_turn_events("Hello")
    assert item["item"]["content"][0]["text"] == "Hello"
    assert response == {"type": "response.create"}


def test_build_user_turn_events_rejects_empty_prompt() -> None:
    with pytest.raises(XaiVoiceConfigurationError, match="prompt"):
        build_user_turn_events("   ")


def test_parse_server_event_rejects_invalid_json_and_oversize() -> None:
    with pytest.raises(XaiVoiceProtocolError, match="valid JSON"):
        parse_server_event("{", max_event_bytes=1024)
    with pytest.raises(XaiVoiceProtocolError, match="size limit"):
        parse_server_event("x" * 1025, max_event_bytes=1024)
    with pytest.raises(XaiVoiceProtocolError, match="JSON object"):
        parse_server_event("[]", max_event_bytes=1024)


def test_parse_server_event_rejects_duplicate_json_keys() -> None:
    with pytest.raises(XaiVoiceProtocolError, match="duplicate JSON keys"):
        parse_server_event(
            '{"type":"session.created","type":"session.updated"}',
            max_event_bytes=1024,
        )


def test_response_collector_limits_transcript_and_event_count() -> None:
    transcript_limited = ResponseCollector(
        max_audio_bytes=1024,
        max_transcript_bytes=1024,
        max_response_events=100,
    )
    transcript_limited.consume(
        {"type": "response.created", "response": {"id": "resp_transcript"}}
    )
    with pytest.raises(XaiVoiceProtocolError, match="transcript exceeded"):
        transcript_limited.consume(
            {
                "type": "response.output_audio_transcript.delta",
                "delta": "x" * 1025,
            }
        )

    event_limited = ResponseCollector(
        max_audio_bytes=1024,
        max_transcript_bytes=1024,
        max_response_events=100,
    )
    event_limited.consume(
        {"type": "response.created", "response": {"id": "resp_events"}}
    )
    for _ in range(99):
        event_limited.consume({"type": "rate_limits.updated"})
    with pytest.raises(XaiVoiceProtocolError, match="event-count limit"):
        event_limited.consume({"type": "rate_limits.updated"})


def test_response_collector_rejects_invalid_response_id_and_odd_pcm() -> None:
    invalid_id = ResponseCollector(max_audio_bytes=1024)
    with pytest.raises(XaiVoiceProtocolError, match="invalid response id"):
        invalid_id.consume(
            {"type": "response.created", "response": {"id": "../../escape"}}
        )

    odd_pcm = ResponseCollector(max_audio_bytes=1024)
    odd_pcm.consume({"type": "response.created", "response": {"id": "resp_odd"}})
    odd_pcm.consume(
        {
            "type": "response.output_audio.delta",
            "delta": base64.b64encode(b"x").decode("ascii"),
        }
    )
    with pytest.raises(XaiVoiceProtocolError, match="odd byte count"):
        odd_pcm.consume({"type": "response.done", "response": {"status": "completed"}})


def test_terminal_rendering_removes_escape_and_control_characters() -> None:
    assert _safe_terminal_text("safe\x1b[31m red\x00\x9b") == "safe[31m red"


class _FakeWebSocket:
    def __init__(self, events: list[dict[str, object]]) -> None:
        self.events = [json.dumps(event) for event in events]
        self.sent: list[str] = []
        self.closed = False

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def recv(self) -> str:
        return self.events.pop(0)

    async def close(self, *, code: int, reason: str) -> None:
        self.closed = True


def test_client_rejects_non_completed_response_status() -> None:
    client = XaiVoiceClient(api_key="test-key", config=VoiceSessionConfig())
    client._websocket = _FakeWebSocket(
        [
            {"type": "response.created", "response": {"id": "resp_failed"}},
            {"type": "response.done", "response": {"status": "failed"}},
        ]
    )
    client._session_ready = True

    with pytest.raises(XaiVoiceRemoteError, match="status=failed"):
        asyncio.run(client.run_turn("hello"))
    assert len(client._websocket.sent) == 2


def test_response_collector_builds_completed_response() -> None:
    collector = ResponseCollector(sample_rate=24000, max_audio_bytes=1024)
    assert collector.consume(
        {"type": "response.created", "response": {"id": "resp_123"}}
    ) is None
    assert collector.consume(
        {"type": "response.output_audio_transcript.delta", "delta": "Hello"}
    ) is None
    pcm = b"\x00\x00\x01\x00"
    assert collector.consume(
        {
            "type": "response.output_audio.delta",
            "delta": base64.b64encode(pcm).decode("ascii"),
        }
    ) is None
    assert collector.consume({"type": "response.output_audio.done"}) is None
    response = collector.consume(
        {"type": "response.done", "response": {"status": "completed"}}
    )
    assert response is not None
    assert response.response_id == "resp_123"
    assert response.transcript == "Hello"
    assert response.pcm_audio == pcm
    assert response.audio_done_seen is True
    assert response.status == "completed"


def test_response_collector_rejects_audio_before_response_created() -> None:
    collector = ResponseCollector(max_audio_bytes=1024)
    with pytest.raises(XaiVoiceProtocolError, match="without an active response"):
        collector.consume(
            {
                "type": "response.output_audio.delta",
                "delta": base64.b64encode(b"\x00\x00").decode("ascii"),
            }
        )


def test_response_collector_rejects_invalid_or_oversized_audio() -> None:
    collector = ResponseCollector(max_audio_bytes=1024)
    collector.consume({"type": "response.created", "response": {"id": "resp"}})
    with pytest.raises(XaiVoiceProtocolError, match="canonical base64"):
        collector.consume({"type": "response.output_audio.delta", "delta": "%%%"})

    oversized = ResponseCollector(max_audio_bytes=1024)
    oversized.consume({"type": "response.created", "response": {"id": "resp"}})
    with pytest.raises(XaiVoiceProtocolError, match="size limit"):
        oversized.consume(
            {
                "type": "response.output_audio.delta",
                "delta": base64.b64encode(b"x" * 1025).decode("ascii"),
            }
        )


def test_pcm16_wav_header_and_length() -> None:
    pcm = b"\x00\x00\x01\x00"
    wav = create_pcm16_wav(pcm, sample_rate=24000)
    assert wav[:4] == b"RIFF"
    assert wav[8:12] == b"WAVE"
    assert wav[36:40] == b"data"
    assert struct.unpack("<I", wav[40:44])[0] == len(pcm)
    assert wav[44:] == pcm


def test_pcm16_wav_rejects_odd_byte_count() -> None:
    with pytest.raises(XaiVoiceProtocolError, match="divisible by two"):
        create_pcm16_wav(b"\x00", sample_rate=24000)


def test_persist_voice_response_is_atomic_hashed_and_non_authoritative(tmp_path: Path) -> None:
    response = VoiceResponse(
        response_id="../../resp:1",
        transcript="Hallo Ära",
        pcm_audio=b"\x00\x00\x01\x00",
        sample_rate=24000,
        status="completed",
        audio_done_seen=True,
        event_types=("response.created", "response.output_audio.done", "response.done"),
    )
    artifacts = persist_voice_response(
        response,
        output_dir=tmp_path,
        persist_audio=True,
        persist_transcript=True,
    )
    assert artifacts.wav_path is not None and artifacts.wav_path.parent == tmp_path
    assert artifacts.transcript_path is not None and artifacts.transcript_path.parent == tmp_path
    assert ".." not in artifacts.wav_path.name
    manifest = json.loads(artifacts.manifest_path.read_text(encoding="utf-8"))
    assert manifest["authoritative"] is False
    assert manifest["audio"]["pcm_sha256"].startswith("sha256:")
    assert manifest["audio"]["wav_sha256"].startswith("sha256:")
    assert manifest["transcript"]["sha256"].startswith("sha256:")
    assert artifacts.transcript_path.read_text(encoding="utf-8") == "Hallo Ära"
    if os.name != "nt":
        assert artifacts.manifest_path.stat().st_mode & 0o777 == 0o600


def test_persist_voice_response_refuses_overwrite(tmp_path: Path) -> None:
    response = VoiceResponse(
        response_id="resp_1",
        transcript="text",
        pcm_audio=b"\x00\x00",
        sample_rate=24000,
        status="completed",
        audio_done_seen=True,
        event_types=("response.done",),
    )
    persist_voice_response(
        response,
        output_dir=tmp_path,
        persist_audio=True,
        persist_transcript=False,
    )
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        persist_voice_response(
            response,
            output_dir=tmp_path,
            persist_audio=True,
            persist_transcript=False,
        )


def test_persist_voice_response_rejects_symlink_output_directory(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation may require elevated Windows privileges")
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    response = VoiceResponse(
        response_id="resp_link",
        transcript="text",
        pcm_audio=b"\x00\x00",
        sample_rate=24000,
        status="completed",
        audio_done_seen=True,
        event_types=("response.done",),
    )
    with pytest.raises(XaiVoiceConfigurationError, match="symbolic link"):
        persist_voice_response(
            response,
            output_dir=linked_dir,
            persist_audio=True,
            persist_transcript=False,
        )
