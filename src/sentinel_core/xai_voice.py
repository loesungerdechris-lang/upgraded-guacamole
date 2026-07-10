"""Fail-closed xAI Voice Agent WebSocket client for SENTINEL.

The voice layer is intentionally non-authoritative. It may present verified tool
results, but it must never manufacture evidence, signatures, approvals, or
execution claims. API keys are read only from the environment and are never
accepted as command-line arguments.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import re
import struct
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlencode

_XAI_REALTIME_ENDPOINT = "wss://api.x.ai/v1/realtime"
_ALLOWED_SAMPLE_RATES = frozenset({8000, 16000, 22050, 24000, 32000, 44100, 48000})
_ALLOWED_REASONING_EFFORTS = frozenset({"high", "none"})
_AGENT_ID_RE = re.compile(r"^agent_[A-Za-z0-9]{8,128}$")
_CONVERSATION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_RESPONSE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_SAFE_FILE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")
_DEFAULT_MAX_EVENT_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_AUDIO_BYTES = 64 * 1024 * 1024
_DEFAULT_MAX_TRANSCRIPT_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_RESPONSE_EVENTS = 10_000
_DEFAULT_INSTRUCTIONS = (
    "You are Ara, the calm voice interface for SENTINEL. "
    "Treat voice as a non-authoritative interaction layer. "
    "Never claim that evidence, a signature, a receipt, an approval, or an external action "
    "exists unless a trusted tool result explicitly proves it. "
    "State uncertainty plainly and do not infer consent from silence, tone, or emotion."
)


class XaiVoiceError(RuntimeError):
    """Base error for the xAI voice boundary."""


class XaiVoiceConfigurationError(XaiVoiceError):
    """Raised when local configuration is invalid or unsafe."""


class XaiVoiceProtocolError(XaiVoiceError):
    """Raised when a remote event violates the expected protocol contract."""


class XaiVoiceRemoteError(XaiVoiceError):
    """Raised when xAI returns an explicit error event."""


@dataclass(frozen=True)
class VoiceSessionConfig:
    """Validated Voice Agent API session configuration."""

    model: str = "grok-voice-latest"
    voice: str = "ara"
    instructions: str = _DEFAULT_INSTRUCTIONS
    sample_rate: int = 24000
    reasoning_effort: str = "high"
    resumption_enabled: bool = False
    max_event_bytes: int = _DEFAULT_MAX_EVENT_BYTES
    max_audio_bytes: int = _DEFAULT_MAX_AUDIO_BYTES
    max_transcript_bytes: int = _DEFAULT_MAX_TRANSCRIPT_BYTES
    max_response_events: int = _DEFAULT_MAX_RESPONSE_EVENTS
    open_timeout_seconds: float = 15.0
    receive_timeout_seconds: float = 120.0
    close_timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        _validate_non_empty_text(self.model, "model", max_length=128)
        _validate_non_empty_text(self.voice, "voice", max_length=256)
        _validate_non_empty_text(self.instructions, "instructions", max_length=32_000)
        if self.sample_rate not in _ALLOWED_SAMPLE_RATES:
            raise XaiVoiceConfigurationError(
                f"sample_rate must be one of {sorted(_ALLOWED_SAMPLE_RATES)}"
            )
        if self.reasoning_effort not in _ALLOWED_REASONING_EFFORTS:
            raise XaiVoiceConfigurationError(
                f"reasoning_effort must be one of {sorted(_ALLOWED_REASONING_EFFORTS)}"
            )
        if not isinstance(self.resumption_enabled, bool):
            raise XaiVoiceConfigurationError("resumption_enabled must be boolean")
        _validate_int_range(self.max_event_bytes, "max_event_bytes", 1024, 16 * 1024 * 1024)
        _validate_int_range(self.max_audio_bytes, "max_audio_bytes", 1024, 512 * 1024 * 1024)
        _validate_int_range(
            self.max_transcript_bytes,
            "max_transcript_bytes",
            1024,
            16 * 1024 * 1024,
        )
        _validate_int_range(
            self.max_response_events,
            "max_response_events",
            100,
            100_000,
        )
        _validate_timeout(self.open_timeout_seconds, "open_timeout_seconds", maximum=120.0)
        _validate_timeout(self.receive_timeout_seconds, "receive_timeout_seconds", maximum=1800.0)
        _validate_timeout(self.close_timeout_seconds, "close_timeout_seconds", maximum=120.0)

    def websocket_url(
        self,
        *,
        conversation_id: str | None = None,
        agent_id: str | None = None,
        allow_undocumented_agent_id: bool = False,
    ) -> str:
        """Return the exact xAI realtime URL with validated query parameters.

        ``agent_id`` is not present in the public xAI Voice Agent API documentation as of
        2026-07-11. The client therefore refuses it unless an operator explicitly opts in.
        """

        query: list[tuple[str, str]] = [("model", self.model)]
        if conversation_id is not None:
            if not self.resumption_enabled:
                raise XaiVoiceConfigurationError(
                    "conversation_id requires resumption_enabled=true"
                )
            if _CONVERSATION_ID_RE.fullmatch(conversation_id) is None:
                raise XaiVoiceConfigurationError("conversation_id has an invalid format")
            query.append(("conversation_id", conversation_id))

        if agent_id is not None:
            if not allow_undocumented_agent_id:
                raise XaiVoiceConfigurationError(
                    "agent_id is undocumented by the public xAI Voice Agent API; "
                    "explicit operator opt-in is required"
                )
            if _AGENT_ID_RE.fullmatch(agent_id) is None:
                raise XaiVoiceConfigurationError("agent_id has an invalid format")
            query.append(("agent_id", agent_id))

        return f"{_XAI_REALTIME_ENDPOINT}?{urlencode(query)}"

    def session_update_event(self) -> dict[str, Any]:
        """Build the documented session.update event."""

        return {
            "type": "session.update",
            "session": {
                "voice": self.voice,
                "instructions": self.instructions,
                "reasoning": {"effort": self.reasoning_effort},
                "turn_detection": {"type": "server_vad"},
                "resumption": {"enabled": self.resumption_enabled},
                "audio": {
                    "input": {
                        "format": {"type": "audio/pcm", "rate": self.sample_rate}
                    },
                    "output": {
                        "format": {"type": "audio/pcm", "rate": self.sample_rate}
                    },
                },
            },
        }


@dataclass(frozen=True)
class VoiceResponse:
    """Completed assistant response captured from one response lifecycle."""

    response_id: str
    transcript: str
    pcm_audio: bytes
    sample_rate: int
    status: str | None
    audio_done_seen: bool
    event_types: tuple[str, ...]

    @property
    def duration_seconds(self) -> float:
        bytes_per_second = self.sample_rate * 2
        return len(self.pcm_audio) / bytes_per_second


@dataclass(frozen=True)
class PersistedVoiceArtifacts:
    """Paths written for an explicitly recorded response."""

    wav_path: Path | None
    transcript_path: Path | None
    manifest_path: Path


@dataclass
class ResponseCollector:
    """Bounded response accumulator that rejects malformed event data."""

    sample_rate: int = 24000
    max_audio_bytes: int = _DEFAULT_MAX_AUDIO_BYTES
    max_transcript_bytes: int = _DEFAULT_MAX_TRANSCRIPT_BYTES
    max_response_events: int = _DEFAULT_MAX_RESPONSE_EVENTS
    _response_id: str | None = field(default=None, init=False)
    _transcript_parts: list[str] = field(default_factory=list, init=False)
    _audio_parts: list[bytes] = field(default_factory=list, init=False)
    _audio_bytes: int = field(default=0, init=False)
    _transcript_bytes: int = field(default=0, init=False)
    _event_count: int = field(default=0, init=False)
    _audio_done_seen: bool = field(default=False, init=False)
    _event_types: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if self.sample_rate not in _ALLOWED_SAMPLE_RATES:
            raise XaiVoiceConfigurationError("collector sample_rate is unsupported")
        _validate_int_range(self.max_audio_bytes, "max_audio_bytes", 1024, 512 * 1024 * 1024)
        _validate_int_range(
            self.max_transcript_bytes,
            "max_transcript_bytes",
            1024,
            16 * 1024 * 1024,
        )
        _validate_int_range(
            self.max_response_events,
            "max_response_events",
            100,
            100_000,
        )

    def consume(self, event: Mapping[str, Any]) -> VoiceResponse | None:
        """Consume one validated event and return a response at response.done."""

        event_type = event.get("type")
        if not isinstance(event_type, str) or not event_type:
            raise XaiVoiceProtocolError("event.type must be a non-empty string")
        self._event_count += 1
        if self._event_count > self.max_response_events:
            raise XaiVoiceProtocolError("response exceeded the configured event-count limit")
        self._event_types.append(event_type)

        if event_type == "response.created":
            if self._response_id is not None:
                raise XaiVoiceProtocolError(
                    "received response.created while another response is active"
                )
            response = event.get("response")
            if not isinstance(response, Mapping):
                raise XaiVoiceProtocolError("response.created is missing response metadata")
            response_id = response.get("id")
            if not isinstance(response_id, str) or not response_id:
                raise XaiVoiceProtocolError("response.created is missing a response id")
            if _RESPONSE_ID_RE.fullmatch(response_id) is None:
                raise XaiVoiceProtocolError("response.created contains an invalid response id")
            self._response_id = response_id
            return None

        if event_type == "response.output_audio_transcript.delta":
            self._require_active_response(event_type)
            delta = event.get("delta")
            if not isinstance(delta, str):
                raise XaiVoiceProtocolError("transcript delta must be a string")
            delta_bytes = len(delta.encode("utf-8"))
            new_size = self._transcript_bytes + delta_bytes
            if new_size > self.max_transcript_bytes:
                raise XaiVoiceProtocolError(
                    "response transcript exceeded the configured size limit"
                )
            self._transcript_parts.append(delta)
            self._transcript_bytes = new_size
            return None

        if event_type == "response.output_audio.delta":
            self._require_active_response(event_type)
            delta = event.get("delta")
            if not isinstance(delta, str) or not delta:
                raise XaiVoiceProtocolError("audio delta must be non-empty base64 text")
            try:
                chunk = base64.b64decode(delta, validate=True)
            except (ValueError, TypeError):
                raise XaiVoiceProtocolError("audio delta is not canonical base64") from None
            if not chunk:
                raise XaiVoiceProtocolError("audio delta decoded to an empty chunk")
            if base64.b64encode(chunk).decode("ascii") != delta:
                raise XaiVoiceProtocolError("audio delta is not canonical base64")
            new_size = self._audio_bytes + len(chunk)
            if new_size > self.max_audio_bytes:
                raise XaiVoiceProtocolError("response audio exceeded the configured size limit")
            self._audio_parts.append(chunk)
            self._audio_bytes = new_size
            return None

        if event_type == "response.output_audio.done":
            self._require_active_response(event_type)
            self._audio_done_seen = True
            return None

        if event_type == "response.done":
            self._require_active_response(event_type)
            response = event.get("response")
            status: str | None = None
            if isinstance(response, Mapping):
                candidate_status = response.get("status")
                if candidate_status is not None and not isinstance(candidate_status, str):
                    raise XaiVoiceProtocolError("response.done status must be a string or null")
                status = candidate_status
            pcm_audio = b"".join(self._audio_parts)
            if len(pcm_audio) % 2 != 0:
                raise XaiVoiceProtocolError("completed PCM16 audio has an odd byte count")
            completed = VoiceResponse(
                response_id=self._response_id or "unknown",
                transcript="".join(self._transcript_parts),
                pcm_audio=pcm_audio,
                sample_rate=self.sample_rate,
                status=status,
                audio_done_seen=self._audio_done_seen,
                event_types=tuple(self._event_types),
            )
            self.reset()
            return completed

        return None

    def reset(self) -> None:
        """Discard any active response state."""

        self._response_id = None
        self._transcript_parts.clear()
        self._audio_parts.clear()
        self._audio_bytes = 0
        self._transcript_bytes = 0
        self._event_count = 0
        self._audio_done_seen = False
        self._event_types.clear()

    def _require_active_response(self, event_type: str) -> None:
        if self._response_id is None:
            raise XaiVoiceProtocolError(f"{event_type} arrived without an active response")


def parse_server_event(raw: str | bytes, *, max_event_bytes: int) -> dict[str, Any]:
    """Parse one bounded UTF-8 JSON object from the WebSocket."""

    _validate_int_range(max_event_bytes, "max_event_bytes", 1024, 16 * 1024 * 1024)
    if isinstance(raw, str):
        encoded = raw.encode("utf-8")
        text = raw
    elif isinstance(raw, bytes):
        encoded = raw
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise XaiVoiceProtocolError("server event is not valid UTF-8") from None
    else:
        raise XaiVoiceProtocolError("server event must be text or bytes")

    if len(encoded) > max_event_bytes:
        raise XaiVoiceProtocolError("server event exceeded the configured size limit")
    try:
        event = json.loads(text, object_pairs_hook=_reject_duplicate_object_pairs)
    except (TypeError, ValueError):
        raise XaiVoiceProtocolError("server event is not valid JSON") from None
    if not isinstance(event, dict):
        raise XaiVoiceProtocolError("server event must be a JSON object")
    event_type = event.get("type")
    if not isinstance(event_type, str) or not event_type:
        raise XaiVoiceProtocolError("server event is missing type")
    return event


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise XaiVoiceProtocolError("server event contains duplicate JSON keys")
        result[key] = value
    return result


def build_user_turn_events(prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a text user turn and its explicit response request."""

    _validate_non_empty_text(prompt, "prompt", max_length=32_000)
    return (
        {
            "type": "conversation.item.create",
            "item": {
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": prompt}],
            },
        },
        {"type": "response.create"},
    )


def persist_voice_response(
    response: VoiceResponse,
    *,
    output_dir: Path,
    persist_audio: bool,
    persist_transcript: bool,
) -> PersistedVoiceArtifacts:
    """Persist explicitly requested artifacts atomically with restrictive permissions."""

    if not persist_audio and not persist_transcript:
        raise XaiVoiceConfigurationError(
            "at least one of persist_audio or persist_transcript must be enabled"
        )
    if not isinstance(output_dir, Path):
        raise XaiVoiceConfigurationError("output_dir must be a pathlib.Path")
    if output_dir.is_symlink():
        raise XaiVoiceConfigurationError("output_dir must not be a symbolic link")
    if output_dir.exists() and not output_dir.is_dir():
        raise XaiVoiceConfigurationError("output_dir must be a directory")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        output_dir.chmod(0o700)
    except OSError:
        pass

    safe_id = _safe_file_component(response.response_id)
    wav_path: Path | None = None
    transcript_path: Path | None = None
    wav_digest: str | None = None
    transcript_digest: str | None = None

    if persist_audio:
        wav_bytes = create_pcm16_wav(response.pcm_audio, sample_rate=response.sample_rate)
        wav_path = output_dir / f"response_{safe_id}.wav"
        _atomic_write(wav_path, wav_bytes)
        wav_digest = _sha256_prefixed(wav_bytes)

    if persist_transcript:
        transcript_bytes = response.transcript.encode("utf-8")
        transcript_path = output_dir / f"response_{safe_id}.txt"
        _atomic_write(transcript_path, transcript_bytes)
        transcript_digest = _sha256_prefixed(transcript_bytes)

    manifest = {
        "schema": "sentinel.xai-voice-artifact-manifest.v1",
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "response_id": response.response_id,
        "status": response.status,
        "authoritative": False,
        "warning": (
            "This manifest provides local integrity metadata only. It is not a SENTINEL "
            "receipt, signature, consent record, approval, or verification decision."
        ),
        "audio": {
            "format": "audio/pcm",
            "encoding": "Linear16 little-endian",
            "sample_rate": response.sample_rate,
            "channels": 1,
            "bit_depth": 16,
            "pcm_bytes": len(response.pcm_audio),
            "duration_seconds": round(response.duration_seconds, 6),
            "pcm_sha256": _sha256_prefixed(response.pcm_audio),
            "audio_done_seen": response.audio_done_seen,
            "persisted": persist_audio,
            "wav_filename": wav_path.name if wav_path else None,
            "wav_sha256": wav_digest,
        },
        "transcript": {
            "characters": len(response.transcript),
            "utf8_bytes": len(response.transcript.encode("utf-8")),
            "sha256": _sha256_prefixed(response.transcript.encode("utf-8")),
            "persisted": persist_transcript,
            "filename": transcript_path.name if transcript_path else None,
            "file_sha256": transcript_digest,
        },
        "event_types": list(response.event_types),
    }
    manifest_path = output_dir / f"response_{safe_id}.manifest.json"
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _atomic_write(manifest_path, manifest_bytes)
    return PersistedVoiceArtifacts(
        wav_path=wav_path,
        transcript_path=transcript_path,
        manifest_path=manifest_path,
    )


def create_pcm16_wav(pcm_audio: bytes, *, sample_rate: int) -> bytes:
    """Wrap mono PCM16 little-endian bytes in a canonical RIFF/WAVE header."""

    if not isinstance(pcm_audio, bytes):
        raise XaiVoiceConfigurationError("pcm_audio must be bytes")
    if sample_rate not in _ALLOWED_SAMPLE_RATES:
        raise XaiVoiceConfigurationError("sample_rate is unsupported")
    if len(pcm_audio) % 2 != 0:
        raise XaiVoiceProtocolError("PCM16 audio length must be divisible by two")
    channels = 1
    bit_depth = 16
    block_align = channels * bit_depth // 8
    byte_rate = sample_rate * block_align
    if len(pcm_audio) > 0xFFFFFFFF - 36:
        raise XaiVoiceProtocolError("PCM data is too large for a RIFF/WAVE container")
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + len(pcm_audio),
        b"WAVE",
        b"fmt ",
        16,
        1,
        channels,
        sample_rate,
        byte_rate,
        block_align,
        bit_depth,
        b"data",
        len(pcm_audio),
    )
    return header + pcm_audio


class XaiVoiceClient:
    """Server-side xAI Voice Agent client with no automatic turn replay."""

    def __init__(
        self,
        *,
        api_key: str,
        config: VoiceSessionConfig,
        agent_id: str | None = None,
        allow_undocumented_agent_id: bool = False,
        transcript_sink: Callable[[str], None] | None = None,
    ) -> None:
        _validate_api_key(api_key)
        self._api_key = api_key
        self._config = config
        self._agent_id = agent_id
        self._allow_undocumented_agent_id = allow_undocumented_agent_id
        self._transcript_sink = transcript_sink
        self._conversation_id: str | None = None
        self._websocket: Any = None
        self._session_ready = False

        # Validate undocumented options before any network activity.
        self._config.websocket_url(
            agent_id=self._agent_id,
            allow_undocumented_agent_id=self._allow_undocumented_agent_id,
        )

    async def __aenter__(self) -> XaiVoiceClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        await self.close()

    async def connect(self) -> None:
        """Open and configure a WebSocket, waiting for session.updated."""

        if self._websocket is not None:
            return
        try:
            import websockets
        except ImportError:
            raise XaiVoiceConfigurationError(
                "Install the voice extra with: python -m pip install -e .[voice]"
            ) from None

        url = self._config.websocket_url(
            conversation_id=self._conversation_id,
            agent_id=self._agent_id,
            allow_undocumented_agent_id=self._allow_undocumented_agent_id,
        )
        try:
            self._websocket = await websockets.connect(
                url,
                additional_headers={"Authorization": f"Bearer {self._api_key}"},
                open_timeout=self._config.open_timeout_seconds,
                close_timeout=self._config.close_timeout_seconds,
                max_size=self._config.max_event_bytes,
                compression=None,
                ping_interval=20,
                ping_timeout=20,
            )
            await self._send_event(self._config.session_update_event())
            await self._wait_for_session_ready()
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Close the WebSocket without exposing credentials or remote payloads."""

        websocket = self._websocket
        self._websocket = None
        self._session_ready = False
        if websocket is None:
            return
        try:
            await websocket.close(code=1000, reason="client shutdown")
        except Exception:
            pass

    async def run_turn(self, prompt: str) -> VoiceResponse:
        """Run one text turn. Ambiguous send failures are never replayed automatically."""

        if self._websocket is None or not self._session_ready:
            await self.connect()
        user_event, response_event = build_user_turn_events(prompt)
        try:
            await self._send_event(user_event)
            await self._send_event(response_event)
        except Exception as exc:
            await self.close()
            raise XaiVoiceProtocolError(
                "turn delivery became ambiguous; the client closed without automatic replay"
            ) from exc

        collector = ResponseCollector(
            sample_rate=self._config.sample_rate,
            max_audio_bytes=self._config.max_audio_bytes,
            max_transcript_bytes=self._config.max_transcript_bytes,
            max_response_events=self._config.max_response_events,
        )
        while True:
            event = await self._receive_event()
            event_type = event["type"]
            self._capture_conversation_id(event)
            if event_type == "error":
                raise _remote_error(event)
            if event_type == "response.output_audio_transcript.delta":
                delta = event.get("delta")
                if isinstance(delta, str) and self._transcript_sink is not None:
                    self._transcript_sink(delta)
            completed = collector.consume(event)
            if completed is not None:
                if completed.status not in {None, "completed"}:
                    status = _safe_remote_field(completed.status, max_length=80) or "unknown"
                    raise XaiVoiceRemoteError(
                        f"xAI response ended without completion; status={status}"
                    )
                return completed

    async def _wait_for_session_ready(self) -> None:
        while True:
            event = await self._receive_event()
            self._capture_conversation_id(event)
            event_type = event["type"]
            if event_type == "error":
                raise _remote_error(event)
            if event_type == "session.updated":
                self._session_ready = True
                return

    async def _send_event(self, event: Mapping[str, Any]) -> None:
        if self._websocket is None:
            raise XaiVoiceProtocolError("WebSocket is not connected")
        payload = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        if len(payload.encode("utf-8")) > self._config.max_event_bytes:
            raise XaiVoiceProtocolError("outbound event exceeded the configured size limit")
        await self._websocket.send(payload)

    async def _receive_event(self) -> dict[str, Any]:
        if self._websocket is None:
            raise XaiVoiceProtocolError("WebSocket is not connected")
        try:
            raw = await asyncio.wait_for(
                self._websocket.recv(),
                timeout=self._config.receive_timeout_seconds,
            )
        except TimeoutError:
            await self.close()
            raise XaiVoiceProtocolError("timed out while waiting for a server event") from None
        return parse_server_event(raw, max_event_bytes=self._config.max_event_bytes)

    def _capture_conversation_id(self, event: Mapping[str, Any]) -> None:
        if event.get("type") != "conversation.created":
            return
        conversation = event.get("conversation")
        if not isinstance(conversation, Mapping):
            raise XaiVoiceProtocolError("conversation.created is missing conversation metadata")
        conversation_id = conversation.get("id")
        if not isinstance(conversation_id, str):
            raise XaiVoiceProtocolError("conversation.created is missing conversation id")
        if _CONVERSATION_ID_RE.fullmatch(conversation_id) is None:
            raise XaiVoiceProtocolError("conversation id has an invalid format")
        if self._config.resumption_enabled:
            self._conversation_id = conversation_id


def _remote_error(event: Mapping[str, Any]) -> XaiVoiceRemoteError:
    error = event.get("error")
    if not isinstance(error, Mapping):
        return XaiVoiceRemoteError("xAI returned an unspecified error")
    code = _safe_remote_field(error.get("code"), max_length=80)
    message = _safe_remote_field(error.get("message"), max_length=300)
    parts = ["xAI returned an error"]
    if code:
        parts.append(f"code={code}")
    if message:
        parts.append(f"message={message}")
    return XaiVoiceRemoteError("; ".join(parts))


def _safe_remote_field(value: Any, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(_safe_terminal_text(value).split())
    return cleaned[:max_length] or None


def _safe_terminal_text(value: str) -> str:
    safe_characters: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character in {"\n", "\r", "\t"}:
            safe_characters.append(character)
        elif codepoint >= 32 and not 127 <= codepoint <= 159:
            safe_characters.append(character)
    return "".join(safe_characters)


def _validate_non_empty_text(value: Any, field_name: str, *, max_length: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise XaiVoiceConfigurationError(f"{field_name} must be non-empty text")
    if len(value) > max_length:
        raise XaiVoiceConfigurationError(f"{field_name} exceeded the maximum length")
    if "\x00" in value:
        raise XaiVoiceConfigurationError(f"{field_name} must not contain NUL bytes")


def _validate_int_range(value: Any, field_name: str, minimum: int, maximum: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise XaiVoiceConfigurationError(
            f"{field_name} must be an integer from {minimum} to {maximum}"
        )


def _validate_timeout(value: Any, field_name: str, *, maximum: float) -> None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise XaiVoiceConfigurationError(f"{field_name} must be numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or not 0 < numeric <= maximum:
        raise XaiVoiceConfigurationError(
            f"{field_name} must be greater than zero and at most {maximum}"
        )


def _validate_api_key(api_key: Any) -> None:
    if not isinstance(api_key, str) or not api_key.strip():
        raise XaiVoiceConfigurationError("XAI_API_KEY is not set")
    if len(api_key) > 4096 or any(character.isspace() for character in api_key):
        raise XaiVoiceConfigurationError("XAI_API_KEY has an invalid format")


def _safe_file_component(value: str) -> str:
    cleaned = _SAFE_FILE_COMPONENT_RE.sub("_", value).strip("._-")
    if not cleaned:
        cleaned = "unknown"
    return cleaned[:120]


def _sha256_prefixed(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _atomic_write(path: Path, data: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"refusing to overwrite existing artifact: {path.name}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            raise FileExistsError(
                f"refusing to overwrite existing artifact: {path.name}"
            ) from None
        except OSError as exc:
            raise XaiVoiceConfigurationError(
                "artifact filesystem does not support secure no-clobber linking"
            ) from exc
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        temporary_path.unlink(missing_ok=True)


def _read_instructions(path_value: str | None) -> str:
    if path_value is None:
        return _DEFAULT_INSTRUCTIONS
    path = Path(path_value)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise XaiVoiceConfigurationError("instructions file could not be read") from exc
    if size > 64_000:
        raise XaiVoiceConfigurationError("instructions file exceeded the size limit")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise XaiVoiceConfigurationError("instructions file must be readable UTF-8") from exc
    _validate_non_empty_text(text, "instructions", max_length=32_000)
    return text


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-xai-voice",
        description="Fail-closed server-side xAI Voice Agent client.",
    )
    parser.add_argument("--prompt", help="Run one text turn; omit for an interactive loop.")
    parser.add_argument("--model", default=os.getenv("XAI_VOICE_MODEL", "grok-voice-latest"))
    parser.add_argument("--voice", default=os.getenv("XAI_VOICE", "ara"))
    parser.add_argument("--instructions-file")
    parser.add_argument(
        "--reasoning-effort",
        choices=sorted(_ALLOWED_REASONING_EFFORTS),
        default=os.getenv("XAI_VOICE_REASONING_EFFORT", "high"),
    )
    parser.add_argument(
        "--sample-rate",
        type=int,
        choices=sorted(_ALLOWED_SAMPLE_RATES),
        default=24000,
    )
    parser.add_argument("--resumption", action="store_true")
    parser.add_argument("--record-audio", action="store_true")
    parser.add_argument("--record-transcript", action="store_true")
    parser.add_argument("--output-dir", default="voice-output")
    parser.add_argument("--no-live-transcript", action="store_true")
    parser.add_argument(
        "--agent-id",
        default=os.getenv("XAI_AGENT_ID"),
        help="Experimental only; the public xAI Voice Agent API does not document agent_id.",
    )
    parser.add_argument(
        "--allow-undocumented-agent-id",
        action="store_true",
        help="Explicitly permit the undocumented agent_id query parameter.",
    )
    return parser


def _write_transcript_delta(delta: str) -> None:
    sys.stdout.write(_safe_terminal_text(delta))
    sys.stdout.flush()


def _print_artifacts(artifacts: PersistedVoiceArtifacts) -> None:
    if artifacts.wav_path is not None:
        print(f"\nAudio: {artifacts.wav_path}")
    if artifacts.transcript_path is not None:
        print(f"Transcript: {artifacts.transcript_path}")
    print(f"Integrity manifest: {artifacts.manifest_path}")


async def _run_cli(args: argparse.Namespace) -> int:
    api_key = os.getenv("XAI_API_KEY")
    if api_key is None:
        raise XaiVoiceConfigurationError("XAI_API_KEY is not set")
    instructions = _read_instructions(args.instructions_file)
    config = VoiceSessionConfig(
        model=args.model,
        voice=args.voice,
        instructions=instructions,
        sample_rate=args.sample_rate,
        reasoning_effort=args.reasoning_effort,
        resumption_enabled=args.resumption,
    )
    sink = None if args.no_live_transcript else _write_transcript_delta
    output_dir = Path(args.output_dir)

    if args.agent_id and args.allow_undocumented_agent_id:
        print(
            "WARNING: agent_id is not documented by the public xAI Voice Agent API; "
            "this run uses an explicit experimental opt-in.",
            file=sys.stderr,
        )

    async with XaiVoiceClient(
        api_key=api_key,
        config=config,
        agent_id=args.agent_id,
        allow_undocumented_agent_id=args.allow_undocumented_agent_id,
        transcript_sink=sink,
    ) as client:
        prompts: Iterable[str]
        if args.prompt is not None:
            prompts = (args.prompt,)
        else:
            prompts = _interactive_prompts()

        for prompt in prompts:
            response = await client.run_turn(prompt)
            if sink is not None:
                print()
            if not response.audio_done_seen and response.pcm_audio:
                print(
                    "WARNING: response.done arrived without response.output_audio.done.",
                    file=sys.stderr,
                )
            if args.record_audio or args.record_transcript:
                artifacts = persist_voice_response(
                    response,
                    output_dir=output_dir,
                    persist_audio=args.record_audio,
                    persist_transcript=args.record_transcript,
                )
                _print_artifacts(artifacts)
    return 0


def _interactive_prompts() -> Iterable[str]:
    while True:
        try:
            prompt = input("you> ")
        except EOFError:
            return
        if prompt.strip().lower() in {"/quit", "/exit"}:
            return
        if prompt.strip():
            yield prompt


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = _build_argument_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_run_cli(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except XaiVoiceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("ERROR: voice session failed closed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
