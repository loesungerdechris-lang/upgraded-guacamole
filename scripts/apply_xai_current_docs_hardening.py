from __future__ import annotations

import subprocess
from pathlib import Path

SOURCE = Path("src/sentinel_core/xai_voice.py")
MAIN_TESTS = Path("tests/test_xai_voice.py")
REGRESSION_TESTS = Path("tests/test_xai_voice_review_regressions.py")
WORKFLOW = Path(".github/workflows/sentinel-xai-voice.yml")
DOCS = Path("docs/xai-voice-agent-security-gate.md")

EXPECTED_BLOBS = {
    SOURCE: "f2104c547e1bb43c3c0de1d195390d60e82e3fcf",
    MAIN_TESTS: "f0fd629ac8fd6635fd2a77bae1d5c5a1ed136af8",
    REGRESSION_TESTS: "b91877445f13739c4abc7cc27b9ed134c366ecf9",
    WORKFLOW: "303708c4ab25dc9751916d8979682041dee178e3",
    DOCS: "9829e272494364fcd046ca64ef977365bf9761e1",
}


def git_blob(path: Path) -> str:
    return subprocess.check_output(
        ["git", "hash-object", str(path)],
        text=True,
    ).strip()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    for path, expected in EXPECTED_BLOBS.items():
        actual = git_blob(path)
        if actual != expected:
            raise RuntimeError(
                f"blob guard failed for {path}: expected {expected}, got {actual}"
            )

    source = SOURCE.read_text(encoding="utf-8")
    source = replace_once(
        source,
        '_XAI_REALTIME_ENDPOINT = "wss://api.x.ai/v1/realtime"\n',
        '_XAI_REALTIME_ENDPOINT = "wss://api.x.ai/v1/realtime"\n'
        '_DEFAULT_MODEL: Final[str] = "grok-voice-think-fast-1.0"\n',
        "default model constant",
    )
    source = replace_once(
        source,
        '    model: str = "grok-voice-latest"\n',
        '    model: str = _DEFAULT_MODEL\n',
        "config default model",
    )
    source = replace_once(
        source,
        '_TRANSCRIPT_DELTA_EVENT_TYPES: Final[frozenset[str]] = frozenset(\n'
        '    {\n'
        '        "response.output_audio_transcript.delta",\n'
        '        "response.text.delta",\n'
        '        "response.output_text.delta",\n'
        '    }\n'
        ')\n',
        '_TRANSCRIPT_DELTA_EVENT_TYPES: Final[frozenset[str]] = frozenset(\n'
        '    {\n'
        '        "response.output_audio_transcript.delta",\n'
        '        "response.text.delta",\n'
        '        "response.output_text.delta",\n'
        '    }\n'
        ')\n'
        '_AUDIO_DELTA_EVENT_TYPES: Final[frozenset[str]] = frozenset(\n'
        '    {\n'
        '        "response.output_audio.delta",\n'
        '        "response.audio.delta",\n'
        '    }\n'
        ')\n',
        "audio event aliases",
    )
    source = replace_once(
        source,
        '        if event_type == "response.output_audio.delta":\n',
        '        if event_type in _AUDIO_DELTA_EVENT_TYPES:\n',
        "audio delta dispatch",
    )
    source = replace_once(
        source,
        '        except Exception:\n'
        '            await self.close()\n'
        '            raise\n\n'
        '    async def close(self) -> None:\n',
        '        except Exception:\n'
        '            self._conversation_id = None\n'
        '            await self.close()\n'
        '            raise\n\n'
        '    async def close(self) -> None:\n',
        "connect failure resumption invalidation",
    )
    source = replace_once(
        source,
        '        except Exception as exc:\n'
        '            await self.close()\n'
        '            raise XaiVoiceProtocolError(\n',
        '        except Exception as exc:\n'
        '            self._conversation_id = None\n'
        '            await self.close()\n'
        '            raise XaiVoiceProtocolError(\n',
        "send failure resumption invalidation",
    )
    source = replace_once(
        source,
        '        except BaseException:\n'
        '            await asyncio.shield(self.close())\n'
        '            raise\n',
        '        except BaseException:\n'
        '            self._conversation_id = None\n'
        '            await asyncio.shield(self.close())\n'
        '            raise\n',
        "receive failure resumption invalidation",
    )
    source = replace_once(
        source,
        '    parser.add_argument("--model", default=os.getenv("XAI_VOICE_MODEL", "grok-voice-latest"))\n',
        '    parser.add_argument("--model", default=os.getenv("XAI_VOICE_MODEL", _DEFAULT_MODEL))\n',
        "CLI model default",
    )
    SOURCE.write_text(source, encoding="utf-8")

    workflow = WORKFLOW.read_text(encoding="utf-8")
    workflow = replace_once(
        workflow,
        "              'wss://api.x.ai/v1/realtime?model=grok-voice-latest'\n",
        "              'wss://api.x.ai/v1/realtime?model=grok-voice-think-fast-1.0'\n",
        "workflow default model assertion",
    )
    WORKFLOW.write_text(workflow, encoding="utf-8")

    main_tests = MAIN_TESTS.read_text(encoding="utf-8")
    anchor = 'def test_agent_id_fails_closed_without_explicit_opt_in() -> None:\n'
    insertion = (
        'def test_default_model_is_version_pinned_for_stability() -> None:\n'
        '    assert VoiceSessionConfig().websocket_url() == (\n'
        '        "wss://api.x.ai/v1/realtime?model=grok-voice-think-fast-1.0"\n'
        '    )\n\n\n'
    )
    main_tests = replace_once(
        main_tests,
        anchor,
        insertion + anchor,
        "default model regression test",
    )
    main_tests = replace_once(
        main_tests,
        '    ).endswith("model=grok-voice-latest&agent_id=agent_TestAgent123456")\n',
        '    ).endswith(\n'
        '        "model=grok-voice-think-fast-1.0&agent_id=agent_TestAgent123456"\n'
        '    )\n',
        "agent id pinned model expectation",
    )
    MAIN_TESTS.write_text(main_tests, encoding="utf-8")

    regressions = REGRESSION_TESTS.read_text(encoding="utf-8")
    regressions = replace_once(
        regressions,
        'import asyncio\n',
        'import asyncio\nimport base64\n',
        "base64 test import",
    )
    audio_anchor = 'def test_text_delta_before_response_is_not_emitted_and_closes_socket() -> None:\n'
    audio_test = (
        'def test_response_audio_delta_alias_is_collected() -> None:\n'
        '    pcm = b"\\x00\\x00\\x01\\x00"\n'
        '    websocket = _FakeWebSocket(\n'
        '        [\n'
        '            {"type": "response.created", "response": {"id": "resp_audio_alias"}},\n'
        '            {\n'
        '                "type": "response.audio.delta",\n'
        '                "delta": base64.b64encode(pcm).decode("ascii"),\n'
        '            },\n'
        '            {"type": "response.done", "response": {"status": "completed"}},\n'
        '        ]\n'
        '    )\n'
        '    client = _ready_client(websocket)\n\n'
        '    response = asyncio.run(client.run_turn("hello"))\n\n'
        '    assert response.pcm_audio == pcm\n'
        '    assert "response.audio.delta" in response.event_types\n\n\n'
    )
    regressions = replace_once(
        regressions,
        audio_anchor,
        audio_test + audio_anchor,
        "audio alias regression test",
    )
    resumption_anchor = 'def test_non_completed_response_closes_and_clears_socket() -> None:\n'
    resumption_test = (
        'def test_protocol_failure_clears_resumption_state() -> None:\n'
        '    websocket = _FakeWebSocket(["{"])\n'
        '    client = _ready_client(\n'
        '        websocket,\n'
        '        config=VoiceSessionConfig(resumption_enabled=True),\n'
        '    )\n'
        '    client._conversation_id = "conversation-1"\n\n'
        '    with pytest.raises(XaiVoiceProtocolError, match="valid JSON"):\n'
        '        asyncio.run(client.run_turn("hello"))\n\n'
        '    assert client._conversation_id is None\n'
        '    assert websocket.closed is True\n'
        '    assert client._websocket is None\n\n\n'
    )
    regressions = replace_once(
        regressions,
        resumption_anchor,
        resumption_test + resumption_anchor,
        "resumption invalidation regression test",
    )
    REGRESSION_TESTS.write_text(regressions, encoding="utf-8")

    docs = DOCS.read_text(encoding="utf-8")
    docs = replace_once(
        docs,
        'wss://api.x.ai/v1/realtime?model=grok-voice-latest',
        'wss://api.x.ai/v1/realtime?model=grok-voice-think-fast-1.0',
        "documented pinned path",
    )
    docs = replace_once(
        docs,
        'The client sends `session.update`, waits for `session.updated`, then sends `conversation.item.create` followed by `response.create`. It consumes the documented response lifecycle and finalizes a response only at `response.done`.\n',
        'The client sends `session.update`, waits for `session.updated`, then sends `conversation.item.create` followed by `response.create`. It consumes the documented response lifecycle and finalizes a response only at `response.done`. The default model is version-pinned because the official `grok-voice-latest` alias is scheduled to change; an alias or newer model requires a separate controlled compatibility test.\n',
        "model pin rationale",
    )
    docs = replace_once(
        docs,
        '- rejects malformed UTF-8, JSON, base64, PCM16, and response lifecycle events;\n',
        '- rejects malformed UTF-8, JSON, base64, PCM16, and response lifecycle events;\n'
        '- accepts both the canonical `response.output_audio.delta` event and the documented `response.audio.delta` compatibility alias through the same bounded audio path;\n',
        "audio alias documentation",
    )
    docs = replace_once(
        docs,
        'The client does not automatically retry a user turn when delivery is ambiguous. This prevents duplicate model responses, duplicate tool calls, duplicate costs, and duplicate external actions. A new turn may be sent only after the previous `response.done` was received or an operator deliberately restarts the interaction.\n',
        'The client does not automatically retry a user turn when delivery is ambiguous. This prevents duplicate model responses, duplicate tool calls, duplicate costs, and duplicate external actions. Any connection, send, parsing, protocol, or response-lifecycle failure also clears the in-memory resumption identifier before reconnect, so cached ambiguous state cannot be resumed automatically. A new turn may be sent only after the previous `response.done` was received or an operator deliberately starts a fresh interaction.\n',
        "resumption fail-closed documentation",
    )
    DOCS.write_text(docs, encoding="utf-8")


if __name__ == "__main__":
    main()
