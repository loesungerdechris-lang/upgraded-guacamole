import base64
import json

import pytest

from sentinel_core.gemma4_gateway import (
    Gemma4GatewayConfig,
    GenerationResult,
    ModelProtocolError,
    RequestValidationError,
    create_app,
    parse_tool_calls,
    validate_messages,
    validate_tools,
)


class FakeBackend:
    def __init__(self, text="ready"):
        self.text = text
        self.calls = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        return GenerationResult(text=self.text, prompt_tokens=7, completion_tokens=3)


def png_data_url(payload=b"\x89PNG\r\n\x1a\nmock"):
    return "data:image/png;base64," + base64.b64encode(payload).decode("ascii")


def test_default_config_is_loopback_and_non_mtp():
    config = Gemma4GatewayConfig().validated()
    assert config.host == "127.0.0.1"
    assert config.resolved_assistant_model_id is None


def test_remote_bind_requires_explicit_switch_and_long_token():
    with pytest.raises(RequestValidationError, match="remote binding is disabled"):
        Gemma4GatewayConfig(host="0.0.0.0").validated()
    with pytest.raises(RequestValidationError, match="requires SENTINEL_GEMMA_API_TOKEN"):
        Gemma4GatewayConfig(host="0.0.0.0", allow_remote_bind=True).validated()
    Gemma4GatewayConfig(
        host="0.0.0.0",
        allow_remote_bind=True,
        api_token="x" * 24,
    ).validated()


def test_mtp_assistant_is_pinned_to_target_model():
    config = Gemma4GatewayConfig(use_mtp=True).validated()
    assert config.resolved_assistant_model_id == "google/gemma-4-E2B-it-assistant"
    with pytest.raises(RequestValidationError, match="must be omitted or exactly"):
        Gemma4GatewayConfig(
            use_mtp=True,
            assistant_model_id="untrusted/assistant",
        ).validated()


def test_message_validation_rejects_remote_image_url():
    with pytest.raises(RequestValidationError, match="base64 data URLs"):
        validate_messages(
            [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {"url": "https://example.com/x.png"},
                        },
                        {"type": "text", "text": "read it"},
                    ],
                }
            ],
            Gemma4GatewayConfig(),
        )


def test_message_validation_accepts_canonical_data_url():
    messages = validate_messages(
        [
            {
                "role": "user",
                "content": [
                    {"type": "image_url", "image_url": {"url": png_data_url()}},
                    {"type": "text", "text": "OCR"},
                ],
            }
        ],
        Gemma4GatewayConfig(),
    )
    assert messages[0]["content"][1]["text"] == "OCR"


def test_message_validation_rejects_noncanonical_base64():
    url = "data:image/png;base64," + base64.b64encode(b"abc").decode("ascii") + "="
    with pytest.raises(RequestValidationError, match="invalid base64|not canonical"):
        validate_messages(
            [
                {
                    "role": "user",
                    "content": [{"type": "image_url", "image_url": {"url": url}}],
                }
            ],
            Gemma4GatewayConfig(),
        )


def test_message_validation_rejects_assistant_final_turn():
    with pytest.raises(RequestValidationError, match="final message"):
        validate_messages(
            [{"role": "assistant", "content": "done"}],
            Gemma4GatewayConfig(),
        )


def test_tool_schema_is_strict_and_deduplicated():
    good = {
        "type": "function",
        "function": {
            "name": "lookup_record",
            "description": "Read one record.",
            "parameters": {
                "type": "object",
                "properties": {"record_id": {"type": "string"}},
                "required": ["record_id"],
            },
        },
    }
    assert validate_tools([good], Gemma4GatewayConfig())[0]["function"]["name"] == (
        "lookup_record"
    )
    with pytest.raises(RequestValidationError, match="duplicate tool name"):
        validate_tools([good, good], Gemma4GatewayConfig())
    bad = json.loads(json.dumps(good))
    bad["function"]["parameters"] = {"type": "string"}
    with pytest.raises(RequestValidationError, match="object schema"):
        validate_tools([bad], Gemma4GatewayConfig())


def test_parse_tool_call_returns_proposal_only():
    text = (
        '<|tool_call>call:lookup_record{record_id:<|"|>A-42<|"|>,'
        "limit:2}<tool_call|><|tool_response>"
    )
    calls = parse_tool_calls(text, {"lookup_record"})
    assert calls[0]["function"]["name"] == "lookup_record"
    assert json.loads(calls[0]["function"]["arguments"]) == {
        "record_id": "A-42",
        "limit": 2,
    }


def test_parse_tool_call_rejects_undeclared_or_malformed_calls():
    with pytest.raises(ModelProtocolError, match="undeclared"):
        parse_tool_calls(
            "<|tool_call>call:delete_all{}<tool_call|>",
            {"lookup_record"},
        )
    with pytest.raises(ModelProtocolError, match="malformed"):
        parse_tool_calls("<|tool_call>broken", {"lookup_record"})


def test_http_gateway_returns_non_authoritative_completion():
    fastapi = pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    backend = FakeBackend("local answer")
    client = TestClient(create_app(Gemma4GatewayConfig(), backend))
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["choices"][0]["message"]["content"] == "local answer"
    assert body["sentinel"] == {
        "authoritative": False,
        "tool_execution": False,
        "receipt_created": False,
    }
    assert backend.calls[0]["max_new_tokens"] == 512
    assert fastapi.__version__


def test_http_gateway_returns_tool_call_without_execution():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    backend = FakeBackend(
        '<|tool_call>call:lookup_record{record_id:<|"|>A-42<|"|>}<tool_call|>'
    )
    client = TestClient(create_app(Gemma4GatewayConfig(), backend))
    response = client.post(
        "/v1/chat/completions",
        json={
            "messages": [{"role": "user", "content": "find A-42"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup_record",
                        "description": "Read one record.",
                        "parameters": {
                            "type": "object",
                            "properties": {"record_id": {"type": "string"}},
                            "required": ["record_id"],
                        },
                    },
                }
            ],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["choices"][0]["finish_reason"] == "tool_calls"
    assert body["choices"][0]["message"]["content"] is None
    assert body["sentinel"]["tool_execution"] is False


def test_bearer_auth_is_constant_time_boundary():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient

    token = "a" * 24
    client = TestClient(create_app(Gemma4GatewayConfig(api_token=token), FakeBackend()))
    assert client.get("/healthz").status_code == 401
    assert client.get("/healthz", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert (
        client.get("/healthz", headers={"Authorization": f"Bearer {token}"}).status_code
        == 200
    )
