"""Fail-closed local HTTP gateway for Google Gemma 4 models.

The gateway exposes generation and tool-call proposals. It deliberately does not
execute model-selected tools, create SENTINEL receipts, or claim model output is
verified evidence.
"""

import argparse
import base64
import binascii
import hmac
import io
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

_ALLOWED_MODEL_CAPABILITIES: dict[str, dict[str, Any]] = {
    "google/gemma-4-E2B-it": {
        "context_tokens": 131_072,
        "audio": True,
        "approx_bf16_gb": 11.4,
        "approx_q4_gb": 2.9,
    },
    "google/gemma-4-E4B-it": {
        "context_tokens": 131_072,
        "audio": True,
        "approx_bf16_gb": 17.9,
        "approx_q4_gb": 4.5,
    },
    "google/gemma-4-12B-it": {
        "context_tokens": 262_144,
        "audio": True,
        "approx_bf16_gb": 26.7,
        "approx_q4_gb": 6.7,
    },
    "google/gemma-4-26B-A4B-it": {
        "context_tokens": 262_144,
        "audio": False,
        "approx_bf16_gb": 57.7,
        "approx_q4_gb": 14.4,
    },
    "google/gemma-4-31B-it": {
        "context_tokens": 262_144,
        "audio": False,
        "approx_bf16_gb": 69.9,
        "approx_q4_gb": 17.5,
    },
}
_ALLOWED_IMAGE_MEDIA_TYPES = {"image/png", "image/jpeg", "image/webp"}
_ALLOWED_VISUAL_TOKEN_BUDGETS = {70, 140, 280, 560, 1120}
_ALLOWED_ROLES = {"system", "user", "assistant"}
_TOOL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_DATA_URL_RE = re.compile(
    r"^data:(image/(?:png|jpeg|webp));base64,([A-Za-z0-9+/]*={0,2})$"
)
_TOOL_CALL_RE = re.compile(
    r"<\|tool_call>call:([A-Za-z_][A-Za-z0-9_]{0,63})\{(.*?)\}<tool_call\|>",
    re.DOTALL,
)
_TOOL_ARG_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]{0,63}):(?:<\|\"\|>(.*?)<\|\"\|>|([^,}]*))",
    re.DOTALL,
)


class GatewayError(ValueError):
    """Base class for safe, user-visible gateway failures."""


class RequestValidationError(GatewayError):
    """The caller supplied a request outside the gateway contract."""


class ModelProtocolError(GatewayError):
    """The model emitted malformed protocol content."""


@dataclass(frozen=True)
class Gemma4GatewayConfig:
    """Runtime configuration for one fixed Gemma 4 model."""

    model_id: str = "google/gemma-4-E2B-it"
    host: str = "127.0.0.1"
    port: int = 8765
    api_token: str | None = None
    allow_remote_bind: bool = False
    use_mtp: bool = False
    assistant_model_id: str | None = None
    max_request_bytes: int = 32 * 1024 * 1024
    max_image_bytes: int = 16 * 1024 * 1024
    max_images: int = 4
    max_text_chars: int = 1_000_000
    max_tools: int = 32
    max_tool_schema_bytes: int = 64 * 1024
    default_max_new_tokens: int = 512
    hard_max_new_tokens: int = 4096

    def validated(self) -> "Gemma4GatewayConfig":
        if self.model_id not in _ALLOWED_MODEL_CAPABILITIES:
            raise RequestValidationError(f"unsupported Gemma 4 model: {self.model_id}")
        if not (1 <= self.port <= 65535):
            raise RequestValidationError("port must be between 1 and 65535")
        if self.max_image_bytes <= 0 or self.max_request_bytes <= 0:
            raise RequestValidationError("byte limits must be positive")
        if self.max_image_bytes > self.max_request_bytes:
            raise RequestValidationError("max_image_bytes cannot exceed max_request_bytes")
        if self.max_images < 1 or self.max_images > 16:
            raise RequestValidationError("max_images must be between 1 and 16")
        if self.default_max_new_tokens < 1:
            raise RequestValidationError("default_max_new_tokens must be positive")
        if self.hard_max_new_tokens < self.default_max_new_tokens:
            raise RequestValidationError(
                "hard_max_new_tokens cannot be below default_max_new_tokens"
            )
        if not _is_loopback_host(self.host):
            if not self.allow_remote_bind:
                raise RequestValidationError(
                    "remote binding is disabled; use --allow-remote-bind explicitly"
                )
            if not self.api_token or len(self.api_token) < 24:
                raise RequestValidationError(
                    "remote binding requires SENTINEL_GEMMA_API_TOKEN with at least 24 characters"
                )
        if self.api_token is not None and len(self.api_token) < 24:
            raise RequestValidationError("API token must contain at least 24 characters")
        if self.use_mtp:
            expected = f"{self.model_id}-assistant"
            if self.assistant_model_id not in {None, expected}:
                raise RequestValidationError(
                    f"assistant_model_id must be omitted or exactly {expected}"
                )
        elif self.assistant_model_id is not None:
            raise RequestValidationError("assistant_model_id requires use_mtp=true")
        return self

    @property
    def resolved_assistant_model_id(self) -> str | None:
        if not self.use_mtp:
            return None
        return self.assistant_model_id or f"{self.model_id}-assistant"


@dataclass(frozen=True)
class GenerationResult:
    """Normalized backend result."""

    text: str
    prompt_tokens: int
    completion_tokens: int


class GenerationBackend(Protocol):
    """Minimal backend contract used by the HTTP layer and tests."""

    def generate(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        visual_token_budget: int,
    ) -> GenerationResult: ...


class TransformersGemma4Backend:
    """Lazy Hugging Face Transformers backend for Gemma 4."""

    def __init__(self, config: Gemma4GatewayConfig):
        self.config = config.validated()
        self._processor: Any = None
        self._model: Any = None
        self._assistant_model: Any = None

    def _load(self) -> None:
        if self._model is not None:
            return
        try:
            from transformers import AutoModelForCausalLM, AutoModelForMultimodalLM, AutoProcessor
        except ImportError as exc:
            raise RuntimeError(
                "Gemma 4 runtime dependencies are missing; install .[gemma4]"
            ) from exc

        self._processor = AutoProcessor.from_pretrained(self.config.model_id)
        self._model = AutoModelForMultimodalLM.from_pretrained(
            self.config.model_id,
            dtype="auto",
            device_map="auto",
        )
        assistant_model_id = self.config.resolved_assistant_model_id
        if assistant_model_id:
            self._assistant_model = AutoModelForCausalLM.from_pretrained(
                assistant_model_id,
                dtype="auto",
                device_map="auto",
            )

    def generate(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_new_tokens: int,
        temperature: float,
        top_p: float,
        visual_token_budget: int,
    ) -> GenerationResult:
        self._load()
        prepared_messages = _materialize_images(messages)
        if hasattr(self._processor, "image_processor"):
            self._processor.image_processor.max_soft_tokens = visual_token_budget

        template_kwargs: dict[str, Any] = {
            "tokenize": True,
            "add_generation_prompt": True,
            "return_dict": True,
            "return_tensors": "pt",
        }
        if tools:
            template_kwargs["tools"] = tools

        try:
            inputs = self._processor.apply_chat_template(prepared_messages, **template_kwargs)
        except TypeError:
            if _count_images(messages):
                raise RuntimeError(
                    "installed Transformers build cannot materialize Gemma 4 images"
                )
            template_kwargs["tokenize"] = False
            template_kwargs.pop("return_dict", None)
            template_kwargs.pop("return_tensors", None)
            prompt = self._processor.apply_chat_template(prepared_messages, **template_kwargs)
            inputs = self._processor(text=prompt, return_tensors="pt")

        inputs = inputs.to(self._model.device)
        input_ids = inputs.get("input_ids")
        prompt_tokens = int(input_ids.shape[-1]) if input_ids is not None else 0
        do_sample = temperature > 0.0
        generation_kwargs: dict[str, Any] = {
            "max_new_tokens": max_new_tokens,
            "do_sample": do_sample,
        }
        if do_sample:
            generation_kwargs.update(temperature=temperature, top_p=top_p)
        if self._assistant_model is not None:
            generation_kwargs["assistant_model"] = self._assistant_model

        output = self._model.generate(**inputs, **generation_kwargs)
        if input_ids is not None:
            generated_tokens = output[0][prompt_tokens:]
        else:
            generated_tokens = output[0]
        text = self._processor.decode(generated_tokens, skip_special_tokens=not bool(tools))
        return GenerationResult(
            text=text,
            prompt_tokens=prompt_tokens,
            completion_tokens=int(len(generated_tokens)),
        )


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    return normalized in {"127.0.0.1", "::1", "localhost"}


def _json_size(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _ensure_json_depth(value: Any, *, max_depth: int = 16, depth: int = 0) -> None:
    if depth > max_depth:
        raise RequestValidationError("tool schema exceeds maximum nesting depth")
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise RequestValidationError("tool schema keys must be strings")
            _ensure_json_depth(nested, max_depth=max_depth, depth=depth + 1)
    elif isinstance(value, list):
        for nested in value:
            _ensure_json_depth(nested, max_depth=max_depth, depth=depth + 1)
    elif value is not None and not isinstance(value, (str, int, float, bool)):
        raise RequestValidationError("tool schema contains a non-JSON value")


def validate_tools(raw_tools: Any, config: Gemma4GatewayConfig) -> list[dict[str, Any]]:
    if raw_tools in (None, []):
        return []
    if not isinstance(raw_tools, list):
        raise RequestValidationError("tools must be a list")
    if len(raw_tools) > config.max_tools:
        raise RequestValidationError(f"at most {config.max_tools} tools are allowed")

    validated: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, tool in enumerate(raw_tools):
        if not isinstance(tool, dict) or set(tool) != {"type", "function"}:
            raise RequestValidationError(f"tool {index} must contain only type and function")
        if tool["type"] != "function" or not isinstance(tool["function"], dict):
            raise RequestValidationError(f"tool {index} must be a function declaration")
        function = tool["function"]
        allowed_keys = {"name", "description", "parameters"}
        if set(function) - allowed_keys:
            raise RequestValidationError(f"tool {index} contains unsupported fields")
        name = function.get("name")
        description = function.get("description", "")
        parameters = function.get("parameters")
        if not isinstance(name, str) or not _TOOL_NAME_RE.fullmatch(name):
            raise RequestValidationError(f"tool {index} has an invalid function name")
        if name in names:
            raise RequestValidationError(f"duplicate tool name: {name}")
        names.add(name)
        if not isinstance(description, str) or len(description) > 2_000:
            raise RequestValidationError(f"tool {name} has an invalid description")
        if not isinstance(parameters, dict) or parameters.get("type") != "object":
            raise RequestValidationError(f"tool {name} parameters must be an object schema")
        _ensure_json_depth(parameters)
        if _json_size(tool) > config.max_tool_schema_bytes:
            raise RequestValidationError(f"tool {name} schema is too large")
        validated.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": description,
                    "parameters": parameters,
                },
            }
        )
    return validated


def _decode_image_data_url(data_url: str, config: Gemma4GatewayConfig) -> tuple[str, bytes]:
    match = _DATA_URL_RE.fullmatch(data_url)
    if not match:
        raise RequestValidationError(
            "images must be base64 data URLs using PNG, JPEG, or WebP"
        )
    media_type, payload = match.groups()
    if media_type not in _ALLOWED_IMAGE_MEDIA_TYPES:
        raise RequestValidationError("unsupported image media type")
    if len(payload) > ((config.max_image_bytes + 2) // 3) * 4 + 4:
        raise RequestValidationError("encoded image exceeds the configured size limit")
    try:
        decoded = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RequestValidationError("image contains invalid base64") from exc
    canonical = base64.b64encode(decoded).decode("ascii")
    if canonical != payload:
        raise RequestValidationError("image base64 is not canonical")
    if not decoded or len(decoded) > config.max_image_bytes:
        raise RequestValidationError("image exceeds the configured size limit")
    return media_type, decoded


def validate_messages(raw_messages: Any, config: Gemma4GatewayConfig) -> list[dict[str, Any]]:
    if not isinstance(raw_messages, list) or not raw_messages:
        raise RequestValidationError("messages must be a non-empty list")
    if len(raw_messages) > 256:
        raise RequestValidationError("too many messages")

    total_text_chars = 0
    total_bytes = 0
    image_count = 0
    validated: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_messages):
        if not isinstance(raw, dict) or set(raw) != {"role", "content"}:
            raise RequestValidationError(
                f"message {index} must contain only role and content"
            )
        role = raw.get("role")
        content = raw.get("content")
        if role not in _ALLOWED_ROLES:
            raise RequestValidationError(f"message {index} has an unsupported role")
        if isinstance(content, str):
            total_text_chars += len(content)
            total_bytes += len(content.encode("utf-8"))
            normalized_content: str | list[dict[str, Any]] = content
        elif isinstance(content, list):
            if role != "user":
                raise RequestValidationError("multipart content is allowed only for user messages")
            normalized_parts: list[dict[str, Any]] = []
            for part_index, part in enumerate(content):
                if not isinstance(part, dict) or "type" not in part:
                    raise RequestValidationError(
                        f"message {index} part {part_index} is malformed"
                    )
                if part["type"] == "text":
                    if set(part) != {"type", "text"} or not isinstance(part.get("text"), str):
                        raise RequestValidationError("text parts require exactly type and text")
                    text = part["text"]
                    total_text_chars += len(text)
                    total_bytes += len(text.encode("utf-8"))
                    normalized_parts.append({"type": "text", "text": text})
                elif part["type"] == "image_url":
                    if set(part) != {"type", "image_url"}:
                        raise RequestValidationError(
                            "image parts require exactly type and image_url"
                        )
                    image_url = part.get("image_url")
                    if not isinstance(image_url, dict) or set(image_url) != {"url"}:
                        raise RequestValidationError("image_url must contain only url")
                    url = image_url.get("url")
                    if not isinstance(url, str):
                        raise RequestValidationError("image_url.url must be a string")
                    media_type, decoded = _decode_image_data_url(url, config)
                    image_count += 1
                    total_bytes += len(decoded)
                    normalized_parts.append(
                        {
                            "type": "image_url",
                            "image_url": {"url": url},
                            "_media_type": media_type,
                        }
                    )
                else:
                    raise RequestValidationError(
                        f"message {index} part {part_index} has unsupported type"
                    )
            if not normalized_parts:
                raise RequestValidationError("multipart message cannot be empty")
            normalized_content = normalized_parts
        else:
            raise RequestValidationError(f"message {index} content must be text or parts")
        validated.append({"role": role, "content": normalized_content})

    if total_text_chars > config.max_text_chars:
        raise RequestValidationError("request text exceeds the configured limit")
    if image_count > config.max_images:
        raise RequestValidationError(f"at most {config.max_images} images are allowed")
    if total_bytes > config.max_request_bytes:
        raise RequestValidationError("request exceeds the configured byte limit")
    if raw_messages[-1].get("role") == "assistant":
        raise RequestValidationError("the final message must not have assistant role")
    return validated


def _count_images(messages: list[dict[str, Any]]) -> int:
    count = 0
    for message in messages:
        if isinstance(message["content"], list):
            count += sum(1 for part in message["content"] if part["type"] == "image_url")
    return count


def _materialize_images(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not _count_images(messages):
        return messages
    try:
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError("Pillow is required for Gemma 4 image input") from exc

    materialized: list[dict[str, Any]] = []
    for message in messages:
        content = message["content"]
        if not isinstance(content, list):
            materialized.append(message)
            continue
        parts: list[dict[str, Any]] = []
        for part in content:
            if part["type"] == "text":
                parts.append(part)
                continue
            payload = part["image_url"]["url"].split(",", 1)[1]
            decoded = base64.b64decode(payload, validate=True)
            with Image.open(io.BytesIO(decoded)) as image:
                image.verify()
            image = Image.open(io.BytesIO(decoded)).convert("RGB")
            parts.append({"type": "image", "image": image})
        materialized.append({"role": message["role"], "content": parts})
    return materialized


def _cast_tool_value(value: str) -> Any:
    stripped = value.strip()
    lowered = stripped.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    if re.fullmatch(r"-?(?:0|[1-9]\d*)", stripped):
        try:
            return int(stripped)
        except ValueError:
            pass
    if re.fullmatch(r"-?(?:0|[1-9]\d*)\.\d+(?:[eE][+-]?\d+)?", stripped):
        try:
            return float(stripped)
        except ValueError:
            pass
    return stripped.strip("'\"")


def parse_tool_calls(text: str, allowed_tool_names: set[str]) -> list[dict[str, Any]]:
    has_marker = "<|tool_call>" in text or "<tool_call|>" in text
    calls: list[dict[str, Any]] = []
    for match in _TOOL_CALL_RE.finditer(text):
        name, args_text = match.groups()
        if name not in allowed_tool_names:
            raise ModelProtocolError(f"model requested undeclared tool: {name}")
        arguments: dict[str, Any] = {}
        for key, quoted, plain in _TOOL_ARG_RE.findall(args_text):
            if key in arguments:
                raise ModelProtocolError(f"model emitted duplicate argument: {key}")
            value = quoted if quoted != "" else plain
            arguments[key] = _cast_tool_value(value)
        residue = _TOOL_ARG_RE.sub("", args_text).strip(" ,\n\r\t")
        if residue:
            raise ModelProtocolError("model emitted an unparseable tool argument")
        calls.append(
            {
                "id": f"call_{uuid.uuid4().hex[:24]}",
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps(arguments, ensure_ascii=False, separators=(",", ":")),
                },
            }
        )
    if has_marker and not calls:
        raise ModelProtocolError("model emitted malformed tool-call protocol")
    return calls


def create_app(
    config: Gemma4GatewayConfig | None = None,
    backend: GenerationBackend | None = None,
) -> Any:
    """Build the FastAPI application without loading model weights."""

    resolved = (config or Gemma4GatewayConfig()).validated()
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
        from pydantic import BaseModel, ConfigDict, Field
    except ImportError as exc:
        raise RuntimeError("FastAPI runtime dependencies are missing; install .[gemma4]") from exc

    generation_backend = backend or TransformersGemma4Backend(resolved)

    class ChatRequest(BaseModel):
        model_config = ConfigDict(extra="forbid")

        model: str | None = None
        messages: list[dict[str, Any]]
        tools: list[dict[str, Any]] | None = None
        tool_choice: str = "auto"
        max_tokens: int | None = Field(default=None, ge=1)
        temperature: float = Field(default=0.0, ge=0.0, le=2.0)
        top_p: float = Field(default=1.0, gt=0.0, le=1.0)
        visual_token_budget: int = 280
        stream: bool = False

    app = FastAPI(
        title="SENTINEL Gemma 4 Gateway",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    def authorize(authorization: str | None = Header(default=None)) -> None:
        if resolved.api_token is None:
            return
        prefix = "Bearer "
        if not authorization or not authorization.startswith(prefix):
            raise HTTPException(status_code=401, detail="missing bearer token")
        supplied = authorization[len(prefix) :]
        if not hmac.compare_digest(supplied, resolved.api_token):
            raise HTTPException(status_code=401, detail="invalid bearer token")

    @app.get("/healthz")
    def healthz(_: None = Depends(authorize)) -> dict[str, Any]:
        return {
            "status": "ok",
            "model": resolved.model_id,
            "weights_loaded": getattr(generation_backend, "_model", None) is not None,
            "authoritative": False,
            "tool_execution": False,
        }

    @app.get("/v1/models")
    def models(_: None = Depends(authorize)) -> dict[str, Any]:
        capabilities = _ALLOWED_MODEL_CAPABILITIES[resolved.model_id]
        return {
            "object": "list",
            "data": [
                {
                    "id": resolved.model_id,
                    "object": "model",
                    "owned_by": "google",
                    "context_tokens": capabilities["context_tokens"],
                    "modalities": ["text", "image"],
                    "native_audio_available": capabilities["audio"],
                    "audio_gateway_enabled": False,
                    "function_calling": True,
                    "mtp_enabled": resolved.use_mtp,
                    "authoritative": False,
                }
            ],
        }

    @app.post("/v1/chat/completions")
    def chat_completions(
        request: ChatRequest,
        _: None = Depends(authorize),
    ) -> dict[str, Any]:
        if request.stream:
            raise HTTPException(status_code=400, detail="streaming is not enabled")
        if request.model is not None and request.model != resolved.model_id:
            raise HTTPException(status_code=400, detail="request model does not match gateway model")
        if request.tool_choice not in {"auto", "none"}:
            raise HTTPException(status_code=400, detail="tool_choice must be auto or none")
        if request.visual_token_budget not in _ALLOWED_VISUAL_TOKEN_BUDGETS:
            raise HTTPException(
                status_code=400,
                detail="visual_token_budget must be one of 70, 140, 280, 560, 1120",
            )
        max_new_tokens = request.max_tokens or resolved.default_max_new_tokens
        if max_new_tokens > resolved.hard_max_new_tokens:
            raise HTTPException(status_code=400, detail="max_tokens exceeds the gateway limit")
        try:
            messages = validate_messages(request.messages, resolved)
            tools = validate_tools(request.tools, resolved)
            if request.tool_choice == "none":
                tools = []
            result = generation_backend.generate(
                messages=messages,
                tools=tools,
                max_new_tokens=max_new_tokens,
                temperature=request.temperature,
                top_p=request.top_p,
                visual_token_budget=request.visual_token_budget,
            )
            tool_calls = parse_tool_calls(
                result.text,
                {tool["function"]["name"] for tool in tools},
            )
        except RequestValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ModelProtocolError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        content = None if tool_calls else result.text
        finish_reason = "tool_calls" if tool_calls else "stop"
        message: dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls:
            message["tool_calls"] = tool_calls
        return {
            "id": f"chatcmpl_{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": resolved.model_id,
            "choices": [
                {
                    "index": 0,
                    "message": message,
                    "finish_reason": finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": result.prompt_tokens,
                "completion_tokens": result.completion_tokens,
                "total_tokens": result.prompt_tokens + result.completion_tokens,
            },
            "sentinel": {
                "authoritative": False,
                "tool_execution": False,
                "receipt_created": False,
            },
        }

    return app


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SENTINEL Gemma 4 local gateway")
    parser.add_argument(
        "--model",
        default=os.getenv("SENTINEL_GEMMA_MODEL", "google/gemma-4-E2B-it"),
        choices=sorted(_ALLOWED_MODEL_CAPABILITIES),
    )
    parser.add_argument("--host", default=os.getenv("SENTINEL_GEMMA_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("SENTINEL_GEMMA_PORT", "8765")),
    )
    parser.add_argument("--allow-remote-bind", action="store_true")
    parser.add_argument("--use-mtp", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    config = Gemma4GatewayConfig(
        model_id=args.model,
        host=args.host,
        port=args.port,
        api_token=os.getenv("SENTINEL_GEMMA_API_TOKEN"),
        allow_remote_bind=args.allow_remote_bind,
        use_mtp=args.use_mtp,
    ).validated()
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Uvicorn is missing; install .[gemma4]") from exc
    uvicorn.run(create_app(config), host=config.host, port=config.port, log_level="info")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
