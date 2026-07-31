# SENTINEL Gemma 4 Local Gateway Security Gate

## Purpose

This change adds a local, OpenAI-style HTTP boundary for Google Gemma 4. It is designed for private text analysis, image understanding and OCR, and function-call proposal generation on operator-controlled hardware.

The model is not a trust root. Its output is always marked `authoritative: false` and cannot create a verification decision, signature, consent record, approval, execution claim, or SENTINEL receipt.

```text
Caller
  -> strict HTTP request validation
  -> fixed Gemma 4 model
  -> text / image generation or tool-call proposal
  -> external policy and human-confirmation gate
  -> separately executed tool, if approved
  -> independently verified SENTINEL evidence path
```

## Officially documented capability basis

The implementation follows Google’s Gemma 4 documentation current on 16 July 2026:

- model family: E2B, E4B, 12B, 26B A4B, and 31B instruction-tuned variants;
- text and image input for all models;
- native audio capability on E2B, E4B, and 12B, but audio is not exposed by this gateway yet;
- native system-role and function-calling support;
- 128K context on small variants and 256K on medium variants;
- variable image token budgets of 70, 140, 280, 560, or 1120;
- optional per-target MTP assistant checkpoints for speculative decoding.

Primary references:

- https://ai.google.dev/gemma/docs/core/model_card_4
- https://ai.google.dev/gemma/docs/core
- https://ai.google.dev/gemma/docs/capabilities/text/function-calling-gemma4
- https://ai.google.dev/gemma/docs/capabilities/vision/image
- https://ai.google.dev/gemma/docs/mtp/mtp
- https://ai.google.dev/gemma/apache_2

Performance percentages from third-party summaries are not encoded as acceptance criteria unless confirmed by a primary benchmark source.

## Model and memory selection

The gateway pins one model at process start. Requests cannot switch models dynamically.

Approximate model-weight memory from Google’s model overview, before KV-cache and runtime overhead:

| Model | BF16 | Q4 | Context | Native audio model capability |
|---|---:|---:|---:|---|
| E2B | 11.4 GB | 2.9 GB | 128K | yes |
| E4B | 17.9 GB | 4.5 GB | 128K | yes |
| 12B | 26.7 GB | 6.7 GB | 256K | yes |
| 26B A4B | 57.7 GB | 14.4 GB | 256K | no |
| 31B | 69.9 GB | 17.5 GB | 256K | no |

The default is `google/gemma-4-E2B-it` because it is the smallest official instruction-tuned target. The repository does not download weights in CI.

## HTTP surface

The gateway provides:

- `GET /healthz`
- `GET /v1/models`
- `POST /v1/chat/completions`

The completion request supports:

- `system`, `user`, and `assistant` message roles;
- text content;
- base64 PNG, JPEG, and WebP data URLs;
- validated JSON-schema function declarations;
- `tool_choice` values `auto` and `none`;
- deterministic generation by default (`temperature: 0`);
- visual token budgets `70`, `140`, `280`, `560`, and `1120`;
- optional MTP speculative decoding at server start.

Streaming is rejected in the first boundary. Audio and video are intentionally not exposed until separate resource, parser, privacy, and artifact gates exist.

## Network and authentication boundary

Default bind address:

```text
127.0.0.1:8765
```

A non-loopback bind is rejected unless both conditions are met:

1. `--allow-remote-bind` is present;
2. `SENTINEL_GEMMA_API_TOKEN` contains at least 24 characters.

The token is accepted only through the environment and compared using `hmac.compare_digest`. It must not be placed in Git, shell history, screenshots, test fixtures, logs, or support bundles.

This gateway does not provide TLS termination. Any approved remote deployment must place it behind a separately reviewed authenticated TLS reverse proxy and must not expose the raw Uvicorn port publicly.

## Image and SSRF boundary

Remote image URLs are rejected. The API accepts only canonical base64 data URLs for PNG, JPEG, and WebP.

This prevents the model-serving process from becoming an SSRF client or silently retrieving changing external content. Limits are enforced for:

- total request bytes;
- image bytes;
- number of images;
- text characters.

Images are verified with Pillow before inference. Image output is never treated as OCR truth without review against the source image.

## Function-calling boundary

Gemma 4 may propose a function call. The gateway:

- accepts only explicit, unique allowlisted function declarations;
- validates function names and JSON-schema shape;
- caps schema count, size, and depth;
- parses only the documented Gemma tool-call token format;
- rejects undeclared functions, duplicate arguments, malformed protocol, and unparseable residue;
- returns tool calls to the caller;
- never executes the call.

A separate executor must implement policy authorization, argument validation against the declared schema, idempotency, human confirmation, timeout, output validation, and receipt handling. Dynamic execution through `globals()`, `eval`, `exec`, shell invocation, or unrestricted imports is prohibited.

## Installation

```powershell
python -m pip install -e ".[dev,gemma4]"
```

Model access may require the operator to accept the model license on Hugging Face and authenticate through the normal Hugging Face mechanism. Credentials remain outside the repository.

## Local launch

```powershell
$env:SENTINEL_GEMMA_MODEL = "google/gemma-4-E2B-it"
sentinel-gemma4-api
```

MTP launch:

```powershell
sentinel-gemma4-api --use-mtp
```

The gateway resolves the assistant checkpoint to exactly:

```text
<target-model>-assistant
```

A caller cannot inject a different drafter model.

## Example text request

```powershell
$body = @{
  messages = @(
    @{ role = "system"; content = "Separate observation, hypothesis, and evidence." }
    @{ role = "user"; content = "Summarize this note." }
  )
  temperature = 0
} | ConvertTo-Json -Depth 10

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8765/v1/chat/completions" `
  -ContentType "application/json" `
  -Body $body
```

## Example OCR request

The image must be encoded locally. No remote URL is accepted.

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Evidence\page.png")
$dataUrl = "data:image/png;base64," + [Convert]::ToBase64String($bytes)
$body = @{
  messages = @(
    @{
      role = "user"
      content = @(
        @{ type = "image_url"; image_url = @{ url = $dataUrl } }
        @{ type = "text"; text = "Transcribe all visible text. Mark uncertain characters explicitly." }
      )
    }
  )
  visual_token_budget = 1120
  temperature = 0
} | ConvertTo-Json -Depth 12

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8765/v1/chat/completions" `
  -ContentType "application/json" `
  -Body $body
```

A token budget of 1120 can require materially more memory. Start with 280 or 560 and increase only for small text or fine detail.

## Verification

Offline checks:

```powershell
ruff check src tests
pytest -q tests/test_gemma4_gateway.py
```

CI performs no weight download, no Hugging Face authentication, no network inference, no tool execution, and no external publication.

## Activation status

**GO:** code, review, offline unit tests, dependency installation in an isolated environment, and a local non-sensitive smoke test.

**HOLD:** merge, production use, remote exposure, processing confidential archives, bulk OCR claims, tool execution, audio/video activation, fine-tuning, public benchmark claims, and any model download that creates material storage or compute cost.

Before release, capture:

1. exact target and assistant model revisions;
2. accepted license and provenance record;
3. SHA-256 or provider revision identifiers for downloaded artifacts;
4. hardware, precision, peak memory, and latency measurements;
5. one text, one OCR, and one tool-call protocol test;
6. logs reviewed for credentials and personal data;
7. independent review of the exact commit;
8. a decision receipt separate from model output.
