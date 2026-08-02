# SENTINEL xAI Voice Agent Security Gate

## Purpose

The xAI Voice Agent client is a server-side interaction adapter. It can stream a user text turn to the xAI Realtime WebSocket API, receive transcript and PCM16 audio deltas, and optionally persist local review artifacts.

It is not a trust root and cannot issue SENTINEL verification decisions.

```text
User text or microphone layer
  -> xAI Voice Agent session
  -> transcript and audio response
  -> optional policy-gated tool request
  -> independently verified SENTINEL result
  -> voice presentation of that result
```

The voice model must never create or imply a receipt, signature, consent record, approval, execution result, or `RC_VERIFIED` state without a trusted tool result that proves the claim.

## Documented API path

The default connection uses only the public xAI Voice Agent API model parameter:

```text
wss://api.x.ai/v1/realtime?model=grok-voice-think-fast-1.0
```

The client sends `session.update`, waits for `session.updated`, then sends `conversation.item.create` followed by `response.create`. It consumes the documented response lifecycle and finalizes a response only at `response.done`. The default model is version-pinned because the official `grok-voice-latest` alias is scheduled to change; an alias or newer model requires a separate controlled compatibility test.

The public xAI Voice Agent API documentation did not document an `agent_id` query parameter when this boundary was implemented on 2026-07-11. The client therefore rejects `agent_id` by default. An operator may enable the parameter only through the explicit `--allow-undocumented-agent-id` switch for a controlled compatibility test. That switch is not a production approval.

## Invariant instruction boundary

`VoiceSessionConfig.instructions` is application context, not a caller-replaceable system prompt. Every construction path — CLI file input, direct library use, reconnect, and `session.update` — calls the same client-side composition function.

The final prompt always contains the immutable SENTINEL non-authoritative boundary before and after subordinate application text. Application text is Unicode-normalized and case-folded for conservative override detection. Suspected attempts to ignore, bypass, weaken, or contradict the boundary fail during configuration before any network request is made.

The pattern check is only defense in depth. The primary security property is structural: the caller cannot supply the final WebSocket instruction value directly, and `session.update` accepts only the client-composed effective instructions.

## Authentication boundary

- `XAI_API_KEY` is read only from the process environment.
- The API key is not accepted as a command-line argument.
- The key is never written to artifacts or included in error messages.
- Browser and mobile clients must use short-lived xAI ephemeral tokens rather than embedding the server API key.
- No credential value belongs in Git, `.env` files, CI logs, screenshots, transcripts, or support bundles.

## Privacy defaults

Recording is disabled by default.

The client writes no audio or transcript unless the operator explicitly adds:

```text
--record-audio
--record-transcript
```

Recording voice may process personal data and biometric-adjacent characteristics. Before enabling recording in a pilot, define the lawful purpose, disclosure, retention period, access controls, deletion process, and whether explicit consent is required. Tone or emotion must not be treated as consent or authorization.

## Protocol and resource controls

The client:

- fixes the WebSocket origin to `wss://api.x.ai`;
- validates model, voice, sample rate, reasoning mode, conversation ID, and experimental agent ID values;
- limits individual JSON events to 2 MiB by default;
- limits one response to 64 MiB of decoded audio by default;
- rejects malformed UTF-8, JSON, base64, PCM16, and response lifecycle events;
- accepts both the canonical `response.output_audio.delta` event and the documented `response.audio.delta` compatibility alias through the same bounded audio path;
- waits for `session.updated` before sending a user turn;
- uses explicit receive and connection timeouts;
- disables WebSocket compression;
- does not automatically replay a turn after an ambiguous send failure;
- stores only mono PCM16 little-endian WAV data at the configured sample rate.

Transcript accumulation accepts the xAI-native and compatibility event names `response.text.delta`, `response.output_text.delta`, and `response.output_audio_transcript.delta`. A text event may use the documented `delta` field or a compatible `text` field, but conflicting values fail closed. Every accepted text fragment passes active-response lifecycle validation and the configured UTF-8 byte limit before it is emitted live, returned in `VoiceResponse.transcript`, or persisted.

No operating-system media player is spawned. This avoids command injection, unexpected child processes, and platform-specific playback behavior inside the trusted client.

## Artifact handling

When recording is explicitly enabled, files are created atomically and existing files are never overwritten. The client attempts to apply:

- output directory mode `0700`;
- artifact mode `0600`;
- sanitized response IDs for filenames;
- SHA-256 digests for PCM audio, WAV bytes, and transcript bytes.

Each recording includes a JSON integrity manifest. The manifest is deliberately marked:

```json
"authoritative": false
```

It is local integrity metadata only. It is not signed, not a SENTINEL receipt, and not evidence that the model output is true.

## Session resumption and reconnect behavior

Session resumption is opt-in. When enabled, the client captures the server-provided conversation ID and may use it for a later connection. The ID is held only in process memory by this implementation.

The client does not automatically retry a user turn when delivery is ambiguous. This prevents duplicate model responses, duplicate tool calls, duplicate costs, and duplicate external actions. Any connection, send, parsing, protocol, or response-lifecycle failure also clears the in-memory resumption identifier before reconnect, so cached ambiguous state cannot be resumed automatically. A new turn may be sent only after the previous `response.done` was received or an operator deliberately starts a fresh interaction.

## Tool-use boundary

No SENTINEL, Azure, email, payment, publication, or customer action may be exposed as a direct unrestricted voice tool.

A future tool integration must enforce all of the following:

1. strict JSON schema validation;
2. explicit allowlisted tool names;
3. policy authorization outside the model;
4. idempotency keys for side-effecting requests;
5. human confirmation for binding, costly, legal, privacy-sensitive, or public actions;
6. independently verified tool outputs;
7. receipt generation only by the existing trusted evidence path;
8. no secrets or personal data returned in spoken error messages.

## Installation and use

Install the isolated optional dependency:

```bash
python -m pip install -e .[dev,voice]
```

The development extra pins Ruff to the exact version proven by the reviewed CI baseline. Tool upgrades require an explicit, separately reviewed change rather than floating into an unrelated security PR.

Run a non-recording text smoke test after `XAI_API_KEY` has been injected through the local secret-management process:

```bash
sentinel-xai-voice --prompt "Describe your capabilities and limitations in two sentences."
```

Explicitly record a test response only in an approved local directory:

```bash
sentinel-xai-voice \
  --prompt "State the non-authoritative voice boundary." \
  --record-audio \
  --record-transcript \
  --output-dir voice-output
```

An undocumented hosted-agent compatibility test requires both an environment-provided `XAI_AGENT_ID` and the explicit command switch:

```bash
sentinel-xai-voice \
  --allow-undocumented-agent-id \
  --prompt "State your configured identity and limitations."
```

Do not place the concrete hosted agent ID in source control.

## Verification commands

```bash
ruff check src tests
pytest -q \
  tests/test_xai_voice.py \
  tests/test_xai_voice_review_regressions.py
```

The dedicated GitHub Actions workflow installs the voice extra, applies static boundary checks, imports the runtime dependency, and executes the offline tests. It performs no live xAI request and requires no API secret.

Regression coverage proves that programmatic application instructions cannot replace the invariant boundary; Unicode and whitespace override variants are rejected; documented text-delta aliases are accumulated and emitted; and pre-response, oversized, malformed, or conflicting text events close and clear the authenticated WebSocket without emitting unaccepted text.

## Live activation gate

The implementation may be reviewed and merged without activating a live agent. A pilot or public claim remains **HOLD** until:

1. the standard documented `model=grok-voice-latest` handshake succeeds;
2. `session.updated`, `response.created`, transcript/audio deltas, and `response.done` are observed on one controlled prompt;
3. the returned audio format matches the configured PCM16 sample rate;
4. logs and artifacts are inspected for credentials and unintended personal data;
5. recording disclosure, retention, access, and deletion rules are approved;
6. the custom hosted agent path is confirmed by xAI or proven by a controlled current-head handshake;
7. all side-effecting tools remain disabled or pass a separate policy and receipt gate;
8. an independent review confirms the current commit.

Until those conditions are met, the correct external status is: **implementation ready for controlled smoke testing; production and custom-agent activation HOLD**.
