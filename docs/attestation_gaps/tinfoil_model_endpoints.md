# Tinfoil Model Endpoints: Verify Probe Covers Chat Only

`teep verify` tests end-to-end encryption with one chat completion, the
probe. Ten Tinfoil models serve no chat completions endpoint, so teep's
verifier does not test their encryption today. Their other factors give the
same results as Tinfoil's chat models. Tinfoil's model list states the
endpoint of each model, so the gap is in teep, not in Tinfoil's
documentation.

## The Problem

Anyone who checks a Tinfoil model before use, such as a user's client or an
auditor, needs to send it a real request to see that encryption works. The
request must go to an endpoint that the model serves. A model without chat
completions answers a chat request with HTTP 404, so a check that sends only
chat cannot test it. Each request body stays encrypted to the attested key,
but no check confirms a full encrypted exchange before use.

## Impact

**The encryption of models without chat completions is not tested before
use.**

- **Who:** Tinfoil, or a party that controls a Tinfoil model enclave.
- **What they do:** serve a model without chat completions whose encryption
  does not work.
- **What they get:** a model that passes verification without an encryption
  test. They read no request: teep encrypts each request body to the attested
  key.
- **What stops it today:** EHBP (HPKE X25519 with AES-256-GCM, full-body
  encryption) encrypts the whole body of every request that teep sends with
  E2EE on, and the response must decrypt under the same session. For
  `nomic-embed-text`, `qwen3-tts` and `voxtral-tts`, the first real request in
  `teep serve` checks the encryption, and a decryption failure blocks the
  request. `teep serve` refuses audio transcription while encryption is on,
  and has no route for `/redact`, `/v1/convert/file`, `/v1/realtime` or
  `/v1/decisions`. No request to these models is sent unencrypted, but nothing
  confirms their encryption. In `teep verify`, nothing: the factor stays
  skipped.

## Technical Background

Tinfoil's model list (`inference.tinfoil.sh/v1/models`) gives, for each model,
a `type` and an `endpoints` list of the paths that the model serves. Teep does
not read this list during verification.

The probe of `teep verify` is one streaming chat completion through EHBP. The
model must answer with a body that teep decrypts.

## Detailed Gap Analysis

Tinfoil's model list of 2026-11-14 has ten models whose `endpoints` have no
`/v1/chat/completions`:

| Model | `type` | `endpoints` |
| --- | --- | --- |
| `nomic-embed-text` | embedding | `/v1/embeddings` |
| `pii-filter` | safety | `/redact` |
| `doc-upload` | document | `/v1/convert/file` |
| `whisper-large-v3-turbo` | audio | `/v1/audio/transcriptions` |
| `qwen3-tts` | tts | `/v1/audio/speech` |
| `voxtral-tts` | tts | `/v1/audio/speech` |
| `voxtral-mini-4b-realtime` | audio | `/v1/realtime` |
| `decision-large` | decision | `/v1/decisions` |
| `decision-medium` | decision | `/v1/decisions` |
| `decision-small` | decision | `/v1/decisions` |

On 2026-11-14, six of them got the chat probe: `nomic-embed-text`,
`pii-filter`, `qwen3-tts`, `voxtral-mini-4b-realtime`, `voxtral-tts` and
`whisper-large-v3-turbo`. Each answered "upstream returned HTTP 404: Not
found.", and `e2ee_usable` failed and blocked the model.

`voxtral-small-24b` serves audio transcription and also chat completions, so
it gets the chat probe.

## Remediation

- **teep:** read the `endpoints` field of Tinfoil's model list during
  verification in place of a fixed table, and probe each model on an endpoint
  that it serves, such as embeddings or speech, which EHBP already encrypts.
- **Tinfoil:** none. The model list states the endpoints.

## References

- [Tinfoil provider support: models the probe does not cover](../providers/tinfoil/tinfoil_support.md#models-the-probe-does-not-cover)
- [NEAR Model Endpoints: No Endpoint in the Model List](near_model_endpoints.md)
- [The table of unprobed Tinfoil models in teep](../../internal/provider/tinfoil/kinds.go)

## Teep Status

`teep verify` sends no chat probe to the ten models above and logs a warning.
`e2ee_usable` stays skipped, enforced and not probed, with the detail "not
probed: the model serves <endpoint>; the verify probe sends a chat
completion". It counts as skipped and does not block. A model that is not in
the table gets the chat probe, so a new model without chat completions fails
the factor and is reported.

`teep serve` does not change.
