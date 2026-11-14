# NEAR Model Endpoints: No Endpoint in the Model List

NEAR's model list does not state which endpoint each model serves. A client
that checks end-to-end encryption with a test request cannot choose the right
request for a model that does not serve chat, so the encryption of five NEAR
models is not tested by teep's verifier today. The models still pass every
other check, and a real request confirms their encryption.

## The Problem

Anyone who checks a NEAR model before use, such as a user's client or an
auditor, needs to send it a real request to see that encryption works. NEAR's
model list gives each model's input and output kinds but no endpoint, and for
two models the kinds are the same as for a chat model. A client therefore
cannot tell which request a model accepts, and one model serves an endpoint
that NEAR does not document.

## Impact

**The encryption of non-chat models is not tested before use.**

- **Who:** NEAR, or a party that controls a NEAR model deployment.
- **What they do:** serves a non-chat model whose encryption does not work,
  or that answers in plaintext.
- **What they get:** a model that passes verification without an encryption
  test.
- **What stops it today:** for the embeddings, reranking and image models,
  the first real request in `teep serve` checks the encryption, and a
  decryption failure blocks the model. For the audio model with encryption on
  and for `openai/privacy-filter`, `teep serve` refuses or has no route, so no
  request is sent unencrypted, but nothing confirms the encryption. In
  `teep verify`, nothing: the factor stays skipped.

## Technical Background

NEAR's model list (`cloud-api.near.ai/v1/models`) gives, for each model,
`architecture.inputModalities`, `architecture.outputModalities` and
`supported_features`. It has no endpoint field. NearDirect's endpoint list
(`completions.near.ai/endpoints`) maps a model to a host, not to an endpoint.

`teep verify` tests end-to-end encryption with one streaming chat completion.
The model must answer with encrypted fields that teep decrypts.

## Detailed Gap Analysis

On 2026-11-14, NEAR answered the chat test request of these models as follows:

| Model | Kinds in the model list | Endpoint | NearCloud | NearDirect |
| --- | --- | --- | --- | --- |
| `black-forest-labs/FLUX.2-klein-4B` | text → image | image generation | 502 | 500 |
| `Qwen/Qwen3-Embedding-0.6B` | text → embedding | embeddings | 400 | 404 |
| `Qwen/Qwen3-Reranker-0.6B` | text → text | reranking | 400 | 404 |
| `openai/whisper-large-v3` | audio → text | audio transcription | 400 | 404 |
| `openai/privacy-filter` | text → text | not documented | 400 | 404 |

The NearCloud 400 answer reads "Provider failed for model '…': Upstream
request failed", with type `invalid_request_error` and param `model`. FLUX.2
answered "model currently unavailable".

The reranker and `openai/privacy-filter` have the same kinds as the chat
models (text → text). Only their empty `supported_features` and their names
set them apart, which is not a contract.

## Remediation

- **NEAR:** add the served endpoint (or endpoints) to each entry of the model
  list, and document the endpoint of `openai/privacy-filter`.
- **teep:** test each model on the endpoint it serves, with the encryption
  that teep already applies to embeddings, images and reranking.

## References

- [Models the probe does not cover](../providers/near/near_attestation.md#models-the-probe-does-not-cover)
- [API support: NEAR endpoints and encryption](../api_support.md#e2ee-support-matrix)
- [The model list in teep](../../internal/provider/nearroute/kinds.go)

## Teep Status

`teep verify` sends no chat test request to the five models above and logs a
warning. `e2ee_usable` stays skipped, enforced and not probed, with the detail
"not probed: the model serves <kind>; the verify probe sends a chat
completion". It counts as skipped and does not block. A model that is not in
the list gets the chat test request, so a new model of another kind fails the
factor and is reported.

`teep serve` does not change. A real embeddings, reranking or image request
confirms the encryption of those three models, as for any other model. `teep
serve` refuses audio transcription while encryption is on, and has no route
for `openai/privacy-filter`, so nothing confirms the encryption of those two.
