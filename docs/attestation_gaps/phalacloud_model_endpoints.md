# Phala Cloud Model Endpoints: No Endpoint Field in the Model List

`teep verify` tests end-to-end encryption with one chat completion, called
the probe. Four Phala Cloud models have no text output modality, so teep's
verifier does not test their encryption today. Phala Cloud's model list has
no endpoint field. Only modalities, pricing keys and, for one model, the
free-text description show which endpoint a model serves. `teep serve` has
no Phala Cloud path for image generation, audio transcription or
`/v1/systemone`, so it serves none of these models.

## The Problem

Anyone who checks a Phala Cloud model before use, such as a user's client or
an auditor, needs to send it a real request to see that encryption works. The
request must go to an endpoint that the model serves. The model list has no
field that states that endpoint, and a model without chat completions answers
a chat request with an error.

## Impact

**The encryption of models without text output is not tested before use.**

- **Who:** Phala Cloud, or a party that controls a Phala Cloud model
  deployment or the gateway.
- **What they do:** serve a model without chat completions whose encryption
  does not work.
- **What they get:** a model that passes verification without an encryption
  test. They read no request through teep: teep sends these models no request
  that they serve.
- **What stops it today:** `teep serve` has no Phala Cloud path for these
  endpoints. It sends these models only chat completions, encrypted when E2EE
  is on, and the gateway refuses them. Nothing confirms their encryption. In
  `teep verify`, nothing: the factor stays skipped.

## Technical Background

Phala Cloud's model list gives, for each model, `input_modalities`,
`output_modalities`, `pricing` and a `description`. It has no endpoint field.

The probe of `teep verify` is one streaming chat completion with E2EE v2.
The model must answer with encrypted fields that teep decrypts, and the
response must carry a receipt that teep checks.

## Detailed Gap Analysis

Phala Cloud's model list of 2026-11-14 has four models whose output modality
is not text:

| Model | Modalities in the model list | Endpoint kind (derived by teep) |
| --- | --- | --- |
| `black-forest-labs/flux.2-klein-4b` | text → image | image generation |
| `openai/whisper-large-v3` | audio → transcription | audio transcription |
| `mistralai/voxtral-small-24b-2507` | audio → transcription | audio transcription |
| `jaredpalmer/kev-4b` | text → decisions | `/v1/systemone` (named in the description) |

On 2026-11-14, `jaredpalmer/kev-4b` got the chat probe, and the gateway
answered "upstream returned HTTP 404: no route available for model
jaredpalmer/kev-4b". `e2ee_usable`, which Phala Cloud's policy allows to
fail, failed, and the report did not block. The reports of
`black-forest-labs/flux.2-klein-4b` and `openai/whisper-large-v3` were
blocked by `aci_session_verified`, because teep does not verify the evidence
of their gateway session, so they got no probe. The run of 2026-11-14 made
no report for `mistralai/voxtral-small-24b-2507`.

## Remediation

- **Phala Cloud:** add the served endpoint (or endpoints) to each entry of the
  model list, as a field.
- **teep:** probe each model on an endpoint that it serves, once E2EE v2
  covers that endpoint.

## References

- [Phala Cloud provider support: known limitations](../providers/phalacloud/phalacloud_support.md#known-limitations)
- [Tinfoil Model Endpoints: Verify Probe Covers Chat Only](tinfoil_model_endpoints.md)
- [NEAR Model Endpoints: No Endpoint in the Model List](near_model_endpoints.md)
- [The table of unprobed Phala Cloud models in teep](../../internal/provider/phalacloud/kinds.go)

## Teep Status

`teep verify` sends no chat probe to the four models above and logs a
warning. `e2ee_usable`, which the policy allows to fail, stays skipped with
the detail "not probed: the model serves <kind>; the verify probe sends a
chat completion". `aci_receipt_verified`, which is enforced, stays skipped
with the detail "no probe: the model serves <kind>; …". Neither blocks.
Because `e2ee_usable` is allowed to fail, a failed probe did not block
either: the skip changes the detail in the report, not whether the report
blocks. A model that is not in the table gets the chat probe, so a new model
without chat completions fails the factor and is reported.

`teep serve` has no Phala Cloud path for these endpoints, so no request
confirms the encryption of these four models.
