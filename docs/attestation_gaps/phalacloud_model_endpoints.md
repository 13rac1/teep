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
  endpoints. For Phala Cloud it routes only chat completions and embeddings,
  and it refuses embeddings while E2EE is on. On 2026-11-14 the gateway
  answered a chat completion for `jaredpalmer/kev-4b` with HTTP 404, and
  teep blocked the reports of `black-forest-labs/flux.2-klein-4b` and
  `openai/whisper-large-v3`, so it sent them no request. Nothing confirms
  the encryption of the four models. In `teep verify`, nothing: no probe
  runs.

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

Two runs of `teep verify` on 2026-11-14 tested these models. In the first,
made before teep skipped the probe for them, `jaredpalmer/kev-4b` got the
chat probe, and the gateway answered "upstream returned HTTP 404: no route
available for model jaredpalmer/kev-4b". In both runs,
`aci_session_verified` blocked the reports of
`black-forest-labs/flux.2-klein-4b` and `openai/whisper-large-v3`, because
teep does not verify the evidence of their gateway session; a blocked report
gets no probe. Neither run made a report for
`mistralai/voxtral-small-24b-2507`.

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

`teep verify` sends no chat probe to the four models above while E2EE is
on, the default. When the report does not block, teep logs a warning and two
factors stay skipped: `e2ee_usable`, which the policy allows to fail, gets
the detail "not probed: the model serves <kind>; the verify probe sends a
chat completion", and `aci_receipt_verified`, which is enforced, gets the
detail "no probe: the model serves <kind>; …". Neither blocks. A blocked
report gets no probe either and keeps its own details: `e2ee_usable` reads
"E2EE configured; pending live test" and `aci_receipt_verified` reads "no
probe: the report blocks inference requests". On 2026-11-14 the reports of
`black-forest-labs/flux.2-klein-4b` and `openai/whisper-large-v3` blocked,
so only `jaredpalmer/kev-4b` got the "not probed" details. Because
`e2ee_usable` is allowed to fail, a failed probe would not block either. A model that is not in the table gets the chat probe, so a new model
without chat completions fails the factor and is reported.

`teep serve` has no Phala Cloud path for these endpoints, so no request
confirms the encryption of these four models.
