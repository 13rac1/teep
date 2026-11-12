# NanoGPT Chutes Evidence: No Nonce Binding, No Serving Instance

For some models that Chutes serves, NanoGPT relays the hardware evidence of
every machine that runs the model, but not the encryption key that each
machine binds into its evidence. Without these keys a client cannot check
that any of the evidence was made for its request, and nothing tells the
client which machine answers the request. teep reports what it can verify
for these models and blocks requests to them.

## The Problem

The attackers are the relay between the client and the machines that run
the model, and anyone who can send evidence through it. They can show a
client evidence that was made for another request, and they choose the
machine that receives the prompts and makes the answers. A client that does
every check available today learns that the listed machines ran genuine,
non-debug confidential-computing hardware at some time, but not that the
evidence is fresh or that any of these machines serves its request.

## Impact

### Gap 1: The evidence is not bound to the request

- **Who:** the relay, or a holder of an earlier evidence response.
- **What they do:** answer a new request with evidence that was made
  earlier, for another request.
- **What they get:** the client sees old evidence as current, so a machine
  that changed or stopped since then looks attested.
- **What stops it today:** nothing that the client can check.

### Gap 2: Nothing names the machine that serves the request

- **Who:** the relay, or the operator of a machine that is not in the
  evidence.
- **What they do:** send the request to a machine that the evidence does
  not list, such as a machine that the response lists as failed.
- **What they get:** the prompts and answers, on a machine with no
  attestation.
- **What stops it today:** nothing that the client can check.

---

## Technical Background

Chutes runs each model on a set of instances. Each instance is a TDX
virtual machine with one or more NVIDIA GPUs, and holds an ML-KEM-768 key
for end-to-end encryption. The Chutes API publishes two documents for a
model:

- The instance list (`/e2e/instances/{chute}`): each instance id with its
  `e2e_pubkey`.
- The evidence response (`/chutes/{chute}/evidence?nonce=<hex>`): for each
  instance, its TDX quote, its GPU evidence, a TLS certificate, and an
  `attested_body` with a `signature`. The response also has
  `failed_instance_ids` and `excluded_instance_ids`.

Each quote binds the client nonce and the instance key:

```
REPORTDATA[0:32]  = SHA256(nonce_hex + e2e_pubkey_base64)
REPORTDATA[32:64] = SHA256(SPKI DER of the entry's certificate)
```

The GPU evidence answers the same value, `REPORTDATA[0:32]`, as its SPDM
requester nonce. A client that has both documents computes the first half
from its nonce and the key in the instance list, and so checks that the
quote and the GPU evidence are fresh and bound to that key. The full
Chutes model is in [Chutes/sek8s Integrity Chain](sek8s_integrity.md).

NanoGPT answers `GET /v1/tee/attestation?model=<model>&nonce=<hex>` for
these models with the evidence response alone.

---

## Detailed Gap Analysis

### What the relayed responses show

On 2026-11-12, 10 of the 20 NanoGPT TEE models answered with the Chutes
evidence response. For each of the 10:

- The top-level members were exactly `evidence`, `excluded_instance_ids`
  and `failed_instance_ids`. Each entry had exactly `attested_body`,
  `certificate`, `gpu_evidence`, `instance_id`, `quote`, `signature` and
  `tee_type`.
- The response listed 4 to 43 instances, with no instance id twice. The
  bodies were 281,412 to 2,956,002 bytes.
- No member carried an `e2e_pubkey`, and no instance list was relayed.
- In the entries checked, the quote was a TDX v4 quote. `REPORTDATA[0:32]`
  was the SPDM requester nonce of the GPU evidence, and was not
  `SHA256(nonce_hex)`. `REPORTDATA[32:64]` was the SHA-256 of the SPKI of
  the entry's certificate (CN `attestation-service`, issued by
  `O=chutes, OU=sek8s, CN=sek8s-vm-root-ca`). More than one instance had
  the same certificate.
- Each `attested_body` stated the nonce of the request. Its `signature` is
  made under a key that Chutes does not publish, so a client cannot verify
  it: the stated nonce is an assertion of the provider.
- `excluded_instance_ids` was empty in all 10 responses.
  `failed_instance_ids` was empty in 9 and held 2 ids in one response; the
  2 ids had no entry in `evidence`.

The meaning of `failed_instance_ids` and `excluded_instance_ids` is not
documented. Their names suggest instances whose evidence could not be
collected, and instances left out of the evidence.

### Consequences

- Without `e2e_pubkey`, a client cannot compute the preimage of
  `REPORTDATA[0:32]`. No quote and no GPU evidence in the response can be
  shown to bind the client nonce (Gap 1).
- The response lists every instance of the model and names none as the
  one that serves the request. The request goes to NanoGPT over TLS, and
  no attestation binds the TLS key of `nano-gpt.com` or names the instance
  that NanoGPT forwards to (Gap 2).

### teep factor behavior

A re-verification of the TEE/qwen3.6-27b response, without network
access, gives:

- `tee_quote_signature`, `tee_cert_chain` and `tee_debug_disabled` pass
  for the first instance, and `nvidia_payload_present` and
  `nvidia_claims` pass.
- `signing_key_present` fails ("signing_key field absent from attestation
  response") and `e2ee_capable` fails ("enclave public key absent"). Both
  are enforced, so teep blocks requests.
- `tee_reportdata_binding` fails ("enclave public key absent; REPORTDATA
  binding cannot be verified"), and `nvidia_signature` fails because the
  requester nonce needs `e2e_pubkey`.
- The report header shows `Candidates: 1/6 evaluated`.

---

## Remediation

Two changes close the gaps. Each one alone leaves the other gap open.

- **Relay the instance list.** Return the instance id and `e2e_pubkey` of
  each instance in the evidence, from the same fetch as the evidence. A
  client then checks `REPORTDATA[0:32]` and the GPU requester nonce of
  each instance against its own nonce (closes Gap 1).
- **Name the serving instance and encrypt to it.** State which instance
  serves the request, and let the client encrypt the request to that
  instance's `e2e_pubkey`, as the direct Chutes API does. Only the
  attested instance can then read the request (closes Gap 2).

---

## References

- [Chutes/sek8s Integrity Chain](sek8s_integrity.md): the Chutes
  attestation model and its REPORTDATA binding.
- [NanoGPT provider support](../providers/nanogpt/nanogpt_support.md):
  NanoGPT routing and the formats it relays.
- [`chutes.ParseEvidence`](../../internal/provider/chutes/chutes.go) and
  [`chutes.ReportDataVerifier`](../../internal/provider/chutes/reportdata.go).

---

## Teep Status

- `formatdetect` detects the response as the Chutes format, and
  `nanogpt.parseChutesEvidence` parses it with `chutes.ParseEvidence`. Every
  entry must pass the checks of the Chutes attested-session path, and the
  instance ids must be unique across the evidence and the two lists. teep
  reports the first instance, with no signing key.
- A non-empty `failed_instance_ids` or `excluded_instance_ids` is logged
  at warn level and is not refused.
- NanoGPT reads at most 8 MiB and accepts at most 64 instances.
- `signing_key_present` and `e2ee_capable` stay enforced, and NanoGPT
  Chutes-evidence models stay blocked.
- When the instance list is relayed, teep can check the nonce binding of
  each instance with `chutes.ReportDataVerifier`. When the serving
  instance is named and requests can be encrypted to it, teep can bind
  each request to one attested instance.
