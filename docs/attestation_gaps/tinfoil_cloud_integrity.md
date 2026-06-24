# Tinfoil Cloud Integrity: Router-Terminated Attestation and EHBP

Tinfoil cloud routing verifies and encrypts traffic to the confidential model router, not to the selected model inference endpoint. The client-facing HPKE key is generated or loaded by the router CVM boot/shim layer and is bound to the router's attestation; the selected inference endpoint's own HPKE key may be authenticated by the router, but it is not used for the client's cloud-mode request body. As a result, cloud-mode EHBP terminates at the router shim, plaintext exists inside the router trust boundary before backend forwarding, and external clients cannot prove that the selected inference machine had NVIDIA SPDM encryption active for the request.

## The Problem

Tinfoil's cloud endpoint places a confidential router between the client and the model inference enclave. Clients can verify the router's attestation, TLS key, and EHBP key, and that EHBP key is the key that decrypts the client's request body. The key is not obtained from the selected inference endpoint for the request path; it is the router CVM's own HPKE key, created or loaded by the router CVM boot/shim layer and authenticated by the router CVM attestation.

The selected inference endpoint also has its own HPKE key, and the router can authenticate that key when it verifies backend attestation. However, cloud-mode forwarding does not use the backend HPKE key for the client's request body. The router stores backend HPKE metadata, but forwards to backends over a separate router-managed TLS hop pinned to the backend's attested TLS fingerprint. Clients cannot independently verify which backend inference enclave the router selected for a given request, nor can they verify the backend's fresh GPU evidence from the same evidence chain used to authorize that request.

This is a weaker trust boundary than direct-to-inference architectures. In a direct architecture, the inference endpoint's own attestation authenticates its own transport and encryption keys, and the same endpoint that decrypts the request is the endpoint whose CPU, GPU, and connectivity state was verified. In Tinfoil cloud mode, the request body is decrypted by the router shim, passed in plaintext to the router workload, routed, possibly modified, and then forwarded to a backend enclave over a separate router-managed TLS hop.

The practical consequence is that Tinfoil cloud mode is a router-confidentiality design, not a model-endpoint end-to-end encryption design. The router may be confidentially measured and useful, but it remains in the plaintext trusted computing base for inference request and response bodies.

## Impact

No compensating client-visible control currently closes this gap for cloud-routed requests. The router does perform internal backend attestation and TLS pinning, and it can authenticate backend HPKE keys during that process, but the client-visible attestation and HPKE key bind only the router. The backend checks are not exported as fresh, client-verifiable evidence for the selected inference endpoint, and the backend HPKE key is not used to keep the request body opaque to the router.

**Security impact:**

- A router compromise can observe plaintext request bodies after EHBP decryption and plaintext response bodies before EHBP response encryption. This includes chat messages, uploaded document content, tool options, file-conversion inputs, audio payloads, and model outputs that pass through cloud routing.
- Any code path running inside the router trust boundary after shim decryption can access inference plaintext. The local shim-to-router-workload hop is plaintext, so a compromised router workload, debugging hook, unsafe logging path, memory disclosure issue, or malicious router image can harvest bodies before backend TLS forwarding.
- EHBP in cloud mode does not add cryptographic protection against router compromise. It authenticates delivery to the router CVM's HPKE key, but the selected inference endpoint's HPKE key is not the recipient key for the client request body.
- Clients cannot prove that the selected inference endpoint had active NVIDIA SPDM evidence, encrypted GPU connectivity, or an expected backend GPU topology for the request. They can only prove that the router claimed to have selected and verified an acceptable backend.
- Backend substitution or backend policy drift is not independently detectable by external verifiers unless they trust the router's internal verification implementation and current state.
- Response confidentiality has the same router boundary: backend responses are visible to the router before the router shim encrypts the response body back to the client.

**Operational impact:**

- Security-conscious consumers must choose between using the feature-rich cloud router and minimizing plaintext TCB by connecting directly to model endpoints.
- External verification reports for cloud mode must be explicit that GPU/SPDM and inference-endpoint integrity are router-enforced properties, not independently client-enforced properties.
- Any provider-side change in backend attestation policy can alter the actual inference trust boundary without a corresponding change in client-visible attestation evidence.
- Cloud-mode documentation and API labels must avoid implying "end-to-end to the inference enclave" unless a future protocol encrypts the body to the backend's attested HPKE key or forwards fresh backend evidence with a request binding.

---

## Technical Background

### Tinfoil Cloud Request Flow

Tinfoil cloud mode has three distinct trust boundaries:

```text
client
  |
  |  EHBP request body encrypted to router HPKE key
  |  TLS to router
  v
Tinfoil confidential model router
  |
  |  plaintext body is parsed, routed, possibly modified
  |  TLS to backend, pinned to backend attested TLS key
  v
selected model inference enclave
```

The public client verifies one enclave identity before sending the request: the router. That verification yields the router's TLS fingerprint and HPKE public key. The router then verifies backend inference enclaves internally and stores each backend's attested TLS fingerprint and HPKE key in its own model state, but the second hop uses TLS pinning rather than EHBP.

### EHBP Trust Boundary

EHBP encrypts HTTP message bodies to a server HPKE key. The server-side middleware decrypts the request body before passing it to the application handler and encrypts the response body after the application handler writes it. Therefore, EHBP's confidentiality boundary is exactly the process that owns the HPKE private key.

For a direct model endpoint, that can be the inference enclave itself. For Tinfoil cloud mode, the attested HPKE key belongs to the router enclave. Once the router decrypts the body, any router code path that reads, rewrites, logs, transforms, or forwards the request sees plaintext.

### HPKE Key Origin

Tinfoil's HPKE identity is generated or loaded by the CVM boot/shim layer, not by the model application container. The boot code loads or creates `/mnt/ramdisk/private/hpke_key.json`, exports the public key, and binds that public key into the hardware attestation body. The shim later loads the same private identity and uses it for EHBP middleware.

That means each Tinfoil CVM can have its own attested HPKE key:

- a router CVM has a router HPKE key
- an inference CVM has an inference endpoint HPKE key

Which key is used depends on which enclave the client verified and addressed. In `tinfoil_v3_cloud`, the client verifies the cloud router domain, so the EHBP transport is built from the router CVM's attested HPKE public key. The inference endpoint's own HPKE key may be authenticated by the router during backend attestation, but it is not the key used for the client's cloud-mode EHBP request.

### What Backend Attestation Proves Internally

The router does perform meaningful internal backend validation. For each backend enclave, it fetches remote attestation, verifies the attestation, verifies hardware measurements for TDX guests, checks that the backend measurement matches the configured model source measurement, and constructs a reverse proxy pinned to the backend's attested TLS fingerprint.

That protects the router-to-backend network hop from ordinary network substitution. It does not, by itself, let the client enforce backend integrity, because the client receives neither the selected backend's full attestation document nor a cryptographic binding between the user's request and the backend evidence.

---

## Verification Surface

### Client-Verifiable in Cloud Mode

External clients can verify:

- router enclave attestation
- router code measurement against the router supply-chain measurement
- router TLS certificate/key binding
- router HPKE key binding
- freshness for the router attestation when a fresh attestation bundle or nonce-backed format is used
- encrypted HTTP body transport to the router HPKE key

### Router-Enforced but Not Client-Enforced

The router can enforce:

- backend inference enclave attestation
- backend source measurement matching configured model measurements
- backend TDX hardware measurement policy
- backend TLS key pinning
- backend load and overload selection policy

These are important controls, but in cloud mode they are server-side controls. A client can audit router source code or query status metadata, but cannot independently verify the fresh backend evidence for the selected request without trusting the router's implementation and state.

### Not Established by Cloud EHBP

Cloud EHBP does not establish:

- encryption all the way to the selected inference enclave
- client-verifiable proof that the selected inference endpoint generated the EHBP key
- client-verifiable proof that NVIDIA SPDM encryption is active on the selected inference endpoint
- protection of plaintext from the router enclave

---

## Detailed Gap Analysis

### EHBP Terminates Before the Router Application Handler

The Tinfoil shim wraps the upstream router handler with EHBP middleware:

- [cvmimage/tinfoil/cmd/shim/api.go:181](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/api.go#L181) creates `ehbpMiddleware := ehbpIdentity.Middleware()`.
- [cvmimage/tinfoil/cmd/shim/api.go:216](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/api.go#L216) applies that middleware around the proxy handler that forwards to the workload.
- [cvmimage/tinfoil/cmd/shim/api.go:253-L258](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/api.go#L253-L258) registers that wrapped proxy handler for normal workload requests.
- [cvmimage/tinfoil/cmd/shim/api.go:188-L192](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/api.go#L188-L192) forwards the post-middleware request to the upstream workload over local HTTP and removes the EHBP encapsulated-key header.

The EHBP middleware itself confirms the trust boundary. Its comments state that encrypted requests are decrypted and plaintext requests pass through; the implementation calls `DecryptRequestWithContext` before invoking the next handler ([encrypted-http-body-protocol/identity/middleware.go:56-L80](https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/8ebf500afce435362cf7e8e360bd6ec31cc731ee/identity/middleware.go#L56-L80)). It then replaces `r.Body` with a decrypted stream before calling the application handler ([encrypted-http-body-protocol/identity/middleware.go:97-L112](https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/8ebf500afce435362cf7e8e360bd6ec31cc731ee/identity/middleware.go#L97-L112)).

The router README describes the resulting architecture directly: the router "terminates TLS connections (optionally with EHBP), inspects the model name, and directs it to a verified secure inference enclave" ([confidential-model-router/README.md:3](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/README.md#L3)).

**Conclusion:** the user's EHBP body is plaintext inside the router workload before backend routing occurs.

### Router Code Reads and Mutates Plaintext Request Bodies

The router reads the decrypted body to choose the model and perform router-owned behavior:

- `/v1/audio/speech` reads and parses the JSON body to extract or default the model ([confidential-model-router/main.go:394-L412](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L394-L412)).
- multipart audio requests are parsed to extract the model and then restored for forwarding ([confidential-model-router/main.go:413-L424](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L413-L424)).
- generic OpenAI-compatible requests are fully read and unmarshaled ([confidential-model-router/main.go:427-L438](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L427-L438)).
- router-only option blobs are extracted from the plaintext body ([confidential-model-router/main.go:440-L448](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L440-L448)).
- the router reads the model field from the plaintext request ([confidential-model-router/main.go:450-L460](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L450-L460)).
- the router may run tool loops locally ([confidential-model-router/main.go:462-L468](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L462-L468), [548-L556](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L548-L556)).
- the router rewrites some file inputs, strips or injects priority, modifies streaming usage options, and re-marshals the body ([confidential-model-router/main.go:471-L546](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L471-L546)).

These are intentional router features, but they prove that cloud-mode EHBP does not keep inference request bodies opaque to the router.

### Backend Attestation Is Consumed by the Router, Not Forwarded as Request Ground Truth

The router's `addEnclave` path fetches and verifies backend attestation, validates hardware measurements when required, checks the backend measurement against the model's configured source measurement, and stores backend TLS/HPKE values ([confidential-model-router/manager/manager.go:152-L206](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/manager/manager.go#L152-L206)).

When the router forwards requests, it builds a reverse proxy to the backend host using `TLSBoundRoundTripper` pinned to the backend TLS fingerprint ([confidential-model-router/manager/proxy.go:137-L158](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/manager/proxy.go#L137-L158)). The main request path chooses an enclave only after the plaintext body has been parsed and routing policy has run ([confidential-model-router/main.go:561-L590](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/main.go#L561-L590)).

The router status endpoint exposes model state and serialized backend key fingerprints ([confidential-model-router/manager/manager.go:233-L246](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/manager/manager.go#L233-L246), [383-L391](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/manager/manager.go#L383-L391)). This is not equivalent to forwarding backend attestation. It does not provide the raw backend CPU report, GPU evidence, NVSwitch evidence, certificate signature, supply-chain bundle, nonce binding, or a cryptographic proof that the exposed backend entry was the endpoint selected for the user's request.

**Conclusion:** backend attestation is a router-internal admission control, not a client-enforced verification factor for cloud-routed requests.

### Client EHBP Uses the Single Verified Enclave Key

The Tinfoil JS client fetches one attestation bundle, verifies it, and creates the transport from the attested HPKE key ([tinfoil-js/packages/tinfoil/src/secure-client.ts:239-L260](https://github.com/tinfoilsh/tinfoil-js/blob/896eb65193ce303a87499059f1f066f736d4de80/packages/tinfoil/src/secure-client.ts#L239-L260), [293-L299](https://github.com/tinfoilsh/tinfoil-js/blob/896eb65193ce303a87499059f1f066f736d4de80/packages/tinfoil/src/secure-client.ts#L293-L299)). The attestation bundle fetch returns one domain and one attestation report ([tinfoil-js/packages/tinfoil/src/atc.ts:18-L49](https://github.com/tinfoilsh/tinfoil-js/blob/896eb65193ce303a87499059f1f066f736d4de80/packages/tinfoil/src/atc.ts#L18-L49)).

The encrypted-body transport creates an EHBP transport for the base origin using that one HPKE key ([tinfoil-js/packages/tinfoil/src/encrypted-body-fetch.ts:99-L141](https://github.com/tinfoilsh/tinfoil-js/blob/896eb65193ce303a87499059f1f066f736d4de80/packages/tinfoil/src/encrypted-body-fetch.ts#L99-L141)). In default cloud routing, the verified enclave is the router domain, so the HPKE key is the router's HPKE key.

The V3 attestation construction binds the HPKE key into the attested report data ([cvmimage/tinfoil/internal/attestation/attestation.go:130-L143](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/internal/attestation/attestation.go#L130-L143), [170-L205](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/internal/attestation/attestation.go#L170-L205)). That is a useful binding, but it authenticates whichever enclave produced the attestation. For cloud mode, that enclave is the router.

### HPKE Key Source Investigation

The HPKE identity used by the first-hop EHBP exchange is created inside the CVM boot/shim environment:

- [cvmimage/tinfoil/internal/boot/paths.go:15-L20](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/internal/boot/paths.go#L15-L20) defines `HPKEKeyPath` under the private ramdisk, which the comments describe as accessible only to boot, egress, and shim processes.
- [cvmimage/tinfoil/cmd/boot/identity.go:38](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/boot/identity.go#L38) loads or creates the HPKE identity from that path.
- [cvmimage/tinfoil/cmd/boot/identity.go:64-L79](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/boot/identity.go#L64-L79) generates a new HPKE identity with `identity.NewIdentity()`, persists it with mode `0600`, or loads the existing identity.
- [cvmimage/tinfoil/cmd/boot/identity.go:43-L56](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/boot/identity.go#L43-L56) exports the public key bytes into the node identity.
- [cvmimage/tinfoil/internal/attestation/attestation.go:28-L37](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/internal/attestation/attestation.go#L28-L37) defines the V2 attestation body as `TLSKeyFP || HPKEKey`.
- [cvmimage/tinfoil/cmd/boot/cpuattest.go:24-L33](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/boot/cpuattest.go#L24-L33) copies that generated public key into the attestation body before requesting the hardware report.
- [cvmimage/tinfoil/cmd/shim/main.go:146-L162](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/main.go#L146-L162) loads the same private HPKE identity for the shim and builds the fresh-attestation identity body from the shim's public key.
- [cvmimage/tinfoil/cmd/shim/api.go:216-L258](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/api.go#L216-L258) wraps normal workload requests in EHBP middleware, and [cvmimage/tinfoil/cmd/shim/api.go:400](https://github.com/tinfoilsh/cvmimage/blob/329d2302ba51680f8f89e7fac9257554d8ada2d6/tinfoil/cmd/shim/api.go#L400) exposes the public HPKE config endpoint from that same shim identity.

This establishes that the key in use for a cloud request is generated at the router CVM, not at the selected inference endpoint. More precisely, it is generated by the router CVM's boot/shim layer and then used by the router CVM's shim to decrypt the request before forwarding plaintext to the router workload.

Inference endpoints also have their own attested HPKE keys because they use the same CVM image machinery. The router does obtain those keys when it verifies backend attestation: [confidential-model-router/manager/manager.go:176-L205](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/manager/manager.go#L176-L205) fetches backend attestation, verifies it, and stores `verification.HPKEPublicKey` as `hpkeKey`.

However, the router does not use the backend HPKE key to protect the router-to-inference hop. A search of the router code shows `hpkeKey` is stored, serialized in status, and reloaded, but not passed into the forwarding path. Backend forwarding uses only TLS pinning: [confidential-model-router/manager/proxy.go:137-L158](https://github.com/tinfoilsh/confidential-model-router/blob/284f6662056101d204cc71ede00d62f95d97a76a/manager/proxy.go#L137-L158) constructs a reverse proxy with `TLSBoundRoundTripper{ExpectedPublicKey: publicKeyFP}`. The Go client follows the same single-key pattern for EHBP: it stores the verified enclave's `HPKEPublicKey` as ground truth ([tinfoil-go/verifier/client/client.go:259-L263](https://github.com/tinfoilsh/tinfoil-go/blob/11febe2f8e79d82c4f3806d2f737184abcbedf91/verifier/client/client.go#L259-L263), [323-L327](https://github.com/tinfoilsh/tinfoil-go/blob/11febe2f8e79d82c4f3806d2f737184abcbedf91/verifier/client/client.go#L323-L327)) and builds the EHBP transport from that key ([tinfoil-go/ehbp_transport.go:229-L264](https://github.com/tinfoilsh/tinfoil-go/blob/11febe2f8e79d82c4f3806d2f737184abcbedf91/ehbp_transport.go#L229-L264), [324-L338](https://github.com/tinfoilsh/tinfoil-go/blob/11febe2f8e79d82c4f3806d2f737184abcbedf91/ehbp_transport.go#L324-L338)).

**Conclusion:** the selected inference endpoint does generate and expose its own HPKE key, and the router can authenticate that key through backend attestation. But in `tinfoil_v3_cloud`, that endpoint HPKE key is not used for the client request body. The client encrypts to the router CVM's HPKE key, the router shim decrypts before the router application handles the request, and plaintext exists inside the router trust boundary. There is a plaintext local hop from the router CVM shim to the router workload before the router re-forwards the request to the selected inference endpoint.

### EHBP Security Property Verification

The review claim is verified:

- EHBP is cryptographically real and attestation-bound for whichever Tinfoil CVM the client verifies.
- In `tinfoil_v3_cloud`, the HPKE private key that decrypts the client body is generated or loaded by the router CVM boot/shim layer and held by the router CVM.
- The selected inference endpoint has its own HPKE key, and the router can authenticate it through backend attestation, but that key is not used for the client-to-cloud EHBP body.
- The router sees plaintext request bodies before forwarding.
- The router-to-inference hop uses TLS pinned to internally verified backend TLS keys, not a client-originated EHBP channel to the inference enclave.
- Therefore, EHBP adds no cryptographic protection against router compromise and does not prove inference-endpoint GPU/SPDM state to the client.

This is not a flaw in the EHBP protocol itself. It is a trust-boundary mismatch between the cloud router architecture and claims that imply end-to-end encryption to the inference machine.

---

## Remediation

### Preferred: Direct Inference Mode for Strong End-to-End Claims

For workloads that require plaintext to be visible only inside the selected inference endpoint, clients should connect directly to per-model inference enclaves. In that mode, the client can verify the inference enclave's own attestation, bind transport keys to that attestation, and encrypt request bodies to the inference enclave's own HPKE key.

This is the cleanest way to make the security statement true:

- the endpoint that decrypts the request is the endpoint that produced the attestation
- the GPU/SPDM evidence belongs to the endpoint handling the request
- the router is removed from the plaintext trusted computing base

### Cloud Mode: Publish Selected Backend Evidence

If cloud routing must preserve router features, the provider should expose client-verifiable backend evidence for the selected inference endpoint. A practical design would include:

- the selected backend hostname or stable backend identity
- the backend's fresh attestation document
- backend GPU and NVSwitch evidence
- backend TLS fingerprint and HPKE key, even if HPKE is not used on the second hop
- backend supply-chain measurement material
- a router signature over the selected backend evidence and request-routing decision
- a client nonce or request digest binding the evidence to the request being routed

This would not remove the router from the plaintext TCB, but it would let clients verify that the router selected a backend with the expected CPU/GPU integrity properties.

### Cloud Mode: End-to-Backend Request Encryption

To remove the router from the body plaintext boundary while keeping router-mediated discovery, cloud mode would need a two-stage design:

1. router returns selected backend attestation and backend HPKE key to the client
2. client encrypts the inference body to the backend HPKE key
3. router forwards the opaque encrypted body to the selected backend
4. backend decrypts and processes the request

This would require protocol changes because the router currently needs plaintext access for model extraction, routing defaults, file rewriting, usage option injection, and router-owned tools. The request envelope would need to separate router-visible routing metadata from backend-confidential inference content.

### Documentation and Verification Policy

Until one of the above changes exists, cloud mode should be documented and enforced as:

- router-attested request confidentiality
- router-enforced backend attestation
- not end-to-end encryption to the inference enclave
- not client-enforced backend GPU/SPDM verification

Verification software should report cloud backend integrity as "router-enforced" rather than "client-verified." Policies that require inference-endpoint end-to-end encryption or client-verifiable GPU evidence should fail closed for `tinfoil_v3_cloud` and require direct inference mode or a future cloud protocol that forwards backend evidence with a request binding.
