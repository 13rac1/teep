# Tinfoil Cloud Integrity: Router Plaintext and Unbound Downstream Evidence

Tinfoil cloud routing gives customers a single attested entry point and enables centralized model selection, file conversion, and server-side tools. The client attests the confidential router, while the router separately admits the inference, document-conversion, web-search, and code-execution enclaves that may participate in a request. This creates two security gaps. First, the client receives no authenticated evidence proving which of those downstream workloads and releases handled its request. Second, the router decrypts inference content and can send plaintext or delegated authority into those workloads. Tinfoil should document both limitations explicitly and offer direct inference or backend-addressed EHBP to customers who do not accept that evidence and trust boundary.

## The Problem

Tinfoil cloud routing introduces two related security gaps.

First, clients receive no downstream-authenticated proof of the workloads that participated in routed processing. For model inference, the missing proof covers the selected endpoint, release, model weights, hardware state, and key epoch. For document conversion and router-owned tools, it covers the helper enclave, release, parser or tool implementation, key epoch, and the input and output attributed to that helper. Tinfoil exposes useful router status, backend attribution metadata, and endpoint-specific audit bundles, but these are separate observations. The router can identify and attest acceptable downstream hosts for its own use; the client does not receive a backend- or helper-authenticated statement that a particular release handled its request.

Second, inference bodies are confidential only as far as the router. The router decrypts each body, reads and may rewrite it, selects downstream services, and opens new protected connections to them. Encryption on each network hop does not prevent the router or an invoked helper from observing or altering the plaintext it receives. This is broader than a passive-relay boundary: document handling exposes files to decoding and parser code, while router-owned tools turn model output into server-side web or code-execution actions. Some agent deployments can activate those capabilities through an already-authenticated inference client. This delegation is opaque to the agent software and the secure inference proxy, and the code bases in use on these paths can not be validated by clients via attestation receipts, due to the first security gap.

### Consequences of the Two Gaps

**Gap 1 limits what clients can prove about routed processing.** Router attestation shows that an expected router release received the request and was programmed to admit downstream workloads. It does not prove to the client which inference endpoint, document converter, web-search enclave, or code-execution enclave participated; which release, hardware state, dependencies, or key epoch each used; or what document parsing helper code produced a particular result. The technical basis and supply-chain consequences are detailed in [Gap 1](#gap-1-backend-and-helper-evidence-is-not-bound-to-request-processing).

**Gap 2 expands the plaintext and delegated-authority boundary accepted with cloud routing.** The router receives inference content as plaintext so it can inspect, rewrite, and route requests. File conversion, router-owned tool loops, billing, delegated authorization, and helper enclaves extend that boundary beyond a simple gateway. A vulnerability or malicious result in any authorized path can therefore affect customer data, model input, or delegated actions. The full router, tool, agent-framework, and helper-service surface is detailed in [Gap 2](#gap-2-ehbp-terminates-at-the-router-and-expands-the-trusted-surface).

Routed mode therefore offers centralized features in exchange for trusting the router's downstream admission decisions and the plaintext-processing surface behind them. Direct inference (or a future routed mode carrying EHBP addressed to the backend) offers a smaller, client-verifiable boundary but cannot retain router features that require plaintext. Tinfoil should make this choice visible in documentation, verification output, and mode selection rather than presenting router attestation as equivalent to downstream verification or end-to-inference confidentiality. The [remediation](#remediation) section describes these steps; the [NEAR AI comparison](#contrast-near-ai-keeps-the-model-in-the-client-verification-chain) shows one deployed precedent for separating gateway routing from model confidentiality and processing evidence.

## Impact

Tinfoil has compensating controls, but none closes either gap. Body encryption protects data through browsers and TLS-terminating proxies that cannot enforce an attested TLS fingerprint. The router verifies attestations for downstream enclaves and pins its connections; model boot code validates attached GPUs before serving. Router status and endpoint-specific bundles support independent fleet auditing. These controls protect individual stages, but they neither keep plaintext from the router nor carry backend-authenticated or helper-authenticated participation evidence to the client.

The plaintext gap includes more than an intermediary reading a prompt. The router parses and rewrites attacker-influenced request structures, decodes inline files, dispatches binary documents to a parser-bearing helper, interprets model output, and can invoke web-search or code-execution services. Billing and delegated authorization add further services and credentials to the processing graph. Self-modifying or misconfigured agent frameworks can activate Tinfoil-specific router functionality: OpenClaw can add the required fields under its default trusted-operator configuration, whereas Hermes defaults to human approval to modify its primary configuration to allow this. Together these paths materially enlarge the exploitable code, plaintext, and delegated-authority surface accepted with the router boundary.

**Security impact:**

- A client cannot prove which model, document-conversion, web-search, or code-execution release participated in a routed request; verify its request-time hardware, dependencies, or key epoch; or bind a helper's input and output to client-verified evidence.
- A compromised, vulnerable, or malicious router workload can observe or alter chat messages, uploaded documents, audio, tool inputs, credentials embedded in router options, and model outputs.
- When a request enables a router-owned tool, a prompt-injected, jailbroken, faulty, or malicious model can cause the router to execute matching model-generated calls. This can enable public internet access, disclose prompt-derived data in search queries, operate on a persistent code-execution workspace, consume billable resources, and exercise the caller's delegated tool authority without a separate approval step.
- Router features can fan plaintext and authority out beyond the router and selected model: binary documents are sent to a document-conversion enclave, tool arguments and results traverse MCP tool enclaves, code-execution credentials are attached to MCP calls, and inference credentials participate in billing and delegated-authorization flows. These services may receive separate router-enforced attestation and TLS protection, but their evidence and exact participation are not independently visible or request-bound at the client.
- Defense in depth between the client and router does not protect against compromise inside the router boundary because both body encryption and any direct router TLS pin terminate there.
- The router can attribute a response to a backend that exists and verifies correctly at audit time without producing backend-authenticated proof that this backend handled the earlier request.
- A compromised authorized release workflow can publish a malicious model or helper that passes provenance and measurement checks without changing the router release. Targeted behavior can then distinguish ordinary audit traffic from selected tenants, prompts, files, or tool calls.
- Short-lived model or helper releases can disappear between periodic status or bundle checks, leaving no client-held evidence that the router admitted or invoked them.

**Operational impact:**

- Security-conscious customers must choose between router features and minimizing the plaintext trusted computing base through direct inference.
- External reports cannot distinguish router-enforced downstream admission and TLS pinning, model-boot-enforced GPU validation, current-fleet auditing, and properties actually bound to a request.
- Auditors can monitor current endpoints but must continuously archive status and bundles to detect transient model or helper changes, and even then cannot prove which workloads handled a request.
- The limitation is a protocol and product choice rather than an inherent cost of confidential gateway routing; customers can compare it with providers that keep backend evidence and content encryption client-verifiable.
- Cloud security claims must avoid "end-to-end to the inference enclave," "client-verified backend," or "client-verified tool execution" unless the routing protocol changes.

---

## Technical Background

### Cloud Request Flow

Tinfoil cloud routing has three processing boundaries:

```text
client
  |
  |  body encrypted to router HPKE key
  |  outer TLS may terminate at router or a proxy
  v
Tinfoil confidential model router
  |
  |  body is plaintext, parsed, routed, and possibly modified
  |  new TLS connection pinned to backend's attested TLS key
  v
selected model inference enclave
```

The client verifies the router and encrypts the body to the router CVM's attested HPKE key. A client capable of direct TLS pinning can also enforce the router's attested TLS fingerprint. Browsers and proxy deployments may be unable to enforce that fingerprint end to end, and EHBP remains valuable in those cases because the body stays encrypted through the intermediary. In all cloud deployments, however, the inner body encryption ends at the router rather than the model backend.

The router verifies backend CPU attestation, checks the runtime measurement against the authorized model release measurement, and constructs a reverse proxy pinned to the backend's attested TLS key. The backend also has an attested HPKE key, but the router records that key as metadata and does not use it for forwarding.

### EHBP Trust Boundary

EHBP encrypts HTTP bodies to a server HPKE key. Server middleware replaces an encrypted request body with a decrypted stream before invoking the application handler, and encrypts the body written by that handler on the way back. Its AEAD uses empty associated data, so ordinary HTTP headers such as `Tinfoil-Enclave` are not authenticated by EHBP body encryption ([EHBP specification](https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/8528a8dc5ad45c213f14f9bab46a748fda7e18cc/SPEC.md#L59-L69)).

Each Tinfoil CVM has its own HPKE identity. A router CVM therefore has a router key and an inference CVM has a different backend key. Security depends on which CVM the client verifies and addresses; default cloud routing verifies and encrypts to the router.

### Backend Admission and GPU Enforcement

The router's backend admission path requests the nonce-less legacy CPU attestation document. It verifies the CPU quote, applicable TDX platform measurements, the release measurement, and the attested TLS and HPKE values.

GPU enforcement occurs elsewhere. During backend boot, the CVM locally validates GPU SPDM evidence and applicable topology before enabling GPU request processing. A nonce-bearing V3 attestation request can collect fresh CPU, GPU, and NVSwitch evidence, but the router admission path does not make that request. The router instead trusts the measured backend boot code to have enforced GPU policy.

### Existing Audit Surfaces

Tinfoil exposes three useful but separate audit surfaces:

- Router status publishes model repositories, release tags, source measurements, backend hostnames, and backend TLS/HPKE metadata.
- Each ordinary backend response includes a router-generated `Tinfoil-Enclave` header naming the selected host.
- ATC accepts an enclave URL and repository and can assemble an endpoint-specific bundle containing CPU attestation, release digest and tag, Sigstore evidence, VCEK, and the enclave certificate.

Together these let a client identify the host claimed by the router and independently audit that endpoint later. They do not bind the later evidence to the earlier request, preserve a history of router admission decisions, or make the attribution a backend-authenticated statement.

### Contrast: NEAR AI Keeps the Model in the Client Verification Chain

NEAR AI Cloud also offers a unified confidential gateway in front of model TEEs, but deliberately keeps the model backend in the client's cryptographic verification chain.

The gateway attestation endpoint returns model attestations in response to a client nonce. Each model record exposes CPU and GPU evidence, the model signing key, and the digest-pinned compose manifest; the TDX report data binds the signing identity and nonce, while the compose hash is checked against the verified `mr_config` measurement ([NEAR model verification](https://docs.near.ai/cloud/verification/model/)). The client therefore has the backend evidence and exact container configuration as verification inputs rather than receiving only the gateway's verdict. NEAR's verifier uses the image digests from that attested manifest to locate source and Sigstore build provenance, associate a deployed image with a source revision and workflow, and support independent supply-chain review ([NEAR AI Cloud Verifier](https://github.com/nearai/nearai-cloud-verifier/tree/6a9c0c57dd9b2b47bbd2682df4a685c50210096e)).

For confidentiality, NEAR's opt-in E2EE mode encrypts protected request fields to the model public key obtained from model attestation. The gateway routing form carries `X-Model-Pub-Key`, which NEAR documents as required when routing encrypted requests through the gateway; `X-Encrypt-All-Fields` extends protection beyond message content to tool definitions, tool calls, and other sensitive fields ([NEAR E2EE guide](https://docs.near.ai/cloud/guides/e2ee-chat-completions/)). This separates router-visible routing metadata from model-confidential inference content instead of giving the gateway the content decryption key.

For processing integrity, a NEAR `provider_tee` signature is produced by the model TEE under the signing identity from model attestation. It covers the model ID, the hash of the exact request bytes received by the model, and the hash of the exact response bytes it sent ([NEAR chat verification](https://docs.near.ai/cloud/verification/chat/)). This is the backend-authenticated receipt missing from Tinfoil cloud routing.

| Property | Tinfoil cloud routing | NEAR AI E2EE gateway path |
|---|---|---|
| Backend evidence available to client | Router status and a separately requested endpoint bundle | Fresh client-nonce-bound model CPU/GPU evidence and attested compose manifest |
| Sensitive-content recipient | Router HPKE key; router workload receives plaintext | Model-attested public key; gateway forwards protected fields as ciphertext |
| Backend selection and attribution | Router selects a host and emits `Tinfoil-Enclave` | Client selects an attested model key for E2EE; model TEE can sign the processing record |
| Request/response binding | No backend-authenticated commitment | `provider_tee` signature covers model ID, request hash, and response hash |
| Supply-chain audit input | Backend digest and bundle consumed internally by router | Digest-pinned backend compose exposed in quote-bound evidence for independent provenance review |

This comparison does not claim that signed provenance makes every NEAR artifact benign; an authorized release path can still be compromised. The difference is auditability and data-plane binding: the exact backend configuration and signing identity are visible to the client, protected content is addressed to that identity, and the backend can authenticate what it processed. E2EE must be enabled, full sensitive-field coverage requires `X-Encrypt-All-Fields`, and gateway-rewritten response streams can carry a gateway signature rather than a byte-exact `provider_tee` signature. The `provider_tee` signature binds processing to the model identity but does not itself cover the release digest or attestation epoch, so it is a precedent for backend authentication rather than the complete stage 2 design proposed below. NEAR also offers direct model endpoints when clients want to remove the gateway from the path entirely ([NEAR private inference](https://docs.near.ai/cloud/private-inference/)). These qualifications limit the guarantee for particular modes, but the design still provides concrete, deployed precedents for the changes proposed in this report.

Tinfoil already has much of the machinery needed to follow this pattern: the router authenticates the backend's HPKE key, TLS key, measurements, and release evidence. The central change is to preserve those results across the client boundary and use the backend key and identity in the data plane, rather than consuming them only inside the router.

---

## Detailed Gap Analysis

The first gap concerns evidence: neither model-backend nor helper-service admission is carried to the client as an authenticated processing proof. The second concerns authority: EHBP ends at a workload that parses and rewrites plaintext and can dispatch those other privileged services. Gap 2 therefore includes the router's ordinary plaintext processing, router-owned tool execution, the agent-framework paths that can activate those tools through authenticated hosts, and the resulting fan-out to helper services.

### Gap 1: Backend and Helper Evidence Is Not Bound to Request Processing

The router performs meaningful admission control, but its evidence is not carried into a client-verifiable processing proof. `addEnclave` fetches legacy CPU attestation without a nonce, verifies it and applicable TDX platform measurements, compares the backend and source measurements, and stores the TLS and HPKE values ([manager.go:247-L342](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L247-L342)). Backend forwarding uses a reverse proxy with `TLSBoundRoundTripper` pinned to the admitted TLS fingerprint ([proxy.go:176-L205](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/proxy.go#L176-L205)). The stored backend HPKE key is not part of the forwarding transport.

The router does not verify fresh backend GPU evidence during admission. Backend boot verifies GPUs before enabling them ([boot/main.go:113-L138](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/boot/main.go#L113-L138)), while fresh GPU/NVSwitch collection occurs only on a nonce-bearing V3 attestation request ([shim/api.go:326-L375](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/api.go#L326-L375)). The cloud chain therefore proves that the router admitted code expected to enforce GPU policy, not that the router or client inspected fresh backend GPU evidence for the request.

The evidence gap extends beyond model inference. When the router delegates document processing, it selects a separately admitted `doc-upload` enclave, constructs an in-memory multipart request, and sends the decoded file and request authorization header over a connection pinned to that helper's admitted TLS key ([file_inputs.go:101-L222](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/manager/file_inputs.go#L101-L222)). This is meaningful **router-enforced helper attestation**, but it is not part of the client's router attestation: the router measurement covers the router release, not the `doc-upload` release or its parser dependencies. The cloud protocol does not give the client the helper evidence used for that conversion or a helper-authenticated receipt binding the converter's identity, release, and output to the uploaded file.

To the extent that parser code and dependencies are packaged in the measured `doc-upload` image, they are indirectly committed by that helper release's measurement. That does not make them client-verifiable in the routed transaction. The public router source neither provides the parser inventory and versions represented by the helper measurement nor lets the client apply its own acceptance policy to them before submitting the file. A client must therefore trust the router's helper-admission decision and the accepted converter release without a client-held attestation record showing which parsing code participated.

Router-owned web-search and code-execution services follow the same evidence pattern. Once an authenticated request activates a tool profile, the router resolves the corresponding tool-server model, connects to a separately admitted and TLS-pinned MCP enclave, sends model-selected arguments and delegated metadata, and inserts the returned result into model history ([http_client.go:231-L253](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/manager/http_client.go#L231-L253), [tool_loop.go:103-L235](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/tool_loop.go#L103-L235)). The client receives neither the tool enclave evidence used by the router nor a tool-generated receipt binding the tool release, call arguments, result, and inference request. The final model response therefore authenticates none of those facts to the client.

Even client-visible attestation of a tool enclave would cover only the measured tool code and configuration. It would not authenticate external search providers, fetched websites, DNS answers, package repositories, network destinations, or other services contacted during execution. Those dependencies can influence tool results or behavior without changing the measured enclave release. Tool evidence must therefore distinguish the identity of the executing enclave from the provenance and trustworthiness of external data and actions.

The current attribution and audit features narrow the gap but do not close it:

- Status serializes repository, tag, source measurement, backend hostname, TLS fingerprint, and HPKE key ([manager.go:46-L50](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L46-L50), [manager.go:366-L382](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L366-L382), [manager.go:840-L848](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L840-L848)). It does not include the verified digest, supply-chain bundle, fresh evidence, or admission history.
- `Tinfoil-Enclave` names the host selected by the router ([manager.go:806-L822](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L806-L822)). It is neither produced by the backend nor authenticated as part of the EHBP response body.
- ATC can assemble a bundle for a caller-supplied enclave and repository ([atc.ts:11-L57](https://github.com/tinfoilsh/tinfoil-js/blob/50e664521d69f45de84c494b1fdca2131465d028/packages/tinfoil/src/atc.ts#L11-L57), [attestation.go:354-L385](https://github.com/tinfoilsh/tinfoil-go/blob/173ed2fb593ba8cebab1f97a32f114395153c083/verifier/attestation/attestation.go#L354-L385)). It verifies an endpoint separately, but contains no commitment to the earlier request or response.
- File conversion has no corresponding client-visible attribution in the rewritten inference transaction. The converter's result is absorbed into the model input; the client receives no helper-generated identity, release statement, or commitment to the source file and converted output.
- Router-owned tool execution likewise produces no client-visible tool attribution. Tool arguments and results become part of the router-managed model loop without a tool-enclave signature or commitment identifying the executing release.

Consequently, a client may be able to show separately that an acceptable endpoint exists, but not that it processed the inference, document, or tool call under the inspected hardware, model weights, key, and release epoch. For `doc-upload` and router-owned tools, the client additionally lacks a transaction-level statement identifying which helper participated and what input and output it handled.

#### Supply-Chain Consequences

The router selects the latest release tag, fetches its artifact digest and Sigstore bundle, verifies the bundle, and retains the tag and resulting measurement ([manager.go:927-L966](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L927-L966)). Status does not expose the digest or transparency material, and the router keeps no client-visible history of previously admitted releases.

Signed provenance authenticates a release path; it does not establish that every artifact produced by that path is benign. Relevant incidents demonstrate the needed attack primitives:

- A compromised ESLint maintainer account published malicious patch versions, including one unpublished after 36 minutes ([ESLint postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)).
- An authorized event-stream maintainer introduced a targeted encrypted payload that behaved harmlessly outside the victim environment and remained difficult to detect for months ([npm incident report](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)).
- A poisoned GitHub Actions cache caused malicious code to execute in a legitimate TanStack release runner and use its OIDC trusted-publisher capability; the publish workflow itself was not modified ([TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)).

Auditing the router source establishes how it validates this material, but not that every artifact subsequently emitted by an authorized backend or helper release path is benign. A similarly compromised accepted model, `doc-upload`, web-search, or code-execution release path could produce an internally valid measurement and provenance record without changing the router. For the converter or tool enclave, a compromised dependency can also be hidden inside a measurement whose parser or execution inventory is not exposed to the client. A targeted backend or helper could then handle normal audit traffic honestly while intercepting selected requests, files, or tool calls. External services contacted by a correctly measured tool can independently return malicious or targeted content. Without request-bound evidence or a durable admission log, later endpoint auditing may miss both the affected request and a short-lived release.

NEAR's design does not prevent an authorized workflow from producing a malicious artifact either, but it changes what the client can audit. Its model evidence exposes the digest-pinned backend compose manifest, and its model signing identity can be connected to both that evidence and a processing receipt. A client can therefore archive the exact artifact identity used in its trust decision, apply its own provenance policy, and link the selected backend identity to the request. Tinfoil already produces most of the underlying evidence; the gap is that cloud routing consumes it behind the router boundary instead of preserving it for the client and binding it to processing.

### Gap 2: EHBP Terminates at the Router and Expands the Trusted Surface

The shim creates EHBP middleware and applies it outside the handler that invokes the local workload proxy ([shim/api.go:194-L219](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/api.go#L194-L219)). The proxy director then targets local HTTP and removes the encapsulated-key header before forwarding ([shim/api.go:197-L206](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/api.go#L197-L206)).

The middleware calls `DecryptRequestWithContext`, installs the decrypted stream, prepares response encryption, and only then calls the next application handler ([identity/middleware.go:52-L123](https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/8528a8dc5ad45c213f14f9bab46a748fda7e18cc/identity/middleware.go#L52-L123)). The router README accurately summarizes that the router terminates TLS and optional EHBP before inspecting the model name and selecting an inference enclave ([router README](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/README.md#L1-L3)).

The router then exercises intentional plaintext features:

- It parses speech and multipart audio requests to select or default models ([main.go:630-L665](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L630-L665)).
- It fully reads and decodes generic OpenAI-compatible bodies, extracts router-only options, and resolves the model ([main.go:668-L723](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L668-L723)).
- It rewrites file inputs, strips or injects priority, injects cache-routing state, modifies streaming usage options, and re-marshals the request ([main.go:726-L831](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L726-L831)).
- It may execute router-owned tool loops before ordinary backend dispatch ([main.go:833-L864](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L833-L864)).

This is conclusive evidence that cloud EHBP provides confidentiality to the router, not through the router. The selected inference endpoint has its own HPKE key, but the cloud client never uses that key for its request body.

The key ownership follows directly from the boot path. `HPKEKeyPath` is private to CVM boot, egress, and shim processes ([boot/paths.go:15-L23](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/internal/boot/paths.go#L15-L23)). Boot loads or creates the identity and exports its public key ([boot/identity.go:38-L79](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/boot/identity.go#L38-L79)), binds it with the TLS key in CPU attestation ([boot/cpuattest.go:24-L33](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/boot/cpuattest.go#L24-L33)), and the shim loads the same private identity ([shim/main.go:146-L162](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/main.go#L146-L162)). In cloud routing those operations occur in the router CVM.

The first consequence is architectural: routing fans plaintext and delegated authority out to model, document, tool, billing, and control-plane services. The two following subsections then examine important and potentially surprising parts of that graph. Router-owned tools can provide network and execution paths even when a customer believes its agent is restricted, while inline-file handling exposes attacker-influenced bytes to router and document-processing code before inference begins.

#### Plaintext and Authority Fan Out to Additional Services

Router features expand the processing graph beyond the three-boundary processing diagram above:

```text
client or inference proxy
          |
          v
confidential router -+--> document-conversion enclave
                     +--> selected model enclave
                     +--> web-search / code-execution MCP enclaves
                     +--> control plane for delegation and usage reporting
```

The additional links have compensating controls but remain part of the trusted system:

- MCP sessions terminate at separate router-admitted and TLS-pinned tool enclaves ([http_client.go:231-L253](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/manager/http_client.go#L231-L253)). Those services receive model-selected arguments, tool-specific credentials or metadata, and an authorization credential. Web queries can contain prompt-derived secrets; fetched URLs and code-execution commands can exercise network, filesystem, or package-install behavior to the extent the downstream tool service permits it. Destination filtering, sandbox isolation, egress control, and SSRF prevention are therefore security properties of those other releases, not established by the router source alone.
- Inline file handling can decode and rewrite content in the router and send non-inline-text formats to `doc-upload`. The final subsection traces this path, including its parser, prompt-injection, and agent-mediated triggers.
- The router bounds incoming bodies at 64 MiB, but path-routed OpenAI requests are still fully read, decoded into generic maps, modified, and re-marshaled; file paths can additionally base64-decode and transform large content ([main.go:38-L38](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/main.go#L38), [main.go:91-L100](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/main.go#L91-L100), [main.go:688-L705](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/main.go#L688-L705)). Multiple in-memory representations, conversion work, and up to ten model/tool iterations create availability and cost-amplification risk in a shared, multi-tenant router even when confidentiality controls hold.
- The router-side tool mode increases the number of parsers, response transformations, internal requests, and security releases that can affect one inference. A vulnerability in the central router has a multi-model, multi-tenant blast radius; a malicious model response also becomes input to router JSON/SSE parsers and tool dispatch rather than being passed only to the requesting client.
- Production builds compile the local tool transcript logger out, which is an important mitigation. A binary deliberately built with the `toolruntime_debug` tag and run with debug mode can write prompt excerpts, model reasoning/content, tool arguments, and tool results to local files ([local_debug_disabled.go:1-L45](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/local_debug_disabled.go#L1-L45), [local_debug_enabled.go:85-L178](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/local_debug_enabled.go#L85-L178)). This should be documented as a prohibited production build/runtime combination and checked in release policy rather than presented as behavior of the normal release.

Attestation of the router authenticates the reviewed orchestration logic, not the code inside `doc-upload`, web search, code execution, or another helper. The router performs separate attestation and TLS-key admission for those helper enclaves, which protects their use according to router policy but does not make their measurements part of the client's router attestation. The client does not receive the helper evidence and therefore cannot prove which helper release participated in a particular request or bind helper outputs to that request; helper plaintext access also remains outside the selected model's boundary. The same "router verdict versus client-verifiable evidence" distinction therefore applies to model, document, and tool backends.

This graph is not merely a list of internal dependencies. Some of its branches expose capabilities that a customer may believe were excluded by its agent deployment. Router-owned tools are the clearest example.

#### Tinfoil Router Tools are Available to Self-Modifying Agents

The router's plaintext role is active, not merely observational. A request enables its server-side web-search or code-execution profile by including `web_search_options`, valid `code_execution_options`, or the corresponding Responses API tool type ([profile.go:79-L115](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/profile.go#L79-L115)). The router then opens an MCP session, injects the service's tool definitions into the model request, and treats returned calls with those names as router-owned ([session_registry.go:52-L117](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/session_registry.go#L52-L117), [tool_call.go:89-L151](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/tool_call.go#L89-L151)). This may be unexpected for customers that restricted an agent's ordinary internet tools or configured it to use only an inference API: router-side capabilities are activated by fields on that already-authenticated inference request and execute in Tinfoil helper services, outside the agent's local network boundary.

As detailed in [Gap 1](#gap-1-backend-and-helper-evidence-is-not-bound-to-request-processing), the client receives no tool-enclave evidence or tool-generated receipt for these calls. The additional Gap 2 concern is authority: after activation, model output can cause those separately operated services to perform network or code-execution actions under credentials and policy enforced beyond the client's verified boundary.

Activation and execution are separate steps. A model cannot enable a router profile merely by inventing a tool call: the authenticated request must enable it first. Once enabled, however, the model response drives execution. The router invokes matching calls, adds their results to model history, and can repeat the loop up to ten times without a fresh user confirmation or a separate non-model authorization decision ([tool_loop.go:103-L235](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/tool_loop.go#L103-L235)). Argument validation, prompt warnings, and optional prompt-injection or PII checks reduce risk but do not change who makes the execution decision ([prompt.go:13-L18](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/prompt.go#L13-L18), [websearch_options.go:325-L365](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/websearch_options.go#L325-L365)).

This creates two paths to an unwanted router action. First, after a profile was intentionally enabled, prompt injection, a converted document, malicious search content, model error, or a compromised backend can induce a matching call. Second, an agent with control over its host environment may be able to enable the profile in a later authenticated request even without knowing the provider or inference proxy API key: the framework accepts a model-controlled configuration change, then its existing client attaches the credential normally.

OpenClaw and Hermes Agent are the best examples of agents that can make use of Tinfoil Router Tools under either default or common deployment configurations:

- **OpenClaw exposes the path by default.** Its OpenAI-compatible client merges `extra_body` into requests, allowing the Tinfoil router tool fields to be added, while its default trusted-operator configuration leaves agent sandboxing off and permits gateway-host execution without approval. A model-controlled host action can therefore modify OpenClaw configuration to add Tinfoil's web-search or code-execution fields; model configuration hot-applies, so a later ordinary inference call carries them with the gateway-managed credential ([agent configuration](https://github.com/openclaw/openclaw/blob/main/docs/gateway/config-agents.md), [sandboxing](https://github.com/openclaw/openclaw/blob/main/docs/gateway/sandboxing.md), [exec approvals](https://github.com/openclaw/openclaw/blob/main/docs/tools/exec-approvals.md), [configuration and hot reload](https://github.com/openclaw/openclaw/blob/main/docs/gateway/configuration.md)). OpenClaw's typed administrative path requires approval, but that does not prevent raw host-file modification through the default unrestricted code execution tools.
- **Hermes supports the fields but normally requires approval to add them.** Its custom-provider `extra_body` values are merged into Chat Completions requests, and its default terminal backend runs locally. Current file tools nevertheless refuse direct writes to `~/.hermes/config.yaml`, while shell commands that modify that security-sensitive file enter the dangerous-command approval flow; the default approval mode requires a human decision ([provider documentation](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/integrations/providers.md), [request builder](https://github.com/NousResearch/hermes-agent/blob/main/agent/transports/chat_completions.py), [configuration](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/configuration.md), [file-tool protection](https://github.com/NousResearch/hermes-agent/blob/main/tools/file_tools.py), [approval protection](https://github.com/NousResearch/hermes-agent/blob/main/tools/approval.py), [security defaults](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/security.md)). Hermes can enable Tinfoil router-side tools automatically if approvals are weakened, the fields were already configured, or another model-writable configuration path is exposed.

These findings describe the frameworks' default trust models, not fixed properties of either framework. Enabling OpenClaw sandboxing, restricting host execution, and keeping configuration outside model-writable paths would mitigate access to Tinfoil router-side tools. Conversely, weakening, skipping, or misinterpreting Hermes approvals or using an alternate or mirrored configuration file path will enable access to Tinfoil router-side tools.

Code-execution credentials themselves are stripped before the model request, but the Tinfoil router attaches them to the MCP session ([options.go:53-L147](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/options.go#L53-L147), [profile.go:118-L143](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/toolruntime/profile.go#L118-L143)). A manipulated model can therefore exercise the delegated authority without seeing or printing the credential. The combination of authenticated profile activation followed by model-directed tool execution is the source of agent framework risk with respect to access to Tinfoil's router-side tools. Ordinary client-declared function tools remain the client's responsibility and are not generally executed by this router runtime.

Router-owned tools show how the fan-out can bypass assumptions about an agent's local capabilities or internet access ability. Inline file processing exposes a different aspect of the same graph: untrusted bytes are decoded and sometimes dispatched to another helper before they become model input.

#### Inline Files Expose a Document-Parsing and Prompt-Injection Surface

The router recognizes inline files in both supported OpenAI request shapes. For the Responses API it walks `input[].content[]` for `type: "input_file"` parts containing `filename` and `file_data`. For Chat Completions it walks `messages[].content[]` for `type: "file"` parts with the same fields nested under `file`. The traversal does not restrict processing to user-role messages. An authenticated caller can therefore reach this path through an ordinary user upload or through any client-managed history item that the client serializes in the recognized shape. The router rejects `file_id` in this path and requires inline data, so an OpenAI file identifier or URL alone does not trigger it ([responses_file_inputs.go](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/responses_file_inputs.go)).

`file_data` may be raw padded or unpadded base64, or a `data:<media-type>;base64,...` URL. After decoding, the router uses attacker-supplied filename and media type together with a UTF-8 check to choose the next operation. Text-like content is converted directly to a string and inserted into the model request under an attachment heading. Other content is copied into an in-memory multipart request and sent to a separately admitted `doc-upload` enclave for Markdown conversion, OCR, vision processing, page rendering, or raw conversion according to the selected mode. Returned Markdown is inserted as model-visible text; image mode returns page text and base64 page images that the router rewrites into model content parts ([responses_file_inputs.go](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/responses_file_inputs.go), [file_inputs.go:101-L222](https://github.com/tinfoilsh/confidential-model-router/blob/f8355f7b076e3d2fdc6417595f70efa5769b2404/manager/file_inputs.go#L101-L222)). A caller can also reach the converter directly through the authenticated multipart `/v1/convert/file` route without using the JSON base64 wrapper.

As established in [Gap 1](#gap-1-backend-and-helper-evidence-is-not-bound-to-request-processing), `doc-upload` has a distinct, router-enforced attestation boundary: its measured release may commit to bundled parser code, but neither that evidence nor a helper-authenticated conversion receipt reaches the client. The additional Gap 2 consequence is exposure. The router and converter receive the file as plaintext, and the client cannot exclude their decoding and parsing code from the trusted surface while retaining automatic cloud conversion.

This creates several distinct vulnerability classes:

- **Router availability.** Base64 is not itself a likely native-code exploit surface in Go, but it causes the router to retain the encoded JSON string, decoded bytes, rewritten object graph, re-marshaled body, and, for binary files, an additional multipart copy. The 64 MiB incoming-body limit bounds the encoded request rather than the complete working set. Repeated file parts, concurrent requests, and clients that resend the original attachment in history amplify memory and conversion work.
- **Document-parser compromise or exhaustion.** The router does not establish a magic-number or format allowlist before dispatching non-text bytes. Mislabeled, malformed, polyglot, compressed, deeply nested, or computationally pathological documents can therefore reach the converter. Relevant vulnerability classes include defects in PDF, archive, image, font, OCR, and document-library dependencies; decompression or output expansion; and excessive CPU, memory, or conversion time. The public router source establishes this reachability but does not identify the private `doc-upload` parser stack, so it cannot by itself establish that a particular parser CVE is exploitable.
- **Credential and plaintext exposure in another workload.** The router forwards both the decoded document and the request authorization header to `doc-upload`. Process separation means a parser exploit does not automatically compromise the router process, but the helper still receives sensitive plaintext and a credential and is part of the product trust boundary.
- **Unbounded or amplified helper output.** The reviewed conversion client reads the complete helper response before JSON decoding. Large Markdown or page-image results can therefore expand memory use again inside the shared router.
- **Prompt injection after successful conversion.** Converted document text is not merely returned to the caller; it becomes input to the selected model. Instructions embedded in an untrusted PDF, office document, or other attachment can consequently influence model behavior and, when tools are enabled, induce downstream actions or disclosure. Parser isolation does not address this semantic attack.

The trigger boundary is important. A model response cannot directly enter this path merely by printing an `input_file`-shaped object, and the router's own web-search and code-execution results are appended as strings inside an internal loop that does not re-run the incoming-file rewrite. A model can nevertheless trigger conversion indirectly when its host agent executes a file-producing or file-reading tool and serializes the result into a later authenticated request. The OpenAI Agents SDK makes this concrete: a model-invoked function tool can return `ToolOutputFileContent`, which the SDK turns into a Responses `input_file` block and populates with `file_data` when provided ([file-returning function tools](https://openai.github.io/openai-agents-python/tools/#returning-images-or-files-from-function-tools), [tool-output serialization](https://openai.github.io/openai-agents-python/ref/items/)). LangChain likewise supports base64 PDF content and translates its standard file block into the Chat Completions `type: "file"` and `file_data` shape recognized by the router ([LangChain multimodal inputs](https://docs.langchain.com/oss/python/integrations/chat/openai#multimodal-inputs-images-pdfs-audio)). In these cases the model selects or influences a tool, but the agent runtime supplies the authenticated request and the bytes.

OpenClaw and Hermes do not appear to turn their ordinary text-returning file tools into these raw file blocks by default. OpenClaw's documented attachment-extraction path marks extracted file text as external and untrusted and states that PDF fallback page images are not forwarded to the model ([OpenClaw media understanding](https://github.com/openclaw/openclaw/blob/main/docs/nodes/media-understanding.md)). Hermes describes file reads, web fetches, email, gateway messages, MCP responses, and tool results as untrusted input surfaces, while its standard file and terminal results are ordinarily textual ([Hermes trust model](https://github.com/NousResearch/hermes-agent/security)). For either framework, a plugin, provider adapter, custom tool, or model-controlled host action that constructs a recognized inline-file request can still reach Tinfoil conversion. Capability to create the request should not be confused with automatic conversion of every inbound attachment.

The same attachment therefore behaves materially differently under the three product boundaries:

- **Current cloud routing:** the client encrypts to the router. The router decrypts and base64-decodes the file, may send it and the authorization header to `doc-upload`, injects converted text or images into the model request, and then forwards a newly protected request to the inference enclave. The router, converter, and inference endpoint all participate in processing the attachment, while the client verifies only the router boundary directly.
- **Direct inference:** the client verifies and connects to the selected inference enclave, so neither the router nor `doc-upload` receives the body. A router-specific inline document request is not automatically converted and may be rejected unless that inference release natively implements the format. The client must instead pre-convert the document into model-native text or images, or deliberately select an inference release whose attested code includes an acceptable parser. In the former case the parser is client-side; in the latter it is part of the client-verified inference boundary.
- **End-to-end EHBP through a router:** the client verifies the selected inference endpoint and encrypts the protected body to that endpoint's HPKE key. An opaque router cannot inspect `file_data`, choose a conversion mode, invoke `doc-upload`, or rewrite the result. File handling must therefore follow the same choices as direct inference: client-side conversion or an explicitly attested backend parser. The router may retain routing metadata, but its parser and helper-service surface is cryptographically excluded from protected attachment content.

Losing transparent router conversion in direct and opaque-EHBP modes is not a regression in the security property; it is the mechanism that removes the router and document helper from the attachment's plaintext and parser trust boundary. Tinfoil can offer both behaviors, but the product should present them as an explicit feature-versus-boundary choice rather than suggesting that the same confidentiality guarantee applies to automatic cloud file handling.

---

## Remediation

The confidentiality and integrity gaps require separate changes. Publishing evidence does not remove router plaintext, and backend encryption alone does not provide a durable release and processing record. For Gap 2, controls inside the router cannot remove the router from the vulnerability surface; the architectural remedy is to let the client address EHBP to the inference endpoint or connect to that endpoint directly.

### 1. Provide End-to-Inference EHBP and Preserve Direct Access

Clients that do not accept the router's plaintext and code surface need a mode in which EHBP terminates at the selected inference endpoint. The client should verify the backend's own fresh attestation, bind EHBP to its HPKE key, and then either send that opaque envelope through a router that cannot decrypt it or connect directly to the per-model enclave.

Direct access is the simplest realization because the endpoint decrypting the request is also the endpoint whose CPU, GPU, software, and keys the client verified. Opaque routed EHBP can retain gateway reachability and model selection, but it requires a selection handshake and a request envelope that separates router-visible routing metadata from backend-confidential content. In either form, router-owned rewriting, file conversion, tools, and content-derived cache routing must be disabled or moved to the client or backend; retaining them would retain the router plaintext boundary the mode is meant to avoid.

### 2. Staple Downstream Evidence and Processing Receipts

Cloud responses should carry evidence for the inference backend that handled the request:

- stable backend identity and hostname;
- fresh client-nonce-bound CPU, GPU, and applicable NVSwitch evidence;
- attested TLS fingerprint and HPKE key;
- release digest, tag, signing identity, and transparency evidence;
- a backend-authenticated receipt covering a request commitment, response commitment, attestation epoch, and release digest.

When document conversion or a router-owned tool participates, the response should also staple that helper's identity, attestation epoch, release and provenance evidence, and a helper-authenticated receipt covering its call arguments or source-file commitment, result commitment, and parent inference-request commitment. Tool receipts should identify relevant external destinations and services while making clear that enclave attestation does not authenticate their content.

A router signature over its routing decision is useful for accountability but cannot replace downstream receipts: it remains an assertion by the component whose enforcement is being audited. This stage would let clients verify which model and helper workloads participated while leaving the router in the plaintext trusted computing base.

NEAR's `provider_tee` signature is a concrete precedent for this stage: an attested model signing identity authenticates the model ID together with request and response hashes. Tinfoil could adopt the same pattern while additionally covering its release digest and attestation epoch.

### 3. Implement Opaque Routed EHBP

When clients retain the cloud entry point instead of connecting directly, removing router plaintext requires a two-stage protocol:

1. The router selects a backend and returns its fresh attestation and HPKE key.
2. The client verifies the evidence and encrypts inference content to that backend key.
3. The router forwards the opaque body.
4. The backend decrypts it and authenticates its response and processing receipt.

The request envelope must separate router-visible routing metadata from backend-confidential inference content. Existing router features that inspect or rewrite prompts, files, tool options, priority, usage settings, or cache state would need privacy-preserving redesign, relocation to the client/backend, or explicit exclusion from this mode.

NEAR's E2EE gateway path is a concrete precedent for this separation. The client obtains a model-attested public key, sends the selected key as routing metadata, encrypts sensitive fields to that key, and supplies a client key for the model's encrypted response. The gateway retains model selection and routing while losing authority to decrypt the protected fields.

### Deployment Priority

| Stage | Change | Security gained | Residual gap |
|---|---|---|---|
| 1 | Document the actual boundary and preserve direct inference | Accurate claims and a router-bypassing option for sensitive workloads | Routed cloud mode still sees plaintext; no cloud processing proof |
| 2 | Staple fresh model/helper evidence and downstream receipts | Request-bound participation integrity and durable release evidence | Router and invoked helpers still see plaintext |
| 3 | Address EHBP to the backend, routed opaquely or sent directly | Router, its tool runtime, and helper-service fan-out removed from the protected-content boundary | Router-visible routing metadata remains in scope for opaque routing |

Until stages 2 and 3 exist, cloud mode should be described as router-attested body confidentiality, router-enforced downstream admission and TLS pinning, model-boot-enforced GPU validation, and out-of-band endpoint auditing, rather than client-verified downstream processing or end-to-inference encryption. Tool-enabled cloud mode should additionally be described as delegating actions within the helper service's controls to model-generated calls. Client-side field rejection, credential separation, user confirmation, and least-privilege tool policy can reduce accidental activation or abuse, but they are defense in depth for clients that remain in router mode; they do not remediate the router's plaintext or vulnerability surface.

---

## References

**Tinfoil source code:**

- [cvmimage at `282479badb65e7b866afd733cf586367c0599911`](https://github.com/tinfoilsh/cvmimage/tree/282479badb65e7b866afd733cf586367c0599911)
- [confidential-model-router at `91c9bbe971046c93bacb4b889a10595399ce7be8`](https://github.com/tinfoilsh/confidential-model-router/tree/91c9bbe971046c93bacb4b889a10595399ce7be8)
- [confidential-model-router tool-runtime review at `f8355f7b076e3d2fdc6417595f70efa5769b2404`](https://github.com/tinfoilsh/confidential-model-router/tree/f8355f7b076e3d2fdc6417595f70efa5769b2404)
- [encrypted-http-body-protocol at `8528a8dc5ad45c213f14f9bab46a748fda7e18cc`](https://github.com/tinfoilsh/encrypted-http-body-protocol/tree/8528a8dc5ad45c213f14f9bab46a748fda7e18cc)
- [tinfoil-js at `50e664521d69f45de84c494b1fdca2131465d028`](https://github.com/tinfoilsh/tinfoil-js/tree/50e664521d69f45de84c494b1fdca2131465d028)
- [tinfoil-go at `173ed2fb593ba8cebab1f97a32f114395153c083`](https://github.com/tinfoilsh/tinfoil-go/tree/173ed2fb593ba8cebab1f97a32f114395153c083)

**Agent framework capability surfaces:**

- [OpenAI Agents SDK file-returning function tools](https://openai.github.io/openai-agents-python/tools/#returning-images-or-files-from-function-tools)
- [OpenAI Agents SDK tool-output serialization](https://openai.github.io/openai-agents-python/ref/items/)
- [LangChain OpenAI multimodal file inputs](https://docs.langchain.com/oss/python/integrations/chat/openai#multimodal-inputs-images-pdfs-audio)
- [OpenClaw media and document understanding](https://github.com/openclaw/openclaw/blob/main/docs/nodes/media-understanding.md)
- [Hermes Agent custom-provider request bodies](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/integrations/providers.md)
- [Hermes Agent Chat Completions request builder](https://github.com/NousResearch/hermes-agent/blob/main/agent/transports/chat_completions.py)
- [Hermes Agent configuration and terminal defaults](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/configuration.md)
- [Hermes Agent file-tool configuration protection](https://github.com/NousResearch/hermes-agent/blob/main/tools/file_tools.py)
- [Hermes Agent command-approval protection](https://github.com/NousResearch/hermes-agent/blob/main/tools/approval.py)
- [Hermes Agent security defaults](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/security.md)
- [Hermes Agent trust model](https://github.com/NousResearch/hermes-agent/security)
- [OpenClaw agent request parameters](https://github.com/openclaw/openclaw/blob/main/docs/gateway/config-agents.md)
- [OpenClaw configuration and hot reload](https://github.com/openclaw/openclaw/blob/main/docs/gateway/configuration.md)
- [OpenClaw sandboxing defaults](https://github.com/openclaw/openclaw/blob/main/docs/gateway/sandboxing.md)
- [OpenClaw exec-approval defaults](https://github.com/openclaw/openclaw/blob/main/docs/tools/exec-approvals.md)

**Supply-chain incidents:**

- [ESLint malicious package postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)
- [npm event-stream incident report](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)
- [TanStack npm supply-chain compromise postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)

**NEAR AI comparison:**

- [NEAR AI model verification](https://docs.near.ai/cloud/verification/model/)
- [NEAR AI end-to-end encrypted chat completions](https://docs.near.ai/cloud/guides/e2ee-chat-completions/)
- [NEAR AI chat message verification](https://docs.near.ai/cloud/verification/chat/)
- [NEAR AI private inference and direct completions](https://docs.near.ai/cloud/private-inference/)
- [nearai-cloud-verifier at `6a9c0c57dd9b2b47bbd2682df4a685c50210096e`](https://github.com/nearai/nearai-cloud-verifier/tree/6a9c0c57dd9b2b47bbd2682df4a685c50210096e)
- [NEAR AI documentation source at `e94e73f938cb4852c6d3ab274dad35c345a9e3ff`](https://github.com/nearai/docs/tree/e94e73f938cb4852c6d3ab274dad35c345a9e3ff/docs/cloud)

---

## Teep Status

Teep defines two Tinfoil provider aliases with materially different verification subjects. Both use the fail-closed V3 attestation path, but a passing factor means only that the endpoint named in the corresponding column was verified. `tinfoil_v3_direct` has been disabled since 2026-11-12, because Tinfoil's enclave hosts did not answer attestation requests. Teep therefore has no Tinfoil route that excludes the router. To enable direct mode again, Teep must also read GPU and NVSwitch evidence: today it refuses an enclave that serves device evidence, and without device evidence the enforced `nvidia_payload_present` and `cpu_gpu_chain` factors fail. The `tinfoil_v3_direct` column below describes the direct-mode design, not a route that serves requests.

For `tinfoil_v3_cloud`, Teep accepts only a SEV-SNP router report and reports it in the Tier 4 `gateway_*` factors. Every gateway factor that applies to SEV-SNP is enforced, except `gateway_tee_cert_chain` and `gateway_tee_quote_signature`, which need a request to AMD KDS and are allowed to fail by default. The router answer carries no backend evidence, so the backend `tee_*` factors, `nvidia_payload_present`, `nvidia_signature`, `nvidia_claims`, `cpu_gpu_chain`, `nvswitch_binding` and `measured_model_weights` fail or skip, allowed by default. `cpu_id_registry` also fails, allowed by default. `nvidia_nonce_client_bound` and `nvidia_nras_verified` are not applicable. On 2026-11-14 the reports of all 14 `tinfoil_v3_cloud` models showed this pattern, and no enforced factor failed.

| Property | `tinfoil_v3_cloud` | `tinfoil_v3_direct` |
|---|---|---|
| Endpoint Teep attests | Confidential model router | Selected per-model inference enclave |
| Fresh hardware evidence Teep verifies | Router CPU evidence (SEV-SNP) | Selected backend's CPU evidence only (see above) |
| Supply-chain release Teep verifies | `tinfoilsh/confidential-model-router` | Per-model deployment repository returned by discovery |
| `measured_model_weights` result | Always `Fail` (allowed by default): no backend quote | `Pass` means direct trust: the selected backend's measured configuration matches its per-model Sigstore release and commits to the model volume's dm-verity root |
| Attested TLS and HPKE keys | Router keys; EHBP plaintext is available to the router workload | Selected backend keys; EHBP terminates in the inference enclave |
| Data-plane authentication visible to Teep | Request and response are AEAD-authenticated to the router boundary | Request and response are AEAD-authenticated to the selected inference-enclave key |

In `tinfoil_v3_cloud`, Teep can therefore establish that an expected, freshly attested router release received the request and was programmed to enforce Tinfoil's backend policy. Backend CPU admission and TLS pinning remain router-enforced, GPU validation remains backend-boot-enforced, and status plus endpoint bundles remain out-of-band audit inputs. None of the router's passing factors should be reported as Teep having independently verified the identity, freshness, GPU state, release, or model weights of the backend selected for a request.

Teep currently applies Tinfoil EHBP to the complete request body and does not interpret or deny router-specific tool controls. Consequently, `tinfoil_v3_cloud` can invoke the router's tool runtime whenever the caller body activates it. Teep attests the router, not the `websearch`, `code-execution`, or `doc-upload` enclave selected during that request, and it receives no helper-enclave execution receipt. A Teep deployment that intends to prohibit server-side actions must enforce that as request policy; attestation alone does not disable them.

### Teep Boundary Selection for Router Risk

The architectural mitigation is direct mode, which `tinfoil_v3_direct` implements and which is disabled (see above): it addresses both TLS and EHBP to the selected inference endpoint and bypasses the confidential model router, including its plaintext parsers, rewriting logic, owned-tool loop, and helper-service fan-out. If Tinfoil later supports opaque routed EHBP, Teep could retain a cloud entry point while binding the body to the backend key; until then, cloud and direct mode are distinct trust-boundary choices.

A `tinfoil_v3_cloud` deployment may still reject router-specific tool controls before EHBP encapsulation and isolate authenticated request construction from model-controlled configuration. Such filtering can prevent unwanted use of known router profiles, but it is only defense in depth: it neither removes the router from the plaintext path nor eliminates vulnerabilities in the rest of its request-processing surface. Teep should therefore present direct mode, not tool-capability policy, as the remedy for clients that do not accept the router boundary.

In direct mode, Teep checks the inference boundary itself. It resolves the requested model to a backend domain and per-model deployment repository, obtains a client-nonce-bound attestation from that backend, validates its CPU evidence, and compares its measured configuration with the authenticated Sigstore release for that model deployment. The release-authenticated configuration commits to a particular read-only model-weight volume through its dm-verity root; the measured boot chain authenticates that configuration, and dm-verity validates blocks as the inference runtime reads the weights. Teep then pins the live TLS connection and EHBP encryption to keys from the same backend attestation. Taken together, these checks are designed to establish that the selected enclave authorized to decrypt and serve the request is running the specific model deployment release and committed model-weight volume that Teep verified, rather than merely establishing that an acceptable backend exists somewhere behind an attested router.

The model-weight conclusion is deliberately transitive: Teep does not download and hash every weight file itself. It verifies `Sigstore release -> measured configuration -> dm-verity root`, while the attested kernel enforces the final block-level checks. A failure or skip anywhere in that chain must prevent Teep from reporting the model weights as verified.

Direct mode closes the router-boundary gaps, but it does not produce a durable backend-signed receipt over the request and response. Users requiring end-to-inference body encryption, direct verification of fresh backend hardware evidence, or verification of the specific model-weight release used must reject `tinfoil_v3_cloud`; Teep has no Tinfoil route for them today. Users requiring backend-authenticated request attribution for later audit must wait until Tinfoil adds a request-bound backend signature or equivalent protocol evidence, or use NEAR AI.
