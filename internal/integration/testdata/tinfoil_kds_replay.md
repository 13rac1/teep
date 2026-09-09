# Tinfoil KDS collateral replay provenance

This note applies to `tinfoil_v3_cloud_llama3-3-70b_20260816_230540` and
`tinfoil_v3_cloud_glm-5-2_20260817_003424`.

The attestation, nonce, evidence timestamp, certificate body, and response
headers retain their original August 2026 capture values. The VCEK response
was originally obtained from `kdsintf.amd.com`.

The VCEK replay URL now uses `kds-proxy.tinfoil.sh` to match current Tinfoil
certificate retrieval. Transport metadata was removed from that adapted
record: it does not describe a captured proxy connection. The response filename
retains the original source. The old signing-chain capture is retained as
historical evidence; verification now uses the embedded AMD chain.

A September 8, 2026 live proxy probe negotiated TLS 1.3 and HTTP/2. Its VCEK
certificate had the same public key but a later validity period, so it does
not replace the original certificate used with this historical evidence.
