# Phala Cloud Stream Endings

This table lists every way a streamed Phala Cloud response can end in
`teep serve`, who can cause the ending, whether teep checks the receipt,
against which bytes, and whether the authorization generation ends. It is
the reference for the receipt rules in
[Phala Cloud provider support](phalacloud_support.md#receipts) and the
[retry contracts](../../transport/retries.md). A non-stream response and the
`teep verify` probe follow at the end.

"Content" means at least one upstream line other than a blank separator was relayed to the client: a data chunk (`Chunks`) or a comment, `event:`, `id:` or `retry:` line (`Forwarded`).
"Full" means teep read the rest of the response from the gateway (`finishWithin`, its own 30 s bound, body closed at the bound); the receipt fetch then has its own 30 s bound. The upstream request runs 30 s past teep's attempt deadline, which bounds the relay and the writes, so a full read works after that deadline too. A stream must end within those 30 s and within 1 MiB after the relay stopped; a longer one is the gateway's failure, also when honest.
"Read" means the bytes read before a read error (`Received`).
"Client-ended" means positive evidence only (`endedByClient`): the relay error is the downstream write error, or the error of the incoming request's own context, which has ended.

| # | Ending | Who can cause it | Receipt checked | Against which bytes | Generation ends |
|---|---|---|---|---|---|
| 1 | Clean end, receipt verifies | gateway (normal) | yes | full | no |
| 2 | Clean end, receipt fails a service statement (signature, keyset, served_at, response hash, cited session) | gateway | yes | full | yes |
| 3 | Clean end, receipt names another endpoint, method or model | gateway | yes | full | yes |
| 4 | Clean end, receipt request hash differs | gateway, or a request form teep cannot reproduce | yes | full | no |
| 5 | Clean end, receipt not served (404 on 3 attempts, other status, connection failure) | gateway or network | fetch fails | n/a | yes |
| 6 | Clean end, malformed receipt, or a receipt of another id | gateway | yes | full | yes |
| 7 | HTTP 200 without one valid X-Receipt-Id | gateway | no (refused before the relay) | n/a | yes |
| 8 | Response names another keyset digest | gateway | no (refused before the relay) | n/a | yes |
| 8a | HTTP 2xx other than 200 (201, 202, 203, 206, …), any body | gateway, or a backend status that the gateway passes through | no (refused before the relay) | n/a | yes |
| 8b | HTTP 3xx | gateway | no (refused as a redirect before the relay) | n/a | no |
| 8c | HTTP 4xx or 5xx, or a 412 that is not the session-refusal envelope | gateway or backend (status passed through) | no | n/a | no; status, headers and up to 10 MiB of the body are relayed as the gateway's error answer, stream and non-stream |
| 9 | Reset or parse failure before any upstream line reached the client | gateway or network | no | n/a | no. The client gets teep's own error event or 502; no upstream header or body line reached it (headers are copied only after the pre-relay checks) |
| 9a | A comment, `event:`, `id:` or `retry:` line, then a reset, before any data line | gateway | yes | read | yes, unless the receipt covers exactly what arrived |
| 10 | Reset or cut during content | gateway or network | yes | read (the rest cannot be read) | yes, unless the receipt covers exactly what arrived |
| 11 | Reset after [DONE] | gateway | yes | read = every byte sent | no if the receipt verifies |
| 12 | Content, then a stream that does not parse (error event, error object, non-JSON data, line over 1 MiB, data after [DONE]) | gateway, or a model backend through an honest gateway (non-event records and JSON without `choices` pass the gateway unchanged) | yes | full (tail read 30 s, then the receipt fetch 30 s) | no if the gateway signed what it sent; yes otherwise. Open: after a failure the gateway sends nothing more but may hold the connection and delay or suppress the receipt until the backend reaches EOF (gateway docs/api-reference.md:297-320); a receipt that is not published within the fetch's 3 attempts ends the generation |
| 12a | As 12, and the client hangs up while teep reads the rest | client, after a gateway failure | yes if teep claimed the attempt for the tail read first (tailHold); no if the client's end came first (then as row 17) | full | no for an honest gateway either way; yes if the receipt does not cover the full stream. Both orders are pinned by tests |
| 13 | Content, then a chunk that does not decrypt | gateway | yes | full | yes (response_decryption ends it as before) |
| 13a | [DONE], then an open connection with comment lines | gateway | as rows 1-6 once the gateway closes (FinishSSE reads to EOF before teep writes [DONE] downstream, so the client does not see [DONE] until then); if the client gives up first, row 14 | full | as rows 1-6 |
| 14 | Content, then the gateway stops sending until the client gives up | gateway or a slow backend | yes, after the client left (drain) | read until the drain bound (2 min, 16 MiB from the client's end) | yes, unless the gateway ends and its receipt verifies within the bound |
| 15 | Content, then the gateway stops sending until teep's own attempt deadline (30 min), client still connected | gateway | yes | full if the gateway ends within 30 s after it, else read | no if the gateway signed what it sent and ended in time; yes otherwise |
| 15a | A write to the client fails on the write deadline (teep's attempt deadline), client still connected (a slow reader, or an honest stream still sending at the 30-minute mark) | client's reading or the stream's length, not a client end | yes | full (the upstream request runs 30 s longer) | no if the gateway signed what it sent and ended within the 30 s; yes otherwise |
| 16 | Client hangs up before any content | client | no | n/a | no |
| 17 | Client hangs up after content, before the read from the gateway ended | client | yes, after teep reads the rest (drain) | full within the drain bound | only on a failure the gateway causes (a stall past the bound, a receipt not served or not verified) |
| 18 | Client hangs up after the read from the gateway ended (after [DONE]) | client | yes (server context) | full | only on a failure the gateway causes |
| 19 | Client deadline passes during content (not reachable in teep serve: the incoming request has no deadline, so a client timeout is row 17) | client | as row 17 | as row 17 | as row 17 |
| 20 | Downstream write or flush fails after content, before the client's request context ends | client or network | no | n/a | no; logged. If the client's context ends first, row 17 |

## Non-stream Phala responses (held until the check passes)

| Ending | Receipt checked | Generation ends | Client gets |
|---|---|---|---|
| Clean, receipt verifies | yes, full | no | the response |
| Receipt fails a service statement, malformed, or no X-Receipt-Id | yes | yes | an error |
| Receipt names another endpoint, method or model; request hash differs; receipt not served | yes | no | an error |
| Relay error of any kind | no | no (only response_decryption ends it) | an error, nothing of the body |

## teep verify probe (aci_receipt_verified)

| Ending | Factor |
|---|---|
| Not HTTP 200, another keyset digest, or not an event stream | deferred Skip; e2ee_usable fails |
| Any other outcome without a verified receipt: missing id, reset, no [DONE], chunk that does not decrypt, receipt not served or failed, receipt request failed | enforced Fail (receipt over the full response where readable, else the bytes read) |
| Receipt verifies, stream failed after it | Pass; e2ee_usable fails |
| No API key, --offline, report blocks inference, --reverify of a recorded pass | deferred Skip with the reason |
