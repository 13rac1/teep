package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/e2ee"
	"github.com/13rac1/teep/internal/e2ee/aciv2test"
	"github.com/13rac1/teep/internal/provider"
	"github.com/13rac1/teep/internal/provider/aci"
	"github.com/13rac1/teep/internal/provider/phalacloud"
	"github.com/13rac1/teep/internal/tlsct/testtls"
	"golang.org/x/net/http2"
)

// authorizedSessionID stands for the attested session that the
// authorization pinned.
const authorizedSessionID = "4d849e211f7078bd8d27a748a7ac0ddfe164d2ef5c0e29e6e30292a371276320"

// phalaCase is one exchange of TestAuthorizedPhalaCloudACIv2.
type phalaCase struct {
	name   string
	served string // X-ACI-Keyset-Digest; "" for none
	refuse bool   // answer session_not_accepted
	plain  bool   // the client asks for a non-stream response
	// receipt changes the receipt that the gateway signs; noReceiptID
	// leaves out X-Receipt-Id, and receiptMissing answers HTTP 404 on
	// every receipt GET.
	receipt        func(*aciv2test.Receipt)
	noReceiptID    bool
	receiptMissing bool
	// resetAfterDone sends the whole stream, [DONE] included, and then
	// resets the HTTP/2 stream instead of ending it. resetAfterFirst
	// resets it after the first content chunk; the receipt still covers
	// the whole response, as when the network cuts an honest stream.
	resetAfterDone  bool
	resetAfterFirst bool
	// pauseAfterFirst holds the stream after its first content chunk for
	// longer than a short caller deadline (callerDeadline).
	pauseAfterFirst bool
	callerDeadline  time.Duration
	// clientCancelOn cancels the client's request context once the
	// client has been written a body that contains it: the client hangs
	// up.
	clientCancelOn string
	// tailAfterFirst follows the first content chunk with these bytes and
	// holds the connection open for a while before it closes, so that the
	// relay fails while parsing, not reading.
	tailAfterFirst string
	// signTail signs the receipt over the bytes served with the tail.
	signTail bool
	// laterTail is sent 300 ms after the tail, and is part of the signed
	// response when signTail is set.
	laterTail string
	// hangUpBeforeLaterTail ends the client's request just before the
	// gateway sends laterTail, while teep reads the rest of the stream.
	hangUpBeforeLaterTail bool
	hangUp                *atomic.Pointer[context.CancelFunc]
	// commentThenReset sends one SSE comment line and then resets the
	// stream, before any data line.
	commentThenReset bool
	// resetBeforeLine sends the response headers and then resets the
	// stream, before any line.
	resetBeforeLine bool
	// wantNoGatewayHeader requires that no upstream header reached the
	// client.
	wantNoGatewayHeader bool
	// downstreamFailOn makes the write to the client fail once the body
	// written so far contains it.
	downstreamFailOn string
	// status answers with this 2xx status and a plaintext body instead of
	// the encrypted stream.
	status int
	// modelNumber sends the request with a model that is not a string.
	modelNumber bool
	// duplicateMember sends a request body with a duplicate member in a
	// member that teep does not read.
	duplicateMember bool
	// attemptTimeout replaces teep's stream attempt deadline.
	attemptTimeout time.Duration
	// slowReader stops reading after the first content chunk: every later
	// write blocks until the write deadline and fails on it.
	slowReader bool
	// hangUpBeforeTailClaim ends the client's request just before teep
	// claims the tail read, and waits until that end abandoned the attempt.
	hangUpBeforeTailClaim bool
	// wantNoReceiptGET requires that no receipt GET was sent.
	wantNoReceiptGET bool
	// receiptDelay answers HTTP 404 to the receipt GET until this long
	// after the chat request started.
	receiptDelay time.Duration
	// drainTimeout and drainBytes replace teep's drain bounds;
	// maxElapsed bounds how long the request may take.
	drainTimeout time.Duration
	drainBytes   int64
	maxElapsed   time.Duration
	wantErr      bool
	// wantReceiptGET requires at least one receipt GET.
	wantReceiptGET bool
	wantRelayed    bool
	ended          bool
}

// A Phala Cloud request on the pinned path is encrypted with E2EE v2 to the
// authorized gateway key, pins the authorized attested sessions, goes to the
// attested TLS key, and its response decrypts. The keyset digest of the
// response decides whether the authorization generation stays: the verified
// digest keeps it; another digest or no digest fails the request before
// teep relays it, and ends the generation. A refusal of the pinned sessions (session_not_accepted) fails
// the attempt and ends the generation, so the next attempt verifies the
// sessions again.
//
// Every successful response must have a receipt that verifies (ACI/1
// §9.3). A non-stream response reaches the client only after its receipt
// verifies; a stream reaches the client as it arrives. A receipt whose
// service statements do not verify fails the request and ends the
// generation. A receipt that the gateway does not serve, or whose
// statements about the request differ from it, fails the request and keeps
// the generation: one client's request must not end the authorization that
// every client shares.
func TestAuthorizedPhalaCloudACIv2(t *testing.T) {
	testtls.RunWithFallbackRoot(t, func(t *testing.T, authority *testtls.Authority) {
		t.Helper()
		otherResponse := func(r *aciv2test.Receipt) { r.Response = []byte("other") }
		for _, tc := range []phalaCase{
			{name: "verified digest", served: testKeysetA, wantRelayed: true},
			{name: "verified digest, non-stream", served: testKeysetA, plain: true, wantRelayed: true},
			{name: "other digest", served: testKeysetB, wantErr: true, ended: true},
			{name: "no digest", wantErr: true, ended: true},
			{name: "sessions refused", served: testKeysetA, refuse: true, wantErr: true, ended: true},
			{name: "no receipt id", served: testKeysetA, noReceiptID: true, wantErr: true, ended: true},
			{name: "receipt not served", served: testKeysetA, receiptMissing: true, wantErr: true, wantRelayed: true, ended: true},
			{name: "receipt not served, non-stream", served: testKeysetA, plain: true, receiptMissing: true, wantErr: true},
			{name: "receipt of other response", served: testKeysetA, receipt: otherResponse, wantErr: true, wantRelayed: true, ended: true},
			{name: "receipt of other response, non-stream", served: testKeysetA, plain: true, receipt: otherResponse, wantErr: true, ended: true},
			{name: "receipt of other request", served: testKeysetA, plain: true, receipt: func(r *aciv2test.Receipt) { r.Request = []byte("{}") }, wantErr: true},
			{name: "receipt of other model", served: testKeysetA, plain: true, receipt: func(r *aciv2test.Receipt) { r.Model = "other" }, wantErr: true},
			// For a stream, which reached the client, a receipt that names
			// another model ends the generation; one over another request
			// (the client's choice) keeps it.
			// A 2xx status other than 200 is not an answer that teep can
			// check: it is refused before anything reaches the client, and
			// the generation ends.
			{name: "HTTP 201 with a plaintext stream", served: testKeysetA, status: http.StatusCreated, wantErr: true, ended: true},
			{name: "HTTP 203 with a plaintext body, non-stream", served: testKeysetA, plain: true, status: http.StatusNonAuthoritativeInfo, wantErr: true, ended: true},
			{name: "receipt of other model, stream", served: testKeysetA, receipt: func(r *aciv2test.Receipt) { r.Model = "other" }, wantErr: true, wantRelayed: true, ended: true},
			{name: "receipt of other request, stream", served: testKeysetA, receipt: func(r *aciv2test.Receipt) { r.Request = []byte("{}") }, wantErr: true, wantRelayed: true},
			{name: "receipt cites other session", served: testKeysetA, plain: true, receipt: func(r *aciv2test.Receipt) { r.SessionID = strings.Repeat("cd", 32) }, wantErr: true, ended: true},
			{name: "served after the session", served: testKeysetA, plain: true, receipt: func(r *aciv2test.Receipt) { r.ServedAt = authorizedSessionExpires + 1 }, wantErr: true, ended: true},
			// A stream that fails after content went out still has its
			// receipt checked, against the bytes that arrived. After
			// [DONE] every byte arrived, so the receipt verifies and the
			// generation stays; the request still fails. A stream cut
			// before its end does not match the receipt, which covers the
			// whole response, and the generation ends.
			{name: "stream reset after [DONE]", served: testKeysetA, resetAfterDone: true, wantErr: true, wantRelayed: true, wantReceiptGET: true},
			// After a stream that failed, the gateway can publish its
			// receipt late; teep waits for it within the fetch bound.
			{name: "stream reset after [DONE], receipt published late", served: testKeysetA, resetAfterDone: true, receiptDelay: time.Second, wantErr: true, wantRelayed: true, wantReceiptGET: true},
			{name: "stream reset after the first chunk", served: testKeysetA, resetAfterFirst: true, wantErr: true, wantRelayed: true, wantReceiptGET: true, ended: true},
			// A stream that the relay cannot parse after content went out is
			// the gateway's failure, also while the connection stays open:
			// the receipt is checked and the generation ends.
			{name: "error event after the first chunk", served: testKeysetA, tailAfterFirst: "event: error\n\n", wantErr: true, wantRelayed: true, wantReceiptGET: true, ended: true},
			{name: "upstream error object after the first chunk", served: testKeysetA, tailAfterFirst: "data: {\"error\":{}}\n\n", wantErr: true, wantRelayed: true, wantReceiptGET: true, ended: true},
			{name: "data that is not JSON after the first chunk", served: testKeysetA, tailAfterFirst: "data: not-json\n\n", wantErr: true, wantRelayed: true, wantReceiptGET: true, ended: true},
			{name: "line over 1 MiB after the first chunk", served: testKeysetA, tailAfterFirst: "data: " + strings.Repeat("a", 1<<20+16) + "\n\n", wantErr: true, wantRelayed: true, wantReceiptGET: true, ended: true},
			{name: "data after [DONE] after the first chunk", served: testKeysetA, tailAfterFirst: "data: [DONE]\n\ndata: x\n\n", wantErr: true, wantRelayed: true, wantReceiptGET: true, ended: true},
			// teep reads the rest of the stream before the check, so a
			// gateway that ended its stream with an error and signed what
			// it sent verifies, and the generation stays.
			{name: "error event signed by the receipt", served: testKeysetA, tailAfterFirst: "event: error\n\n", signTail: true, wantErr: true, wantRelayed: true, wantReceiptGET: true},
			// A comment line reaches the client as it is, so the stream
			// counts as delivered although no data line came.
			// Nothing reached the client, so teep answers with its own 502,
			// which carries none of the upstream headers.
			{name: "reset before any line", served: testKeysetA, resetBeforeLine: true, wantErr: true, wantNoGatewayHeader: true},
			{name: "comment then reset, no data", served: testKeysetA, commentThenReset: true, wantErr: true, wantReceiptGET: true, ended: true},
			// The client hangs up when it reads teep's error event, before
			// teep claims the tail read: the stream is drained, and the
			// receipt over the whole stream decides.
			{name: "client hangs up before teep claims the tail read", served: testKeysetA, tailAfterFirst: "event: error\n\n", laterTail: "data: [DONE]\n\n", signTail: true, hangUpBeforeTailClaim: true, wantErr: true, wantRelayed: true, wantReceiptGET: true},
			// The relay error comes first, so teep claims the attempt for the
			// tail read; the client's end after that does not stop the
			// upstream read, and the receipt over the whole stream verifies.
			{name: "client hangs up after teep entered the tail read", served: testKeysetA, tailAfterFirst: "event: error\n\n", laterTail: "data: [DONE]\n\n", signTail: true, hangUpBeforeLaterTail: true, wantErr: true, wantRelayed: true, wantReceiptGET: true},
			// The request body is the client's: a body without a string
			// model fails before anything is sent, so the receipt check
			// (receipt_request_model) never sees one, and the generation
			// stays.
			{name: "request model not a string, stream", served: testKeysetA, modelNumber: true, wantErr: true},
			// teep's own attempt deadline bounds the relay and the writes,
			// and the upstream request runs longer, so the tail read after
			// that deadline reads the rest: a client that stops reading,
			// and an honest stream still sending at teep's deadline, verify
			// over what the gateway sent, and the generation stays.
			{name: "slow reader at teep's deadline", served: testKeysetA, attemptTimeout: 300 * time.Millisecond, slowReader: true, wantErr: true, wantReceiptGET: true},
			{name: "honest stream cut by teep's deadline", served: testKeysetA, attemptTimeout: 300 * time.Millisecond, pauseAfterFirst: true, wantErr: true, wantRelayed: true, wantReceiptGET: true},
			// A request body with a duplicate member, also in a member that
			// teep does not read, is refused before it is sent (the session
			// pin decodes it strictly), so no content goes out unchecked; the
			// generation stays.
			{name: "request body with a duplicate member", served: testKeysetA, duplicateMember: true, wantErr: true},
			{name: "downstream write fails after the first chunk", served: testKeysetA, downstreamFailOn: "Hel", wantErr: true, wantReceiptGET: true},
			// A client that hangs up, or whose deadline passes, must not end
			// the authorization that every client shares.
			// A client that leaves after content: teep stops writing, reads
			// the rest of the stream within the drain bound, and checks the
			// receipt over the whole response. An honest gateway verifies;
			// one that stalls past the drain bound, or sends more than its
			// byte bound, ends the generation. The handler returns within
			// the bound, so its connection slot is free again.
			{name: "client hangs up after the first chunk", served: testKeysetA, clientCancelOn: "Hel", wantErr: true, wantReceiptGET: true},
			{name: "client leaves, the gateway finishes later", served: testKeysetA, clientCancelOn: "Hel", pauseAfterFirst: true, wantErr: true, wantReceiptGET: true},
			{name: "client leaves, the gateway stalls past the drain bound", served: testKeysetA, clientCancelOn: "Hel", pauseAfterFirst: true, drainTimeout: 300 * time.Millisecond, maxElapsed: 1500 * time.Millisecond, wantErr: true, ended: true},
			{name: "client leaves, the gateway exceeds the drain byte bound", served: testKeysetA, clientCancelOn: "Hel", tailAfterFirst: ": x\n\n", laterTail: largeSignedTail, signTail: true, drainBytes: 64 << 10, wantErr: true, ended: true},
			{name: "client leaves, a large honest tail within the drain bound", served: testKeysetA, clientCancelOn: "Hel", tailAfterFirst: ": x\n\n", laterTail: largeSignedTail, signTail: true, wantErr: true, wantReceiptGET: true},
			// After [DONE] upstream reached its end, so the receipt is still
			// checked, under the server's context, and verifies.
			{name: "client hangs up after [DONE]", served: testKeysetA, clientCancelOn: "[DONE]", wantErr: true, wantRelayed: true, wantReceiptGET: true},
			{name: "caller deadline during the stream", served: testKeysetA, pauseAfterFirst: true, callerDeadline: 300 * time.Millisecond, wantErr: true, wantRelayed: true, wantReceiptGET: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				testAuthorizedPhalaCloud(t, authority, &tc)
			})
		}
	})
}

// A Phala Cloud authorization without a pinned session sends no request.
func TestAuthorizedPhalaCloudRequiresPinnedSessions(t *testing.T) {
	route, err := provider.NewResolvedRoute("https://tee.redpill.ai", "")
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: "phalacloud", E2EE: true, Encryptor: aci.NewE2EE(), Preparer: phalacloud.NewPreparer("test")}
	_, _, err = provider.PrepareInference(t.Context(), prov, route, &provider.InferenceInput{Body: []byte(`{"model":"m","messages":[]}`), Path: "/v1/chat/completions", ContentType: "application/json"})
	if err == nil || !strings.Contains(err.Error(), "no verified attested session") {
		t.Fatalf("err = %v, want the missing pin", err)
	}
}

// testKeysetA is the verified keyset digest, testKeysetB another one.
var (
	testKeysetA = "sha256:" + strings.Repeat("aa", 32)
	testKeysetB = "sha256:" + strings.Repeat("bb", 32)
)

// phalaTestGateway answers the chat request of tc and the receipt GET that
// follows it.
func phalaTestGateway(t *testing.T, gw *aciv2test.Gateway, tc *phalaCase, receipt *atomic.Pointer[[]byte], receiptGETs *atomic.Int32) http.HandlerFunc {
	t.Helper()
	var started atomic.Int64
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == aci.ReceiptsPath+"/rcpt-1" {
			receiptGETs.Add(1)
			if r.Header.Get("Authorization") != "Bearer test" {
				t.Errorf("receipt GET Authorization %q", r.Header.Get("Authorization"))
			}
			if tc.receiptDelay > 0 && time.Since(time.Unix(0, started.Load())) < tc.receiptDelay {
				http.NotFound(w, r)
				return
			}
			if tc.receiptMissing || receipt.Load() == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(*receipt.Load())
			return
		}
		started.Store(time.Now().UnixNano())
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer test" {
			t.Errorf("request %s, Authorization %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		req := gw.ReadRequest(r.Header, body)
		var b struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
			Provider struct {
				ACISessionIDs []string `json:"aci_session_ids"`
			} `json:"provider"`
		}
		if err := json.Unmarshal(body, &b); err != nil || len(b.Messages) != 1 {
			t.Errorf("request body: %v", err)
			return
		}
		if len(b.Provider.ACISessionIDs) != 1 || b.Provider.ACISessionIDs[0] != authorizedSessionID {
			t.Errorf("provider.aci_session_ids = %q, want the authorized session", b.Provider.ACISessionIDs)
		}
		if tc.status != 0 {
			w.Header().Set("X-Aci-Keyset-Digest", testKeysetA)
			if tc.plain {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"plaintext-answer"}}]}`)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(tc.status)
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"plaintext-answer\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		if tc.refuse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `{"error":{"message":"none of the pinned sessions can serve this request","type":"session_not_accepted","code":null,"param":null}}`)
			return
		}
		if got, err := gw.DecryptRequestField(req, "messages.0.content", b.Messages[0].Content); err != nil || got != "test" {
			t.Errorf("messages.0.content = %q, %v", got, err)
		}
		stream := gw.Stream(req, "chatcmpl-1", []string{"Hel", "lo"}, true)
		// The gateway hashes the request with the plaintext restored in
		// place of the ciphertext (E2EE v2 §8).
		restored := strings.Replace(string(body), `"`+b.Messages[0].Content+`"`, `"test"`, 1)
		served := tc.served
		if served == "" {
			served = testKeysetA
		}
		signedResponse := stream
		if tc.signTail {
			parts := strings.SplitAfter(stream, "\n\n")
			signedResponse = parts[0] + parts[1] + tc.tailAfterFirst + tc.laterTail
		}
		fields := &aciv2test.Receipt{ID: "rcpt-1", Model: "model", KeysetDigest: served, SessionID: authorizedSessionID, Request: []byte(restored), Response: []byte(signedResponse), ServedAt: authorizedSessionExpires - 10}
		if tc.receipt != nil {
			tc.receipt(fields)
		}
		signed := gw.SignReceipt(fields)
		receipt.Store(&signed)
		if tc.served != "" {
			w.Header().Set("X-Aci-Keyset-Digest", tc.served)
		}
		if !tc.noReceiptID {
			w.Header().Set("X-Receipt-Id", "rcpt-1")
		}
		w.Header().Set("X-Gateway-Header", "1")
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		// Headers that teep's relay sets itself; the gateway's values must
		// not replace teep's.
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("X-Accel-Buffering", "yes")
		writePhalaStream(w, r, tc, stream)
	}
}

// writePhalaStream writes the stream of one phalaCase: whole, cut, reset,
// held, or with a tail.
func writePhalaStream(w http.ResponseWriter, r *http.Request, tc *phalaCase, stream string) {
	switch {
	case tc.resetBeforeLine:
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	case tc.commentThenReset:
		_, _ = io.WriteString(w, ": keep-alive\n\n")
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	case tc.tailAfterFirst != "":
		parts := strings.SplitAfter(stream, "\n\n")
		_, _ = io.WriteString(w, parts[0]+parts[1]+tc.tailAfterFirst)
		http.NewResponseController(w).Flush()
		if tc.laterTail != "" {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(300 * time.Millisecond):
			}
			if tc.hangUpBeforeLaterTail {
				if hangUp := tc.hangUp.Load(); hangUp != nil {
					(*hangUp)()
				}
			}
			_, _ = io.WriteString(w, tc.laterTail)
			http.NewResponseController(w).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	case tc.pauseAfterFirst:
		parts := strings.SplitAfter(stream, "\n\n")
		_, _ = io.WriteString(w, parts[0]+parts[1])
		http.NewResponseController(w).Flush()
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
		}
		_, _ = io.WriteString(w, strings.Join(parts[2:], ""))
	case tc.resetAfterFirst:
		// The role chunk, then the first content chunk.
		parts := strings.SplitAfter(stream, "\n\n")
		_, _ = io.WriteString(w, parts[0]+parts[1])
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	case tc.resetAfterDone:
		_, _ = io.WriteString(w, stream)
		http.NewResponseController(w).Flush()
		panic(http.ErrAbortHandler)
	default:
		_, _ = io.WriteString(w, stream)
	}
}

// checkPhalaResponse checks what reached the client and how many receipt
// GETs teep sent for one phalaCase.
func checkPhalaResponse(t *testing.T, tc *phalaCase, rec *inferenceRecorder, receiptGETs int32) {
	t.Helper()
	if relayed := strings.Contains(rec.Body.String(), "Hel") && strings.Contains(rec.Body.String(), "lo"); relayed != tc.wantRelayed {
		t.Errorf("decrypted content relayed = %v, want %v", relayed, tc.wantRelayed)
	}
	if strings.Contains(rec.Body.String(), "plaintext-answer") {
		t.Error("a plaintext answer reached the client")
	}
	if tc.wantRelayed && !tc.wantErr {
		checkRelayHeaders(t, rec.Header(), tc.plain)
	}
	if tc.plain && !tc.wantRelayed && rec.Body.Len() > 0 {
		t.Errorf("non-stream response written before its receipt verified: %d %q", rec.Code, rec.Body.String())
	}
	if want := int32(aci.ReceiptAttempts); tc.receiptMissing && receiptGETs != want {
		t.Errorf("%d receipt GETs, want %d", receiptGETs, want)
	}
	if tc.wantNoReceiptGET && receiptGETs != 0 {
		t.Errorf("%d receipt GETs, want none", receiptGETs)
	}
	if tc.wantNoGatewayHeader && (rec.Code != http.StatusBadGateway || rec.Header().Get("X-Gateway-Header") != "" || rec.Header().Get("X-Receipt-Id") != "") {
		t.Errorf("client status=%d gateway header=%q receipt id=%q; want teep's 502 without upstream headers", rec.Code, rec.Header().Get("X-Gateway-Header"), rec.Header().Get("X-Receipt-Id"))
	}
	if tc.noReceiptID && rec.Header().Get("X-Gateway-Header") != "" {
		t.Error("a refused response sent a gateway header to the client")
	}
	if tc.wantReceiptGET && receiptGETs == 0 {
		t.Error("the stream failed after content went out, and its receipt was not checked")
	}
}

// hangUpRecorder cancels the client's request context once the body written
// to it contains on, as a client that closes its connection does.
type hangUpRecorder struct {
	*inferenceRecorder
	on     string
	cancel context.CancelFunc
}

func (h *hangUpRecorder) Write(p []byte) (int, error) {
	n, err := h.inferenceRecorder.Write(p)
	if strings.Contains(h.Body.String(), h.on) {
		h.cancel()
	}
	return n, err
}

// slowRecorder is a client that stops reading once the body written to it
// contains after: a later write blocks until the write deadline and fails
// on it, as a write to a connection whose receive window is full does.
type slowRecorder struct {
	*inferenceRecorder
	after string
}

func (s *slowRecorder) Write(p []byte) (int, error) {
	if strings.Contains(s.Body.String(), s.after) && !s.deadline.IsZero() {
		time.Sleep(time.Until(s.deadline))
		return 0, os.ErrDeadlineExceeded
	}
	return s.inferenceRecorder.Write(p)
}

// failingRecorder fails every write after the body written to it contains
// on, as a client connection that broke does.
type failingRecorder struct {
	*inferenceRecorder
	on string
}

func (f *failingRecorder) Write(p []byte) (int, error) {
	if strings.Contains(f.Body.String(), f.on) {
		return 0, errors.New("broken pipe")
	}
	return f.inferenceRecorder.Write(p)
}

// largeSignedTail is a tail of about 200 KiB of SSE comments and [DONE],
// larger than one read of the relay.
var largeSignedTail = strings.Repeat(": "+strings.Repeat("a", 98)+"\n\n", 2000) + "data: [DONE]\n\n"

// authorizedSessionExpires is the expires_at of the authorized session.
const authorizedSessionExpires = 1893456000

func testAuthorizedPhalaCloud(t *testing.T, authority *testtls.Authority, tc *phalaCase) {
	t.Helper()
	if tc.hangUpBeforeLaterTail || tc.hangUpBeforeTailClaim {
		tc.hangUp = &atomic.Pointer[context.CancelFunc]{}
	}
	gw := aciv2test.New(t)
	var receipt atomic.Pointer[[]byte]
	var receiptGETs atomic.Int32
	upstream := authority.NewTLSServerWithConfig(t, phalaTestGateway(t, gw, tc, &receipt, &receiptGETs), func(ts *httptest.Server) {
		ts.Config.TLSConfig = ts.TLS
		if err := http2.ConfigureServer(ts.Config, &http2.Server{}); err != nil {
			t.Fatal(err)
		}
	})
	defer upstream.Close()
	fingerprint := sha256.Sum256(upstream.Certificate().RawSubjectPublicKeyInfo)
	server := newTLSBindingTestServerHandle()
	server.authorizations = newAuthorizationStore(10, 2, time.Second)
	server.attemptTimeouts.stream = tc.attemptTimeout
	server.drainBounds = drainBounds{timeout: tc.drainTimeout, bytes: tc.drainBytes}
	if tc.hangUpBeforeTailClaim {
		server.tailClaimHook = func() {
			if hangUp := tc.hangUp.Load(); hangUp != nil {
				(*hangUp)()
			}
			// The watch of the client's context runs in its own goroutine.
			time.Sleep(100 * time.Millisecond)
		}
	}
	defer server.Close()
	route, err := provider.NewResolvedRoute(upstream.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	prov := &provider.Provider{Name: "phalacloud", BaseURL: upstream.URL, APIKey: "test", StaticRoute: route, UsesTLSBinding: true, E2EE: true, Encryptor: aci.NewE2EE(), Preparer: phalacloud.NewPreparer("test")}
	key, err := route.AuthorizationKey(prov.Name, "model")
	if err != nil {
		t.Fatal(err)
	}
	report := &attestation.VerificationReport{
		Provider: prov.Name, Model: "model", BackendFormat: attestation.FormatACI1, ACIKeysetDigest: testKeysetA,
		ACISessionIDs:     []string{authorizedSessionID},
		ACIPinnedSessions: []attestation.ACIPinnedSession{{ID: authorizedSessionID, EstablishedAt: authorizedSessionExpires - 3600, ExpiresAt: authorizedSessionExpires}},
		ACIReceiptKeys:    []attestation.ACIReceiptKey{{KeyID: aciv2test.ReceiptKeyID, Algo: "ed25519", PublicKey: gw.ReceiptPublicKeyHex()}},
		ACIKeysetNotAfter: authorizedSessionExpires + 3600,
		TLSAuthority:      route.Authority(), TLSKeyFP: hex.EncodeToString(fingerprint[:]),
		Factors: []attestation.FactorResult{{Name: attestation.FactorTEEReportData, Status: attestation.Pass}, {Name: attestation.FactorE2EEUsable, Status: attestation.Skip}},
	}
	candidate, err := newAuthorization(key, report, gw.PubKeyHex(), true, false)
	if err != nil {
		t.Fatal(err)
	}
	value := loadTestAuthorization(t, server.authorizations, key, candidate)
	body := `{"model":"model","stream":true,"messages":[{"role":"user","content":"test"}]}`
	if tc.duplicateMember {
		body = `{"model":"model","stream":true,"metadata":{"k":1,"k":2},"messages":[{"role":"user","content":"test"}]}`
	}
	if tc.modelNumber {
		body = `{"model":7,"stream":true,"messages":[{"role":"user","content":"test"}]}`
	}
	if tc.plain {
		body = `{"model":"model","messages":[{"role":"user","content":"test"}]}`
	}
	input := &authorizedRequest{provider: prov, route: route, key: key, body: []byte(body), model: "model", stream: !tc.plain, path: "/v1/chat/completions", contentType: "application/json", endpoint: e2ee.EndpointChat}
	timeout := 10 * time.Second
	if tc.callerDeadline > 0 {
		timeout = tc.callerDeadline
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	if tc.hangUp != nil {
		tc.hangUp.Store(&cancel)
	}
	rec := newInferenceRecorder()
	var w http.ResponseWriter = rec
	if tc.clientCancelOn != "" {
		w = &hangUpRecorder{inferenceRecorder: rec, on: tc.clientCancelOn, cancel: cancel}
	}
	if tc.downstreamFailOn != "" {
		w = &failingRecorder{inferenceRecorder: rec, on: tc.downstreamFailOn}
	}
	if tc.slowReader {
		w = &slowRecorder{inferenceRecorder: rec, after: "Hel"}
	}
	started := time.Now()
	_, err = server.inferAuthorized(ctx, w, input)
	if elapsed := time.Since(started); tc.maxElapsed > 0 && elapsed > tc.maxElapsed {
		t.Errorf("the request took %s, want at most %s: the drain held the handler past its bound", elapsed, tc.maxElapsed)
	}
	if (err != nil) != tc.wantErr {
		t.Fatalf("err = %v, want error %v", err, tc.wantErr)
	}
	checkPhalaResponse(t, tc, rec, receiptGETs.Load())
	current, ok := server.authorizations.acquire(key)
	if gotEnded := !ok || current.generation != value.generation; gotEnded != tc.ended {
		t.Errorf("generation ended = %v, want %v", gotEnded, tc.ended)
	}
}

// checkRelayHeaders requires the headers that teep's relay sets: the
// encrypted request of a non-stream response is a stream upstream, and teep
// answers with the reassembled JSON body; a stream keeps teep's event-stream
// headers. The upstream headers that teep does not set still reach the
// client.
func checkRelayHeaders(t *testing.T, h http.Header, nonStream bool) {
	t.Helper()
	want := map[string]string{"Content-Type": "text/event-stream", "Cache-Control": "no-cache", "X-Accel-Buffering": "no", "X-Gateway-Header": "1"}
	if nonStream {
		want = map[string]string{"Content-Type": "application/json", "X-Gateway-Header": "1"}
	}
	for name, value := range want {
		if got := h.Get(name); got != value {
			t.Errorf("client %s = %q, want %q", name, got, value)
		}
	}
}
