#!/usr/bin/env bash
set -euo pipefail

# E2E test for teep against the live Venice API.
# Requires VENICE_API_KEY. Builds and runs the actual binary.

MODEL="${VENICE_E2EE_MODEL:-e2ee-qwen3-5-122b-a10b}"
PORT=$((RANDOM % 50000 + 10000))
BASE="http://127.0.0.1:$PORT"
PID=""
WORK=""
START_TIME=""

status() { printf -- "--- %s\n" "$1" >&2; }
pass()   { printf -- "  ✓ %s\n" "$1" >&2; }
fail()   { printf -- "  ✗ %s\n" "$1" >&2; exit 1; }

cleanup() {
	if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
		kill "$PID" 2>/dev/null || true
		wait "$PID" 2>/dev/null || true
	fi
	if [[ -n "$WORK" ]]; then
		rm -rf "$WORK"
	fi
	if [[ -n "$START_TIME" ]]; then
		local elapsed=$(( $(date +%s) - START_TIME ))
		printf -- "--- done (%ds)\n" "$elapsed" >&2
	fi
}
trap cleanup EXIT

START_TIME=$(date +%s)

if [[ -z "${VENICE_API_KEY:-}" ]]; then
	echo "VENICE_API_KEY not set" >&2
	exit 1
fi

WORK=$(mktemp -d)
BIN="$WORK/teep"

# curl_check performs a curl request, captures the HTTP status code and body,
# and fails with full diagnostics if the request fails or returns non-2xx.
# Usage: curl_check LABEL [curl args...]
# Sets: CURL_BODY (response body), CURL_STATUS (HTTP status code)
curl_check() {
	local label="$1"; shift
	local tmpfile="$WORK/curl_body"

	printf "  > curl %s\n" "$*" >&2

	local http_code
	http_code=$(curl --silent --show-error --output "$tmpfile" --write-out "%{http_code}" "$@") || {
		local rc=$?
		echo "  curl failed (exit $rc) for: $label" >&2
		if [[ -f "$tmpfile" ]]; then
			echo "  body: $(cat "$tmpfile")" >&2
		fi
		fail "$label: curl error $rc"
	}

	CURL_BODY=$(cat "$tmpfile")
	CURL_STATUS="$http_code"

	if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
		echo "  HTTP $http_code for: $label" >&2
		echo "  body: $CURL_BODY" >&2
		fail "$label: HTTP $http_code"
	fi
}

# --- build ---
status "build"
printf "  > go build -o %s ./cmd/teep\n" "$BIN" >&2
go build -o "$BIN" ./cmd/teep
pass "binary built"

# --- verify (standalone, no server) ---
status "verify"
printf "  > %s verify venice --model %s --offline --save-dir %s\n" "$BIN" "$MODEL" "$WORK" >&2
OUTPUT=$("$BIN" verify venice --model "$MODEL" --offline --save-dir "$WORK" 2>&1)
SCORE=$(echo "$OUTPUT" | grep "^Score:" || true)
if [[ -z "$SCORE" ]]; then
	echo "  output: $OUTPUT" >&2
	fail "verify output missing Score line"
fi
pass "$SCORE"

if ! ls "$WORK"/venice_attestation_*.json >/dev/null 2>&1; then
	fail "no attestation data saved"
fi
pass "attestation data saved"

# --- serve ---
status "serve (port $PORT)"
printf "  > TEEP_LISTEN_ADDR=127.0.0.1:%s %s serve --offline &\n" "$PORT" "$BIN" >&2
TEEP_LISTEN_ADDR="127.0.0.1:$PORT" "$BIN" serve --offline &
PID=$!

# Wait for readiness by polling /v1/models.
printf "  > polling %s/v1/models ...\n" "$BASE" >&2
for i in $(seq 1 20); do
	if curl -sf "$BASE/v1/models" >/dev/null 2>&1; then
		break
	fi
	if ! kill -0 "$PID" 2>/dev/null; then
		fail "server exited unexpectedly"
	fi
	sleep 0.5
done
curl_check "models" "$BASE/v1/models"
pass "server ready, models: $CURL_BODY"

# --- chat non-streaming ---
status "chat non-streaming"
curl_check "chat non-streaming" "$BASE/v1/chat/completions" \
	-H "Content-Type: application/json" \
	-d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in exactly two words\"}],\"stream\":false}"

echo "  response: ${CURL_BODY:0:200}..." >&2
if ! grep -q '"choices"' <<< "$CURL_BODY"; then
	fail "response missing choices"
fi
CONTENT=$(grep -o '"content":"[^"]*"' <<< "$CURL_BODY" | head -1 | cut -d'"' -f4 || true)
if [[ -z "$CONTENT" ]]; then
	fail "empty content in response"
fi
pass "HTTP 200, content: \"$CONTENT\""

# --- chat streaming ---
status "chat streaming"
curl_check "chat streaming" -N "$BASE/v1/chat/completions" \
	-H "Content-Type: application/json" \
	-d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in exactly two words\"}],\"stream\":true}"

CHUNK_COUNT=$(grep -c "^data: " <<< "$CURL_BODY" || true)
echo "  response: ${CHUNK_COUNT} SSE data lines" >&2
if ! grep -q "^data: " <<< "$CURL_BODY"; then
	echo "  body (first 5 lines):" >&2
	head -5 <<< "$CURL_BODY" >&2
	fail "no SSE data lines"
fi
if ! grep -q "data: \[DONE\]" <<< "$CURL_BODY"; then
	echo "  body (first 5 lines):" >&2
	head -5 <<< "$CURL_BODY" >&2
	fail "missing [DONE] sentinel"
fi
pass "HTTP 200, SSE with [DONE] (${CHUNK_COUNT} chunks)"

# --- report ---
status "report"
curl_check "report" "$BASE/v1/tee/report?provider=venice&model=$MODEL"

echo "  response: ${CURL_BODY:0:200}..." >&2
if ! grep -q '"provider"' <<< "$CURL_BODY"; then
	fail "report missing provider field"
fi
if ! grep -q '"factors"' <<< "$CURL_BODY"; then
	fail "report missing factors field"
fi
PASSED=$(grep -o '"passed":[0-9]*' <<< "$CURL_BODY" | cut -d: -f2 || true)
FAILED=$(grep -o '"failed":[0-9]*' <<< "$CURL_BODY" | cut -d: -f2 || true)
SKIPPED=$(grep -o '"skipped":[0-9]*' <<< "$CURL_BODY" | cut -d: -f2 || true)
pass "report: ${PASSED} passed, ${FAILED} failed, ${SKIPPED} skipped"
