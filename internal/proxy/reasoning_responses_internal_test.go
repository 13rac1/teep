package proxy

import (
	"slices"
	"strings"
	"testing"
)

func TestResponsesRequestStats_FunctionCallMissingReasoningPriorTurn(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"},
			{"role": "user", "content": "continue"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if stats.LastUserMessageIndex != 3 {
		t.Fatalf("LastUserMessageIndex = %d, want 3", stats.LastUserMessageIndex)
	}
	if !slices.Equal(stats.FunctionCallIndexes, []int{1}) {
		t.Fatalf("FunctionCallIndexes = %v, want [1]", stats.FunctionCallIndexes)
	}
	if !slices.Equal(stats.FunctionCallMissingReasoningPriorIndexes, []int{1}) {
		t.Fatalf("FunctionCallMissingReasoningPriorIndexes = %v, want [1]", stats.FunctionCallMissingReasoningPriorIndexes)
	}
	if len(stats.FunctionCallMissingReasoningActiveIndexes) != 0 {
		t.Fatalf("FunctionCallMissingReasoningActiveIndexes = %v, want []", stats.FunctionCallMissingReasoningActiveIndexes)
	}
}

func TestResponsesRequestStats_FunctionCallWithAdjacentReasoningNotFlagged(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "reasoning", "id": "r1", "summary": []},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if !slices.Equal(stats.ReasoningItemIndexes, []int{1}) {
		t.Fatalf("ReasoningItemIndexes = %v, want [1]", stats.ReasoningItemIndexes)
	}
	if len(stats.FunctionCallMissingReasoningPriorIndexes) != 0 || len(stats.FunctionCallMissingReasoningActiveIndexes) != 0 {
		t.Fatalf("expected no missing-reasoning function_call, got prior=%v active=%v",
			stats.FunctionCallMissingReasoningPriorIndexes, stats.FunctionCallMissingReasoningActiveIndexes)
	}
}

func TestResponsesRequestStats_ActiveFunctionCallMissingReasoning(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": "loop"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"},
			{"type": "function_call", "call_id": "c2", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c2", "output": "ok"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if !slices.Equal(stats.FunctionCallMissingReasoningActiveIndexes, []int{1, 3}) {
		t.Fatalf("FunctionCallMissingReasoningActiveIndexes = %v, want [1 3]", stats.FunctionCallMissingReasoningActiveIndexes)
	}
}

func TestResponsesRequestStats_TrailingUserAfterFunctionCallOutput(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"},
			{"role": "user", "content": "please continue"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if !stats.TrailingUserAfterFunctionCallOutput {
		t.Fatal("TrailingUserAfterFunctionCallOutput = false, want true")
	}
	if stats.TrailingUserIndex != 3 || stats.TrailingUserPrevFunctionCallOutputIndex != 2 {
		t.Fatalf("trailing indexes = (%d, %d), want (3, 2)", stats.TrailingUserIndex, stats.TrailingUserPrevFunctionCallOutputIndex)
	}
}

func TestResponsesRequestStats_TrailingAssistantMessageDoesNotFlagSandwich(t *testing.T) {
	body := []byte(`{
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"},
			{"role": "assistant", "content": "done"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if stats.TrailingUserAfterFunctionCallOutput {
		t.Fatal("TrailingUserAfterFunctionCallOutput = true, want false")
	}
}

func TestResponsesRequestStats_ReasoningNotPreservedAcrossTurns(t *testing.T) {
	body := []byte(`{
		"reasoning": {"effort": "high"},
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if !stats.ReasoningEffortPresent || stats.ReasoningEffort != "high" {
		t.Fatalf("ReasoningEffortPresent/Effort = %v/%q, want true/high", stats.ReasoningEffortPresent, stats.ReasoningEffort)
	}
	if !responsesReasoningNotPreservedAcrossTurns(&stats) {
		t.Fatal("responsesReasoningNotPreservedAcrossTurns = false, want true")
	}
}

func TestResponsesRequestStats_IncludeReasoningEncryptedContentSuppressesSignal(t *testing.T) {
	body := []byte(`{
		"reasoning": {"effort": "high"},
		"store": false,
		"include": ["reasoning.encrypted_content"],
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if !stats.IncludeHasReasoningEncryptedContent {
		t.Fatal("IncludeHasReasoningEncryptedContent = false, want true")
	}
	if responsesReasoningNotPreservedAcrossTurns(&stats) {
		t.Fatal("responsesReasoningNotPreservedAcrossTurns = true, want false (include covers it)")
	}
}

func TestResponsesRequestStats_StoreTrueSuppressesSignal(t *testing.T) {
	body := []byte(`{
		"reasoning": {"effort": "high"},
		"store": true,
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if responsesReasoningNotPreservedAcrossTurns(&stats) {
		t.Fatal("responsesReasoningNotPreservedAcrossTurns = true, want false (store:true covers it)")
	}
}

func TestResponsesRequestStats_PreviousResponseIDSuppressesSignal(t *testing.T) {
	body := []byte(`{
		"reasoning": {"effort": "high"},
		"previous_response_id": "resp_123",
		"input": [
			{"role": "user", "content": "continue"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if !stats.PreviousResponseIDPresent {
		t.Fatal("PreviousResponseIDPresent = false, want true")
	}
	if responsesReasoningNotPreservedAcrossTurns(&stats) {
		t.Fatal("responsesReasoningNotPreservedAcrossTurns = true, want false (previous_response_id covers it)")
	}
}

func TestResponsesRequestStats_ReasoningItemsReplayedSuppressesSignal(t *testing.T) {
	body := []byte(`{
		"reasoning": {"effort": "high"},
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "reasoning", "id": "r1", "summary": []},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"}
		]
	}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if responsesReasoningNotPreservedAcrossTurns(&stats) {
		t.Fatal("responsesReasoningNotPreservedAcrossTurns = true, want false (reasoning items were replayed)")
	}
}

func TestResponsesRequestStats_BareStringInputIsNotAnError(t *testing.T) {
	body := []byte(`{"input": "hello"}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if stats.ItemCount != 0 {
		t.Fatalf("ItemCount = %d, want 0", stats.ItemCount)
	}
	if stats.DetermineIssueCount != 0 {
		t.Fatalf("DetermineIssueCount = %d, want 0: %v", stats.DetermineIssueCount, stats.DetermineIssues)
	}
}

func TestResponsesRequestStats_InputNotArrayOrStringIsDetermineIssue(t *testing.T) {
	body := []byte(`{"input": 42}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if stats.DetermineIssueCount == 0 {
		t.Fatal("DetermineIssueCount = 0, want > 0")
	}
}

func TestResponsesRequestStats_ItemMissingRoleIsDetermineIssue(t *testing.T) {
	body := []byte(`{"input": [{"content": "hi"}]}`)
	stats, err := responsesRequestStats(body)
	if err != nil {
		t.Fatalf("responsesRequestStats: %v", err)
	}
	if stats.DetermineIssueCount == 0 {
		t.Fatal("DetermineIssueCount = 0, want > 0")
	}
}

func TestResponsesRequestStats_MalformedBodyReturnsError(t *testing.T) {
	if _, err := responsesRequestStats([]byte(`not json`)); err == nil {
		t.Fatal("responsesRequestStats: want error for malformed JSON body")
	}
}

func TestLogResponsesRequestStats_NeverLogsMessageOrArgumentText(t *testing.T) {
	s := &Server{}
	const secretMarker = "TOP_SECRET_ARGUMENT_VALUE_MUST_NOT_APPEAR_IN_LOGS"
	body := []byte(`{
		"reasoning": {"effort": "high"},
		"input": [
			{"role": "user", "content": "` + secretMarker + `"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{\"secret\":\"` + secretMarker + `\"}"},
			{"type": "function_call_output", "call_id": "c1", "output": "` + secretMarker + `"},
			{"role": "user", "content": "` + secretMarker + `"}
		]
	}`)
	logs := captureSlog(t, func() {
		logResponsesRequestStats(t.Context(), &s.reasoningResponsesStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/responses", body)
	})
	if strings.Contains(logs, secretMarker) {
		t.Fatalf("log output leaked message/argument content:\n%s", logs)
	}
	for _, want := range []string{
		"msg=\"agent framework appended a trailing user message after function_call_output",
		"reasoning_diagnostics_issue=https://github.com/13rac1/teep/issues/124",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogResponsesRequestStats_MetadataUnavailableWarnsOnMalformedBody(t *testing.T) {
	s := &Server{}
	logs := captureSlog(t, func() {
		logResponsesRequestStats(t.Context(), &s.reasoningResponsesStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/responses", []byte(`not json`))
	})
	if !strings.Contains(logs, "responses request reasoning metadata unavailable") {
		t.Fatalf("log output missing metadata-unavailable warning:\n%s", logs)
	}
}

func TestLogResponsesRequestStats_RateLimited(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"input": [
			{"role": "user", "content": "do a thing"},
			{"type": "function_call", "call_id": "c1", "name": "run", "arguments": "{}"},
			{"type": "function_call_output", "call_id": "c1", "output": "ok"},
			{"role": "user", "content": "please continue"}
		]
	}`)
	logs := captureSlog(t, func() {
		logResponsesRequestStats(t.Context(), &s.reasoningResponsesStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/responses", body)
		logResponsesRequestStats(t.Context(), &s.reasoningResponsesStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/responses", body)
	})
	count := strings.Count(logs, "agent framework appended a trailing user message after function_call_output")
	if count != 1 {
		t.Fatalf("trailing-user warning logged %d times, want 1 (rate-limited):\n%s", count, logs)
	}
}
