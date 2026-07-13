package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func chatTemplateBool(t *testing.T, body []byte, field string) (value, present bool) {
	t.Helper()
	var req struct {
		ChatTemplateKwargs map[string]json.RawMessage `json:"chat_template_kwargs"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal request: %v", err)
	}
	raw, ok := req.ChatTemplateKwargs[field]
	if !ok {
		return false, false
	}
	var decoded bool
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal chat_template_kwargs.%s: %v", field, err)
	}
	return decoded, true
}

func TestRepairChatReasoningPreservation_PriorTurnGLMInjects(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:GLM-Future", "glm-future", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	if repair.family != "glm" || repair.flag != "chat_template_kwargs.clear_thinking=false" {
		t.Fatalf("repair = %#v, want glm clear_thinking=false", repair)
	}
	if !slices.Equal(repair.reasons, []string{reasoningRepairReasonPriorTurn}) {
		t.Fatalf("repair reasons = %v, want [%s]", repair.reasons, reasoningRepairReasonPriorTurn)
	}
	value, present := chatTemplateBool(t, repaired, "clear_thinking")
	if !present || value {
		t.Fatalf("clear_thinking = %v present=%v, want false present=true", value, present)
	}
}

func TestRepairChatReasoningPreservation_TrailingUserKimiInjects(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("vendor:KIMI-next", "other", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	if repair.family != "kimi" || repair.flag != "chat_template_kwargs.preserve_thinking=true" {
		t.Fatalf("repair = %#v, want kimi preserve_thinking=true", repair)
	}
	wantReasons := []string{reasoningRepairReasonPriorTurn, reasoningRepairReasonTrailingUser}
	if !slices.Equal(repair.reasons, wantReasons) {
		t.Fatalf("repair reasons = %v, want %v", repair.reasons, wantReasons)
	}
	value, present := chatTemplateBool(t, repaired, "preserve_thinking")
	if !present || !value {
		t.Fatalf("preserve_thinking = %v present=%v, want true present=true", value, present)
	}
}

func TestRepairChatReasoningPreservation_PriorTurnDeepSeekInjectsDespiteTools(t *testing.T) {
	body := []byte(`{
		"tools": [{"type": "function", "function": {"name": "x", "parameters": {"type": "object"}}}],
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:deepseek-vFuture", "upstream", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	if repair.family != "deepseek" || repair.flag != "chat_template_kwargs.drop_thinking=false" {
		t.Fatalf("repair = %#v, want deepseek drop_thinking=false", repair)
	}
	value, present := chatTemplateBool(t, repaired, "drop_thinking")
	if !present || value {
		t.Fatalf("drop_thinking = %v present=%v, want false present=true", value, present)
	}
}

func TestRepairChatReasoningPreservation_DoesNotOverrideExplicitFlag(t *testing.T) {
	body := []byte(`{
		"chat_template_kwargs": {"clear_thinking": true},
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:glm", "glm", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair != nil {
		t.Fatalf("repair = %#v, want nil", repair)
	}
	value, present := chatTemplateBool(t, repaired, "clear_thinking")
	if !present || !value {
		t.Fatalf("clear_thinking = %v present=%v, want true present=true", value, present)
	}
}

func TestRepairChatReasoningPreservation_OverridesNullFlag(t *testing.T) {
	body := []byte(`{
		"chat_template_kwargs": {"clear_thinking": null},
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:glm", "glm", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	value, present := chatTemplateBool(t, repaired, "clear_thinking")
	if !present || value {
		t.Fatalf("clear_thinking = %v present=%v, want false present=true", value, present)
	}
}

func TestRepairChatReasoningPreservation_OverridesInvalidTypedFlag(t *testing.T) {
	body := []byte(`{
		"chat_template_kwargs": {"clear_thinking": "false"},
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:glm", "glm", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	value, present := chatTemplateBool(t, repaired, "clear_thinking")
	if !present || value {
		t.Fatalf("clear_thinking = %v present=%v, want false present=true", value, present)
	}

	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.ChatTemplateClearThinkingPresent {
		t.Fatal("ChatTemplateClearThinkingPresent = true, want false for invalid typed value")
	}
	if stats.DetermineIssueCount != 1 {
		t.Fatalf("DetermineIssueCount = %d, want 1", stats.DetermineIssueCount)
	}
	if !slices.Contains(stats.DetermineIssues, "chat_template_kwargs.clear_thinking is not a boolean") {
		t.Fatalf("DetermineIssues = %v, want invalid clear_thinking issue", stats.DetermineIssues)
	}
}

func TestRepairChatReasoningPreservationWithStats_ReturnsRepairedStats(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, stats, repair, err := repairChatReasoningPreservationWithStats("provider:glm", "glm", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservationWithStats: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	if stats == nil {
		t.Fatal("stats = nil, want repaired stats")
	}
	if !stats.ChatTemplateClearThinkingPresent || stats.ChatTemplateClearThinking {
		t.Fatalf("clear_thinking stats present=%v value=%v, want present=true value=false",
			stats.ChatTemplateClearThinkingPresent, stats.ChatTemplateClearThinking)
	}
	if !slices.Equal(stats.PriorTurnPreservedReasoningIndexes, []int{1}) {
		t.Fatalf("PriorTurnPreservedReasoningIndexes = %v, want [1]", stats.PriorTurnPreservedReasoningIndexes)
	}
	value, present := chatTemplateBool(t, repaired, "clear_thinking")
	if !present || value {
		t.Fatalf("clear_thinking body = %v present=%v, want false present=true", value, present)
	}
}

func TestRepairChatReasoningPreservation_UnknownModelSkipsStatsParse(t *testing.T) {
	body := []byte(`{"messages": [1]}`)
	tests := []struct {
		name          string
		model         string
		upstreamModel string
	}{
		{
			name:          "unrelated provider",
			model:         "other:model",
			upstreamModel: "model",
		},
		{
			name:          "provider prefix contains known family",
			model:         "deepseek_proxy:model",
			upstreamModel: "model",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repaired, repair, err := repairChatReasoningPreservation(tt.model, tt.upstreamModel, body)
			if err != nil {
				t.Fatalf("repairChatReasoningPreservation: %v", err)
			}
			if repair != nil {
				t.Fatalf("repair = %#v, want nil", repair)
			}
			if !slices.Equal(repaired, body) {
				t.Fatalf("repaired body changed: got %s want %s", repaired, body)
			}
		})
	}
}

func TestRepairChatReasoningPreservation_KnownModelSkipsMalformedStats(t *testing.T) {
	body := []byte(`{"messages": [1]}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:glm", "glm", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair != nil {
		t.Fatalf("repair = %#v, want nil", repair)
	}
	if !slices.Equal(repaired, body) {
		t.Fatalf("repaired body changed: got %s want %s", repaired, body)
	}
}

func TestRepairChatReasoningPreservation_NonObjectChatTemplateKwargsDoesNotReject(t *testing.T) {
	body := []byte(`{
		"chat_template_kwargs": "invalid",
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	repaired, repair, err := repairChatReasoningPreservation("provider:glm", "glm", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair != nil {
		t.Fatalf("repair = %#v, want nil", repair)
	}
	if !slices.Equal(repaired, body) {
		t.Fatalf("repaired body changed: got %s want %s", repaired, body)
	}
}

func TestChatRequestStats_OptionalNullAndMalformedFields(t *testing.T) {
	body := []byte(`{
		"chat_template_kwargs": null,
		"tools": null,
		"messages": [{"role": "user"}]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats null optional fields: %v", err)
	}
	if stats.ChatTemplateClearThinkingPresent || stats.ToolsPresent || stats.ToolsCount != 0 || stats.DetermineIssueCount != 0 {
		t.Fatalf("stats for null optional fields = %#v, want absent kwargs/tools with no determine issues", stats)
	}

	body = []byte(`{
		"tools": [],
		"messages": [{"role": "user"}]
	}`)
	stats, err = chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats empty tools: %v", err)
	}
	if stats.ToolsPresent || stats.ToolsCount != 0 || stats.DetermineIssueCount != 0 {
		t.Fatalf("stats for empty tools = %#v, want no tools present and no determine issues", stats)
	}

	body = []byte(`{
		"chat_template_kwargs": "invalid",
		"tools": {"type": "function"},
		"messages": [{"role": "user"}]
	}`)
	stats, err = chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats malformed optional fields: %v", err)
	}
	if stats.DetermineIssueCount != 2 {
		t.Fatalf("DetermineIssueCount = %d, want 2", stats.DetermineIssueCount)
	}
	for _, want := range []string{
		"chat_template_kwargs is not an object",
		"tools is not an array",
	} {
		if !slices.Contains(stats.DetermineIssues, want) {
			t.Fatalf("DetermineIssues = %v, missing %q", stats.DetermineIssues, want)
		}
	}
}

func TestChatRequestStats_RoleDetermineIssuesDistinguishMissingAndInvalid(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"content": "missing"},
			{"role": 123}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.DetermineIssueCount != 2 {
		t.Fatalf("DetermineIssueCount = %d, want 2", stats.DetermineIssueCount)
	}
	for _, want := range []string{
		"message 0 missing string role",
		"message 1 role is not a string",
	} {
		if !slices.Contains(stats.DetermineIssues, want) {
			t.Fatalf("DetermineIssues = %v, missing %q", stats.DetermineIssues, want)
		}
	}
}

func TestChatRequestStats_MessagesDetermineIssues(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		wantIssue string
	}{
		{
			name:      "missing messages",
			body:      []byte(`{}`),
			wantIssue: "messages field missing",
		},
		{
			name:      "null messages",
			body:      []byte(`{"messages": null}`),
			wantIssue: "messages field is null",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats, err := chatRequestStats(tt.body)
			if err != nil {
				t.Fatalf("chatRequestStats: %v", err)
			}
			if stats.DetermineIssueCount != 1 {
				t.Fatalf("DetermineIssueCount = %d, want 1", stats.DetermineIssueCount)
			}
			if !slices.Contains(stats.DetermineIssues, tt.wantIssue) {
				t.Fatalf("DetermineIssues = %v, missing %q", stats.DetermineIssues, tt.wantIssue)
			}
		})
	}
}

func TestChatRequestStats_ToolCallsDetermineIssues(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "tool_calls": {"id": "call_1"}},
			{"role": "assistant", "tool_calls": null}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.DetermineIssueCount != 1 {
		t.Fatalf("DetermineIssueCount = %d, want 1", stats.DetermineIssueCount)
	}
	if !slices.Contains(stats.DetermineIssues, "message 1 tool_calls is not an array") {
		t.Fatalf("DetermineIssues = %v, missing invalid tool_calls issue", stats.DetermineIssues)
	}
	if !slices.Equal(stats.RoleSequence, []string{"user", "assistant[stripped]", "assistant[stripped]"}) {
		t.Fatalf("RoleSequence = %v, want stripped assistant messages", stats.RoleSequence)
	}
}

func TestRawStringLen(t *testing.T) {
	tests := []struct {
		name      string
		msg       map[string]json.RawMessage
		wantLen   int
		wantFound bool
		wantValid bool
	}{
		{
			name:      "simple string",
			msg:       map[string]json.RawMessage{"reasoning_content": json.RawMessage(`"abc"`)},
			wantLen:   3,
			wantFound: true,
			wantValid: true,
		},
		{
			name:      "escaped string falls back to decoded length",
			msg:       map[string]json.RawMessage{"reasoning_content": json.RawMessage(`"a\"b"`)},
			wantLen:   3,
			wantFound: true,
			wantValid: true,
		},
		{
			name:      "empty string",
			msg:       map[string]json.RawMessage{"reasoning_content": json.RawMessage(`""`)},
			wantLen:   0,
			wantFound: true,
			wantValid: true,
		},
		{
			name:      "null is absent",
			msg:       map[string]json.RawMessage{"reasoning_content": json.RawMessage(`null`)},
			wantFound: false,
			wantValid: true,
		},
		{
			name:      "non-string is invalid",
			msg:       map[string]json.RawMessage{"reasoning_content": json.RawMessage(`123`)},
			wantFound: true,
			wantValid: false,
		},
		{
			name:      "malformed string-shaped value is invalid",
			msg:       map[string]json.RawMessage{"reasoning_content": json.RawMessage(`"a"b"`)},
			wantFound: true,
			wantValid: false,
		},
		{
			name:      "missing is absent",
			msg:       map[string]json.RawMessage{},
			wantFound: false,
			wantValid: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotLen, gotFound, gotValid := rawStringLen(tc.msg, "reasoning_content")
			if gotLen != tc.wantLen || gotFound != tc.wantFound || gotValid != tc.wantValid {
				t.Fatalf("rawStringLen = (%d, %v, %v), want (%d, %v, %v)",
					gotLen, gotFound, gotValid, tc.wantLen, tc.wantFound, tc.wantValid)
			}
		})
	}
}

func TestRawVisibleContent(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want bool
	}{
		{
			name: "simple non-empty string",
			raw:  json.RawMessage(`"hello"`),
			want: true,
		},
		{
			name: "empty string",
			raw:  json.RawMessage(`""`),
			want: false,
		},
		{
			name: "escaped null character is non-empty decoded string",
			raw:  json.RawMessage(`"\u0000"`),
			want: true,
		},
		{
			name: "empty array",
			raw:  json.RawMessage(`[]`),
			want: false,
		},
		{
			name: "whitespace empty array",
			raw:  json.RawMessage(`[ 	]`),
			want: false,
		},
		{
			name: "non-empty array",
			raw:  json.RawMessage(`[{}]`),
			want: true,
		},
		{
			name: "empty object",
			raw:  json.RawMessage(`{}`),
			want: false,
		},
		{
			name: "whitespace empty object",
			raw: json.RawMessage(`{ 
			}`),
			want: false,
		},
		{
			name: "non-empty object",
			raw:  json.RawMessage(`{"type":"text","text":""}`),
			want: true,
		},
		{
			name: "malformed string-shaped value",
			raw:  json.RawMessage(`"a"b"`),
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := rawVisibleContent(tc.raw); got != tc.want {
				t.Fatalf("rawVisibleContent(%s) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestChatRequestStats(t *testing.T) {
	body := []byte(`{
		"model": "tinfoil_v3_direct:glm-5-2",
		"messages": [
			{"role": "system", "content": "s"},
			{"role": "user", "content": "u"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "tool", "content": "t"},
			{"role": "assistant", "reasoning": "defg"},
			{"role": "tool", "content": "t"},
			{"role": "assistant", "reasoning_content": "", "reasoning": "hi"},
			{"role": "tool", "content": "t"},
			{"role": "user", "content": "u"},
			{"role": "assistant", "reasoning": null}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.MessageCount != 10 {
		t.Fatalf("MessageCount = %d, want 10", stats.MessageCount)
	}
	if stats.RoleCount != 10 {
		t.Fatalf("RoleCount = %d, want 10", stats.RoleCount)
	}
	wantRoles := []string{"system", "user", "assistant[think, tool_call]", "tool_result", "assistant[think, tool_call]", "tool_result", "assistant[think, tool_call]", "tool_result", "user", "assistant[stripped]"}
	if !slices.Equal(stats.RoleSequence, wantRoles) {
		t.Fatalf("RoleSequence = %v, want %v", stats.RoleSequence, wantRoles)
	}
	if !slices.Equal(stats.AssistantReasoningContentIndexes, []int{2, 6}) {
		t.Fatalf("AssistantReasoningContentIndexes = %v, want [2 6]", stats.AssistantReasoningContentIndexes)
	}
	if !slices.Equal(stats.AssistantReasoningContentLens, []int{3, 0}) {
		t.Fatalf("AssistantReasoningContentLens = %v, want [3 0]", stats.AssistantReasoningContentLens)
	}
	if !slices.Equal(stats.AssistantReasoningIndexes, []int{4, 6}) {
		t.Fatalf("AssistantReasoningIndexes = %v, want [4 6]", stats.AssistantReasoningIndexes)
	}
	if !slices.Equal(stats.AssistantReasoningLens, []int{4, 2}) {
		t.Fatalf("AssistantReasoningLens = %v, want [4 2]", stats.AssistantReasoningLens)
	}
	if !slices.Equal(stats.ActiveMissingReasoningIndexes, []int{9}) {
		t.Fatalf("ActiveMissingReasoningIndexes = %v, want [9]", stats.ActiveMissingReasoningIndexes)
	}
	if !slices.Equal(stats.PriorTurnPreservedReasoningIndexes, []int{2, 4, 6}) {
		t.Fatalf("PriorTurnPreservedReasoningIndexes = %v, want [2 4 6]", stats.PriorTurnPreservedReasoningIndexes)
	}
	if !slices.Equal(stats.PriorTurnPreservedReasoningLens, []int{3, 4, 2}) {
		t.Fatalf("PriorTurnPreservedReasoningLens = %v, want [3 4 2]", stats.PriorTurnPreservedReasoningLens)
	}
	if stats.TrailingUserAddendumIndex != -1 {
		t.Fatalf("TrailingUserAddendumIndex = %d, want -1", stats.TrailingUserAddendumIndex)
	}
	if len(stats.TrailingUserLostReasoningIndexes) != 0 {
		t.Fatalf("TrailingUserLostReasoningIndexes = %v, want []", stats.TrailingUserLostReasoningIndexes)
	}
}

func TestLogChatRequestStats(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"model": "tinfoil_v3_direct:glm-5-2",
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "reasoning": "abc"}
		]
	}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	for _, want := range []string{
		"level=DEBUG",
		"msg=\"chat request metadata\"",
		"model=tinfoil_v3_direct:glm-5-2",
		"provider=tinfoil_v3_direct",
		"upstream_model=glm-5-2",
		"path=/v1/chat/completions",
		"message_count=3",
		"role_count=3",
		"role_sequence=\"[system user assistant[think]]\"",
		"assistant_reasoning_content_count=1",
		"assistant_reasoning_content_indexes=[2]",
		"assistant_reasoning_content_lens=[3]",
		"assistant_reasoning_count=1",
		"assistant_reasoning_indexes=[2]",
		"assistant_reasoning_lens=[3]",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func assertReasoningDiagnosticContext(t *testing.T, logs string) {
	t.Helper()
	for _, want := range []string{
		"reasoning_diagnostics_issue=https://github.com/13rac1/teep/issues/124",
		"reasoning_diagnostics_rate_limit=1x/hour",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestChatRequestLogAttrs_CapsSlicesWhenLimitProvided(t *testing.T) {
	const total = chatRequestWarnAttrSliceLimit + 3
	stats := &chatRequestLogStats{
		MessageCount: total,
		RoleCount:    total,
	}
	for idx := range total {
		stats.RoleSequence = append(stats.RoleSequence, "assistant")
		stats.AssistantReasoningIndexes = append(stats.AssistantReasoningIndexes, idx)
	}

	fullAttrs := fmt.Sprint(chatRequestLogAttrs("model", "provider", "upstream", "/v1/chat/completions", stats, -1))
	if strings.Contains(fullAttrs, "role_sequence_truncated") || strings.Contains(fullAttrs, "assistant_reasoning_indexes_truncated") {
		t.Fatalf("full attrs unexpectedly truncated: %s", fullAttrs)
	}
	if !strings.Contains(fullAttrs, "assistant_reasoning_indexes [0 1 2") || !strings.Contains(fullAttrs, "34") {
		t.Fatalf("full attrs missing complete indexes: %s", fullAttrs)
	}

	cappedAttrs := fmt.Sprint(chatRequestLogAttrs("model", "provider", "upstream", "/v1/chat/completions", stats, chatRequestWarnAttrSliceLimit))
	for _, want := range []string{
		"role_sequence_truncated true",
		"role_sequence_total 35",
		"assistant_reasoning_indexes_truncated true",
		"assistant_reasoning_indexes_total 35",
	} {
		if !strings.Contains(cappedAttrs, want) {
			t.Fatalf("capped attrs missing %q:\n%s", want, cappedAttrs)
		}
	}
	if strings.Contains(cappedAttrs, "34") {
		t.Fatalf("capped attrs includes values past the limit: %s", cappedAttrs)
	}
}

func TestChatRequestStats_ReasoningStrippingClassification(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant"},
			{"role": "tool"},
			{"role": "user"},
			{"role": "assistant"},
			{"role": "tool"},
			{"role": "assistant", "reasoning": ""}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.LastUserIndex != 4 {
		t.Fatalf("LastUserIndex = %d, want 4", stats.LastUserIndex)
	}
	if !slices.Equal(stats.PriorTurnMissingReasoningIndexes, []int{2}) {
		t.Fatalf("PriorTurnMissingReasoningIndexes = %v, want [2]", stats.PriorTurnMissingReasoningIndexes)
	}
	if !slices.Equal(stats.AssistantReasoningIndexes, []int{7}) {
		t.Fatalf("AssistantReasoningIndexes = %v, want [7]", stats.AssistantReasoningIndexes)
	}
	if !slices.Equal(stats.AssistantReasoningLens, []int{0}) {
		t.Fatalf("AssistantReasoningLens = %v, want [0]", stats.AssistantReasoningLens)
	}
	if !slices.Equal(stats.ActiveMissingReasoningIndexes, []int{5, 7}) {
		t.Fatalf("ActiveMissingReasoningIndexes = %v, want [5 7]", stats.ActiveMissingReasoningIndexes)
	}
	if !slices.Equal(stats.ActiveMissingReasoningToolCallIndexes, []int{5}) {
		t.Fatalf("ActiveMissingReasoningToolCallIndexes = %v, want [5]", stats.ActiveMissingReasoningToolCallIndexes)
	}
}

func TestChatRequestStats_TrailingUserAddendumClearsCurrentTurnReasoning(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "reasoning": "defg", "tool_calls": [{"id": "call_2", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.LastUserIndex != 6 {
		t.Fatalf("LastUserIndex = %d, want 6", stats.LastUserIndex)
	}
	if stats.TrailingUserAddendumIndex != 6 {
		t.Fatalf("TrailingUserAddendumIndex = %d, want 6", stats.TrailingUserAddendumIndex)
	}
	if stats.TrailingUserPrevUserIndex != 1 {
		t.Fatalf("TrailingUserPrevUserIndex = %d, want 1", stats.TrailingUserPrevUserIndex)
	}
	if !slices.Equal(stats.TrailingUserLostReasoningIndexes, []int{2, 4}) {
		t.Fatalf("TrailingUserLostReasoningIndexes = %v, want [2 4]", stats.TrailingUserLostReasoningIndexes)
	}
	if !slices.Equal(stats.TrailingUserLostReasoningLens, []int{3, 4}) {
		t.Fatalf("TrailingUserLostReasoningLens = %v, want [3 4]", stats.TrailingUserLostReasoningLens)
	}
	if stats.ChatTemplateClearThinkingPresent {
		t.Fatalf("ChatTemplateClearThinkingPresent = true, want false")
	}
	if stats.chatTemplateClearThinkingFalse() {
		t.Fatalf("chatTemplateClearThinkingFalse = true, want false")
	}
}

func TestChatRequestStats_TrailingUserAfterAssistantAnswerDoesNotWarn(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "content": "final answer"},
			{"role": "user", "content": "follow up"}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.TrailingUserAddendumIndex != -1 {
		t.Fatalf("TrailingUserAddendumIndex = %d, want -1", stats.TrailingUserAddendumIndex)
	}
	if len(stats.TrailingUserLostReasoningIndexes) != 0 {
		t.Fatalf("TrailingUserLostReasoningIndexes = %v, want []", stats.TrailingUserLostReasoningIndexes)
	}
}

func TestChatRequestStats_TrailingUserAfterToolCallWithoutReasoning(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant"},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if stats.TrailingUserAddendumIndex != 3 {
		t.Fatalf("TrailingUserAddendumIndex = %d, want 3", stats.TrailingUserAddendumIndex)
	}
	if stats.TrailingUserPrevUserIndex != 0 {
		t.Fatalf("TrailingUserPrevUserIndex = %d, want 0", stats.TrailingUserPrevUserIndex)
	}
	if len(stats.TrailingUserLostReasoningIndexes) != 0 {
		t.Fatalf("TrailingUserLostReasoningIndexes = %v, want []", stats.TrailingUserLostReasoningIndexes)
	}
	if !slices.Equal(stats.TrailingUserMissingReasoningIndexes, []int{1}) {
		t.Fatalf("TrailingUserMissingReasoningIndexes = %v, want [1]", stats.TrailingUserMissingReasoningIndexes)
	}
}

func TestChatRequestStats_ClearThinkingFalse(t *testing.T) {
	body := []byte(`{
		"chat_template_kwargs": {"clear_thinking": false},
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	if !stats.ChatTemplateClearThinkingPresent {
		t.Fatalf("ChatTemplateClearThinkingPresent = false, want true")
	}
	if stats.ChatTemplateClearThinking {
		t.Fatalf("ChatTemplateClearThinking = true, want false")
	}
	if !stats.chatTemplateClearThinkingFalse() {
		t.Fatalf("chatTemplateClearThinkingFalse = false, want true")
	}
}

func captureSlogWithLevel(t *testing.T, level slog.Level, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

type enabledLevelsHandler struct {
	slog.Handler
	levels map[slog.Level]bool
}

func (h enabledLevelsHandler) Enabled(_ context.Context, level slog.Level) bool {
	return h.levels[level]
}

func captureSlogWithEnabledLevels(t *testing.T, levels map[slog.Level]bool, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	base := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(enabledLevelsHandler{Handler: base, levels: levels}))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}

func TestLogChatRequestStats_ReasoningStripSignalsRateLimited(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant"},
			{"role": "tool"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "tool_calls": [{"id": "call_2", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
			{"role": "tool"}
		]
	}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	infoMsg := "msg=\"agent framework is stripping prior turn reasoning messages; this is known to be bad for coding agents\""
	if count := strings.Count(logs, infoMsg); count != 1 {
		t.Fatalf("prior-turn INFO log count = %d, want 1:\n%s", count, logs)
	}
	warnMsg := "msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("active WARN log count = %d, want 1:\n%s", count, logs)
	}
	assertReasoningDiagnosticContext(t, logs)
	for _, want := range []string{
		"level=INFO",
		"assistant_missing_reasoning_prior_turn_indexes=[2]",
		"level=WARN",
		"assistant_missing_reasoning_active_indexes=\"[5 7]\"",
		"assistant_tool_call_missing_reasoning_active_indexes=\"[5 7]\"",
		"assistant_user_message_missing_reasoning_active_indexes=[]",
		"role_sequence=\"[system user assistant[tool_call] tool_result user assistant[tool_call] tool_result assistant[tool_call] tool_result]\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStatsWithStats_UsesProvidedStats(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	stats, err := chatRequestStats(body)
	if err != nil {
		t.Fatalf("chatRequestStats: %v", err)
	}
	malformedBody := []byte(`{"messages": [1]}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", malformedBody, &stats, nil)
	})
	if strings.Contains(logs, "msg=\"chat request reasoning metadata unavailable\"") {
		t.Fatalf("log reparsed malformed body despite supplied stats:\n%s", logs)
	}
	for _, want := range []string{
		"msg=\"agent framework preserved prior turn reasoning fields, but model chat template will ignore them without model-specific preserved-thinking flag\"",
		"assistant_preserved_reasoning_prior_turn_indexes=[1]",
		"model_reasoning_preservation_flag=\"chat_template_kwargs.clear_thinking=false\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_InfoDisabledDoesNotConsumeInfoLimiter(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant"},
			{"role": "user"}
		]
	}`)
	_ = captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	logs := captureSlogWithLevel(t, slog.LevelDebug, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	infoMsg := "msg=\"agent framework is stripping prior turn reasoning messages; this is known to be bad for coding agents\""
	if count := strings.Count(logs, infoMsg); count != 1 {
		t.Fatalf("prior-turn INFO log count after warn-only pass = %d, want 1:\n%s", count, logs)
	}
}

func TestLogChatRequestStats_WarnDisabledDoesNotConsumeWarnLimiter(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "tool_calls": [{"id": "call_2", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
			{"role": "tool"}
		]
	}`)
	_ = captureSlogWithEnabledLevels(t, map[slog.Level]bool{slog.LevelInfo: true}, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("active WARN log count after info-only pass = %d, want 1:\n%s", count, logs)
	}
}

func TestLogChatRequestStats_SingleActiveToolCallDoesNotWarn(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"}
		]
	}`)
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	if strings.Contains(logs, "msg=\"chat request metadata\"") {
		t.Fatalf("unexpected DEBUG metadata log in warn-only mode:\n%s", logs)
	}
	warnMsg := "msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\""
	if strings.Contains(logs, warnMsg) {
		t.Fatalf("unexpected active reasoning WARN log for a single tool call:\n%s", logs)
	}
}

func TestLogChatRequestStats_SingleActiveAssistantMessageDoesNotWarn(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "content": "I cannot help with that."}
		]
	}`)
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\""
	if strings.Contains(logs, warnMsg) {
		t.Fatalf("unexpected active reasoning WARN log for a single assistant message:\n%s", logs)
	}
}

func TestLogChatRequestStats_TwoActiveAssistantMessagesWarn(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "content": "First update."},
			{"role": "assistant", "refusal": "Second update."}
		]
	}`)
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("active assistant WARN log count = %d, want 1:\n%s", count, logs)
	}
	for _, want := range []string{
		"assistant_missing_reasoning_active_indexes=\"[1 2]\"",
		"assistant_tool_call_missing_reasoning_active_indexes=[]",
		"assistant_user_message_missing_reasoning_active_indexes=\"[1 2]\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_NoSignalDoesNotSuppressLaterWarning(t *testing.T) {
	s := &Server{}
	noSignalBody := []byte(`{"messages": [{"role": "user", "content": "hello"}]}`)
	activeMissingBody := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "tool_calls": [{"id": "call_2", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
			{"role": "tool"}
		]
	}`)
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", noSignalBody, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", activeMissingBody, nil, nil)
	})
	warnMsg := "msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("active WARN log count = %d, want 1:\n%s", count, logs)
	}
}

func TestLogChatRequestStats_DiagnosticDoesNotSuppressOtherCategory(t *testing.T) {
	s := &Server{}
	activeMissingBody := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "tool_calls": [{"id": "call_2", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
			{"role": "tool"}
		]
	}`)
	trailingUserBody := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", activeMissingBody, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", trailingUserBody, nil, nil)
	})
	for _, want := range []string{
		"msg=\"agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields\"",
		"msg=\"agent framework may have appended a trailing user message after tool output; model chat template may clear current-turn reasoning\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_TrailingUserAddendumWarns(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "assistant", "reasoning": "defg", "tool_calls": [{"id": "call_2", "type": "function", "function": {"name": "b", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework may have appended a trailing user message after tool output; model chat template may clear current-turn reasoning\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("trailing-user WARN log count = %d, want 1:\n%s", count, logs)
	}
	assertReasoningDiagnosticContext(t, logs)
	for _, want := range []string{
		"level=WARN",
		"role_sequence=\"[system user assistant[think, tool_call] tool_result assistant[think, tool_call] tool_result user]\"",
		"trailing_user_addendum_index=6",
		"trailing_user_prev_user_index=1",
		"assistant_reasoning_lost_by_trailing_user_indexes=\"[2 4]\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_TrailingUserAddendumSuppressesWarnWhenClearThinkingFalse(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"chat_template_kwargs": {"clear_thinking": false},
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework may have appended a trailing user message after tool output; model chat template may clear current-turn reasoning\""
	if strings.Contains(logs, warnMsg) {
		t.Fatalf("unexpected trailing-user WARN log:\n%s", logs)
	}
	for _, want := range []string{
		"level=DEBUG",
		"trailing_user_addendum_index=4",
		"assistant_reasoning_lost_by_trailing_user_indexes=[2]",
		"chat_template_clear_thinking_present=true",
		"chat_template_clear_thinking_false=true",
		"chat_template_clear_thinking=false",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_TrailingUserAfterToolCallWithoutReasoningWarns(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"tools": [{"type": "function", "function": {"name": "x", "parameters": {"type": "object"}}}],
		"messages": [
			{"role": "user"},
			{"role": "assistant"},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework sent malformed tool-loop history: current tool-call reasoning is stripped and a trailing user message after tool output may cause the model to lose reasoning or tool-result context\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("trailing-user missing-reasoning WARN log count = %d, want 1:\n%s", count, logs)
	}
	infoMsg := "msg=\"agent framework is stripping prior turn reasoning messages; this is known to be bad for coding agents\""
	if strings.Contains(logs, infoMsg) {
		t.Fatalf("unexpected prior-turn INFO for trailing-user tool-call turn:\n%s", logs)
	}
	for _, want := range []string{
		"level=WARN",
		"role_sequence=\"[user assistant[tool_call] tool_result user]\"",
		"trailing_user_addendum_index=3",
		"trailing_user_prev_user_index=0",
		"assistant_reasoning_lost_by_trailing_user_indexes=[]",
		"assistant_missing_reasoning_by_trailing_user_indexes=[1]",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_IncompleteStatsInferTrailingUserAfterToolCallWithoutReasoning(t *testing.T) {
	s := &Server{}
	stats := &chatRequestLogStats{
		MessageCount:                        4,
		RoleCount:                           4,
		RoleSequence:                        []string{"user", "assistant", "tool", "user"},
		LastUserIndex:                       3,
		PriorTurnMissingReasoningIndexes:    []int{1},
		TrailingUserAddendumIndex:           -1,
		TrailingUserPrevUserIndex:           -1,
		ToolsPresent:                        true,
		ToolsCount:                          31,
		ChatTemplateClearThinkingPresent:    false,
		ChatTemplatePreserveThinking:        false,
		ChatTemplateDropThinkingPresent:     false,
		ChatTemplatePreserveThinkingPresent: false,
	}
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", nil, stats, nil)
	})
	warnMsg := "msg=\"agent framework sent malformed tool-loop history: current tool-call reasoning is stripped and a trailing user message after tool output may cause the model to lose reasoning or tool-result context\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("trailing-user missing-reasoning WARN log count = %d, want 1:\n%s", count, logs)
	}
	infoMsg := "msg=\"agent framework is stripping prior turn reasoning messages; this is known to be bad for coding agents\""
	if strings.Contains(logs, infoMsg) {
		t.Fatalf("unexpected prior-turn INFO for inferred trailing-user tool-call turn:\n%s", logs)
	}
	for _, want := range []string{
		"level=WARN",
		"role_sequence=\"[user assistant[tool_call] tool_result user]\"",
		"trailing_user_addendum_index=3",
		"trailing_user_prev_user_index=0",
		"assistant_missing_reasoning_by_trailing_user_indexes=[1]",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_ReasoningPreservationRepairWarns(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "system"},
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	repairedBody, repair, err := repairChatReasoningPreservation("tinfoil_v3_direct:glm-5-2", "glm-5-2", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", repairedBody, nil, repair)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", repairedBody, nil, repair)
	})
	priorRepairMsg := "msg=\"agent framework preserved prior turn reasoning fields; teep repaired model reasoning preservation by providing model-specific preserved-thinking flag\""
	if count := strings.Count(logs, priorRepairMsg); count != 1 {
		t.Fatalf("prior-turn repair WARN log count = %d, want 1:\n%s", count, logs)
	}
	trailingRepairMsg := "msg=\"agent framework may have appended a trailing user message after tool output; teep repaired current-turn reasoning preservation by providing model-specific preserved-thinking flag\""
	if count := strings.Count(logs, trailingRepairMsg); count != 1 {
		t.Fatalf("trailing-user repair WARN log count = %d, want 1:\n%s", count, logs)
	}
	for _, unexpected := range []string{
		"msg=\"teep repaired model reasoning preservation by injecting model-specific chat template flag after detecting known model\"",
		"msg=\"agent framework may have appended a trailing user message after tool output; model chat template may clear current-turn reasoning\"",
		"msg=\"agent framework preserved prior turn reasoning fields, but model chat template will ignore them without model-specific preserved-thinking flag\"",
	} {
		if strings.Contains(logs, unexpected) {
			t.Fatalf("unexpected unrepaired/generic WARN log %q:\n%s", unexpected, logs)
		}
	}
	assertReasoningDiagnosticContext(t, logs)
	for _, want := range []string{
		"level=WARN",
		"model_reasoning_preservation_family=glm",
		"model_reasoning_preservation_flag=\"chat_template_kwargs.clear_thinking=false\"",
		"reasoning_preservation_repair_reasons=\"[prior_turn_reasoning trailing_user_after_tool]\"",
		"chat_template_clear_thinking_present=true",
		"chat_template_clear_thinking_false=true",
		"chat_template_clear_thinking=false",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_TrailingUserRepairWarnsAtWarnLevel(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning_content": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool"},
			{"role": "user", "content": "continue"}
		]
	}`)
	repairedBody, repair, err := repairChatReasoningPreservation("tinfoil_v3_direct:glm-5-2", "glm-5-2", body)
	if err != nil {
		t.Fatalf("repairChatReasoningPreservation: %v", err)
	}
	if repair == nil {
		t.Fatal("repair = nil, want repair")
	}
	logs := captureSlogWithLevel(t, slog.LevelWarn, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", repairedBody, nil, repair)
	})
	priorRepairMsg := "msg=\"agent framework preserved prior turn reasoning fields; teep repaired model reasoning preservation by providing model-specific preserved-thinking flag\""
	if count := strings.Count(logs, priorRepairMsg); count != 1 {
		t.Fatalf("prior-turn repair WARN log count = %d, want 1:\n%s", count, logs)
	}
	trailingRepairMsg := "msg=\"agent framework may have appended a trailing user message after tool output; teep repaired current-turn reasoning preservation by providing model-specific preserved-thinking flag\""
	if count := strings.Count(logs, trailingRepairMsg); count != 1 {
		t.Fatalf("trailing-user repair WARN log count = %d, want 1:\n%s", count, logs)
	}
	for _, want := range []string{
		"model_reasoning_preservation_family=glm",
		"model_reasoning_preservation_flag=\"chat_template_kwargs.clear_thinking=false\"",
		"reasoning_preservation_repair_reasons=\"[prior_turn_reasoning trailing_user_after_tool]\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_ModelReasoningPreservationFlagWarns(t *testing.T) {
	tests := []struct {
		name          string
		model         string
		providerName  string
		upstreamModel string
		body          []byte
		family        string
		flag          string
	}{
		{
			name:          "glm mixed case routed model",
			model:         "any_provider:Vendor/GLM-Future-99",
			providerName:  "any_provider",
			upstreamModel: "Vendor/Other-Model",
			body: []byte(`{
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning_content": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
			family: "glm",
			flag:   "chat_template_kwargs.clear_thinking=false",
		},
		{
			name:          "kimi mixed case upstream model",
			model:         "third_party:moonshot-model",
			providerName:  "third_party",
			upstreamModel: "MoonshotAI/KIMI-K3-Future",
			body: []byte(`{
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
			family: "kimi",
			flag:   "chat_template_kwargs.preserve_thinking=true",
		},
		{
			name:          "deepseek mixed case routed model",
			model:         "aggregator:DEEPSEEK-vFuture",
			providerName:  "aggregator",
			upstreamModel: "vendor/reasoner",
			body: []byte(`{
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
			family: "deepseek",
			flag:   "chat_template_kwargs.drop_thinking=false",
		},
		{
			name:          "deepseek tools present without trailing user tool loop",
			model:         "tinfoil_v3_direct:deepseek-v4-pro",
			providerName:  "tinfoil_v3_direct",
			upstreamModel: "deepseek-v4-pro",
			body: []byte(`{
				"tools": [{"type": "function", "function": {"name": "x", "parameters": {"type": "object"}}}],
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
			family: "deepseek",
			flag:   "chat_template_kwargs.drop_thinking=false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{}
			logs := captureSlog(t, func() {
				logChatRequestStats(t.Context(), &s.reasoningStripLogs, tt.model, tt.providerName, tt.upstreamModel, "/v1/chat/completions", tt.body, nil, nil)
				logChatRequestStats(t.Context(), &s.reasoningStripLogs, tt.model, tt.providerName, tt.upstreamModel, "/v1/chat/completions", tt.body, nil, nil)
			})
			warnMsg := "msg=\"agent framework preserved prior turn reasoning fields, but model chat template will ignore them without model-specific preserved-thinking flag\""
			if count := strings.Count(logs, warnMsg); count != 1 {
				t.Fatalf("model preservation WARN log count = %d, want 1:\n%s", count, logs)
			}
			assertReasoningDiagnosticContext(t, logs)
			for _, want := range []string{
				"level=WARN",
				"assistant_preserved_reasoning_prior_turn_indexes=[1]",
				"assistant_preserved_reasoning_prior_turn_lens=[3]",
				"model_reasoning_preservation_family=" + tt.family,
				"model_reasoning_preservation_flag=\"" + tt.flag + "\"",
			} {
				if !strings.Contains(logs, want) {
					t.Fatalf("log output missing %q:\n%s", want, logs)
				}
			}
		})
	}
}

func TestLogChatRequestStats_ModelReasoningPreservationFlagSuppressesWarn(t *testing.T) {
	tests := []struct {
		name          string
		model         string
		upstreamModel string
		body          []byte
	}{
		{
			name:          "glm clear thinking false",
			model:         "tinfoil_v3_direct:glm-5-2",
			upstreamModel: "glm-5-2",
			body: []byte(`{
				"chat_template_kwargs": {"clear_thinking": false},
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning_content": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
		},
		{
			name:          "kimi preserve thinking true",
			model:         "tinfoil_v3_direct:kimi-k2-6",
			upstreamModel: "kimi-k2-6",
			body: []byte(`{
				"chat_template_kwargs": {"preserve_thinking": true},
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
		},
		{
			name:          "deepseek drop thinking false",
			model:         "tinfoil_v3_direct:deepseek-v4-pro",
			upstreamModel: "deepseek-v4-pro",
			body: []byte(`{
				"chat_template_kwargs": {"drop_thinking": false},
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning": "abc"},
					{"role": "user", "content": "next"}
				]
			}`),
		},
		{
			name:          "deepseek trailing user tool loop",
			model:         "tinfoil_v3_direct:deepseek-v4-pro",
			upstreamModel: "deepseek-v4-pro",
			body: []byte(`{
				"tools": [{"type": "function", "function": {"name": "x", "parameters": {"type": "object"}}}],
				"messages": [
					{"role": "user"},
					{"role": "assistant", "reasoning": "abc", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "x", "arguments": "{}"}}]},
					{"role": "tool"},
					{"role": "user", "content": "next"}
				]
			}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{}
			logs := captureSlog(t, func() {
				logChatRequestStats(t.Context(), &s.reasoningStripLogs, tt.model, "tinfoil_v3_direct", tt.upstreamModel, "/v1/chat/completions", tt.body, nil, nil)
			})
			warnMsg := "msg=\"agent framework preserved prior turn reasoning fields, but model chat template will ignore them without model-specific preserved-thinking flag\""
			if strings.Contains(logs, warnMsg) {
				t.Fatalf("unexpected model preservation WARN log:\n%s", logs)
			}
		})
	}
}

func TestLogChatRequestStats_DeepSeekDropThinkingTrueWithToolsWarns(t *testing.T) {
	s := &Server{}
	body := []byte(`{
		"chat_template_kwargs": {"drop_thinking": true},
		"tools": [{"type": "function", "function": {"name": "x", "parameters": {"type": "object"}}}],
		"messages": [
			{"role": "user"},
			{"role": "assistant", "reasoning": "abc"},
			{"role": "user", "content": "next"}
		]
	}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:deepseek-v4-pro", "tinfoil_v3_direct", "deepseek-v4-pro", "/v1/chat/completions", body, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:deepseek-v4-pro", "tinfoil_v3_direct", "deepseek-v4-pro", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"agent framework preserved prior turn reasoning fields, but model chat template will ignore them without model-specific preserved-thinking flag\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("model preservation WARN log count = %d, want 1:\n%s", count, logs)
	}
	assertReasoningDiagnosticContext(t, logs)
	for _, want := range []string{
		"level=WARN",
		"tools_present=true",
		"chat_template_drop_thinking_present=true",
		"chat_template_drop_thinking=true",
		"chat_template_drop_thinking_false=false",
		"model_reasoning_preservation_family=deepseek",
		"model_reasoning_preservation_flag=\"chat_template_kwargs.drop_thinking=false\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_IndeterminateRateLimited(t *testing.T) {
	s := &Server{}
	body := []byte(`{"messages": [{"role": "user"}, {"role": 123}]}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"chat request reasoning metadata could not be fully determined\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("indeterminate WARN log count = %d, want 1:\n%s", count, logs)
	}
	assertReasoningDiagnosticContext(t, logs)
	for _, want := range []string{
		"level=WARN",
		"determine_issue_count=1",
		"determine_issues=\"[message 1 role is not a string]\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_MissingMessagesIndeterminateWarns(t *testing.T) {
	s := &Server{}
	body := []byte(`{}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"chat request reasoning metadata could not be fully determined\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("indeterminate WARN log count = %d, want 1:\n%s", count, logs)
	}
	for _, want := range []string{
		"level=WARN",
		"determine_issue_count=1",
		"determine_issues=\"[messages field missing]\"",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestLogChatRequestStats_UnavailableRateLimited(t *testing.T) {
	s := &Server{}
	body := []byte(`{"messages": [1]}`)
	logs := captureSlog(t, func() {
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
		logChatRequestStats(t.Context(), &s.reasoningStripLogs, "tinfoil_v3_direct:glm-5-2", "tinfoil_v3_direct", "glm-5-2", "/v1/chat/completions", body, nil, nil)
	})
	warnMsg := "msg=\"chat request reasoning metadata unavailable\""
	if count := strings.Count(logs, warnMsg); count != 1 {
		t.Fatalf("unavailable WARN log count = %d, want 1:\n%s", count, logs)
	}
	assertReasoningDiagnosticContext(t, logs)
	for _, want := range []string{
		"level=WARN",
		"model=tinfoil_v3_direct:glm-5-2",
		"provider=tinfoil_v3_direct",
		"path=/v1/chat/completions",
		"err=",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("log output missing %q:\n%s", want, logs)
		}
	}
}

func TestChatRequestStatsLoggingEnabledRespectsRateLimiter(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	now := time.Now()
	limiter := &hourlyLogLimiter{last: map[string]time.Time{
		chatReasoningMetadataUnavailableLogKey:   now,
		chatPriorTurnReasoningStrippedLogKey:     now,
		chatPriorTurnReasoningNotPreservedLogKey: now,
		chatActiveReasoningStrippedLogKey:        now,
		chatTrailingUserReasoningLostLogKey:      now,
		chatReasoningMetadataIndeterminateLogKey: now,
	}}
	if chatRequestStatsLoggingEnabled(t.Context(), limiter) {
		t.Fatal("chatRequestStatsLoggingEnabled = true with warn-only logging and all diagnostic keys rate-limited, want false")
	}

	limiter.last[chatActiveReasoningStrippedLogKey] = now.Add(-reasoningStripLogInterval - time.Second)
	if !chatRequestStatsLoggingEnabled(t.Context(), limiter) {
		t.Fatal("chatRequestStatsLoggingEnabled = false with an expired warn diagnostic key, want true")
	}
	limiter.last[chatActiveReasoningStrippedLogKey] = now
	if chatRequestStatsLoggingEnabled(t.Context(), limiter) {
		t.Fatal("chatRequestStatsLoggingEnabled = true with all warn diagnostic keys rate-limited, want false")
	}
}

// ---------------------------------------------------------------------------
// Phase 4 (GH issue #124): opt-in prompt-sandwich merge repair.
// ---------------------------------------------------------------------------

func promptSandwichBody(trailingExtra string) []byte {
	return []byte(`{
		"messages": [
			{"role": "user", "content": "please run the tool"},
			{"role": "assistant", "reasoning": "thinking...", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool", "content": "tool result"},
			{"role": "user", "content": "continue please"` + trailingExtra + `}
		]
	}`)
}

func messageContents(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal repaired body: %v", err)
	}
	out := make([]string, len(req.Messages))
	for i, m := range req.Messages {
		out[i] = m.Content
	}
	return out
}

func messageCount(t *testing.T, body []byte) int {
	t.Helper()
	var req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("unmarshal repaired body: %v", err)
	}
	return len(req.Messages)
}

func TestRepairPromptSandwichMerge_MergesLosslessly(t *testing.T) {
	body := promptSandwichBody("")
	repaired, stats, err := repairPromptSandwichMerge(t.Context(), &hourlyLogLimiter{}, "provider:some-unknown-family", "provider", "some-unknown-family", "/v1/chat/completions", false, body, nil)
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if messageCount(t, repaired) != 3 {
		t.Fatalf("message count = %d, want 3 (trailing message merged away)", messageCount(t, repaired))
	}
	contents := messageContents(t, repaired)
	want := "please run the tool\n\ncontinue please"
	if contents[0] != want {
		t.Fatalf("merged prior user content = %q, want %q", contents[0], want)
	}
	if stats == nil {
		t.Fatal("stats = nil, want refreshed stats after merge")
	}
	if stats.TrailingUserAddendumIndex >= 0 {
		t.Fatalf("stats.TrailingUserAddendumIndex = %d after merge, want -1 (no more trailing addendum)", stats.TrailingUserAddendumIndex)
	}
}

func TestRepairPromptSandwichMerge_ParsesStatsWhenNil(t *testing.T) {
	// repairChatReasoningPreservationWithStats returns nil stats for
	// unknown families (it short-circuits before parsing); the merge repair
	// must still work by parsing the body itself in that case.
	body := promptSandwichBody("")
	repaired, _, err := repairPromptSandwichMerge(t.Context(), &hourlyLogLimiter{}, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", false, body, nil)
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if messageCount(t, repaired) != 3 {
		t.Fatalf("message count = %d, want 3", messageCount(t, repaired))
	}
}

func TestRepairPromptSandwichMerge_NoTrailingAddendumIsNoop(t *testing.T) {
	body := []byte(`{"messages": [{"role": "user", "content": "hi"}]}`)
	repaired, _, err := repairPromptSandwichMerge(t.Context(), &hourlyLogLimiter{}, "provider:model", "provider", "model", "/v1/chat/completions", false, body, nil)
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if !bytes.Equal(repaired, body) {
		t.Fatalf("repaired body = %s, want unchanged %s", repaired, body)
	}
}

func TestRepairPromptSandwichMerge_SkipsKnownFamily(t *testing.T) {
	// Families with a known chat-template flag are handled by
	// repairChatReasoningPreservationWithStats; the merge repair must not
	// also mutate the request for those.
	body := promptSandwichBody("")
	repaired, _, err := repairPromptSandwichMerge(t.Context(), &hourlyLogLimiter{}, "provider:glm-5-2", "provider", "glm-5-2", "/v1/chat/completions", false, body, nil)
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if messageCount(t, repaired) != 4 {
		t.Fatalf("message count = %d, want 4 (unchanged for known family)", messageCount(t, repaired))
	}
}

func TestRepairPromptSandwichMerge_SkipsE2EEProviderWithWarn(t *testing.T) {
	body := promptSandwichBody("")
	limiter := &hourlyLogLimiter{}
	var repaired []byte
	var err error
	logs := captureSlog(t, func() {
		repaired, _, err = repairPromptSandwichMerge(t.Context(), limiter, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", true, body, nil)
	})
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if messageCount(t, repaired) != 4 {
		t.Fatalf("message count = %d, want 4 (unchanged for E2EE provider)", messageCount(t, repaired))
	}
	if !strings.Contains(logs, "prompt-sandwich merge repair skipped: provider uses field-level E2EE") {
		t.Fatalf("log output missing E2EE-skip WARN:\n%s", logs)
	}
	assertReasoningDiagnosticContext(t, logs)
}

func TestRepairPromptSandwichMerge_SkipsLossyNonStringContentWithWarn(t *testing.T) {
	body := []byte(`{
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "please run the tool"}]},
			{"role": "assistant", "reasoning": "thinking...", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool", "content": "tool result"},
			{"role": "user", "content": "continue please"}
		]
	}`)
	limiter := &hourlyLogLimiter{}
	var repaired []byte
	var err error
	logs := captureSlog(t, func() {
		repaired, _, err = repairPromptSandwichMerge(t.Context(), limiter, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", false, body, nil)
	})
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if messageCount(t, repaired) != 4 {
		t.Fatalf("message count = %d, want 4 (unchanged: non-string content parts cannot merge losslessly)", messageCount(t, repaired))
	}
	if !strings.Contains(logs, "prompt-sandwich merge repair skipped: trailing user message could not be merged losslessly") {
		t.Fatalf("log output missing lossy-skip WARN:\n%s", logs)
	}
}

func TestRepairPromptSandwichMerge_SkipsLossyExtraFieldOnTrailingMessage(t *testing.T) {
	body := promptSandwichBody(`, "name": "reminder-bot"`)
	repaired, _, err := repairPromptSandwichMerge(t.Context(), &hourlyLogLimiter{}, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", false, body, nil)
	if err != nil {
		t.Fatalf("repairPromptSandwichMerge: %v", err)
	}
	if messageCount(t, repaired) != 4 {
		t.Fatalf("message count = %d, want 4 (unchanged: extra field on trailing message would be silently dropped)", messageCount(t, repaired))
	}
}

func TestRepairPromptSandwichMerge_AppliedWarnIsRateLimited(t *testing.T) {
	body := promptSandwichBody("")
	limiter := &hourlyLogLimiter{}
	logs := captureSlog(t, func() {
		if _, _, err := repairPromptSandwichMerge(t.Context(), limiter, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", false, body, nil); err != nil {
			t.Fatalf("repairPromptSandwichMerge: %v", err)
		}
		if _, _, err := repairPromptSandwichMerge(t.Context(), limiter, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", false, body, nil); err != nil {
			t.Fatalf("repairPromptSandwichMerge: %v", err)
		}
	})
	count := strings.Count(logs, "prompt-sandwich merge repair applied")
	if count != 1 {
		t.Fatalf("applied WARN logged %d times, want 1 (rate-limited):\n%s", count, logs)
	}
}

func TestRepairPromptSandwichMerge_NeverLogsMessageContent(t *testing.T) {
	const secretMarker = "TOP_SECRET_USER_MESSAGE_CONTENT_MUST_NOT_APPEAR_IN_LOGS"
	body := []byte(`{
		"messages": [
			{"role": "user", "content": "` + secretMarker + `"},
			{"role": "assistant", "reasoning": "thinking...", "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "a", "arguments": "{}"}}]},
			{"role": "tool", "content": "tool result"},
			{"role": "user", "content": "` + secretMarker + `"}
		]
	}`)
	logs := captureSlog(t, func() {
		if _, _, err := repairPromptSandwichMerge(t.Context(), &hourlyLogLimiter{}, "provider:unknown-family", "provider", "unknown-family", "/v1/chat/completions", false, body, nil); err != nil {
			t.Fatalf("repairPromptSandwichMerge: %v", err)
		}
	})
	if strings.Contains(logs, secretMarker) {
		t.Fatalf("log output leaked message content:\n%s", logs)
	}
}

func TestMergeTrailingUserIntoPriorUser_MissingMessagesFieldIsLossy(t *testing.T) {
	req := map[string]json.RawMessage{}
	_, _, _, lossy, err := mergeTrailingUserIntoPriorUser(req, 0, 1)
	if err != nil {
		t.Fatalf("mergeTrailingUserIntoPriorUser: %v", err)
	}
	if !lossy {
		t.Fatal("lossy = false, want true when messages field is missing")
	}
}

func TestMergeTrailingUserIntoPriorUser_OutOfRangeIndexesAreLossy(t *testing.T) {
	req := map[string]json.RawMessage{
		"messages": json.RawMessage(`[{"role":"user","content":"a"}]`),
	}
	_, _, _, lossy, err := mergeTrailingUserIntoPriorUser(req, 0, 5)
	if err != nil {
		t.Fatalf("mergeTrailingUserIntoPriorUser: %v", err)
	}
	if !lossy {
		t.Fatal("lossy = false, want true for out-of-range addendum index")
	}
}

func TestIsExactlyRoleAndContentKeys(t *testing.T) {
	yes, _ := unmarshalJSONObject(json.RawMessage(`{"role":"user","content":"hi"}`))
	if !isExactlyRoleAndContentKeys(yes) {
		t.Error("isExactlyRoleAndContentKeys(role+content) = false, want true")
	}
	no, _ := unmarshalJSONObject(json.RawMessage(`{"role":"user","content":"hi","name":"x"}`))
	if isExactlyRoleAndContentKeys(no) {
		t.Error("isExactlyRoleAndContentKeys(role+content+name) = true, want false")
	}
}

func TestPlainStringContent(t *testing.T) {
	if s, ok := plainStringContent(json.RawMessage(`"hello"`)); !ok || s != "hello" {
		t.Errorf("plainStringContent(string) = (%q, %v), want (hello, true)", s, ok)
	}
	if _, ok := plainStringContent(json.RawMessage(`["a","b"]`)); ok {
		t.Error("plainStringContent(array) = ok, want not ok")
	}
	if _, ok := plainStringContent(json.RawMessage(`null`)); ok {
		t.Error("plainStringContent(null) = ok, want not ok")
	}
	if _, ok := plainStringContent(json.RawMessage(``)); ok {
		t.Error("plainStringContent(empty) = ok, want not ok")
	}
}
