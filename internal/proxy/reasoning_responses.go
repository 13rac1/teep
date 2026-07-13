package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// This file extends the reasoning-loss diagnostics added by GH issue #123
// (reasoning.go) to the /v1/responses endpoint (GH issue #124 Phase 1).
//
// The Responses API request shape differs from chat completions: instead of
// a flat "messages" array, "input" is an array of typed items (message,
// function_call, function_call_output, reasoning), and cross-turn state can
// additionally be carried server-side via "previous_response_id". Detection
// here is WARN/INFO-only (metadata: role/type/counts/field-presence, never
// message text) — there is no repair step yet, pending confirmation that the
// Tinfoil /v1/responses upstream accepts an equivalent to
// chat_template_kwargs (see docs/plans/2026-07-06-gh-issue-124.md, Phase 1
// "Open questions").

const (
	responsesActiveFunctionCallMissingReasoningWarnThreshold = 2

	responsesReasoningMetadataUnavailableLogKey          = "responses_reasoning_metadata_unavailable"
	responsesPriorTurnFunctionCallMissingReasoningLogKey = "responses_prior_turn_function_call_missing_reasoning"
	responsesActiveFunctionCallMissingReasoningLogKey    = "responses_active_function_call_missing_reasoning"
	responsesTrailingUserAfterFunctionCallOutputLogKey   = "responses_trailing_user_after_function_call_output"
	responsesReasoningNotPreservedAcrossTurnsLogKey      = "responses_reasoning_not_preserved_across_turns"
	responsesReasoningMetadataIndeterminateLogKey        = "responses_reasoning_metadata_indeterminate"
)

// responsesRequestLogStats holds metadata-only statistics extracted from a
// /v1/responses request body. Never populate this with message/argument
// text — only roles, types, counts, indexes, and field-presence booleans.
type responsesRequestLogStats struct {
	ItemCount int

	LastUserMessageIndex int

	FunctionCallIndexes                       []int
	FunctionCallMissingReasoningPriorIndexes  []int
	FunctionCallMissingReasoningActiveIndexes []int

	ReasoningItemIndexes []int

	TrailingUserAfterFunctionCallOutput     bool
	TrailingUserIndex                       int
	TrailingUserPrevFunctionCallOutputIndex int

	PreviousResponseIDPresent bool
	PreviousResponseIDEmpty   bool

	StorePresent bool
	Store        bool

	IncludePresent                      bool
	IncludeHasReasoningEncryptedContent bool

	ReasoningEffortPresent bool
	ReasoningEffort        string

	DetermineIssueCount int
	DetermineIssues     []string
}

type responsesItemMeta struct {
	itemType   string
	itemTypeOK bool
	role       string
	roleOK     bool
}

func newResponsesRequestLogStats(itemCount int) responsesRequestLogStats {
	return responsesRequestLogStats{
		ItemCount:                               itemCount,
		LastUserMessageIndex:                    -1,
		TrailingUserIndex:                       -1,
		TrailingUserPrevFunctionCallOutputIndex: -1,
	}
}

func responsesRequestStats(body []byte) (responsesRequestLogStats, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return responsesRequestLogStats{}, err
	}
	return responsesRequestStatsFromRaw(raw)
}

func responsesRequestStatsFromRaw(req map[string]json.RawMessage) (responsesRequestLogStats, error) {
	rawInput, inputPresent := req["input"]
	items, decodedAsArray := decodeResponsesInputItems(rawInput, inputPresent)

	stats := newResponsesRequestLogStats(len(items))
	if inputPresent && !isJSONNull(rawInput) && !decodedAsArray {
		var s string
		if err := json.Unmarshal(rawInput, &s); err != nil {
			addResponsesDetermineIssue(&stats, "input field is not an array or string")
		}
	}

	annotateResponsesTopLevelSignals(&stats, req)

	metas := make([]responsesItemMeta, len(items))
	for idx, raw := range items {
		obj, ok := unmarshalJSONObject(raw)
		if !ok {
			addResponsesDetermineIssue(&stats, fmt.Sprintf("input item %d is not an object", idx))
			continue
		}
		annotateResponsesItemMeta(&stats, &metas[idx], idx, obj)
	}
	annotateResponsesFunctionCallReasoning(&stats, metas)
	annotateResponsesTrailingUserAfterFunctionCallOutput(&stats, metas)

	return stats, nil
}

// decodeResponsesInputItems decodes the "input" field into an item array.
// The Responses API also allows "input" to be a bare string (single-turn
// convenience with no history) — that is not an error and yields no items.
// The second return value is false only when input is present, non-null, and
// fails to decode as an array (the caller then checks for the string form).
func decodeResponsesInputItems(raw json.RawMessage, present bool) ([]json.RawMessage, bool) {
	if !present || isJSONNull(raw) {
		return nil, true
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	return items, true
}

// responsesItemType extracts the "type" discriminator from an input item.
// Items without an explicit "type" are the plain {role, content} shorthand
// for a message item.
func responsesItemType(item map[string]json.RawMessage) (string, bool) {
	raw, ok := item["type"]
	if !ok {
		return "message", true
	}
	if isJSONNull(raw) {
		return "message", true
	}
	var t string
	if err := json.Unmarshal(raw, &t); err != nil {
		return "", false
	}
	return t, true
}

func annotateResponsesItemMeta(stats *responsesRequestLogStats, meta *responsesItemMeta, idx int, obj map[string]json.RawMessage) {
	itemType, ok := responsesItemType(obj)
	if !ok {
		addResponsesDetermineIssue(stats, fmt.Sprintf("input item %d type is not a string", idx))
		return
	}
	meta.itemType = itemType
	meta.itemTypeOK = true

	switch itemType {
	case "message":
		role, present, valid := rawStringField(obj, "role")
		switch {
		case !present:
			addResponsesDetermineIssue(stats, fmt.Sprintf("input item %d missing string role", idx))
		case !valid:
			addResponsesDetermineIssue(stats, fmt.Sprintf("input item %d role is not a string", idx))
		default:
			meta.role = role
			meta.roleOK = true
			if role == "user" {
				stats.LastUserMessageIndex = idx
			}
		}
	case "reasoning":
		stats.ReasoningItemIndexes = append(stats.ReasoningItemIndexes, idx)
	}
}

// annotateResponsesFunctionCallReasoning implements the Case-1 analog: an
// assistant function_call item with no immediately preceding "reasoning"
// item means the framework dropped the reasoning that (per the model's
// protocol) should have preceded the tool call. Classified as prior-turn
// (INFO) vs active-turn (WARN, once repeated) using the same last-user-turn
// boundary idea as the chat-completions detector.
func annotateResponsesFunctionCallReasoning(stats *responsesRequestLogStats, metas []responsesItemMeta) {
	for idx, meta := range metas {
		if !meta.itemTypeOK || meta.itemType != "function_call" {
			continue
		}
		stats.FunctionCallIndexes = append(stats.FunctionCallIndexes, idx)
		if idx > 0 && metas[idx-1].itemTypeOK && metas[idx-1].itemType == "reasoning" {
			continue
		}
		switch {
		case stats.LastUserMessageIndex < 0:
			addResponsesDetermineIssue(stats, fmt.Sprintf("input item %d is a function_call but no user message was found to establish a turn boundary", idx))
		case idx < stats.LastUserMessageIndex:
			stats.FunctionCallMissingReasoningPriorIndexes = append(stats.FunctionCallMissingReasoningPriorIndexes, idx)
		default:
			stats.FunctionCallMissingReasoningActiveIndexes = append(stats.FunctionCallMissingReasoningActiveIndexes, idx)
		}
	}
}

// annotateResponsesTrailingUserAfterFunctionCallOutput implements the Case-2
// analog: a trailing user "message" item appended immediately after a
// function_call_output item is the Responses-API shape of the chat
// "prompt sandwich" (a reminder message inserted after tool output that can
// cause the chat template to strip current-turn reasoning).
func annotateResponsesTrailingUserAfterFunctionCallOutput(stats *responsesRequestLogStats, metas []responsesItemMeta) {
	lastIdx := len(metas) - 1
	if lastIdx < 1 {
		return
	}
	last := metas[lastIdx]
	if !last.itemTypeOK || last.itemType != "message" || !last.roleOK || last.role != "user" {
		return
	}
	prevIdx := lastIdx - 1
	prev := metas[prevIdx]
	if !prev.itemTypeOK || prev.itemType != "function_call_output" {
		return
	}
	stats.TrailingUserAfterFunctionCallOutput = true
	stats.TrailingUserIndex = lastIdx
	stats.TrailingUserPrevFunctionCallOutputIndex = prevIdx
}

// annotateResponsesTopLevelSignals reads the Responses-specific top-level
// fields that determine whether reasoning can be preserved across turns at
// all: previous_response_id (server-side state), store/include (whether the
// client asked to replay encrypted reasoning on a stateless integration),
// and reasoning.effort (whether reasoning was requested in the first place).
func annotateResponsesTopLevelSignals(stats *responsesRequestLogStats, req map[string]json.RawMessage) {
	if raw, ok := req["previous_response_id"]; ok && !isJSONNull(raw) {
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			addResponsesDetermineIssue(stats, "previous_response_id is not a string")
		} else {
			stats.PreviousResponseIDPresent = true
			stats.PreviousResponseIDEmpty = id == ""
		}
	}

	if value, present, valid := rawBoolField(req, "store"); present {
		if !valid {
			addResponsesDetermineIssue(stats, "store is not a boolean")
		} else {
			stats.StorePresent = true
			stats.Store = value
		}
	}

	if raw, ok := req["include"]; ok && !isJSONNull(raw) {
		var include []string
		if err := json.Unmarshal(raw, &include); err != nil {
			addResponsesDetermineIssue(stats, "include is not a string array")
		} else {
			stats.IncludePresent = true
			stats.IncludeHasReasoningEncryptedContent = slices.Contains(include, "reasoning.encrypted_content")
		}
	}

	raw, ok := req["reasoning"]
	if !ok || isJSONNull(raw) {
		return
	}
	obj, ok := unmarshalJSONObject(raw)
	if !ok {
		addResponsesDetermineIssue(stats, "reasoning is not an object")
		return
	}
	effortRaw, ok := obj["effort"]
	if !ok || isJSONNull(effortRaw) {
		return
	}
	var effort string
	if err := json.Unmarshal(effortRaw, &effort); err != nil {
		addResponsesDetermineIssue(stats, "reasoning.effort is not a string")
		return
	}
	stats.ReasoningEffortPresent = true
	stats.ReasoningEffort = effort
}

// responsesReasoningNotPreservedAcrossTurns reports the combined
// Responses-specific signal: the client asked for reasoning effort in a
// request that includes at least one function_call (i.e. a tool-loop that
// will need another turn), but no reasoning items were replayed and none of
// the three preservation mechanisms the Responses API offers are in use:
// include: ["reasoning.encrypted_content"], store:true (server-side state),
// or previous_response_id (continuing server-side state from a prior turn).
func responsesReasoningNotPreservedAcrossTurns(stats *responsesRequestLogStats) bool {
	return stats.ReasoningEffortPresent &&
		len(stats.FunctionCallIndexes) > 0 &&
		len(stats.ReasoningItemIndexes) == 0 &&
		!stats.IncludeHasReasoningEncryptedContent &&
		(!stats.StorePresent || !stats.Store) &&
		!stats.PreviousResponseIDPresent
}

func addResponsesDetermineIssue(stats *responsesRequestLogStats, issue string) {
	stats.DetermineIssueCount++
	const maxDetermineIssuesLogged = 8
	if len(stats.DetermineIssues) < maxDetermineIssuesLogged {
		stats.DetermineIssues = append(stats.DetermineIssues, issue)
	}
}

func responsesRequestBaseLogAttrs(model, providerName, upstreamModel, path string, stats *responsesRequestLogStats) []any {
	return []any{
		"model", model,
		"provider", providerName,
		"upstream_model", upstreamModel,
		"path", path,
		"item_count", stats.ItemCount,
		"function_call_count", len(stats.FunctionCallIndexes),
		"reasoning_item_count", len(stats.ReasoningItemIndexes),
	}
}

func responsesRequestLogAttrs(model, providerName, upstreamModel, path string, stats *responsesRequestLogStats, sliceLimit int) []any {
	attrs := responsesRequestBaseLogAttrs(model, providerName, upstreamModel, path, stats)
	attrs = appendIntSliceAttr(attrs, "function_call_indexes", stats.FunctionCallIndexes, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "reasoning_item_indexes", stats.ReasoningItemIndexes, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "function_call_missing_reasoning_prior_turn_indexes", stats.FunctionCallMissingReasoningPriorIndexes, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "function_call_missing_reasoning_active_indexes", stats.FunctionCallMissingReasoningActiveIndexes, sliceLimit)
	attrs = append(attrs,
		"trailing_user_after_function_call_output", stats.TrailingUserAfterFunctionCallOutput,
		"previous_response_id_present", stats.PreviousResponseIDPresent,
		"store_present", stats.StorePresent,
		"include_present", stats.IncludePresent,
		"include_has_reasoning_encrypted_content", stats.IncludeHasReasoningEncryptedContent,
		"reasoning_effort_present", stats.ReasoningEffortPresent,
	)
	if stats.TrailingUserAfterFunctionCallOutput {
		attrs = append(attrs,
			"trailing_user_index", stats.TrailingUserIndex,
			"trailing_user_prev_function_call_output_index", stats.TrailingUserPrevFunctionCallOutputIndex)
	}
	if stats.StorePresent {
		attrs = append(attrs, "store", stats.Store)
	}
	if stats.ReasoningEffortPresent {
		attrs = append(attrs, "reasoning_effort", stats.ReasoningEffort)
	}
	return attrs
}

// responsesRequestStatsLoggingEnabled mirrors chatRequestStatsLoggingEnabled:
// a cheap pre-check so the (already inexpensive, but non-zero) parse and
// attribute-building work is skipped when nothing would end up logged,
// either because the level isn't enabled or the hourly limiter would
// suppress every category anyway.
func responsesRequestStatsLoggingEnabled(ctx context.Context, limiter *hourlyLogLimiter) bool {
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		return true
	}
	infoEnabled := slog.Default().Enabled(ctx, slog.LevelInfo)
	warnEnabled := slog.Default().Enabled(ctx, slog.LevelWarn)
	if !infoEnabled && !warnEnabled {
		return false
	}
	if limiter == nil {
		return true
	}
	now := time.Now()
	if infoEnabled && limiter.anyAllowed(now, responsesPriorTurnFunctionCallMissingReasoningLogKey) {
		return true
	}
	if !warnEnabled || !limiter.anyAllowed(now,
		responsesReasoningMetadataUnavailableLogKey,
		responsesActiveFunctionCallMissingReasoningLogKey,
		responsesTrailingUserAfterFunctionCallOutputLogKey,
		responsesReasoningNotPreservedAcrossTurnsLogKey,
		responsesReasoningMetadataIndeterminateLogKey) {
		return false
	}
	return true
}

// logResponsesRequestStats is the /v1/responses counterpart to
// logChatRequestStats (reasoning.go). It is WARN/INFO-only: no repair is
// attempted here (see the file-level doc comment for why), and it never
// logs message or argument text — only roles, item types, counts, indexes,
// and field-presence booleans.
func logResponsesRequestStats(ctx context.Context, limiter *hourlyLogLimiter, model, providerName, upstreamModel, path string, body []byte) {
	if !responsesRequestStatsLoggingEnabled(ctx, limiter) {
		return
	}
	stats, err := responsesRequestStats(body)
	if err != nil {
		if allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, responsesReasoningMetadataUnavailableLogKey) {
			slog.WarnContext(ctx, "responses request reasoning metadata unavailable",
				reasoningDiagnosticAttrs([]any{
					"model", model,
					"provider", providerName,
					"upstream_model", upstreamModel,
					"path", path,
				}, "err", err)...)
		}
		return
	}

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		slog.DebugContext(ctx, "responses request metadata",
			responsesRequestLogAttrs(model, providerName, upstreamModel, path, &stats, -1)...)
	}

	warnAttrs := responsesRequestLogAttrs(model, providerName, upstreamModel, path, &stats, chatRequestWarnAttrSliceLimit)

	if len(stats.FunctionCallMissingReasoningPriorIndexes) > 0 &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelInfo, responsesPriorTurnFunctionCallMissingReasoningLogKey) {
		slog.InfoContext(ctx, "agent framework is stripping prior-turn reasoning items before function_call in /v1/responses requests; this is known to be bad for coding agents",
			reasoningDiagnosticAttrs(warnAttrs)...)
	}

	if len(stats.FunctionCallMissingReasoningActiveIndexes) >= responsesActiveFunctionCallMissingReasoningWarnThreshold &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, responsesActiveFunctionCallMissingReasoningLogKey) {
		slog.WarnContext(ctx, "agent framework may be stripping reasoning items before repeated active-turn function_call entries in /v1/responses requests",
			reasoningDiagnosticAttrs(warnAttrs)...)
	}

	if stats.TrailingUserAfterFunctionCallOutput &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, responsesTrailingUserAfterFunctionCallOutputLogKey) {
		slog.WarnContext(ctx, "agent framework appended a trailing user message after function_call_output in /v1/responses; model chat template may clear current-turn reasoning (prompt sandwich)",
			reasoningDiagnosticAttrs(warnAttrs)...)
	}

	if responsesReasoningNotPreservedAcrossTurns(&stats) &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, responsesReasoningNotPreservedAcrossTurnsLogKey) {
		slog.WarnContext(ctx, "responses request asks for reasoning effort but has no mechanism to preserve it across turns: no reasoning items replayed, store is not enabled, include does not request reasoning.encrypted_content, and no previous_response_id is set",
			reasoningDiagnosticAttrs(warnAttrs)...)
	}

	if stats.DetermineIssueCount > 0 &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, responsesReasoningMetadataIndeterminateLogKey) {
		slog.WarnContext(ctx, "responses request reasoning metadata could not be fully determined",
			reasoningDiagnosticAttrs(warnAttrs,
				"determine_issue_count", stats.DetermineIssueCount,
				"determine_issues", stats.DetermineIssues)...)
	}
}
