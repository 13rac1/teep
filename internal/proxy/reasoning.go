package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	reasoningStripLogInterval           = time.Hour
	activeMissingReasoningWarnThreshold = 2

	reasoningDiagnosticsIssueURL  = "https://github.com/13rac1/teep/issues/124"
	reasoningDiagnosticsRateLimit = "1x/hour"

	chatReasoningMetadataUnavailableLogKey   = "chat_reasoning_metadata_unavailable"
	chatPriorTurnReasoningStrippedLogKey     = "chat_prior_turn_reasoning_stripped"
	chatPriorTurnReasoningNotPreservedLogKey = "chat_prior_turn_reasoning_not_preserved_by_model"
	chatActiveReasoningStrippedLogKey        = "chat_active_reasoning_stripped"
	chatTrailingUserReasoningLostLogKey      = "chat_trailing_user_reasoning_lost"
	chatReasoningMetadataIndeterminateLogKey = "chat_reasoning_metadata_indeterminate"

	reasoningRepairReasonPriorTurn    = "prior_turn_reasoning"
	reasoningRepairReasonTrailingUser = "trailing_user_after_tool"

	chatRequestWarnAttrSliceLimit = 32
)

type chatRequestLogStats struct {
	MessageCount                             int
	RoleCount                                int
	RoleSequence                             []string
	AssistantReasoningContentIndexes         []int
	AssistantReasoningContentLens            []int
	AssistantReasoningIndexes                []int
	AssistantReasoningLens                   []int
	LastUserIndex                            int
	PriorTurnMissingReasoningIndexes         []int
	PriorTurnPreservedReasoningIndexes       []int
	PriorTurnPreservedReasoningLens          []int
	ActiveMissingReasoningIndexes            []int
	ActiveMissingReasoningToolCallIndexes    []int
	ActiveMissingReasoningUserMessageIndexes []int
	TrailingUserAddendumIndex                int
	TrailingUserPrevUserIndex                int
	TrailingUserLostReasoningIndexes         []int
	TrailingUserLostReasoningLens            []int
	TrailingUserMissingReasoningIndexes      []int
	ChatTemplateClearThinkingPresent         bool
	ChatTemplateClearThinking                bool
	ChatTemplatePreserveThinkingPresent      bool
	ChatTemplatePreserveThinking             bool
	ChatTemplateDropThinkingPresent          bool
	ChatTemplateDropThinking                 bool
	ToolsPresent                             bool
	ToolsCount                               int
	DetermineIssueCount                      int
	DetermineIssues                          []string
}

type chatMessageLogMeta struct {
	role                       string
	roleOK                     bool
	assistantHasReasoning      bool
	assistantReasoningLen      int
	assistantHasToolCalls      bool
	assistantHasMessageContent bool
	assistantHasRefusal        bool
	assistantHasVisibleContent bool
}

type chatRequestReasoningState struct {
	raw   map[string]json.RawMessage
	stats chatRequestLogStats
}

func chatRequestStats(body []byte) (chatRequestLogStats, error) {
	state, err := parseChatRequestReasoningState(body)
	if err != nil {
		return chatRequestLogStats{}, err
	}
	return state.stats, nil
}

func parseChatRequestReasoningState(body []byte) (*chatRequestReasoningState, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	stats, err := chatRequestStatsFromRaw(raw)
	if err != nil {
		return nil, err
	}
	return &chatRequestReasoningState{raw: raw, stats: stats}, nil
}

func chatRequestStatsFromRaw(req map[string]json.RawMessage) (chatRequestLogStats, error) {
	var messages []map[string]json.RawMessage
	rawMessages, messagesPresent := req["messages"]
	messagesNull := isJSONNull(rawMessages)
	if messagesPresent && !messagesNull {
		raw := rawMessages
		if err := json.Unmarshal(raw, &messages); err != nil {
			return chatRequestLogStats{}, err
		}
	}

	stats := newChatRequestLogStats(len(messages))
	switch {
	case !messagesPresent:
		addDetermineIssue(&stats, "messages field missing")
	case messagesNull:
		addDetermineIssue(&stats, "messages field is null")
	}
	chatTemplateKwargs := decodeChatTemplateKwargs(&stats, req["chat_template_kwargs"])
	annotateTools(&stats, req["tools"])
	annotateChatTemplateBool(&stats, chatTemplateKwargs, "clear_thinking")
	annotateChatTemplateBool(&stats, chatTemplateKwargs, "preserve_thinking")
	annotateChatTemplateBool(&stats, chatTemplateKwargs, "drop_thinking")

	metas := make([]chatMessageLogMeta, len(messages))
	for idx, msg := range messages {
		role, present, valid := rawStringField(msg, "role")
		if present && valid {
			stats.RoleCount++
			metas[idx].role = role
			metas[idx].roleOK = true
			if role == "user" {
				stats.LastUserIndex = idx
			}
		}
		switch {
		case !present:
			addDetermineIssue(&stats, fmt.Sprintf("message %d missing string role", idx))
		case !valid:
			addDetermineIssue(&stats, fmt.Sprintf("message %d role is not a string", idx))
		}
		if role != "assistant" {
			continue
		}
		annotateAssistantMessageStats(&stats, &metas[idx], idx, msg)
	}
	stats.RoleSequence = chatDisplayRoleSequence(metas)

	for idx, meta := range metas {
		if !meta.roleOK || meta.role != "assistant" || meta.assistantHasReasoning {
			continue
		}
		switch {
		case stats.LastUserIndex < 0:
			addDetermineIssue(&stats, "assistant messages present but no user message found")
		case idx < stats.LastUserIndex:
			stats.PriorTurnMissingReasoningIndexes = append(stats.PriorTurnMissingReasoningIndexes, idx)
		case idx > stats.LastUserIndex:
			stats.ActiveMissingReasoningIndexes = append(stats.ActiveMissingReasoningIndexes, idx)
			if assistantToolTurnShape(metas, idx) {
				stats.ActiveMissingReasoningToolCallIndexes = append(stats.ActiveMissingReasoningToolCallIndexes, idx)
			}
			if meta.assistantHasVisibleContent {
				stats.ActiveMissingReasoningUserMessageIndexes = append(stats.ActiveMissingReasoningUserMessageIndexes, idx)
			}
		}
	}
	for idx, meta := range metas {
		if !meta.roleOK || meta.role != "assistant" || !meta.assistantHasReasoning {
			continue
		}
		if stats.LastUserIndex >= 0 && idx < stats.LastUserIndex {
			stats.PriorTurnPreservedReasoningIndexes = append(stats.PriorTurnPreservedReasoningIndexes, idx)
			stats.PriorTurnPreservedReasoningLens = append(stats.PriorTurnPreservedReasoningLens, meta.assistantReasoningLen)
		}
	}
	annotateTrailingUserReasoningLoss(&stats, metas)
	return stats, nil
}

func bestEffortChatRequestReasoningState(body []byte) (*chatRequestReasoningState, bool) {
	state, err := parseChatRequestReasoningState(body)
	if err != nil {
		return nil, false
	}
	return state, true
}

func newChatRequestLogStats(messageCount int) chatRequestLogStats {
	stats := chatRequestLogStats{
		MessageCount:              messageCount,
		LastUserIndex:             -1,
		TrailingUserAddendumIndex: -1,
		TrailingUserPrevUserIndex: -1,
	}
	return stats
}

func decodeChatTemplateKwargs(stats *chatRequestLogStats, raw json.RawMessage) map[string]json.RawMessage {
	if len(bytes.TrimSpace(raw)) == 0 || isJSONNull(raw) {
		return nil
	}
	chatTemplateKwargs, ok := unmarshalJSONObject(raw)
	if !ok {
		addDetermineIssue(stats, "chat_template_kwargs is not an object")
		return nil
	}
	return chatTemplateKwargs
}

func annotateTools(stats *chatRequestLogStats, raw json.RawMessage) {
	if len(bytes.TrimSpace(raw)) == 0 || isJSONNull(raw) {
		return
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(raw, &tools); err != nil {
		addDetermineIssue(stats, "tools is not an array")
		return
	}
	stats.ToolsPresent = len(tools) > 0
	stats.ToolsCount = len(tools)
}

func annotateAssistantMessageStats(stats *chatRequestLogStats, meta *chatMessageLogMeta, idx int, msg map[string]json.RawMessage) {
	if rawVisibleContent(msg["content"]) {
		meta.assistantHasMessageContent = true
		meta.assistantHasVisibleContent = true
	}
	if rawVisibleStringField(msg, "refusal") {
		meta.assistantHasRefusal = true
		meta.assistantHasVisibleContent = true
	}
	hasToolCalls, present, valid := rawJSONArrayHasElements(msg["tool_calls"])
	if !valid {
		addDetermineIssue(stats, fmt.Sprintf("message %d tool_calls is not an array", idx))
	}
	if present && hasToolCalls {
		meta.assistantHasToolCalls = true
	}
	annotateAssistantReasoningField(stats, meta, idx, msg, "reasoning_content")
	annotateAssistantReasoningField(stats, meta, idx, msg, "reasoning")
}

func annotateAssistantReasoningField(stats *chatRequestLogStats, meta *chatMessageLogMeta, idx int, msg map[string]json.RawMessage, field string) {
	n, present, valid := rawStringLen(msg, field)
	if !valid {
		addDetermineIssue(stats, fmt.Sprintf("message %d %s is not a string", idx, field))
		return
	}
	if !present {
		return
	}
	switch field {
	case "reasoning_content":
		stats.AssistantReasoningContentIndexes = append(stats.AssistantReasoningContentIndexes, idx)
		stats.AssistantReasoningContentLens = append(stats.AssistantReasoningContentLens, n)
	case "reasoning":
		stats.AssistantReasoningIndexes = append(stats.AssistantReasoningIndexes, idx)
		stats.AssistantReasoningLens = append(stats.AssistantReasoningLens, n)
	}
	if n > 0 {
		meta.assistantHasReasoning = true
		if n > meta.assistantReasoningLen {
			meta.assistantReasoningLen = n
		}
	}
}

func chatDisplayRoleSequence(metas []chatMessageLogMeta) []string {
	roles := make([]string, 0, len(metas))
	for idx, meta := range metas {
		if !meta.roleOK {
			continue
		}
		if meta.role == "assistant" {
			roles = append(roles, assistantDisplayRole(metas, idx))
			continue
		}
		if meta.role == "tool" {
			roles = append(roles, "tool_result")
			continue
		}
		roles = append(roles, meta.role)
	}
	return roles
}

func assistantDisplayRole(metas []chatMessageLogMeta, idx int) string {
	meta := metas[idx]
	parts := make([]string, 0, 4)
	if meta.assistantHasReasoning {
		parts = append(parts, "think")
	}
	if meta.assistantHasMessageContent {
		parts = append(parts, "msg")
	}
	if assistantToolTurnShape(metas, idx) {
		parts = append(parts, "tool_call")
	}
	if meta.assistantHasRefusal {
		parts = append(parts, "refusal")
	}
	if len(parts) == 0 {
		parts = append(parts, "stripped")
	}
	return "assistant[" + strings.Join(parts, ", ") + "]"
}

func annotateChatTemplateBool(stats *chatRequestLogStats, chatTemplateKwargs map[string]json.RawMessage, field string) {
	value, present, valid := rawBoolField(chatTemplateKwargs, field)
	if !present {
		return
	}
	if !valid {
		addDetermineIssue(stats, fmt.Sprintf("chat_template_kwargs.%s is not a boolean", field))
		return
	}
	setChatTemplateBool(stats, field, value)
}

func setChatTemplateBool(stats *chatRequestLogStats, field string, value bool) {
	switch field {
	case "clear_thinking":
		stats.ChatTemplateClearThinkingPresent = true
		stats.ChatTemplateClearThinking = value
	case "preserve_thinking":
		stats.ChatTemplatePreserveThinkingPresent = true
		stats.ChatTemplatePreserveThinking = value
	case "drop_thinking":
		stats.ChatTemplateDropThinkingPresent = true
		stats.ChatTemplateDropThinking = value
	}
}

func (stats *chatRequestLogStats) chatTemplateClearThinkingFalse() bool {
	return stats.ChatTemplateClearThinkingPresent && !stats.ChatTemplateClearThinking
}

func (stats *chatRequestLogStats) chatTemplatePreserveThinkingTrue() bool {
	return stats.ChatTemplatePreserveThinkingPresent && stats.ChatTemplatePreserveThinking
}

func (stats *chatRequestLogStats) chatTemplateDropThinkingFalse() bool {
	return stats.ChatTemplateDropThinkingPresent && !stats.ChatTemplateDropThinking
}

func annotateTrailingUserReasoningLoss(stats *chatRequestLogStats, metas []chatMessageLogMeta) {
	lastIdx := len(metas) - 1
	if lastIdx < 1 {
		return
	}
	if !metas[lastIdx].roleOK || metas[lastIdx].role != "user" {
		return
	}
	prevIdx := lastIdx - 1
	if !metas[prevIdx].roleOK || metas[prevIdx].role != "tool" {
		return
	}
	prevUserIdx := -1
	for idx := lastIdx - 1; idx >= 0; idx-- {
		if metas[idx].roleOK && metas[idx].role == "user" {
			prevUserIdx = idx
			break
		}
	}
	if prevUserIdx < 0 {
		return
	}
	lostIndexes, lostLens, missingIndexes := trailingUserReasoningImpacts(metas, prevUserIdx, lastIdx)
	if len(lostIndexes) == 0 && len(missingIndexes) == 0 {
		return
	}
	stats.TrailingUserAddendumIndex = lastIdx
	stats.TrailingUserPrevUserIndex = prevUserIdx
	stats.TrailingUserLostReasoningIndexes = lostIndexes
	stats.TrailingUserLostReasoningLens = lostLens
	stats.TrailingUserMissingReasoningIndexes = missingIndexes
}

func trailingUserReasoningImpacts(metas []chatMessageLogMeta, prevUserIdx, lastIdx int) (lostIndexes, lostLens, missingIndexes []int) {
	for idx := prevUserIdx + 1; idx < lastIdx; idx++ {
		meta := metas[idx]
		if !meta.roleOK || meta.role != "assistant" || !assistantToolTurnShape(metas, idx) {
			continue
		}
		if meta.assistantHasVisibleContent {
			continue
		}
		if meta.assistantHasReasoning {
			lostIndexes = append(lostIndexes, idx)
			lostLens = append(lostLens, meta.assistantReasoningLen)
		} else {
			missingIndexes = append(missingIndexes, idx)
		}
	}
	return lostIndexes, lostLens, missingIndexes
}

func assistantToolTurnShape(metas []chatMessageLogMeta, idx int) bool {
	if idx < 0 || idx >= len(metas) {
		return false
	}
	if metas[idx].assistantHasToolCalls {
		return true
	}
	nextIdx := idx + 1
	return nextIdx < len(metas) && metas[nextIdx].roleOK && metas[nextIdx].role == "tool"
}

func statsWithInferredTrailingUserMissingReasoning(stats *chatRequestLogStats) *chatRequestLogStats {
	stats = statsWithDisplayRoleSequence(stats)
	if stats == nil || stats.TrailingUserAddendumIndex >= 0 {
		return stats
	}
	addendumIdx, prevUserIdx, missingIndexes := inferTrailingUserMissingReasoningFromRoles(stats)
	if len(missingIndexes) == 0 {
		return stats
	}
	copyStats := *stats
	copyStats.TrailingUserAddendumIndex = addendumIdx
	copyStats.TrailingUserPrevUserIndex = prevUserIdx
	copyStats.TrailingUserMissingReasoningIndexes = missingIndexes
	return &copyStats
}

func statsWithDisplayRoleSequence(stats *chatRequestLogStats) *chatRequestLogStats {
	if stats == nil || !slices.Contains(stats.RoleSequence, "assistant") {
		return stats
	}
	copyStats := *stats
	copyStats.RoleSequence = make([]string, len(stats.RoleSequence))
	for idx, role := range stats.RoleSequence {
		if role == "assistant" {
			copyStats.RoleSequence[idx] = assistantDisplayRoleFromStats(stats, idx)
			continue
		}
		if role == "tool" {
			copyStats.RoleSequence[idx] = "tool_result"
			continue
		}
		copyStats.RoleSequence[idx] = role
	}
	return &copyStats
}

func assistantDisplayRoleFromStats(stats *chatRequestLogStats, idx int) string {
	parts := make([]string, 0, 3)
	if statsAssistantHasReasoning(stats, idx) {
		parts = append(parts, "think")
	}
	if slices.Contains(stats.ActiveMissingReasoningUserMessageIndexes, idx) {
		parts = append(parts, "msg")
	}
	if statsAssistantHasToolCallShape(stats, idx) {
		parts = append(parts, "tool_call")
	}
	if len(parts) == 0 {
		parts = append(parts, "stripped")
	}
	return "assistant[" + strings.Join(parts, ", ") + "]"
}

func statsAssistantHasToolCallShape(stats *chatRequestLogStats, idx int) bool {
	if slices.Contains(stats.ActiveMissingReasoningToolCallIndexes, idx) {
		return true
	}
	nextIdx := idx + 1
	return nextIdx < len(stats.RoleSequence) && isToolResultDisplayRole(stats.RoleSequence[nextIdx])
}

func statsAssistantHasReasoning(stats *chatRequestLogStats, idx int) bool {
	return positiveLenForIndex(stats.AssistantReasoningContentIndexes, stats.AssistantReasoningContentLens, idx) ||
		positiveLenForIndex(stats.AssistantReasoningIndexes, stats.AssistantReasoningLens, idx)
}

func positiveLenForIndex(indexes, lens []int, idx int) bool {
	for pos, value := range indexes {
		if value == idx && pos < len(lens) && lens[pos] > 0 {
			return true
		}
	}
	return false
}

func inferTrailingUserMissingReasoningFromRoles(stats *chatRequestLogStats) (addendumIdx, prevUserIdx int, missingIndexes []int) {
	roles := stats.RoleSequence
	if len(roles) != stats.MessageCount {
		return -1, -1, nil
	}
	lastIdx := len(roles) - 1
	if lastIdx < 2 || roles[lastIdx] != "user" || !isToolResultDisplayRole(roles[lastIdx-1]) {
		return -1, -1, nil
	}
	prevUserIdx = -1
	for idx := lastIdx - 1; idx >= 0; idx-- {
		if roles[idx] == "user" {
			prevUserIdx = idx
			break
		}
	}
	if prevUserIdx < 0 {
		return -1, -1, nil
	}
	for _, idx := range stats.PriorTurnMissingReasoningIndexes {
		if idx <= prevUserIdx || idx >= lastIdx {
			continue
		}
		nextIdx := idx + 1
		if idx < len(roles) && isAssistantDisplayRole(roles[idx]) && nextIdx < len(roles) && isToolResultDisplayRole(roles[nextIdx]) {
			missingIndexes = append(missingIndexes, idx)
		}
	}
	return lastIdx, prevUserIdx, missingIndexes
}

func isAssistantDisplayRole(role string) bool {
	return role == "assistant" || strings.HasPrefix(role, "assistant[")
}

func isToolResultDisplayRole(role string) bool {
	return role == "tool" || role == "tool_result"
}

func addDetermineIssue(stats *chatRequestLogStats, issue string) {
	stats.DetermineIssueCount++
	const maxDetermineIssuesLogged = 8
	if len(stats.DetermineIssues) < maxDetermineIssuesLogged {
		stats.DetermineIssues = append(stats.DetermineIssues, issue)
	}
}

func rawStringField(msg map[string]json.RawMessage, field string) (value string, present, valid bool) {
	raw, ok := msg[field]
	if !ok {
		return "", false, true
	}
	if isJSONNull(raw) {
		return "", false, true
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true, false
	}
	return value, true, true
}

func rawStringLen(msg map[string]json.RawMessage, field string) (n int, present, valid bool) {
	raw, ok := msg[field]
	if !ok {
		return 0, false, true
	}
	if isJSONNull(raw) {
		return 0, false, true
	}
	if inner, ok, simple := simpleJSONStringBytes(raw); ok && simple {
		return len(inner), true, true
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, true, false
	}
	return len(value), true, true
}

func rawVisibleStringField(msg map[string]json.RawMessage, field string) bool {
	value, present, valid := rawStringField(msg, field)
	return present && valid && value != ""
}

func rawVisibleContent(raw json.RawMessage) bool {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false
	}
	if inner, ok, simple := simpleJSONStringBytes(raw); ok {
		if simple {
			return len(inner) > 0
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return false
		}
		return value != ""
	}
	if visible, ok := rawVisibleJSONContainer(raw); ok {
		return visible
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return jsonValueHasVisibleContent(value)
}

func rawVisibleJSONContainer(raw json.RawMessage) (visible, ok bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 {
		return false, false
	}
	var closeDelim byte
	switch trimmed[0] {
	case '[':
		closeDelim = ']'
	case '{':
		closeDelim = '}'
	default:
		return false, false
	}
	idx := 1
	for idx < len(trimmed) && isJSONWhitespace(trimmed[idx]) {
		idx++
	}
	if idx < len(trimmed) && trimmed[idx] == closeDelim {
		idx++
		for idx < len(trimmed) && isJSONWhitespace(trimmed[idx]) {
			idx++
		}
		if idx == len(trimmed) {
			return false, true
		}
	}
	return true, true
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\r' || b == '\t'
}

func simpleJSONStringBytes(raw json.RawMessage) (inner []byte, ok, simple bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 2 || trimmed[0] != '"' || trimmed[len(trimmed)-1] != '"' {
		return nil, false, false
	}
	inner = trimmed[1 : len(trimmed)-1]
	for _, b := range inner {
		switch b {
		case '\\', '"':
			return inner, true, false
		}
		if b < 0x20 {
			return inner, true, false
		}
	}
	return inner, true, true
}

func jsonValueHasVisibleContent(value any) bool {
	switch v := value.(type) {
	case string:
		return v != ""
	case nil:
		return false
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

func rawJSONArrayHasElements(raw json.RawMessage) (hasElements, present, valid bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false, false, true
	}
	if isJSONNull(raw) {
		return false, false, true
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return false, true, false
	}
	return len(items) > 0, true, true
}

func rawBoolField(msg map[string]json.RawMessage, field string) (value, present, valid bool) {
	raw, ok := msg[field]
	if !ok {
		return false, false, true
	}
	return optionalRawBool(raw)
}

func optionalRawBool(raw json.RawMessage) (value, present, valid bool) {
	if isJSONNull(raw) {
		return false, false, true
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, true, false
	}
	return value, true, true
}

func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 4 &&
		trimmed[0] == 'n' &&
		trimmed[1] == 'u' &&
		trimmed[2] == 'l' &&
		trimmed[3] == 'l'
}

type hourlyLogLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (l *hourlyLogLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = make(map[string]time.Time)
	}
	if prev, ok := l.last[key]; ok && now.Sub(prev) < reasoningStripLogInterval {
		return false
	}
	l.last[key] = now
	return true
}

func (l *hourlyLogLimiter) anyAllowed(now time.Time, keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		return true
	}
	for _, key := range keys {
		if prev, ok := l.last[key]; !ok || now.Sub(prev) >= reasoningStripLogInterval {
			return true
		}
	}
	return false
}

func chatRequestLogAttrs(model, providerName, upstreamModel, path string, stats *chatRequestLogStats, sliceLimit int) []any {
	attrs := chatRequestBaseLogAttrs(model, providerName, upstreamModel, path, stats)
	attrs = appendStringSliceAttr(attrs, "role_sequence", stats.RoleSequence, sliceLimit)
	attrs = append(attrs,
		"assistant_reasoning_content_count", len(stats.AssistantReasoningContentIndexes))
	attrs = appendIntSliceAttr(attrs, "assistant_reasoning_content_indexes", stats.AssistantReasoningContentIndexes, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "assistant_reasoning_content_lens", stats.AssistantReasoningContentLens, sliceLimit)
	attrs = append(attrs,
		"assistant_reasoning_count", len(stats.AssistantReasoningIndexes))
	attrs = appendIntSliceAttr(attrs, "assistant_reasoning_indexes", stats.AssistantReasoningIndexes, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "assistant_reasoning_lens", stats.AssistantReasoningLens, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "assistant_preserved_reasoning_prior_turn_indexes", stats.PriorTurnPreservedReasoningIndexes, sliceLimit)
	attrs = appendIntSliceAttr(attrs, "assistant_preserved_reasoning_prior_turn_lens", stats.PriorTurnPreservedReasoningLens, sliceLimit)
	attrs = append(attrs,
		"tools_present", stats.ToolsPresent,
		"tools_count", stats.ToolsCount,
		"chat_template_clear_thinking_present", stats.ChatTemplateClearThinkingPresent,
		"chat_template_clear_thinking_false", stats.chatTemplateClearThinkingFalse(),
		"chat_template_preserve_thinking_present", stats.ChatTemplatePreserveThinkingPresent,
		"chat_template_preserve_thinking_true", stats.chatTemplatePreserveThinkingTrue(),
		"chat_template_drop_thinking_present", stats.ChatTemplateDropThinkingPresent,
		"chat_template_drop_thinking_false", stats.chatTemplateDropThinkingFalse(),
	)
	if stats.ChatTemplateClearThinkingPresent {
		attrs = append(attrs, "chat_template_clear_thinking", stats.ChatTemplateClearThinking)
	}
	if stats.ChatTemplatePreserveThinkingPresent {
		attrs = append(attrs, "chat_template_preserve_thinking", stats.ChatTemplatePreserveThinking)
	}
	if stats.ChatTemplateDropThinkingPresent {
		attrs = append(attrs, "chat_template_drop_thinking", stats.ChatTemplateDropThinking)
	}
	if stats.TrailingUserAddendumIndex >= 0 {
		attrs = append(attrs,
			"trailing_user_addendum_index", stats.TrailingUserAddendumIndex,
			"trailing_user_prev_user_index", stats.TrailingUserPrevUserIndex)
		attrs = appendIntSliceAttr(attrs, "assistant_reasoning_lost_by_trailing_user_indexes", stats.TrailingUserLostReasoningIndexes, sliceLimit)
		attrs = appendIntSliceAttr(attrs, "assistant_reasoning_lost_by_trailing_user_lens", stats.TrailingUserLostReasoningLens, sliceLimit)
		attrs = appendIntSliceAttr(attrs, "assistant_missing_reasoning_by_trailing_user_indexes", stats.TrailingUserMissingReasoningIndexes, sliceLimit)
	}
	return attrs
}

func chatRequestDiagnosticLogAttrs(model, providerName, upstreamModel, path string, stats *chatRequestLogStats, sliceLimit int) []any {
	attrs := chatRequestBaseLogAttrs(model, providerName, upstreamModel, path, stats)
	attrs = appendStringSliceAttr(attrs, "role_sequence", stats.RoleSequence, sliceLimit)
	if stats.TrailingUserAddendumIndex >= 0 {
		attrs = append(attrs,
			"trailing_user_addendum_index", stats.TrailingUserAddendumIndex,
			"trailing_user_prev_user_index", stats.TrailingUserPrevUserIndex)
		attrs = appendIntSliceAttr(attrs, "assistant_reasoning_lost_by_trailing_user_indexes", stats.TrailingUserLostReasoningIndexes, sliceLimit)
		attrs = appendIntSliceAttr(attrs, "assistant_missing_reasoning_by_trailing_user_indexes", stats.TrailingUserMissingReasoningIndexes, sliceLimit)
	}
	return attrs
}

func chatRequestBaseLogAttrs(model, providerName, upstreamModel, path string, stats *chatRequestLogStats) []any {
	attrs := []any{
		"model", model,
		"provider", providerName,
		"upstream_model", upstreamModel,
		"path", path,
		"message_count", stats.MessageCount,
		"role_count", stats.RoleCount,
	}
	return attrs
}

func appendIntSliceAttr(attrs []any, key string, values []int, limit int) []any {
	if limit >= 0 && len(values) > limit {
		return append(attrs,
			key, values[:limit],
			key+"_truncated", true,
			key+"_total", len(values))
	}
	return append(attrs, key, values)
}

func appendStringSliceAttr(attrs []any, key string, values []string, limit int) []any {
	if limit >= 0 && len(values) > limit {
		return append(attrs,
			key, values[:limit],
			key+"_truncated", true,
			key+"_total", len(values))
	}
	return append(attrs, key, values)
}

func excludeIntSlice(values, excluded []int) []int {
	if len(values) == 0 || len(excluded) == 0 {
		return values
	}
	out := make([]int, 0, len(values))
	for _, value := range values {
		if !slices.Contains(excluded, value) {
			out = append(out, value)
		}
	}
	return out
}

type reasoningPreservationCheck struct {
	provider  string
	family    string
	flag      string
	field     string
	value     bool
	present   bool
	effective bool
}

func modelFamilyMatches(family string, modelNames ...string) bool {
	for _, name := range modelNames {
		if strings.Contains(strings.ToLower(modelNameForFamilyMatch(name)), family) {
			return true
		}
	}
	return false
}

func modelNameForFamilyMatch(name string) string {
	_, modelName, ok := strings.Cut(name, ":")
	if ok {
		return modelName
	}
	return name
}

// modelReasoningPreservationFamilyKnown reports whether model/upstreamModel
// belongs to a model family with a known chat-template preservation flag
// (glm, kimi, deepseek). This is intentionally provider-agnostic: it gates
// whether reasoning-loss *detection* runs at all (parsing chat request
// stats), and detection must run for every provider regardless of whether
// that provider's upstream API will actually accept an injected
// chat_template_kwargs field. The provider-scoped injection decision is made
// separately, downstream, by modelReasoningPreservationCheck (see below) and
// the AcceptsChatTemplateKwargs gate in repairChatReasoningPreservationWithStats.
func modelReasoningPreservationFamilyKnown(model, upstreamModel string) bool {
	return modelFamilyMatches("glm", model, upstreamModel) ||
		modelFamilyMatches("kimi", model, upstreamModel) ||
		modelFamilyMatches("deepseek", model, upstreamModel)
}

// modelReasoningPreservationCheck resolves the chat-template preservation
// flag (if any) for a request, scoped by the resolved provider:model
// identity the proxy already computes at the request-routing call site
// (providerName is prov.Name; see proxy.go). providerName is carried on the
// returned reasoningPreservationCheck for attribution/diagnostics; the flag
// family/field/value themselves are a property of the model, not the
// provider, but the caller-supplied providerName keys this lookup so that
// the same family served by two different providers is never conflated:
// per GH #124, Tinfoil forwards an injected chat_template_kwargs field to
// vLLM, while Venice's strict request schema rejects it with HTTP 400 for
// the identical GLM/DeepSeek family — the *injection* decision for that
// distinction is made by the provider's AcceptsChatTemplateKwargs capability
// in repairChatReasoningPreservationWithStats, not here; effective/present
// here reflect only what's actually in the request body so that detection
// (WARN diagnostics) is correct for every provider even when injection is
// skipped.
func modelReasoningPreservationCheck(providerName, model, upstreamModel string, stats *chatRequestLogStats) (reasoningPreservationCheck, bool) {
	switch {
	case modelFamilyMatches("glm", model, upstreamModel):
		return reasoningPreservationCheck{
			provider:  providerName,
			family:    "glm",
			flag:      "chat_template_kwargs.clear_thinking=false",
			field:     "clear_thinking",
			value:     false,
			present:   stats.ChatTemplateClearThinkingPresent,
			effective: stats.chatTemplateClearThinkingFalse(),
		}, true
	case modelFamilyMatches("kimi", model, upstreamModel):
		return reasoningPreservationCheck{
			provider:  providerName,
			family:    "kimi",
			flag:      "chat_template_kwargs.preserve_thinking=true",
			field:     "preserve_thinking",
			value:     true,
			present:   stats.ChatTemplatePreserveThinkingPresent,
			effective: stats.chatTemplatePreserveThinkingTrue(),
		}, true
	case modelFamilyMatches("deepseek", model, upstreamModel):
		return reasoningPreservationCheck{
			provider: providerName,
			family:   "deepseek",
			flag:     "chat_template_kwargs.drop_thinking=false",
			field:    "drop_thinking",
			value:    false,
			present:  stats.ChatTemplateDropThinkingPresent,
			effective: stats.chatTemplateDropThinkingFalse() ||
				(!stats.ChatTemplateDropThinkingPresent && stats.deepSeekToolLoopPreservesReasoning()),
		}, true
	default:
		return reasoningPreservationCheck{}, false
	}
}

func (stats *chatRequestLogStats) deepSeekToolLoopPreservesReasoning() bool {
	return len(stats.TrailingUserLostReasoningIndexes) > 0 || len(stats.TrailingUserMissingReasoningIndexes) > 0
}

type reasoningPreservationRepair struct {
	family  string
	flag    string
	field   string
	value   bool
	reasons []string
}

func repairChatReasoningPreservation(providerName, model, upstreamModel string, acceptsChatTemplateKwargs bool, body []byte) ([]byte, *reasoningPreservationRepair, error) {
	repaired, _, repair, err := repairChatReasoningPreservationWithStats(providerName, model, upstreamModel, acceptsChatTemplateKwargs, body)
	return repaired, repair, err
}

// repairChatReasoningPreservationWithStats runs Phase 3 (GH issue #124)
// reasoning-preservation repair: for a model family with a known chat-
// template preservation flag, inject that flag into chat_template_kwargs
// when the agent framework's history shows reasoning would otherwise be
// lost. acceptsChatTemplateKwargs is the resolved provider's capability
// (provider.Provider.AcceptsChatTemplateKwargs) confirming that its upstream
// API tolerates an unrecognized chat_template_kwargs field; when false
// (e.g. Venice, which 400s on unrecognized top-level keys), the *injection*
// step is skipped so the request is never broken by this repair — but
// stats are still parsed and returned so the caller's detection
// diagnostics (WARN logs) keep firing regardless of provider.
func repairChatReasoningPreservationWithStats(providerName, model, upstreamModel string, acceptsChatTemplateKwargs bool, body []byte) ([]byte, *chatRequestLogStats, *reasoningPreservationRepair, error) {
	if !modelReasoningPreservationFamilyKnown(model, upstreamModel) {
		return body, nil, nil, nil
	}
	if !bodyHasReasoningField(body) {
		return body, nil, nil, nil
	}
	state, ok := bestEffortChatRequestReasoningState(body)
	if !ok {
		return body, nil, nil, nil
	}
	stats := &state.stats
	preservation, ok := modelReasoningPreservationCheck(providerName, model, upstreamModel, stats)
	if !ok || preservation.present {
		return body, stats, nil, nil
	}
	reasons := reasoningPreservationRepairReasons(stats)
	if len(reasons) == 0 {
		return body, stats, nil, nil
	}
	if !acceptsChatTemplateKwargs {
		// Detection-only: this provider is not confirmed to accept an
		// injected chat_template_kwargs field, so leave the request body
		// untouched rather than risk an upstream 400 (GH #124).
		return body, stats, nil, nil
	}
	repaired, injected, err := injectChatTemplateBool(state.raw, preservation.field, preservation.value)
	if err != nil {
		return body, stats, nil, err
	}
	if !injected {
		return body, stats, nil, nil
	}
	setChatTemplateBool(stats, preservation.field, preservation.value)
	return repaired, stats, &reasoningPreservationRepair{
		family:  preservation.family,
		flag:    preservation.flag,
		field:   preservation.field,
		value:   preservation.value,
		reasons: reasons,
	}, nil
}

func bodyHasReasoningField(body []byte) bool {
	// This is only a parse-saving precheck before chatRequestStats performs
	// structured JSON decoding. False positives are acceptable; false negatives
	// would only skip a possible repair. The quoted probes keep "reasoning"
	// distinct from "reasoning_content" and avoid matching ordinary text.
	return bytes.Contains(body, []byte(`"reasoning"`)) ||
		bytes.Contains(body, []byte(`"reasoning_content"`))
}

func reasoningPreservationRepairReasons(stats *chatRequestLogStats) []string {
	var reasons []string
	if len(stats.PriorTurnPreservedReasoningIndexes) > 0 {
		reasons = append(reasons, reasoningRepairReasonPriorTurn)
	}
	if len(stats.TrailingUserLostReasoningIndexes) > 0 {
		reasons = append(reasons, reasoningRepairReasonTrailingUser)
	}
	return reasons
}

func injectChatTemplateBool(req map[string]json.RawMessage, field string, value bool) (repaired []byte, injected bool, err error) {
	kwargs := make(map[string]json.RawMessage)
	if raw, ok := req["chat_template_kwargs"]; ok && !isJSONNull(raw) {
		var ok bool
		kwargs, ok = unmarshalJSONObject(raw)
		if !ok {
			return nil, false, nil
		}
	}
	if raw, ok := kwargs[field]; ok {
		if _, present, valid := optionalRawBool(raw); present && valid {
			return nil, false, nil
		}
	}

	encodedValue, err := json.Marshal(value)
	if err != nil {
		return nil, false, fmt.Errorf("marshal chat_template_kwargs.%s: %w", field, err)
	}
	kwargs[field] = encodedValue

	encodedKwargs, err := json.Marshal(kwargs)
	if err != nil {
		return nil, false, fmt.Errorf("marshal chat_template_kwargs: %w", err)
	}
	req["chat_template_kwargs"] = encodedKwargs

	repaired, err = json.Marshal(req)
	if err != nil {
		return nil, false, fmt.Errorf("marshal repaired chat request: %w", err)
	}
	return repaired, true, nil
}

func unmarshalJSONObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, false
	}
	return value, true
}

func allowHourlyLogAtLevel(ctx context.Context, limiter *hourlyLogLimiter, level slog.Level, key string) bool {
	if !slog.Default().Enabled(ctx, level) {
		return false
	}
	if limiter == nil {
		return true
	}
	return limiter.allow(key, time.Now())
}

func chatRequestStatsLoggingEnabled(ctx context.Context, limiter *hourlyLogLimiter) bool {
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
	if infoEnabled && limiter.anyAllowed(now, chatPriorTurnReasoningStrippedLogKey) {
		return true
	}
	if !warnEnabled || !limiter.anyAllowed(now,
		chatReasoningMetadataUnavailableLogKey,
		chatPriorTurnReasoningNotPreservedLogKey,
		chatActiveReasoningStrippedLogKey,
		chatTrailingUserReasoningLostLogKey,
		chatReasoningMetadataIndeterminateLogKey) {
		return false
	}
	return true
}

func reasoningDiagnosticAttrs(attrs []any, extra ...any) []any {
	out := make([]any, 0, len(attrs)+len(extra)+4)
	out = append(out, attrs...)
	out = append(out,
		"reasoning_diagnostics_issue", reasoningDiagnosticsIssueURL,
		"reasoning_diagnostics_rate_limit", reasoningDiagnosticsRateLimit)
	out = append(out, extra...)
	return out
}

func logChatRequestStats(ctx context.Context, limiter *hourlyLogLimiter, model, providerName, upstreamModel, path string, body []byte, stats *chatRequestLogStats, repair *reasoningPreservationRepair) {
	if !chatRequestStatsLoggingEnabled(ctx, limiter) {
		return
	}
	if stats == nil {
		parsedStats, err := chatRequestStats(body)
		if err != nil {
			if allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatReasoningMetadataUnavailableLogKey) {
				slog.WarnContext(ctx, "chat request reasoning metadata unavailable",
					reasoningDiagnosticAttrs([]any{
						"model", model,
						"provider", providerName,
						"upstream_model", upstreamModel,
						"path", path,
					}, "err", err)...)
			}
			return
		}
		stats = &parsedStats
	}
	stats = statsWithInferredTrailingUserMissingReasoning(stats)
	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		debugAttrs := chatRequestLogAttrs(model, providerName, upstreamModel, path, stats, -1)
		slog.DebugContext(ctx, "chat request metadata", debugAttrs...)
	}
	warnAttrs := chatRequestDiagnosticLogAttrs(model, providerName, upstreamModel, path, stats, chatRequestWarnAttrSliceLimit)

	priorTurnMissingIndexes := excludeIntSlice(stats.PriorTurnMissingReasoningIndexes, stats.TrailingUserMissingReasoningIndexes)
	if len(priorTurnMissingIndexes) > 0 &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelInfo, chatPriorTurnReasoningStrippedLogKey) {
		slog.InfoContext(ctx, "agent framework is stripping prior turn reasoning messages; this is known to be bad for coding agents",
			reasoningDiagnosticAttrs(warnAttrs,
				"assistant_missing_reasoning_prior_turn_indexes", priorTurnMissingIndexes)...)
	}
	if preservation, ok := modelReasoningPreservationCheck(providerName, model, upstreamModel, stats); ok &&
		len(stats.PriorTurnPreservedReasoningIndexes) > 0 &&
		(!preservation.effective || repairHasReason(repair, reasoningRepairReasonPriorTurn)) &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatPriorTurnReasoningNotPreservedLogKey) {
		msg := "agent framework preserved prior turn reasoning fields, but model chat template will ignore them without model-specific preserved-thinking flag"
		if repairHasReason(repair, reasoningRepairReasonPriorTurn) {
			msg = "agent framework preserved prior turn reasoning fields; teep repaired model reasoning preservation by providing model-specific preserved-thinking flag"
		}
		extra := appendRepairAttrs([]any{
			"model_reasoning_preservation_family", preservation.family,
			"model_reasoning_preservation_flag", preservation.flag,
		}, repair)
		slog.WarnContext(ctx, msg,
			reasoningDiagnosticAttrs(warnAttrs, extra...)...)
	}
	if activeMissingReasoningWarns(stats) &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatActiveReasoningStrippedLogKey) {
		slog.WarnContext(ctx, "agent framework may be stripping reasoning messages during multi-step assistant processing; repeated active-turn assistant messages have no reasoning fields",
			reasoningDiagnosticAttrs(warnAttrs,
				"assistant_missing_reasoning_active_indexes", stats.ActiveMissingReasoningIndexes,
				"assistant_tool_call_missing_reasoning_active_indexes", stats.ActiveMissingReasoningToolCallIndexes,
				"assistant_user_message_missing_reasoning_active_indexes", stats.ActiveMissingReasoningUserMessageIndexes)...)
	}
	trailingUserLostReasoningWarns := len(stats.TrailingUserLostReasoningIndexes) > 0 &&
		(!modelReasoningPreservationEffective(providerName, model, upstreamModel, stats) || repairHasReason(repair, reasoningRepairReasonTrailingUser))
	trailingUserMissingReasoningWarns := len(stats.TrailingUserMissingReasoningIndexes) > 0
	if (trailingUserLostReasoningWarns || trailingUserMissingReasoningWarns) &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatTrailingUserReasoningLostLogKey) {
		msg := "agent framework may have appended a trailing user message after tool output; model chat template may clear current-turn reasoning"
		if repairHasReason(repair, reasoningRepairReasonTrailingUser) {
			msg = "agent framework may have appended a trailing user message after tool output; teep repaired current-turn reasoning preservation by providing model-specific preserved-thinking flag"
		} else if trailingUserMissingReasoningWarns && !trailingUserLostReasoningWarns {
			msg = "agent framework sent malformed tool-loop history: current tool-call reasoning is stripped and a trailing user message after tool output may cause the model to lose reasoning or tool-result context"
		}
		slog.WarnContext(ctx, msg,
			reasoningDiagnosticAttrs(warnAttrs, appendRepairAttrs(nil, repair)...)...)
	}
	if stats.DetermineIssueCount > 0 &&
		allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatReasoningMetadataIndeterminateLogKey) {
		slog.WarnContext(ctx, "chat request reasoning metadata could not be fully determined",
			reasoningDiagnosticAttrs(warnAttrs,
				"determine_issue_count", stats.DetermineIssueCount,
				"determine_issues", stats.DetermineIssues)...)
	}
}

func repairHasReason(repair *reasoningPreservationRepair, reason string) bool {
	return repair != nil && slices.Contains(repair.reasons, reason)
}

func appendRepairAttrs(attrs []any, repair *reasoningPreservationRepair) []any {
	if repair == nil {
		return attrs
	}
	return append(attrs, "reasoning_preservation_repair_reasons", repair.reasons)
}

func modelReasoningPreservationEffective(providerName, model, upstreamModel string, stats *chatRequestLogStats) bool {
	preservation, ok := modelReasoningPreservationCheck(providerName, model, upstreamModel, stats)
	return ok && preservation.effective
}

func activeMissingReasoningWarns(stats *chatRequestLogStats) bool {
	return len(stats.ActiveMissingReasoningToolCallIndexes) >= activeMissingReasoningWarnThreshold ||
		len(stats.ActiveMissingReasoningUserMessageIndexes) >= activeMissingReasoningWarnThreshold
}

// ---------------------------------------------------------------------------
// Phase 4 (GH issue #124): opt-in prompt-sandwich merge repair.
//
// For model families with no known chat-template preservation flag
// (modelReasoningPreservationCheck returns ok=false — those families are
// handled by repairChatReasoningPreservationWithStats/injectChatTemplateBool
// instead), the only server-side mitigation for the Case 2 "prompt
// sandwich" (a trailing user reminder message appended after tool output,
// which some chat templates treat as starting a new turn and therefore
// strip the just-produced reasoning) is to merge that trailing message into
// the prior user message so the template never sees a new user turn.
//
// This is strictly opt-in (config.RepairPromptSandwichEnabled, default
// off), since it mutates client request semantics. It is never applied to
// E2EE providers, and it is all-or-nothing: if the merge cannot be
// performed losslessly, the request is left unmodified and a WARN explains
// why (AGENTS.md: no partial rewrites).
// ---------------------------------------------------------------------------

const (
	chatPromptSandwichRepairAppliedLogKey      = "chat_prompt_sandwich_repair_applied"
	chatPromptSandwichRepairSkippedE2EELogKey  = "chat_prompt_sandwich_repair_skipped_e2ee"
	chatPromptSandwichRepairSkippedLossyLogKey = "chat_prompt_sandwich_repair_skipped_lossy"
)

// repairPromptSandwichMerge implements the Phase 4 opt-in merge repair. It
// is only meaningful when annotateTrailingUserReasoningLoss already fired
// (stats.TrailingUserAddendumIndex >= 0) for a model family with no known
// chat-template preservation flag; stats may be nil (e.g. because the
// caller's family was unknown to repairChatReasoningPreservationWithStats,
// which short-circuits before parsing stats for unknown families), in which
// case this function parses the body itself.
//
// isE2EEField must be true for any provider whose message content is
// subject to field-level E2EE encryption (config: provider e2ee = true) —
// the merge is unconditionally skipped (with a WARN) for those providers.
func repairPromptSandwichMerge(ctx context.Context, limiter *hourlyLogLimiter, model, providerName, upstreamModel, path string, isE2EEField bool, body []byte, stats *chatRequestLogStats) ([]byte, *chatRequestLogStats, error) {
	if stats == nil {
		parsed, ok := bestEffortChatRequestReasoningState(body)
		if !ok {
			return body, nil, nil
		}
		stats = &parsed.stats
	}
	if stats.TrailingUserAddendumIndex < 0 {
		return body, stats, nil
	}
	if modelReasoningPreservationFamilyKnown(model, upstreamModel) {
		// Families with a known chat-template flag are already repaired by
		// repairChatReasoningPreservationWithStats; merging on top would be
		// a second, unnecessary mutation for a case Phase 3 already covers.
		return body, stats, nil
	}

	baseAttrs := []any{
		"model", model,
		"provider", providerName,
		"upstream_model", upstreamModel,
		"path", path,
		"trailing_user_addendum_index", stats.TrailingUserAddendumIndex,
		"trailing_user_prev_user_index", stats.TrailingUserPrevUserIndex,
	}

	if isE2EEField {
		if allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatPromptSandwichRepairSkippedE2EELogKey) {
			slog.WarnContext(ctx, "prompt-sandwich merge repair skipped: provider uses field-level E2EE, so message content must not be rewritten by this repair path",
				reasoningDiagnosticAttrs(baseAttrs)...)
		}
		return body, stats, nil
	}

	state, ok := bestEffortChatRequestReasoningState(body)
	if !ok {
		return body, stats, nil
	}

	merged, mergedInto, removedIdx, lossy, err := mergeTrailingUserIntoPriorUser(state.raw, stats.TrailingUserPrevUserIndex, stats.TrailingUserAddendumIndex)
	if err != nil {
		return body, stats, err
	}
	if lossy {
		if allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatPromptSandwichRepairSkippedLossyLogKey) {
			slog.WarnContext(ctx, "prompt-sandwich merge repair skipped: trailing user message could not be merged losslessly (non-string content, attachments, or extra fields)",
				reasoningDiagnosticAttrs(baseAttrs)...)
		}
		return body, stats, nil
	}

	if allowHourlyLogAtLevel(ctx, limiter, slog.LevelWarn, chatPromptSandwichRepairAppliedLogKey) {
		slog.WarnContext(ctx, "prompt-sandwich merge repair applied: merged trailing user message into the prior user message so the model chat template does not treat it as a new turn",
			reasoningDiagnosticAttrs(append(baseAttrs,
				"merged_into_index", mergedInto,
				"removed_index", removedIdx))...)
	}

	newStats, statsErr := chatRequestStats(merged)
	if statsErr != nil {
		// The repair itself succeeded; a best-effort stats refresh failing
		// is not a reason to fail the request or discard the repair.
		return merged, stats, nil //nolint:nilerr // intentional: stats refresh is best-effort, not the operation's result
	}
	return merged, &newStats, nil
}

// mergeTrailingUserIntoPriorUser merges messages[addendumIdx] (the trailing
// user "reminder" message) into messages[prevUserIdx] (the prior real user
// message) by concatenating their "content" strings with a "\n\n" join, then
// removes the trailing message from the array. All other fields of the
// prior message are preserved untouched.
//
// The merge is only performed when it can be done losslessly:
//   - both messages' "content" fields must be plain JSON strings (not
//     arrays of content parts, not objects, i.e. no multi-part/attachment
//     content), and
//   - the trailing message must have exactly the "role" and "content" keys
//     (any additional field on it, e.g. a "name", would otherwise be
//     silently dropped when the message is removed).
//
// Returns lossy=true (with no error) when the merge cannot be performed
// losslessly; callers must leave body unmodified in that case rather than
// attempt a partial rewrite.
func mergeTrailingUserIntoPriorUser(req map[string]json.RawMessage, prevUserIdx, addendumIdx int) (merged []byte, mergedInto, removedIdx int, lossy bool, err error) {
	rawMessages, ok := req["messages"]
	if !ok {
		return nil, 0, 0, true, nil
	}
	var messages []json.RawMessage
	if jsonErr := json.Unmarshal(rawMessages, &messages); jsonErr != nil {
		return nil, 0, 0, true, nil //nolint:nilerr // intentional: an unparseable "messages" field is reported via lossy=true, not err
	}
	if prevUserIdx < 0 || addendumIdx < 0 || prevUserIdx >= len(messages) || addendumIdx >= len(messages) || addendumIdx <= prevUserIdx {
		return nil, 0, 0, true, nil
	}

	priorObj, ok := unmarshalJSONObject(messages[prevUserIdx])
	if !ok {
		return nil, 0, 0, true, nil
	}
	trailingObj, ok := unmarshalJSONObject(messages[addendumIdx])
	if !ok {
		return nil, 0, 0, true, nil
	}
	if !isExactlyRoleAndContentKeys(trailingObj) {
		return nil, 0, 0, true, nil
	}
	priorContent, ok := plainStringContent(priorObj["content"])
	if !ok {
		return nil, 0, 0, true, nil
	}
	trailingContent, ok := plainStringContent(trailingObj["content"])
	if !ok {
		return nil, 0, 0, true, nil
	}

	mergedContent, err := json.Marshal(priorContent + "\n\n" + trailingContent)
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("marshal merged content: %w", err)
	}
	priorObj["content"] = mergedContent
	mergedPriorRaw, err := json.Marshal(priorObj)
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("marshal merged message: %w", err)
	}

	newMessages := make([]json.RawMessage, 0, len(messages)-1)
	for idx, m := range messages {
		switch idx {
		case addendumIdx:
			continue
		case prevUserIdx:
			newMessages = append(newMessages, mergedPriorRaw)
		default:
			newMessages = append(newMessages, m)
		}
	}
	encodedMessages, err := json.Marshal(newMessages)
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("marshal merged messages array: %w", err)
	}
	req["messages"] = encodedMessages

	repaired, err := json.Marshal(req)
	if err != nil {
		return nil, 0, 0, false, fmt.Errorf("marshal merged request: %w", err)
	}
	return repaired, prevUserIdx, addendumIdx, false, nil
}

// isExactlyRoleAndContentKeys reports whether obj has precisely the two
// keys "role" and "content" and no others — the shape a trailing user
// "reminder" message must have for mergeTrailingUserIntoPriorUser to remove
// it without silently dropping any other field it might carry.
func isExactlyRoleAndContentKeys(obj map[string]json.RawMessage) bool {
	if len(obj) != 2 {
		return false
	}
	_, hasRole := obj["role"]
	_, hasContent := obj["content"]
	return hasRole && hasContent
}

// plainStringContent returns a message's "content" field as a string, and
// ok=true only when the field is present, non-null, and a plain JSON
// string — never an array of content parts or an object (multi-part
// content/attachments), which cannot be merged losslessly by string
// concatenation.
func plainStringContent(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || isJSONNull(raw) {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}
