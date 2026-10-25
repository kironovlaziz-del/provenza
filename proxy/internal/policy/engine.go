// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package policy

// The rule engine, the port of check_action and evaluate_custom_rule in
// backend/app/services/agent_policy_engine.py.

import (
	"fmt"
	"sort"
	"strings"
)

const (
	Allowed         = "allowed"
	Denied          = "denied"
	PendingApproval = "pending_approval"
	modelAction     = "model_call"
)

var modelInvokingTools = map[string]bool{"openai.chat": true, "anthropic.messages": true, "model.invoke": true,
	"llm.chat": true}

// Decision is a verdict and why, worded as the server words it.
type Decision struct {
	Result               string   `json:"decision"`
	Reason               string   `json:"reason"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type agentView struct {
	allowedTools  []string
	allowedModels []string
	maxDepth      int
	status        string
}

type actionContext struct {
	tool         string
	actionType   string
	input        map[string]any
	capabilities []string
	violation    string
}

type customPolicy struct {
	id    any // a number, or nil for a level of the hierarchy
	name  any
	rules any
}

func invokesModel(c *actionContext) bool {
	return c.actionType == modelAction || modelInvokingTools[c.tool]
}

func stringsOf(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, pyStr(x))
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// containsValue is Python's `x in set(list)` for a rule's list.
func containsValue(list any, s string) bool {
	l, _ := list.([]any)
	for _, x := range l {
		if pyEqual(x, s) {
			return true
		}
	}
	return false
}

func evaluateCustomRule(rule map[string]any, c *actionContext) string {
	tool := c.tool
	c.violation = ""
	argVerdict := "ok"
	if rules, ok := rule["argument_rules"]; ok {
		argVerdict, c.violation = evaluateArgumentRules(rules, tool, c.input)
		if argVerdict == "deny" {
			return "deny"
		}
	}
	if v, ok := rule["deny_tools"]; ok && containsValue(v, tool) {
		return "deny"
	}
	modelCall := c.actionType == modelAction
	if v, ok := rule["allow_only_tools"]; ok && !modelCall && !containsValue(v, tool) {
		return "deny"
	}
	if v, ok := rule["deny_tool_patterns"]; ok && tool != "" && matches(tool, stringsOf(v)) {
		return "deny"
	}
	if v, ok := rule["allow_only_tool_patterns"]; ok && !modelCall {
		if tool == "" || !matches(tool, stringsOf(v)) {
			return "deny"
		}
	}
	if v, ok := rule["allow_only_model_patterns"]; ok && invokesModel(c) {
		model := c.input["model"]
		if truthy(model) && !matches(pyStr(model), stringsOf(v)) {
			return "deny"
		}
	}
	if v, ok := rule["deny_action_types"]; ok && containsValue(v, c.actionType) {
		return "deny"
	}
	if v, ok := rule["require_approval_tools"]; ok && containsValue(v, tool) {
		return "approval"
	}
	if v, ok := rule["require_approval_tool_patterns"]; ok && tool != "" && matches(tool, stringsOf(v)) {
		return "approval"
	}
	if argVerdict == "approval" {
		return "approval"
	}
	return "ok"
}

func escalated(child, parent []string) []string {
	has := map[string]bool{}
	for _, p := range parent {
		has[p] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range child {
		if !has[c] && !seen[c] {
			out = append(out, c)
			seen[c] = true
		}
	}
	sort.Strings(out)
	return out
}

// policyName: the policy's name as the server prints it (None prints "None").
func policyName(p customPolicy) string { return pyStr(p.name) }

// checkAction: no delegation chain here (an enforcement point judges the
// agent's own rights; the server judges a chain).
func checkAction(a agentView, granted []string, c *actionContext, policies []customPolicy) Decision {
	if a.status != "active" {
		return Decision{Result: Denied, Reason: fmt.Sprintf("Agent is %s, not active", a.status)}
	}
	if c.tool != "" && !contains(a.allowedTools, c.tool) {
		return Decision{Result: Denied, Reason: fmt.Sprintf("Tool '%s' is not in the agent's allowed tools", c.tool)}
	}
	if invokesModel(c) {
		if model, ok := c.input["model"]; ok && truthy(model) {
			if s, isStr := model.(string); !isStr || !contains(a.allowedModels, s) {
				return Decision{Result: Denied, Reason: fmt.Sprintf("Model '%s' is not in the agent's allowed models",
					pyStr(model))}
			}
		}
	}
	if 0 > a.maxDepth {
		return Decision{Result: Denied, Reason: "Delegation depth exceeded"}
	}
	if esc := escalated(c.capabilities, granted); len(esc) > 0 {
		return Decision{Result: Denied, Reason: "Capability escalation detected: " + strings.Join(esc, ", ")}
	}
	approval := ""
	for _, p := range policies {
		var list []any
		switch r := p.rules.(type) {
		case []any:
			list = r
		default:
			list = []any{r}
		}
		for _, item := range list {
			rule, ok := item.(map[string]any)
			if !ok {
				continue
			}
			verdict := evaluateCustomRule(rule, c)
			suffix := ""
			if c.violation != "" {
				suffix = ": " + c.violation
			}
			if verdict == "deny" {
				return Decision{Result: Denied, Reason: "Blocked by policy '" + policyName(p) + "'" + suffix}
			}
			if verdict == "approval" && approval == "" {
				approval = "Action requires human approval per policy '" + policyName(p) + "'" + suffix
			}
		}
	}
	if approval != "" {
		return Decision{Result: PendingApproval, Reason: approval}
	}
	return Decision{Result: Allowed, Reason: "Action permitted"}
}
