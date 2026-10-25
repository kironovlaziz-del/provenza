// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

// Package policy judges an action by a signed policy release alone - the Go
// port of backend/app/pvp/bundle_eval.py (docs/pvp/edge.md, sections 3.1 and
// 4). Both must decide every case in sdk/testdata/policy-vectors.json alike,
// with the same reason.
//
// What an enforcement point cannot judge from the bundle is left to the
// server, whose verdict is required as well: a delegation chain (Evaluate
// judges the agent's own rights, an upper bound of its rights in any chain)
// and egress actions (the AI domain catalog with its built-in hints).
package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Policy is a verified release: its number and both documents as parsed.
type Policy struct {
	Number   int
	Bundle   map[string]any
	Manifest map[string]any
}

// Request is the action to judge.
type Request struct {
	AgentID    int64
	ActionType string
	ToolName   string
	Input      any // parsed JSON
	// KeyChecked: compare KeyFingerprint (nil: the agent has no key) with
	// the manifest's; false: no agent key at hand (a mediated request)
	KeyChecked     bool
	KeyFingerprint *string
	ToolVersion    *string
	ToolDigest     *string
}

func section(m map[string]any, name string) map[string]any {
	v, _ := m[name].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}

// intOf: a JSON integer (Python int, not bool, not float).
func intOf(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(string(n), ".eE") {
		return 0, false
	}
	i, err := strconv.Atoi(string(n))
	return i, err == nil
}

func sortedSet(v any) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range stringsOf(v) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// NotAfter is the release's validity end (unix seconds).
func (p *Policy) NotAfter() float64 {
	n, ok := asNumber(p.Bundle["not_after"], false)
	if !ok {
		return 0
	}
	return n.f()
}

func (p *Policy) layer(key string) map[string]any {
	return section(section(p.Bundle, "policy_layers"), key)
}

type level struct {
	source string
	doc    map[string]any
}

// hierarchy: organization -> teams (topmost first) -> agent, as the server's signed_chain.
func (p *Policy) hierarchy(agentID int64, agent map[string]any) []level {
	levels := []level{{"organization", p.layer("org")}}
	teams := section(p.Bundle, "teams")
	var chain []level
	seen := map[string]bool{}
	current := agent["team_id"]
	for current != nil && len(chain) < 20 {
		id, ok := intOf(current)
		key := strconv.Itoa(id)
		if !ok || seen[key] {
			break
		}
		seen[key] = true
		t, ok := teams[key].(map[string]any)
		if !ok {
			break
		}
		chain = append(chain, level{"team " + pyStr(t["name"]), p.layer("team:" + key)})
		current = t["parent_id"]
	}
	for i := len(chain) - 1; i >= 0; i-- {
		levels = append(levels, chain[i])
	}
	levels = append(levels, level{"agent " + pyStr(agent["name"]), p.layer(fmt.Sprintf("agent:%d", agentID))})
	return levels
}

// engineRules is hier_policy.engine_rules.
func engineRules(levels []level) ([]customPolicy, *int) {
	var out []customPolicy
	var depth *int
	for _, lv := range levels {
		tools, models := section(lv.doc, "tools"), section(lv.doc, "models")
		rules := map[string]any{}
		if v, ok := tools["allow"]; ok {
			rules["allow_only_tool_patterns"] = v
		}
		if truthy(tools["deny"]) {
			rules["deny_tool_patterns"] = tools["deny"]
		}
		if truthy(tools["require_approval"]) {
			rules["require_approval_tool_patterns"] = tools["require_approval"]
		}
		if v, ok := models["allow"]; ok {
			rules["allow_only_model_patterns"] = v
		}
		if len(rules) > 0 {
			out = append(out, customPolicy{name: lv.source + " policy", rules: rules})
		}
		if v, ok := section(lv.doc, "limits")["max_delegation_depth"]; ok {
			if d, ok := intOf(v); ok && (depth == nil || d < *depth) {
				dd := d
				depth = &dd
			}
		}
	}
	return out, depth
}

// policies: the enabled agent policies of this agent and of all agents,
// highest priority first.
func (p *Policy) policies(agentID int64) []customPolicy {
	type item struct {
		id       int
		priority int
		p        map[string]any
	}
	var items []item
	for k, v := range section(p.Bundle, "agent_policies") {
		pol, ok := v.(map[string]any)
		if !ok || !truthy(pol["enabled"]) {
			continue
		}
		if a := pol["agent_id"]; a != nil {
			if id, ok := intOf(a); !ok || int64(id) != agentID {
				continue
			}
		}
		id, _ := strconv.Atoi(k)
		prio, _ := intOf(pol["priority"])
		items = append(items, item{id, prio, pol})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].priority != items[j].priority {
			return items[i].priority > items[j].priority
		}
		return items[i].id < items[j].id
	})
	out := make([]customPolicy, 0, len(items))
	for _, it := range items {
		rules, ok := it.p["rules"]
		if !ok || rules == nil {
			rules = map[string]any{}
		}
		out = append(out, customPolicy{id: it.id, name: it.p["name"], rules: rules})
	}
	return out
}

// ---------------------------------------------------------------- Tool Registry

type entry struct {
	pattern  string
	status   string
	version  string
	digest   string
	required []string
}

func (p *Policy) registry() (string, []entry) {
	reg := section(p.Bundle, "tool_registry")
	mode, _ := reg["mode"].(string)
	if mode == "" {
		mode = "enforce"
	}
	var out []entry
	for pattern, v := range section(reg, "entries") {
		e, _ := v.(map[string]any)
		status, _ := e["status"].(string)
		version, _ := e["pinned_version"].(string)
		digest, _ := e["pinned_digest"].(string)
		out = append(out, entry{pattern, status, version, digest, stringsOf(e["required_capabilities"])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pattern < out[j].pattern })
	return mode, out
}

func requiredCapabilities(entries []entry, tool string) []string {
	if tool == "" {
		return []string{}
	}
	need := map[string]bool{}
	for _, e := range entries {
		if len(e.required) > 0 && (e.pattern == tool || fnmatchcase(tool, e.pattern)) {
			for _, c := range e.required {
				need[c] = true
			}
		}
	}
	out := make([]string, 0, len(need))
	for c := range need {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func matchEntry(entries []entry, tool string) *entry {
	for i := range entries {
		if entries[i].pattern == tool {
			return &entries[i]
		}
	}
	var best *entry
	for i := range entries {
		e := &entries[i]
		if strings.ContainsAny(e.pattern, "*?[") && fnmatchcase(tool, e.pattern) &&
			(best == nil || runeLen(e.pattern) > runeLen(best.pattern)) {
			best = e
		}
	}
	return best
}

func normalizeDigest(v *string) string {
	if v == nil || *v == "" {
		return ""
	}
	s := strings.ToLower(strings.TrimFunc(*v, isPySpace))
	return strings.TrimPrefix(s, "sha256:")
}

// verifyAgainst is supply_chain.verify_against over the signed Tool Registry.
func verifyAgainst(mode string, entries []entry, tool string, version, digest *string) *Decision {
	const where = "the signed Tool Registry"
	deny := func(reason string) *Decision { return &Decision{Result: Denied, Reason: reason} }
	if tool == "" || mode == "off" {
		return nil
	}
	e := matchEntry(entries, tool)
	if e == nil {
		if mode == "enforce" {
			return deny(fmt.Sprintf("Tool '%s' is not approved in %s (ASI04)", tool, where))
		}
		return nil
	}
	switch e.status {
	case "blocked":
		return deny(fmt.Sprintf("Tool '%s' is blocked in %s (ASI04)", tool, where))
	case "approved":
		var drift, missingParts []string
		if e.version != "" && version != nil && *version != "" && *version != e.version {
			drift = append(drift, fmt.Sprintf("version %s != pinned %s", strRepr(*version), strRepr(e.version)))
		}
		if reported := normalizeDigest(digest); e.digest != "" && reported != "" && reported != e.digest {
			drift = append(drift, "manifest digest differs from the pinned one")
		}
		if len(drift) > 0 && mode == "enforce" {
			return deny(fmt.Sprintf("Tool '%s' differs from %s (%s) (ASI04)", tool, where, strings.Join(drift, "; ")))
		}
		if e.version != "" && (version == nil || *version == "") {
			missingParts = append(missingParts, "version")
		}
		if e.digest != "" && (digest == nil || *digest == "") {
			missingParts = append(missingParts, "manifest digest")
		}
		if len(missingParts) > 0 && mode == "enforce" {
			return deny(fmt.Sprintf("Tool '%s' is pinned in %s; the request must report its %s (ASI04)", tool, where,
				strings.Join(missingParts, " and ")))
		}
		return nil
	}
	if mode == "enforce" {
		return deny(fmt.Sprintf("Tool '%s' is %s in %s (ASI04)", tool, e.status, where))
	}
	return nil
}

// ---------------------------------------------------------------- egress routes

var descriptorKeys = []string{"route", "method", "path", "query_sha256", "body_sha256", "body_bytes"}

// pyUnquote is urllib.parse.unquote: valid %XX sequences decoded (as UTF-8,
// invalid bytes become U+FFFD), anything else kept.
func pyUnquote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var raw []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			if b, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				raw = append(raw, byte(b))
				i += 2
				continue
			}
		}
		raw = append(raw, s[i])
	}
	return strings.ToValidUTF8(string(raw), "�")
}

func isHex(c byte) bool { return (c >= '0' && c <= '9') || (c|0x20 >= 'a' && c|0x20 <= 'f') }

func pathProblem(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "the path must start with /"
	}
	for _, seg := range strings.Split(path, "/") {
		d := pyUnquote(seg)
		if d == "." || d == ".." || strings.ContainsAny(d, "/\\") {
			return "the path has a '.' / '..' segment or an encoded separator"
		}
	}
	return ""
}

func prefixAllows(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if p == "/" || path == p || strings.HasPrefix(path, strings.TrimRight(p, "/")+"/") {
			return true
		}
	}
	return false
}

// routeRules is egress_proxy.route_rules over the signed route.
func routeRules(route map[string]any, tool string, inp map[string]any) *Decision {
	deny := func(reason string) *Decision { return &Decision{Result: Denied, Reason: reason} }
	slug, isStr := inp["route"].(string)
	sameKeys := len(inp) == len(descriptorKeys)
	for _, k := range descriptorKeys {
		if _, ok := inp[k]; !ok {
			sameKeys = false
		}
	}
	if !sameKeys || !isStr || tool != "proxy."+slug {
		return deny("a proxy action names its route in tool_name (proxy.<route>) and describes the request with " +
			"exactly " + strings.Join(descriptorKeys, ", "))
	}
	if route == nil || route["enabled"] != true || route["slug"] != slug {
		return deny(fmt.Sprintf("egress route '%s' does not exist or is disabled", slug))
	}
	method, path := inp["method"], inp["path"]
	if !containsValue(route["methods"], pyStr(method)) || !isString(method) {
		return deny(fmt.Sprintf("method %s is not allowed on route '%s'", pyStr(method), slug))
	}
	ps, ok := path.(string)
	problem := "the path is missing"
	if ok {
		problem = pathProblem(ps)
	}
	if problem != "" {
		return deny(fmt.Sprintf("route '%s': %s", slug, problem))
	}
	if !prefixAllows(ps, stringsOf(route["path_prefixes"])) {
		return deny(fmt.Sprintf("path %s is outside route '%s'", ps, slug))
	}
	size, sizeOK := intOf(inp["body_bytes"])
	limit, _ := intOf(route["max_body_bytes"])
	if !sizeOK || size < 0 || size > limit {
		return deny(fmt.Sprintf("the body is larger than route '%s' allows (%s bytes)", slug, pyStr(route["max_body_bytes"])))
	}
	return nil
}

func isString(v any) bool { _, ok := v.(string); return ok }

// ---------------------------------------------------------------- the verdict

// Evaluate is bundle_eval.evaluate for an action outside any delegation chain.
func Evaluate(p *Policy, r Request, now float64) Decision {
	deny := func(reason string) Decision { return Decision{Result: Denied, Reason: reason} }
	if now > p.NotAfter() {
		return deny(fmt.Sprintf("the signed policy (release #%d) expired; administrators must sign a new release",
			p.Number))
	}
	key := strconv.FormatInt(r.AgentID, 10)
	agent, ok := section(p.Bundle, "agents")[key].(map[string]any)
	if !ok {
		return deny(fmt.Sprintf("agent #%d is not in the signed policy (release #%d)", r.AgentID, p.Number))
	}
	if r.KeyChecked {
		signed, isStr := section(p.Manifest, "agents")[key].(string)
		same := (r.KeyFingerprint == nil && !isStr) || (r.KeyFingerprint != nil && isStr && *r.KeyFingerprint == signed)
		if !same {
			return deny(fmt.Sprintf("agent #%d's key is not the one in the signed manifest (release #%d)",
				r.AgentID, p.Number))
		}
	}
	if r.ActionType == "egress" {
		return deny("egress actions are judged by the server (the AI domain catalog), not by an enforcement point")
	}
	capabilities := sortedSet(agent["capabilities"])
	tools := sortedSet(agent["allowed_tools"])
	depth, _ := intOf(agent["max_delegation_depth"])
	hier, policyDepth := engineRules(p.hierarchy(r.AgentID, agent))
	if policyDepth != nil && *policyDepth < depth {
		depth = *policyDepth
	}
	status, _ := agent["status"].(string)
	view := agentView{allowedTools: tools, allowedModels: stringsOf(agent["allowed_models"]), maxDepth: depth,
		status: status}
	inp, _ := r.Input.(map[string]any)
	if inp == nil {
		inp = map[string]any{}
	}
	switch r.ActionType {
	case modelAction:
		view.allowedTools = append(view.allowedTools, r.ToolName)
	case "proxy":
		slug, _ := inp["route"].(string)
		var route map[string]any
		for _, v := range section(p.Bundle, "egress_routes") {
			if rt, ok := v.(map[string]any); ok && rt["slug"] == slug {
				route = rt
				break
			}
		}
		if d := routeRules(route, r.ToolName, inp); d != nil {
			return *d
		}
	}
	mode, entries := p.registry()
	required := requiredCapabilities(entries, r.ToolName)
	c := &actionContext{tool: r.ToolName, actionType: r.ActionType, input: inp, capabilities: required}
	d := checkAction(view, capabilities, c, append(hier, p.policies(r.AgentID)...))
	d.RequiredCapabilities = required
	if d.Result == Denied || r.ActionType == "proxy" || r.ActionType == modelAction {
		return d
	}
	if s := verifyAgainst(mode, entries, r.ToolName, r.ToolVersion, r.ToolDigest); s != nil {
		s.RequiredCapabilities = required
		return *s
	}
	return d
}
