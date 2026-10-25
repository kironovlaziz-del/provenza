// Copyright (c) 2026 Laziz Kironov
// Licensed under the Apache License, Version 2.0.
// Part of Provenza — https://github.com/kironovlaziz-del/provenza

package provenza

// Settings for Provenza's gateways - the route where enforcement does not
// depend on the agent's code: the gateway holds the provider / MCP server
// credentials, so the agent never has them.

// GatewayPath is the OpenAI-compatible LLM gateway.
const GatewayPath = "/api/v1/gateway/v1"

// ChainHeader carries the delegation chain of an LLM gateway call.
const ChainHeader = "X-Provenza-Chain-Id"

// MCPPath is the MCP gateway (Streamable HTTP).
const MCPPath = "/api/v1/mcp"

// LLMGateway returns the base URL and API key for any OpenAI-compatible client,
// e.g. openai-go: openai.NewClient(option.WithBaseURL(base), option.WithAPIKey(key)).
// Every call is then a PVP action of the agent ("model_call" on "llm.<model>"),
// decided by the server like any other action (allowed models and providers,
// agent policies, quarantine, the breaker, limits). Calls inside a delegation
// chain send the chain id in the ChainHeader header. The gateway does not
// stream yet.
func LLMGateway(a *Agent) (baseURL, apiKey string, err error) {
	server, key, err := a.Credentials()
	if err != nil {
		return "", "", err
	}
	return server + GatewayPath, key, nil
}

// MCPConnection returns the URL and headers to point any MCP client at Provenza
// instead of at the MCP servers themselves. The headers hold the agent's key.
func MCPConnection(a *Agent) (url string, headers map[string]string, err error) {
	server, key, err := a.Credentials()
	if err != nil {
		return "", nil, err
	}
	return server + MCPPath, map[string]string{"Authorization": "Bearer " + key}, nil
}
