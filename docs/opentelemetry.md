# OpenTelemetry export

Provenza sends every PVP decision to your OpenTelemetry collector as an
OTLP log record: policy checks, recorded actions, LLM gateway calls,
delegations and incidents. They show up in the monitoring tools you already
use: Grafana, Datadog, Honeycomb, Elastic, Splunk, or anything an
OpenTelemetry Collector forwards to. When an agent sends its W3C trace
context, its decisions appear inside the agent's own trace.

This copy is for monitoring. It is not signed. The record of what happened
is the [tamper-evident audit log](audit-proofs.md) and the PVP receipts.

## Switch it on

Settings → **SIEM & OpenTelemetry** → **OpenTelemetry** → **Set up**
(administrators):

1. **Collector endpoint**: the collector's OTLP/HTTP address, usually on
   port 4318. Provenza adds `/v1/logs` unless the address already ends with
   it.
2. **Header** (optional): for a collector or a service that needs a key,
   for example `Authorization: Bearer …`, `x-honeycomb-team: …` or
   `DD-API-KEY: …`. The value is stored encrypted and never shown again.
   With the same header name, leave the value empty to keep the stored one.
3. **Test and save**: the collector gets one test record (`pvp.test`)
   first. If it does not accept the record, nothing is saved and the page
   shows the collector's answer.

The export starts when it is switched on. Earlier events are not sent.
New decisions follow within about a minute: a worker runs every 30 seconds
and takes events at least 15 seconds old, so a transaction that is still
open is not skipped.

The page shows where the records go (**Outbound to**), when the last batch
was sent, how many records in total, and the last failure. **Send a test
record** tries the stored settings again.

API (administrators): `GET /api/v1/otel-export/`, `PUT /api/v1/otel-export/`
with `{"enabled", "endpoint", "header_name", "header_value"}`, and
`POST /api/v1/otel-export/test`. Each change is in the audit log, without
the header's value.

### Network

The endpoint is outbound traffic from the Provenza server to the host it
names, through the same SSRF guard as every other address an administrator
types in. Use HTTPS. Plain HTTP is accepted only for a host on your own
network that the operator lists in `OUTBOUND_PRIVATE_ALLOWLIST` (for
example `otel-collector.internal` or `10.0.0.0/8`). A collector on the
same host or network is refused unless it is listed there.

## A collector in front of everything

A minimal OpenTelemetry Collector that takes Provenza's records and passes
them on:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: detailed     # replace with your backend's exporter
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
```

Then, in Provenza, the endpoint is `http://otel-collector.internal:4318`
with `OUTBOUND_PRIVATE_ALLOWLIST=otel-collector.internal`. A service that
takes OTLP/HTTP directly (Honeycomb or Grafana Cloud, for example) can be
the endpoint too, with its key as the header.

## What a record holds

Metadata only, the same as the live view of agent activity. A record never
holds the arguments of a call, prompts, outputs, the free-text reason of a
verdict or the details of an incident.

| | |
|---|---|
| resource | `service.name: provenza`, `provenza.org.id`, and `provenza.url` when `PUBLIC_BASE_URL` is set |
| scope | `provenza.pvp`, version `1` |
| `eventName` | `pvp.action.checked`, `pvp.action.recorded`, `pvp.llm.call`, `pvp.delegation.hop`, `pvp.incident.created` (`pvp.test` for the test record) |
| `timeUnixNano` | when it happened in Provenza |
| `severityNumber` | INFO (9): allowed, completed, verified; WARN (13): denied, held for approval, an LLM call that did not complete, an unverified delegation, a medium incident; ERROR (17): a high or critical incident |
| `body` | one line, e.g. `PVP check: denied tool_call stripe.charge` |
| `traceId`, `spanId` | the agent's trace and span, when it sent them (below) |

Attributes. `pvp.*` are PVP's own. `gen_ai.*` follow the [OpenTelemetry
GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai),
so dashboards that know them read the records as they are. Those
conventions are still in development, and their names may change.

| attribute | events | |
|---|---|---|
| `pvp.event.type`, `pvp.event.id` | all | the kind of event and its id in Provenza |
| `gen_ai.agent.id`, `gen_ai.agent.name` | all | the agent (for a delegation, the one that delegated) |
| `pvp.chain.id` | all | the delegation chain, if any |
| `pvp.decision` | checked, recorded | `allowed`, `denied`, `pending_approval` |
| `pvp.action.type`, `pvp.tool.name` | checked, recorded | `tool_call`, `api_request`, `egress`, … and the tool |
| `gen_ai.operation.name`, `gen_ai.tool.name` | checked, recorded | `execute_tool` and the tool, for tool calls |
| `pvp.policy.id` | checked, recorded | the policy that decided |
| `pvp.guards` | checked, recorded, LLM | the OWASP Agentic codes (ASI01–ASI10) the verdict names |
| `pvp.incident.type` | checked, incident | e.g. `policy_violation`, `capability_escalation` |
| `pvp.duration_ms`, `pvp.checked` | recorded | how long the call took; whether it was checked first |
| `gen_ai.operation.name`, `gen_ai.request.model` | LLM | `chat` and the model asked for |
| `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` | LLM | tokens |
| `pvp.llm.status`, `pvp.provider.id`, `pvp.flags` | LLM | `completed`, `denied`, `rate_limited`, … |
| `pvp.delegation.to_agent.id`, `.to_agent.name`, `.depth`, `.capabilities`, `.verified` | delegation | the hop |
| `pvp.incident.severity` | incident | `low` … `critical` |

## The agent's trace

An agent instrumented with OpenTelemetry sends a `traceparent` header
([W3C Trace Context](https://www.w3.org/TR/trace-context/)) with its
requests. Provenza keeps the trace id and the span id on the check, the
recorded action and the LLM gateway call of that request. The record then
carries them, and the decision shows inside the agent's trace, next to the
span of the tool call.

- **REST** (`/agents/actions/check`, `/agents/actions/record`) and the
  **LLM gateway**: the `traceparent` header.
- **MCP gateway**: `params._meta.traceparent` of the JSON-RPC request, where
  MCP clients carry it. It wins over the header.
- An action recorded without a trace context of its own takes the one of
  its check.

The trace context is correlation data sent by the caller. It never takes
part in a decision and is not part of the signed evidence. A value that is
not a valid `traceparent` is ignored. `tracestate` is not kept.

## Delivery

The database is the source. For each kind of event, the export keeps the
id of the last row sent. It moves only when the collector accepted the
batch.

| the collector answers | what happens |
|---|---|
| 2xx | sent; a partial success (`rejectedLogRecords`) is shown as the last failure |
| 429, 502, 503, 504, any other 4xx or 5xx, no answer | the events wait and go with the next run; the failure is shown |
| 400 (malformed), 413 (too large) | the batch is dropped, as the OTLP specification says, and the failure is shown |

At most 200 events of each kind go in one request, and at most 5 requests
per organization per run, so a collector that comes back after a long time
catches up without a burst. Events that retention (Settings → Retention)
deleted before they were sent are not sent.

Only one worker exports for an organization at a time. When an
administrator changes the settings while a run is in progress, that run
does not write its progress back. The next run then sends the same events
again, so a collector may see a few records twice.

## Not covered

- Spans. Provenza decides about an action at one moment; it does not run it.
  The decisions are log-based events, which OpenTelemetry recommends over
  span events.
- Metrics. The installation's own metrics are for Prometheus
  ([monitoring](monitoring.md)).
- The egress sensor's events go to a SIEM by pull ([SIEM export](siem-export.md)).
- The SDKs do not send `traceparent` on their own yet. Pass it as a header
  where your client lets you.
