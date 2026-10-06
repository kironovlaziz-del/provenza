# Kill switch

Enforcement → **Kill switch** stops AI at one of four levels and undoes each
stop exactly.

| Level | Stops | While in force |
|-------|-------|----------------|
| `agent` | one agent | the agent cannot be switched back on by hand |
| `team` | every agent of the team and of its sub-teams | an agent created in or moved into the team or a team below it - including sub-teams created or moved there later - starts suspended; an agent it stopped stays held even if moved out |
| `all_agents` | every agent of the organization | every new agent starts suspended |
| `org_traffic` | every agent, **and** the gateway, AI requests (new and queued) and the provider playground | as `all_agents`; gateway calls answer `503 kill_switch`, requests `503 kill_switch.traffic_stopped` |

Agents are stopped by suspending them, so every place an agent acts refuses
it already: agent keys, the policy engine, the gateway, delegation, and A2A
messages (refused in enforce mode, flagged in monitor mode).
Agents already suspended or quarantined are left out - they were not stopped
by this decision. With *End their delegation chains* (default) the active
and tripped chains the stopped agents root are terminated.

## Engaging

`POST /api/v1/kill-switch/events` (admin):

```json
{"scope": "team", "target_id": 7, "reason": "unexpected payouts", "terminate_chains": true}
```

- `reason` is required (3-2000 characters).
- `agent` / `team` need `target_id`; the organization-wide levels take none and
  must repeat the scope in `confirm` (`"confirm": "org_traffic"`) - the page
  asks the admin to type `STOP` for that.
- The same stop twice (same level and target) is refused
  (`409 kill_switch.already_active`); a stop at another level is allowed, so
  you can escalate from a team to all traffic.
- `POST /api/v1/agents/{id}/kill` (the agent pages' **Kill**) is the same as
  an agent-level stop and returns its `event_id`; killing again returns the
  stop already in force.
- `org_traffic` also fails AI requests that were queued before the stop; they
  are not resumed when it is lifted.
- Notifications are sent with at most a few seconds' wait, so a slow channel
  never holds the button.

The event records what it changed:

```json
{"agents": [{"id": 12, "name": "billing-bot", "status": "active"}], "chains": [301], "team_ids": [7, 9]}
```

## Lifting

`POST /api/v1/kill-switch/events/{id}/lift` (admin), optional `reason`.
For each agent the stop suspended:

- still suspended and held by no other active stop → back to the status it had
  (**restored**);
- still suspended but another active stop covers it → stays suspended and is
  added to that stop, which restores it when lifted (**kept**);
- changed since - retired, switched on, quarantined - → left alone (**skipped**);
  so is an agent whose role now requires a hybrid key it does not have.

Terminated delegation chains stay terminated; the agents start new ones.
The result is stored on the event (`lift_result`) and shown in the history.

## Records

- Audit log: entity `kill_switch`, actions `engaged` and `lifted` (with the
  agent and chain ids); `agent` / `killed` for the agent-page Kill, and
  `assignment_changed` carries `kill_switch_event_id` when a move into a
  stopped team suspended the agent.
- Notifications: event type `kill_switch` (engaged and lifted).
- `GET /api/v1/kill-switch` (admin, approver): active stops and agents by
  status. `GET /api/v1/kill-switch/events`: history, active stops first.

Engaging, lifting and agent creation take one advisory lock per
organization, so a stop never misses an agent created at the same moment.
Agents killed before this feature have no event: reactivate them as before.
