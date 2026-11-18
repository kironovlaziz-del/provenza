# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
The built-in rule packs (services/rule_packs.py): eight profiles - a whole
policy for a level, applied by replacing it - and ten guards against the
most dangerous things an agent can do, applied by adding their restrictions.
Guards never allow a tool. Tool names follow common patterns (payments.*,
*.delete*); copy a pack and rename them to your own tools.

Read-only: an organization copies one to change it.
"""

BUILTIN = [
    {"slug": "org-strict", "name": "Organization: strict", "kind": "profile", "level": "org", "yaml": """\
# Organization level - STRICT baseline.
# For regulated teams (finance, health, public sector) or a first rollout:
# only reviewed models, the dangerous tools denied for everyone, and
# anything that changes the outside world waits for a person.
# It does not list allowed tools: teams and agents do that at their levels.
version: 1
description: Organization baseline - strict
limits:
  requests_per_minute: 30      # LLM gateway calls per agent per minute
  max_tokens: 2000             # cap on one completion
  max_delegation_depth: 1      # an agent may delegate once; helpers may not re-delegate
models:
  allow: ["gpt-4o-mini", "claude-*"]     # list the models you have reviewed
providers:
  allow: ["openai", "anthropic"]         # connection names or types
tools:
  deny:
    - "shell.*"          # no command execution anywhere in the organization
    - "fs.delete*"
    - "db.drop*"
    - "db.truncate*"
    - "*.admin.*"
  require_approval:
    - "email.send"       # leaves the company
    - "payments.*"       # moves money
    - "db.write*"
    - "db.update*"
    - "db.delete*"
    - "crm.delete*"
    - "git.push*"
    - "deploy.*"
"""},
    {"slug": "org-balanced", "name": "Organization: balanced", "kind": "profile", "level": "org", "yaml": """\
# Organization level - BALANCED baseline.
# For teams already running agents: reading is free, the dangerous few are
# denied, and only what cannot be undone waits for a person.
version: 1
description: Organization baseline - balanced
limits:
  requests_per_minute: 60
  max_tokens: 4096
  max_delegation_depth: 2
tools:
  deny:
    - "shell.*"
    - "db.drop*"
    - "db.truncate*"
  require_approval:
    - "payments.*"
    - "db.delete*"
    - "deploy.production*"
    - "email.send_bulk*"
"""},
    {"slug": "team-support", "name": "Team: customer support", "kind": "profile", "level": "team", "yaml": """\
# Team level - CUSTOMER SUPPORT agents.
# They read the knowledge base and the customer's record, draft replies,
# and send only after a person looked - until you trust the drafts.
version: 1
description: Customer support agents
limits:
  requests_per_minute: 30
  max_tokens: 1500
  max_delegation_depth: 1
tools:
  allow:
    - "kb.*"             # knowledge base search and read
    - "crm.read*"
    - "crm.note*"        # add a note to the customer's record
    - "tickets.*"
    - "email.draft"
    - "email.send"
  deny:
    - "crm.export*"      # no bulk export of customer data
    - "crm.delete*"
  require_approval:
    - "email.send"
    - "tickets.refund*"
    - "tickets.close_bulk*"
"""},
    {"slug": "team-engineering", "name": "Team: engineering", "kind": "profile", "level": "team", "yaml": """\
# Team level - ENGINEERING / coding agents.
# They read and write the repository and run the tests; they do not push to
# protected branches, deploy or touch production data without a person.
version: 1
description: Engineering agents
limits:
  requests_per_minute: 60
  max_tokens: 4096
  max_delegation_depth: 2
tools:
  allow:
    - "git.*"
    - "fs.read*"
    - "fs.write*"
    - "ci.*"
    - "issues.*"
    - "docs.*"
  deny:
    - "git.force_push*"
    - "fs.delete*"
    - "secrets.*"        # agents never read the secret store
  require_approval:
    - "git.push*"
    - "git.merge*"
    - "ci.deploy*"
"""},
    {"slug": "team-finance", "name": "Team: finance", "kind": "profile", "level": "team", "yaml": """\
# Team level - FINANCE / back-office agents.
# They read ledgers and invoices and prepare entries; every posting and
# every payment waits for a person.
version: 1
description: Finance agents
limits:
  requests_per_minute: 20
  max_tokens: 2000
  max_delegation_depth: 1
models:
  allow: ["gpt-4o-mini", "claude-*"]
tools:
  allow:
    - "ledger.read*"
    - "invoices.read*"
    - "invoices.draft*"
    - "bank.statement*"
    - "reports.*"
    - "ledger.post*"
    - "payments.prepare*"
    - "payments.send*"
  deny:
    - "ledger.delete*"
    - "payments.send_bulk*"
  require_approval:
    - "ledger.post*"
    - "payments.send*"
    - "invoices.send*"
"""},
    {"slug": "team-research-readonly", "name": "Team: research, read-only", "kind": "profile", "level": "team", "yaml": """\
# Team level - RESEARCH / analytics agents, READ-ONLY.
# They search, read and summarize. Nothing they can call changes anything,
# so nothing needs approval - and nothing else is reachable.
version: 1
description: Research agents - read only
limits:
  requests_per_minute: 60
  max_tokens: 4096
  max_delegation_depth: 1
tools:
  allow:
    - "kb.*"
    - "search.*"
    - "web.fetch*"
    - "db.read*"
    - "docs.read*"
  deny:
    - "db.write*"
    - "db.update*"
    - "db.delete*"
    - "email.*"
"""},
    {"slug": "agent-new-or-external", "name": "Agent: new or external", "kind": "profile", "level": "agent", "yaml": """\
# Agent level - a NEW or EXTERNAL agent on probation.
# A vendor's agent, a contractor's, or one you have not watched yet:
# low limits, a short allow list, no delegation, everything that writes
# goes to a person. Loosen it after a week of clean audit records.
version: 1
description: New or external agent - probation
limits:
  requests_per_minute: 10
  max_tokens: 1000
  max_delegation_depth: 0      # may not delegate at all
tools:
  allow:
    - "kb.read*"
    - "docs.read*"
    - "tickets.read*"
    - "tickets.comment"
  require_approval:
    - "tickets.comment"
"""},
    {"slug": "lockdown-allow-nothing", "name": "Lockdown: allow nothing", "kind": "profile", "level": "any", "yaml": """\
# Any level - LOCKDOWN: allow nothing.
# Apply it to a team or agent level during an incident review: every tool
# call of the agents under it is refused until you undo the pack
# (Rule packs -> Applied -> Undo).
# For an immediate stop of everything, use "Stop all" instead.
version: 1
description: Lockdown - allow nothing
limits:
  max_delegation_depth: 0
tools:
  allow: []
"""},
    {"slug": "guard-destructive", "name": "Destructive operations", "kind": "guard", "level": "any", "yaml": """\
# Guard - DESTRUCTIVE OPERATIONS.
# Nothing an agent does should erase what cannot be brought back: dropping,
# truncating, wiping and purging are refused outright; a deletion waits for
# a person.
version: 1
description: Guard - destructive operations
tools:
  deny:
    - "*.drop*"
    - "*.truncate*"
    - "*.destroy*"
    - "*.wipe*"
    - "*.purge*"
  require_approval:
    - "*.delete*"
    - "*.remove*"
    - "*.overwrite*"
"""},
    {"slug": "guard-money", "name": "Money movement", "kind": "guard", "level": "any", "yaml": """\
# Guard - MONEY MOVEMENT.
# Every payment, transfer, refund, payout or posting waits for a person;
# bulk payments are refused.
version: 1
description: Guard - money movement
tools:
  deny:
    - "*.send_bulk*"
    - "payments.bulk*"
  require_approval:
    - "payments.*"
    - "*.transfer*"
    - "*.refund*"
    - "*.payout*"
    - "*.charge*"
    - "*.withdraw*"
    - "ledger.post*"
    - "invoices.send*"
"""},
    {"slug": "guard-exfiltration", "name": "Data leaving the company", "kind": "guard", "level": "any", "yaml": """\
# Guard - DATA LEAVING THE COMPANY.
# Exports and dumps are refused; anything that shares, uploads or publishes
# outside waits for a person.
version: 1
description: Guard - data exfiltration
tools:
  deny:
    - "*.export*"
    - "*.dump*"
    - "*.download_all*"
    - "*.backup_download*"
  require_approval:
    - "*.share*"
    - "*.upload*"
    - "*.publish*"
    - "*.send_file*"
    - "web.post*"
    - "http.post*"
"""},
    {"slug": "guard-secrets", "name": "Secrets", "kind": "guard", "level": "any", "yaml": """\
# Guard - SECRETS.
# Agents never read, list or create secrets, keys or credentials: the egress
# proxy holds the credentials an agent's tools need.
version: 1
description: Guard - secrets
tools:
  deny:
    - "secrets.*"
    - "vault.*"
    - "kms.decrypt*"
    - "*.read_secret*"
    - "*.get_secret*"
    - "*.list_secrets*"
    - "*.get_credentials*"
    - "*.create_api_key*"
    - "*.create_token*"
"""},
    {"slug": "guard-production", "name": "Production infrastructure", "kind": "guard", "level": "any", "yaml": """\
# Guard - PRODUCTION INFRASTRUCTURE.
# Deploying, scaling, restarting or reconfiguring production waits for a
# person; tearing infrastructure down is refused.
version: 1
description: Guard - production infrastructure changes
tools:
  deny:
    - "terraform.destroy*"
    - "*.delete_cluster*"
    - "*.delete_database*"
  require_approval:
    - "deploy.*"
    - "*.deploy*"
    - "terraform.*"
    - "k8s.*"
    - "kubectl.*"
    - "*.scale*"
    - "*.restart*"
    - "*.rollback*"
    - "dns.*"
    - "firewall.*"
"""},
    {"slug": "guard-identity", "name": "Identity and access administration", "kind": "guard", "level": "any", "yaml": """\
# Guard - IDENTITY AND ACCESS ADMINISTRATION.
# Who may do what is a person's decision: granting, revoking, adding users
# or resetting passwords waits for one; impersonation and switching off a
# second factor are refused.
version: 1
description: Guard - identity and access administration
tools:
  deny:
    - "*.impersonate*"
    - "*.disable_mfa*"
    - "*.admin.*"
  require_approval:
    - "iam.*"
    - "*.grant*"
    - "*.revoke*"
    - "*.add_user*"
    - "*.create_user*"
    - "*.invite*"
    - "*.add_member*"
    - "*.set_role*"
    - "*.reset_password*"
"""},
    {"slug": "guard-code-exec", "name": "Code and shell execution", "kind": "guard", "level": "any", "yaml": """\
# Guard - CODE AND SHELL EXECUTION.
# An agent that may run arbitrary commands may do anything its host can:
# shells and eval are refused, running a script waits for a person.
version: 1
description: Guard - code and shell execution
tools:
  deny:
    - "shell.*"
    - "bash.*"
    - "powershell.*"
    - "*.exec"
    - "*.exec_*"
    - "*.execute_command*"
    - "*.execute_shell*"
    - "*.eval"
    - "*.eval_*"
    - "*.run_command*"
  require_approval:
    - "*.run_script*"
    - "code.run*"
    - "notebook.run*"
"""},
    {"slug": "guard-mass-messaging", "name": "Mass messaging", "kind": "guard", "level": "any", "yaml": """\
# Guard - MASS MESSAGING.
# One wrong prompt should not reach every customer: broadcasts and bulk
# sends are refused, single messages wait for a person, and agents are kept
# to a modest pace.
version: 1
description: Guard - mass messaging
limits:
  requests_per_minute: 20
tools:
  deny:
    - "*.send_bulk*"
    - "*.broadcast*"
    - "*.mass_*"
    - "*.send_all*"
  require_approval:
    - "email.send*"
    - "*.send_email*"
    - "sms.*"
    - "slack.post*"
    - "*.post_message*"
"""},
    {"slug": "guard-pii-export", "name": "Bulk export of personal data", "kind": "guard", "level": "any", "yaml": """\
# Guard - BULK EXPORT OF PERSONAL DATA.
# Reading one customer's record is work; pulling every customer's is a
# breach: bulk reads and exports of people's data are refused, HR records
# wait for a person.
version: 1
description: Guard - bulk personal data export
tools:
  deny:
    - "crm.export*"
    - "hr.export*"
    - "*.export_customers*"
    - "*.export_users*"
    - "*.export_contacts*"
    - "*.bulk_read*"
    - "*.list_all_customers*"
  require_approval:
    - "hr.*"
    - "*.personal_data*"
"""},
    {"slug": "guard-models", "name": "Reviewed models and providers only", "kind": "guard", "level": "any", "yaml": """\
# Guard - MODEL AND PROVIDER ALLOWLIST.
# Only the models and providers your organization reviewed. Copy this pack
# and list your own before applying it: a level that already has its own
# allow list keeps it (the pack says so when it is applied).
version: 1
description: Guard - reviewed models and providers only
models:
  allow: ["gpt-4o*", "claude-*", "gemini-*"]
providers:
  allow: ["openai", "anthropic", "google"]
"""},
]
