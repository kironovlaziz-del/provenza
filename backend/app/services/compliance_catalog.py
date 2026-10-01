# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Compliance catalog: requirements of EU AI Act, GDPR, ISO/IEC 42001, NIST AI
RMF and OWASP Top 10 for Agentic Applications, each mapped to the Provenza
evidence that supports it.

  check      name of an automatic check in compliance_engine.CHECKS, or None
  attest     True when a person must state it (documents, procedures...);
             with a check as well, the check is shown as supporting evidence
  scope      "org"     evaluated once for the organization
             "system"  evaluated for every AI system it applies to
  applies    for scope=system: "all", "high_risk", "pii", "agents"
  fix        the page where a gap is closed

The references are short pointers for orientation, not legal advice; the
organization stays responsible for its own interpretation.
"""

from typing import Dict, List

CATALOG_VERSION = "2026.10"

FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "eu_ai_act": {"name": "EU AI Act", "ref": "Regulation (EU) 2024/1689"},
    "gdpr": {"name": "GDPR", "ref": "Regulation (EU) 2016/679"},
    "iso42001": {"name": "ISO/IEC 42001", "ref": "ISO/IEC 42001:2023, Annex A"},
    "nist_ai_rmf": {"name": "NIST AI RMF", "ref": "NIST AI 100-1"},
    "owasp_agentic": {"name": "OWASP Agentic Top 10", "ref": "OWASP Top 10 for Agentic Applications"},
}


def R(id, framework, ref, title, *, check=None, attest=False, scope="org", applies="all", fix=None):
    return {"id": id, "framework": framework, "ref": ref, "title": title, "check": check, "attest": attest,
            "scope": scope, "applies": applies, "fix": fix}


REQUIREMENTS: List[dict] = [
    # ------------------------------------------------------------------ EU AI Act
    R("euaia.art4", "eu_ai_act", "Art. 4", "AI literacy of staff dealing with AI systems", attest=True),
    R("euaia.art5", "eu_ai_act", "Art. 5", "No prohibited AI practice in use",
      check="no_unacceptable_in_production", fix="/inventory"),
    R("euaia.art6", "eu_ai_act", "Art. 6, Annex III", "Every AI system classified, risk tier confirmed by a person",
      check="inventory_classified", fix="/inventory"),
    R("euaia.art9", "eu_ai_act", "Art. 9", "Risk management for the high-risk system",
      check="sys_risk_confirmed", scope="system", applies="high_risk", fix="/inventory"),
    R("euaia.art10", "eu_ai_act", "Art. 10", "Data and data governance documented",
      check="sys_data_documented", scope="system", applies="high_risk", fix="/inventory"),
    R("euaia.art11", "eu_ai_act", "Art. 11, Annex IV", "Technical documentation",
      attest=True, scope="system", applies="high_risk"),
    R("euaia.art12", "eu_ai_act", "Art. 12", "Automatic recording of events (logs)",
      check="sys_logged", scope="system", applies="high_risk", fix="/audit"),
    R("euaia.art13", "eu_ai_act", "Art. 13", "Instructions for use / transparency to deployers",
      attest=True, scope="system", applies="high_risk"),
    R("euaia.art14", "eu_ai_act", "Art. 14", "Human oversight",
      check="sys_human_oversight", attest=True, scope="system", applies="high_risk", fix="/agent-approvals"),
    R("euaia.art15", "eu_ai_act", "Art. 15", "Accuracy, robustness and cybersecurity",
      check="sys_robustness", scope="system", applies="high_risk", fix="/agent-injection"),
    R("euaia.art17", "eu_ai_act", "Art. 17", "Quality management system", attest=True),
    R("euaia.art26", "eu_ai_act", "Art. 26", "Deployer obligations: named owner, monitoring, logs kept",
      check="owners_and_monitoring", fix="/inventory"),
    R("euaia.art50", "eu_ai_act", "Art. 50", "Transparency: people know they interact with AI / AI-generated content",
      attest=True),
    R("euaia.art72", "eu_ai_act", "Art. 72", "Post-market monitoring",
      check="monitoring_active", fix="/agent-behavior"),
    R("euaia.art73", "eu_ai_act", "Art. 73", "Serious incidents tracked and reported",
      check="incidents_handled", attest=True, fix="/agent-incidents"),

    # ------------------------------------------------------------------ GDPR
    R("gdpr.art5_1c", "gdpr", "Art. 5(1)(c)", "Data minimisation: personal data masked before it reaches a model",
      check="pii_masking"),
    R("gdpr.art5_1e", "gdpr", "Art. 5(1)(e)", "Storage limitation: raw prompts are not kept forever",
      check="prompt_retention", fix="/queue-ttl"),
    R("gdpr.art17", "gdpr", "Art. 17", "Right to erasure: data can be made unreadable on request",
      check="erasure_capability", fix="/encryption-keys"),
    R("gdpr.art22", "gdpr", "Art. 22", "Automated decisions: a human can intervene",
      check="human_intervention", fix="/agent-approvals"),
    R("gdpr.art25", "gdpr", "Art. 25", "Data protection by design and by default",
      check="privacy_by_design", fix="/agent-memory"),
    R("gdpr.art30", "gdpr", "Art. 30", "Records of processing: AI systems with personal data documented",
      check="pii_systems_documented", fix="/inventory"),
    R("gdpr.art32", "gdpr", "Art. 32", "Security of processing: encryption, access control",
      check="security_of_processing", fix="/encryption-keys"),
    R("gdpr.art33", "gdpr", "Art. 33-34", "Personal data breach notification procedure", attest=True),
    R("gdpr.art35", "gdpr", "Art. 35", "Data protection impact assessment (DPIA)",
      attest=True, scope="system", applies="pii"),

    # ------------------------------------------------------------------ ISO/IEC 42001 Annex A
    R("iso.a2", "iso42001", "A.2", "AI policy", check="ai_policies", attest=True, fix="/policies"),
    R("iso.a3", "iso42001", "A.3", "Roles and responsibilities for AI systems", check="owners_assigned", fix="/inventory"),
    R("iso.a4", "iso42001", "A.4", "Resources for AI systems documented (data, tools)",
      check="resources_documented", fix="/inventory"),
    R("iso.a5", "iso42001", "A.5", "AI system impact assessment", check="inventory_classified", fix="/inventory"),
    R("iso.a6", "iso42001", "A.6", "AI system life cycle managed", check="lifecycle_managed", fix="/inventory"),
    R("iso.a6_2_8", "iso42001", "A.6.2.8", "AI system event logs", check="audit_active", fix="/audit"),
    R("iso.a7", "iso42001", "A.7", "Data for AI systems: provenance and quality",
      check="resources_documented", fix="/inventory"),
    R("iso.a8", "iso42001", "A.8", "Information for interested parties", attest=True),
    R("iso.a9", "iso42001", "A.9", "Responsible use: intended use defined", check="use_cases_linked", fix="/inventory"),
    R("iso.a10", "iso42001", "A.10", "Third-party and supplier relationships",
      check="third_parties_governed", fix="/tool-registry"),

    # ------------------------------------------------------------------ NIST AI RMF
    R("nist.govern1", "nist_ai_rmf", "GOVERN 1", "Policies and procedures for AI risk", check="ai_policies", fix="/policies"),
    R("nist.govern2", "nist_ai_rmf", "GOVERN 2", "Accountability: named owners", check="owners_assigned", fix="/inventory"),
    R("nist.map1", "nist_ai_rmf", "MAP 1", "Context and intended use established", check="use_cases_linked", fix="/inventory"),
    R("nist.map4", "nist_ai_rmf", "MAP 2-4", "Systems categorized, risks identified", check="inventory_classified", fix="/inventory"),
    R("nist.measure2", "nist_ai_rmf", "MEASURE 2", "Systems evaluated and monitored in use", check="monitoring_active", fix="/agent-behavior"),
    R("nist.measure3", "nist_ai_rmf", "MEASURE 3", "Risks tracked over time (incidents)", check="incidents_handled", fix="/agent-incidents"),
    R("nist.manage1", "nist_ai_rmf", "MANAGE 1-2", "Risk responses: approval, containment", check="containment", fix="/agent-breaker"),
    R("nist.manage4", "nist_ai_rmf", "MANAGE 4", "Systems can be deactivated", check="deactivation", fix="/inventory"),

    # ------------------------------------------------------------------ OWASP Agentic Top 10
    R("asi01", "owasp_agentic", "ASI01", "Agent goal hijack (prompt injection)", check="mode:injection", fix="/agent-injection"),
    R("asi02", "owasp_agentic", "ASI02", "Tool misuse (argument constraints)", check="argument_rules", fix="/agent-policies"),
    R("asi03", "owasp_agentic", "ASI03", "Identity and privilege abuse", check="agent_identity", fix="/agent-identity"),
    R("asi04", "owasp_agentic", "ASI04", "Agentic supply chain", check="tool_registry", fix="/tool-registry"),
    R("asi05", "owasp_agentic", "ASI05", "Unexpected code execution", check="mode:code_exec", fix="/agent-code-exec"),
    R("asi06", "owasp_agentic", "ASI06", "Memory and context poisoning", check="mode:memory", fix="/agent-memory"),
    R("asi07", "owasp_agentic", "ASI07", "Insecure inter-agent communication", check="mode:a2a", fix="/agent-messages"),
    R("asi08", "owasp_agentic", "ASI08", "Cascading failures", check="breaker", fix="/agent-breaker"),
    R("asi09", "owasp_agentic", "ASI09", "Human-agent trust exploitation", check="approvals", fix="/agent-approvals"),
    R("asi10", "owasp_agentic", "ASI10", "Rogue agents", check="mode:behavior", fix="/agent-behavior"),
]

BY_ID = {r["id"]: r for r in REQUIREMENTS}
assert len(BY_ID) == len(REQUIREMENTS), "duplicate requirement id"
