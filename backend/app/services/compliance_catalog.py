# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
Compliance catalog: requirements of EU AI Act, GDPR, ISO/IEC 42001, NIST AI
RMF, OWASP Top 10 for Agentic Applications and for LLM Applications, MITRE
ATLAS mitigations, NIS2 and DORA, each mapped to the Provenza evidence that
supports it. NIS2 and DORA cover far more than AI; only what applies to AI
systems is listed, and a person confirms the rest of the organization.

  check      name of an automatic check in compliance_engine.CHECKS, or None
  attest     True when a person must state it (documents, procedures...);
             with a check as well, the check is shown as supporting evidence
  scope      "org"     evaluated once for the organization
             "system"  evaluated for every AI system it applies to
  applies    for scope=system: "all", "high_risk", "pii", "agents"
  roles      EU AI Act only: the operator roles (Art. 3) the obligation is
             addressed to - provider, deployer, importer, distributor. An AI
             system takes part only where it is one of them; a system whose
             roles are not stated takes part everywhere. None: everyone.
  fix        the page where a gap is closed

The references are short pointers for orientation, not legal advice; the
organization stays responsible for its own interpretation.
"""

from typing import Dict, List

CATALOG_VERSION = "2026.12"

FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "eu_ai_act": {"name": "EU AI Act", "ref": "Regulation (EU) 2024/1689"},
    "gdpr": {"name": "GDPR", "ref": "Regulation (EU) 2016/679"},
    "iso42001": {"name": "ISO/IEC 42001", "ref": "ISO/IEC 42001:2023, Annex A"},
    "nist_ai_rmf": {"name": "NIST AI RMF", "ref": "NIST AI 100-1"},
    "owasp_agentic": {"name": "OWASP Agentic Top 10", "ref": "OWASP Top 10 for Agentic Applications"},
    "owasp_llm": {"name": "OWASP LLM Top 10", "ref": "OWASP Top 10 for LLM Applications 2025"},
    "mitre_atlas": {"name": "MITRE ATLAS", "ref": "MITRE ATLAS mitigations"},
    "nis2": {"name": "NIS2", "ref": "Directive (EU) 2022/2555, Art. 21 and 23 - as they apply to AI systems"},
    "dora": {"name": "DORA", "ref": "Regulation (EU) 2022/2554 - as it applies to AI systems"},
}


PROVIDER = ("provider",)
DEPLOYER = ("deployer",)
BOTH = ("provider", "deployer")


def R(id, framework, ref, title, *, check=None, attest=False, scope="org", applies="all", fix=None, roles=None):
    return {"id": id, "framework": framework, "ref": ref, "title": title, "check": check, "attest": attest,
            "scope": scope, "applies": applies, "fix": fix, "roles": list(roles) if roles else None}


REQUIREMENTS: List[dict] = [
    # ------------------------------------------------------------------ EU AI Act
    R("euaia.art4", "eu_ai_act", "Art. 4", "AI literacy of staff dealing with AI systems", attest=True),
    R("euaia.art5", "eu_ai_act", "Art. 5", "No prohibited AI practice in use",
      check="no_unacceptable_in_production", fix="/inventory"),
    R("euaia.art6", "eu_ai_act", "Art. 6, Annex III", "Every AI system classified, risk tier confirmed by a person",
      check="inventory_classified", fix="/inventory"),
    R("euaia.art3", "eu_ai_act", "Art. 3, 16, 23-26", "Our role (provider, deployer, importer, distributor) stated for every AI system",
      check="ai_act_roles_stated", fix="/inventory"),
    R("euaia.art9", "eu_ai_act", "Art. 9", "Risk management for the high-risk system",
      check="sys_risk_confirmed", scope="system", applies="high_risk", fix="/inventory", roles=PROVIDER),
    R("euaia.art10", "eu_ai_act", "Art. 10", "Data and data governance documented",
      check="sys_data_and_bias", scope="system", applies="high_risk", fix="/inventory", roles=PROVIDER),
    R("euaia.art11", "eu_ai_act", "Art. 11, Annex IV", "Technical documentation",
      attest=True, scope="system", applies="high_risk", roles=PROVIDER),
    R("euaia.art12", "eu_ai_act", "Art. 12", "Automatic recording of events (logs)",
      check="sys_logged", scope="system", applies="high_risk", fix="/audit", roles=BOTH),
    R("euaia.art13", "eu_ai_act", "Art. 13", "Instructions for use / transparency to deployers",
      attest=True, scope="system", applies="high_risk", roles=PROVIDER),
    R("euaia.art14", "eu_ai_act", "Art. 14", "Human oversight",
      check="sys_human_oversight", attest=True, scope="system", applies="high_risk", fix="/agent-approvals",
      roles=BOTH),
    R("euaia.art15", "eu_ai_act", "Art. 15", "Accuracy, robustness and cybersecurity",
      check="sys_assurance", scope="system", applies="high_risk", fix="/inventory", roles=PROVIDER),
    R("euaia.art17", "eu_ai_act", "Art. 17", "Quality management system", attest=True, roles=PROVIDER),
    R("euaia.art23", "eu_ai_act", "Art. 23", "Importer: conformity assessment, technical documentation and CE marking checked",
      attest=True, scope="system", applies="high_risk", roles=("importer",)),
    R("euaia.art24", "eu_ai_act", "Art. 24", "Distributor: CE marking, declaration and instructions checked",
      attest=True, scope="system", applies="high_risk", roles=("distributor",)),
    R("euaia.art26", "eu_ai_act", "Art. 26", "Deployer obligations: named owner, monitoring, logs kept",
      check="owners_and_monitoring", fix="/inventory", roles=DEPLOYER),
    R("euaia.art27", "eu_ai_act", "Art. 27", "Fundamental rights impact assessment (public bodies, credit scoring, insurance)",
      check="sys_impact_assessed", scope="system", applies="high_risk", fix="/inventory", roles=DEPLOYER),
    R("euaia.art50", "eu_ai_act", "Art. 50", "Transparency: people know they interact with AI / AI-generated content",
      attest=True, roles=BOTH),
    R("euaia.art72", "eu_ai_act", "Art. 72", "Post-market monitoring",
      check="monitoring_active", fix="/agent-behavior", roles=PROVIDER),
    R("euaia.art73", "eu_ai_act", "Art. 73", "Serious incidents tracked and reported",
      check="incidents_handled", attest=True, fix="/agent-incidents", roles=BOTH),

    # ------------------------------------------------------------------ GDPR
    R("gdpr.art5_1c", "gdpr", "Art. 5(1)(c)", "Data minimisation: only the personal data needed reaches a model",
      attest=True),
    R("gdpr.art5_1e", "gdpr", "Art. 5(1)(e)", "Storage limitation: what agents sent and got back is not kept forever",
      check="content_retention", fix="/retention"),
    R("gdpr.art17", "gdpr", "Art. 17", "Right to erasure: data can be made unreadable on request",
      check="erasure_capability", fix="/encryption-keys"),
    R("gdpr.art22", "gdpr", "Art. 22", "Automated decisions: a human can intervene",
      check="human_intervention", fix="/agent-approvals"),
    R("gdpr.art25", "gdpr", "Art. 25", "Data protection by design and by default",
      check="privacy_by_design", fix="/retention"),
    R("gdpr.art30", "gdpr", "Art. 30", "Records of processing: AI systems with personal data documented",
      check="pii_systems_documented", fix="/inventory"),
    R("gdpr.art32", "gdpr", "Art. 32", "Security of processing: encryption, access control",
      check="security_of_processing", fix="/encryption-keys"),
    R("gdpr.art33", "gdpr", "Art. 33-34", "Personal data breach notification procedure", attest=True),
    R("gdpr.art35", "gdpr", "Art. 35", "Data protection impact assessment (DPIA)",
      check="sys_dpia", scope="system", applies="pii", fix="/inventory"),

    # ------------------------------------------------------------------ ISO/IEC 42001 Annex A
    R("iso.a2", "iso42001", "A.2", "AI policy", check="ai_policies", attest=True, fix="/policy-hierarchy"),
    R("iso.a3", "iso42001", "A.3", "Roles and responsibilities for AI systems", check="owners_assigned", fix="/inventory"),
    R("iso.a4", "iso42001", "A.4", "Resources for AI systems documented (data, tools)",
      check="resources_documented", fix="/inventory"),
    R("iso.a5", "iso42001", "A.5", "AI system impact assessment", check="impact_assessed", fix="/inventory"),
    R("iso.a6", "iso42001", "A.6", "AI system life cycle managed", check="lifecycle_managed", fix="/inventory"),
    R("iso.a6_2_4", "iso42001", "A.6.2.4", "Verification and validation: AI systems tested",
      check="assurance_tested", fix="/inventory"),
    R("iso.a6_2_8", "iso42001", "A.6.2.8", "AI system event logs", check="audit_active", fix="/audit"),
    R("iso.a7", "iso42001", "A.7", "Data for AI systems: provenance and quality",
      check="resources_documented", fix="/inventory"),
    R("iso.a8", "iso42001", "A.8", "Information for interested parties", attest=True),
    R("iso.a9", "iso42001", "A.9", "Responsible use: intended use defined", check="use_cases_linked", fix="/inventory"),
    R("iso.a10", "iso42001", "A.10", "Third-party and supplier relationships",
      check="third_parties_governed", fix="/tool-registry"),

    # ------------------------------------------------------------------ NIST AI RMF
    R("nist.govern1", "nist_ai_rmf", "GOVERN 1", "Policies and procedures for AI risk", check="ai_policies", fix="/policy-hierarchy"),
    R("nist.govern2", "nist_ai_rmf", "GOVERN 2", "Accountability: named owners", check="owners_assigned", fix="/inventory"),
    R("nist.map1", "nist_ai_rmf", "MAP 1", "Context and intended use established", check="use_cases_linked", fix="/inventory"),
    R("nist.map4", "nist_ai_rmf", "MAP 2-4", "Systems categorized, risks identified", check="inventory_classified", fix="/inventory"),
    R("nist.measure1", "nist_ai_rmf", "MEASURE 1", "Methods and metrics: systems tested (evaluation, bias, red teaming)",
      check="assurance_tested", fix="/inventory"),
    R("nist.measure2", "nist_ai_rmf", "MEASURE 2", "Systems evaluated and monitored in use", check="monitoring_active", fix="/agent-behavior"),
    R("nist.measure3", "nist_ai_rmf", "MEASURE 3", "Risks tracked over time (incidents)", check="incidents_handled", fix="/agent-incidents"),
    R("nist.manage1", "nist_ai_rmf", "MANAGE 1-2", "Risk responses: approval, containment", check="containment", fix="/agent-breaker"),
    R("nist.manage4", "nist_ai_rmf", "MANAGE 4", "Systems can be deactivated", check="deactivation", fix="/inventory"),

    # ------------------------------------------------------------------ OWASP Agentic Top 10
    R("asi01", "owasp_agentic", "ASI01", "Agent goal hijack (prompt injection)", attest=True),
    R("asi02", "owasp_agentic", "ASI02", "Tool misuse (argument constraints)", check="argument_rules", fix="/agent-policies"),
    R("asi03", "owasp_agentic", "ASI03", "Identity and privilege abuse", check="agent_identity", fix="/agent-identity"),
    R("asi04", "owasp_agentic", "ASI04", "Agentic supply chain", check="tool_registry", fix="/tool-registry"),
    R("asi05", "owasp_agentic", "ASI05", "Unexpected code execution", attest=True),
    R("asi06", "owasp_agentic", "ASI06", "Memory and context poisoning", attest=True),
    R("asi07", "owasp_agentic", "ASI07", "Insecure inter-agent communication", attest=True),
    R("asi08", "owasp_agentic", "ASI08", "Cascading failures", check="breaker", fix="/agent-breaker"),
    R("asi09", "owasp_agentic", "ASI09", "Human-agent trust exploitation", check="approvals", fix="/agent-approvals"),
    R("asi10", "owasp_agentic", "ASI10", "Rogue agents", check="mode:behavior", fix="/agent-behavior"),

    # ------------------------------------------------------------------ OWASP LLM Top 10 (2025)
    R("llm01", "owasp_llm", "LLM01", "Prompt injection: risky actions need a person, systems tested against misuse",
      check="injection_defenses", fix="/agent-approvals"),
    R("llm02", "owasp_llm", "LLM02", "Sensitive information disclosure", attest=True),
    R("llm03", "owasp_llm", "LLM03", "Supply chain: models, tools and providers governed",
      check="third_parties_governed", fix="/tool-registry"),
    R("llm04", "owasp_llm", "LLM04", "Data and model poisoning: data sources documented",
      check="resources_documented", attest=True, fix="/inventory"),
    R("llm05", "owasp_llm", "LLM05", "Improper output handling: outputs validated before use", attest=True),
    R("llm06", "owasp_llm", "LLM06", "Excessive agency: least privilege for agents' tools",
      check="argument_rules", fix="/agent-policies"),
    R("llm07", "owasp_llm", "LLM07", "System prompt leakage: no secrets or rules only in the prompt", attest=True),
    R("llm08", "owasp_llm", "LLM08", "Vector and embedding weaknesses: access to retrieval data controlled", attest=True),
    R("llm09", "owasp_llm", "LLM09", "Misinformation: outputs evaluated, people oversee",
      check="assurance_tested", fix="/inventory"),
    R("llm10", "owasp_llm", "LLM10", "Unbounded consumption: requests and tokens capped",
      check="consumption_limits", fix="/gateway"),

    # ------------------------------------------------------------------ MITRE ATLAS mitigations
    R("atlas.m0000", "mitre_atlas", "AML.M0000", "Limit release of public information about the AI systems", attest=True),
    R("atlas.m0003", "mitre_atlas", "AML.M0003", "Model hardening: tested against adversarial input",
      check="assurance_tested", fix="/inventory"),
    R("atlas.m0004", "mitre_atlas", "AML.M0004", "Restrict the number of model queries",
      check="consumption_limits", fix="/gateway"),
    R("atlas.m0005", "mitre_atlas", "AML.M0005", "Control access to models and data at rest",
      check="security_of_processing", fix="/encryption-keys"),
    R("atlas.m0007", "mitre_atlas", "AML.M0007", "Sanitize training data", attest=True),
    R("atlas.m0008", "mitre_atlas", "AML.M0008", "Validate the model", check="assurance_tested", fix="/inventory"),
    R("atlas.m0012", "mitre_atlas", "AML.M0012", "Encrypt sensitive information",
      check="security_of_processing", fix="/encryption-keys"),
    R("atlas.m0014", "mitre_atlas", "AML.M0014", "Verify AI artifacts and tools before use",
      check="tool_registry", fix="/tool-registry"),
    R("atlas.m0016", "mitre_atlas", "AML.M0016", "Vulnerability scanning of AI artifacts", attest=True),
    R("atlas.m0018", "mitre_atlas", "AML.M0018", "User training", attest=True),

    # ------------------------------------------------------------------ NIS2 (for AI systems)
    R("nis2.21a", "nis2", "Art. 21(2)(a)", "Risk analysis and security policies cover AI systems",
      check="ai_policies", attest=True, fix="/policy-hierarchy"),
    R("nis2.21b", "nis2", "Art. 21(2)(b)", "Incident handling", check="incidents_handled", fix="/incidents"),
    R("nis2.21c", "nis2", "Art. 21(2)(c)", "Business continuity: AI systems can be stopped and replaced",
      check="deactivation", attest=True, fix="/kill-switch"),
    R("nis2.21d", "nis2", "Art. 21(2)(d)", "Supply chain security: AI providers and tools governed",
      check="third_parties_governed", fix="/tool-registry"),
    R("nis2.21e", "nis2", "Art. 21(2)(e)", "Security in development and maintenance: AI systems tested",
      check="assurance_tested", fix="/inventory"),
    R("nis2.21g", "nis2", "Art. 21(2)(g)", "Cyber hygiene and training", attest=True),
    R("nis2.21h", "nis2", "Art. 21(2)(h)", "Cryptography and encryption", check="security_of_processing",
      fix="/encryption-keys"),
    R("nis2.21i", "nis2", "Art. 21(2)(i)", "Access control and asset management: AI systems inventoried with owners",
      check="owners_assigned", fix="/inventory"),
    R("nis2.21j", "nis2", "Art. 21(2)(j)", "Multi-factor authentication", check="mfa_enforced", fix="/users"),
    R("nis2.23", "nis2", "Art. 23", "Significant incidents reported: early warning in 24 h, notification in 72 h",
      check="incidents_handled", attest=True, fix="/incidents"),

    # ------------------------------------------------------------------ DORA (for AI systems)
    R("dora.6", "dora", "Art. 6", "ICT risk management framework covers AI systems",
      check="ai_policies", attest=True, fix="/policy-hierarchy"),
    R("dora.8", "dora", "Art. 8", "Identification: AI systems inventoried and classified",
      check="inventory_classified", fix="/inventory"),
    R("dora.9", "dora", "Art. 9", "Protection and prevention", check="security_of_processing", fix="/encryption-keys"),
    R("dora.10", "dora", "Art. 10", "Detection of anomalous activity", check="monitoring_active", fix="/agent-behavior"),
    R("dora.11", "dora", "Art. 11", "Response and recovery: AI systems can be contained and stopped",
      check="deactivation", fix="/kill-switch"),
    R("dora.17", "dora", "Art. 17", "ICT incident management", check="incidents_handled", fix="/incidents"),
    R("dora.19", "dora", "Art. 19", "Major ICT incidents reported", attest=True),
    R("dora.24", "dora", "Art. 24-25", "Digital operational resilience testing of AI systems",
      check="assurance_tested", fix="/inventory"),
    R("dora.28", "dora", "Art. 28", "ICT third-party risk: AI providers governed",
      check="third_parties_governed", fix="/tool-registry"),
]

BY_ID = {r["id"]: r for r in REQUIREMENTS}
assert len(BY_ID) == len(REQUIREMENTS), "duplicate requirement id"
