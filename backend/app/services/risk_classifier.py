# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza — https://github.com/kironovlaziz-del/provenza

"""
EU AI Act risk-tier SUGGESTION for an AI system, derived from its declared
domain and flags. Pure and DB-free so it can be unit-tested exhaustively.

This is decision support, not a legal determination: a tier becomes
authoritative only when a human confirms it (see InventoryService).
Article references follow Regulation (EU) 2024/1689.
"""

from dataclasses import dataclass, field
from typing import Iterable, List

ENGINE_VERSION = "2026-09"

TIERS = ("unacceptable", "high", "limited", "minimal")
_SEVERITY = {t: i for i, t in enumerate(TIERS)}  # lower = more severe

DOMAINS = {
    "general": "General purpose / internal productivity",
    "customer_service": "Customer service and support",
    "marketing": "Marketing and content",
    "software_engineering": "Software engineering",
    "healthcare": "Healthcare",
    "finance": "Finance (other than creditworthiness of persons)",
    "biometrics": "Biometrics",
    "critical_infrastructure": "Critical infrastructure",
    "education": "Education and vocational training",
    "employment": "Employment, HR and workers management",
    "essential_services": "Access to essential private and public services",
    "law_enforcement": "Law enforcement",
    "migration": "Migration, asylum and border control",
    "justice_democracy": "Administration of justice and democratic processes",
}

ANNEX_III = {
    "biometrics": "Annex III(1) - biometrics",
    "critical_infrastructure": "Annex III(2) - critical infrastructure",
    "education": "Annex III(3) - education and vocational training",
    "employment": "Annex III(4) - employment, workers management and access to self-employment",
    "essential_services": "Annex III(5) - access to essential private and public services and benefits "
                          "(e.g. creditworthiness, life/health insurance pricing, public benefits, emergency dispatch)",
    "law_enforcement": "Annex III(6) - law enforcement",
    "migration": "Annex III(7) - migration, asylum and border control management",
    "justice_democracy": "Annex III(8) - administration of justice and democratic processes",
}

PROHIBITED_FLAGS = {
    "manipulative_techniques": "Art. 5(1)(a) - subliminal, manipulative or deceptive techniques causing significant harm",
    "exploits_vulnerabilities": "Art. 5(1)(b) - exploiting vulnerabilities due to age, disability or social/economic situation",
    "social_scoring": "Art. 5(1)(c) - social scoring leading to detrimental or unfavourable treatment",
    "criminal_risk_profiling": "Art. 5(1)(d) - predicting criminal offences based solely on profiling or personality traits",
    "untargeted_face_scraping": "Art. 5(1)(e) - untargeted scraping of facial images to build recognition databases",
    "emotion_recognition_workplace_education": "Art. 5(1)(f) - emotion recognition in the workplace or in education",
    "biometric_categorisation_sensitive": "Art. 5(1)(g) - biometric categorisation inferring sensitive attributes",
    "realtime_remote_biometric_id_public": "Art. 5(1)(h) - real-time remote biometric identification in public spaces for law enforcement",
}

SAFETY_FLAGS = {
    "safety_component": "Art. 6(1) and Annex I - safety component of, or itself, a product covered by EU "
                        "harmonisation legislation requiring third-party conformity assessment (e.g. a medical device)",
}

TRANSPARENCY_FLAGS = {
    "interacts_with_humans": "Art. 50(1) - people must be informed that they are interacting with an AI system",
    "generates_synthetic_content": "Art. 50(2) - synthetic audio, image, video or text must be marked as AI-generated",
    "emotion_recognition": "Art. 50(3) - persons exposed to emotion recognition or biometric categorisation must be informed",
    "deepfake": "Art. 50(4) - deep fakes must be disclosed as artificially generated or manipulated",
}

MODIFIER_FLAGS = {
    "profiles_natural_persons": "The system performs profiling of natural persons",
    "narrow_procedural_task": "The system only performs a narrow procedural or preparatory task",
}

FLAGS = {**PROHIBITED_FLAGS, **SAFETY_FLAGS, **TRANSPARENCY_FLAGS, **MODIFIER_FLAGS}


@dataclass
class Classification:
    tier: str
    rationale: List[dict] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "tier": self.tier,
            "rationale": self.rationale,
            "notes": self.notes,
            "engine_version": ENGINE_VERSION,
        }


def validate(domain: str, flags: Iterable[str]) -> None:
    if domain not in DOMAINS:
        raise ValueError(f"unknown domain: {domain}")
    unknown = sorted(set(flags) - set(FLAGS))
    if unknown:
        raise ValueError(f"unknown risk flags: {', '.join(unknown)}")


def classify(domain: str, flags: Iterable[str]) -> Classification:
    flags = set(flags or [])
    validate(domain, flags)
    rationale: List[dict] = []
    notes: List[str] = []

    def add(tier: str, reference: str) -> None:
        rationale.append({"tier": tier, "reference": reference})

    for f in sorted(flags & PROHIBITED_FLAGS.keys()):
        add("unacceptable", PROHIBITED_FLAGS[f])

    if "safety_component" in flags:
        add("high", SAFETY_FLAGS["safety_component"])

    if domain in ANNEX_III:
        add("high", ANNEX_III[domain])
        if "narrow_procedural_task" in flags:
            if "profiles_natural_persons" in flags:
                notes.append("The Art. 6(3) derogation is not available: the system profiles natural "
                             "persons, so it remains high-risk.")
            else:
                notes.append("Art. 6(3) may exempt a system that only performs a narrow procedural task; "
                             "the provider must document that assessment before treating it as not high-risk.")

    for f in sorted(flags & TRANSPARENCY_FLAGS.keys()):
        add("limited", TRANSPARENCY_FLAGS[f])

    if domain == "healthcare" and "safety_component" not in flags:
        notes.append("If the system is, or is part of, a medical device under MDR/IVDR, set "
                     "'safety_component': it is then high-risk under Art. 6(1).")
    if domain == "finance":
        notes.append("Creditworthiness of natural persons and life/health insurance pricing belong to "
                     "'essential_services' (Annex III(5)).")
    if "profiles_natural_persons" in flags and domain not in ANNEX_III:
        notes.append("Profiling of natural persons: check whether the use falls under an Annex III area; "
                     "GDPR Art. 22 may apply to automated decisions.")

    if rationale:
        tier = min((r["tier"] for r in rationale), key=_SEVERITY.__getitem__)
    else:
        tier = "minimal"
        add("minimal", "No Art. 5, Art. 6(1)/Annex I, Annex III or Art. 50 trigger declared")

    if tier == "high" and any(r["tier"] == "limited" for r in rationale):
        notes.append("Art. 50 transparency obligations apply in addition to the high-risk requirements.")
    notes.append("Suggestion only, not legal advice: a human must confirm the tier.")
    return Classification(tier, rationale, notes)
