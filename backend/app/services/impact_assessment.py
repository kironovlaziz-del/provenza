# Copyright (c) 2026 Laziz Kironov
# Licensed under the Apache License, Version 2.0.
# Part of Provenza - https://github.com/kironovlaziz-del/provenza

"""
The impact assessment of an AI system: one questionnaire that covers

  ISO/IEC 42005   AI system impact assessment (context, affected people,
                  impacts, measures, conclusion)
  GDPR Art. 35    data protection impact assessment, in its personal data
                  section
  EU AI Act 27    fundamental rights impact assessment of a deployer:
                  process, period, affected groups, risks of harm, human
                  oversight, measures and complaints
  NIST AI RMF     MAP 1 (context) and MAP 5 (impacts)

The labels here are the English defaults; the UI translates them by id
(ia.q.<id>, ia.o.<option>). A question with required_if is required only
when another answer has that value.
"""

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, List, Optional

TEMPLATE_VERSION = "2026.11"

# How long an approval holds when no review date is given.
DEFAULT_REVIEW = timedelta(days=365)


def Q(id, label, type="text", *, options=None, required=True, required_if=None, help=None):
    return {"id": id, "label": label, "type": type, "options": options or [], "required": required,
            "required_if": required_if, "help": help}


TEMPLATE: List[Dict[str, Any]] = [
    {"id": "purpose", "title": "Purpose and context", "refs": ["ISO/IEC 42005", "NIST MAP 1", "AI Act 27(1)(a)(b)"],
     "questions": [
         Q("purpose", "What is the system for, and in which process is it used?"),
         Q("affected", "Who is affected by its outputs?", "multi",
           options=["employees", "job_applicants", "customers", "patients", "students", "children", "public", "other"]),
         Q("scale", "How many people does it affect in a year?", "choice",
           options=["under_100", "100_10k", "10k_1m", "over_1m"]),
         Q("period", "When and how often is it used?", required=False),
     ]},
    {"id": "rights", "title": "Impact on people", "refs": ["AI Act 27(1)(c)(d)", "ISO/IEC 42005", "NIST MAP 5"],
     "questions": [
         Q("rights", "Which rights or interests could be harmed?", "multi",
           options=["non_discrimination", "privacy", "expression", "access_services", "employment", "education",
                    "health_safety", "due_process", "none"]),
         Q("harm", "What could go wrong for these people, and how?"),
         Q("severity", "How severe would the harm be?", "choice", options=["low", "medium", "high", "critical"]),
         Q("likelihood", "How likely is it?", "choice", options=["rare", "possible", "likely"]),
         Q("reversibility", "Can the harm be undone?", "choice",
           options=["reversible", "hard_to_reverse", "irreversible"]),
     ]},
    {"id": "data", "title": "Personal data (DPIA)", "refs": ["GDPR Art. 35"],
     "questions": [
         Q("personal_data", "Does the system process personal data?", "choice", options=["yes", "no"]),
         Q("categories", "Which kinds?", "multi", required=False, required_if={"personal_data": "yes"},
           options=["identity", "contact", "financial", "location", "behaviour", "special", "children", "criminal"]),
         Q("lawful_basis", "Lawful basis (GDPR Art. 6)", "choice", required=False, required_if={"personal_data": "yes"},
           options=["consent", "contract", "legal_obligation", "vital_interest", "public_task", "legitimate_interest"]),
         Q("necessity", "Why is this data necessary, and what is left out?", required=False,
           required_if={"personal_data": "yes"}),
         Q("retention", "How long is it kept?", required=False, required_if={"personal_data": "yes"}),
         Q("transfers", "Does it leave the EU/EEA?", "choice", required=False, required_if={"personal_data": "yes"},
           options=["no", "adequacy", "safeguards"]),
     ]},
    {"id": "measures", "title": "Measures", "refs": ["ISO/IEC 23894", "NIST MANAGE 1", "AI Act 9, 14, 27(1)(e)(f)"],
     "questions": [
         Q("measures", "What reduces these risks? (testing, limits, policies in Provenza, training)"),
         Q("oversight", "Who oversees the system and can stop or overrule it?"),
         Q("redress", "How can an affected person complain or contest a decision?"),
     ]},
    {"id": "conclusion", "title": "Conclusion", "refs": ["ISO/IEC 42005"],
     "questions": [
         Q("residual", "Residual risk after the measures", "choice", options=["low", "medium", "high"]),
         Q("decision", "Decision", "choice", options=["proceed", "proceed_with_conditions", "do_not_proceed"]),
         Q("conditions", "Conditions", required=False, required_if={"decision": "proceed_with_conditions"}),
         Q("review_date", "Review again by", "date", required=False,
           help="One year from approval when left empty."),
     ]},
]

QUESTIONS: Dict[str, Dict[str, Any]] = {q["id"]: q for s in TEMPLATE for q in s["questions"]}


def _filled(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, list):
        return bool(v)
    return True


def clean(answers: Dict[str, Any]) -> Dict[str, Any]:
    """Keep known questions with values of their type; options must be
    known. Raises ValueError with the question id on a wrong value."""
    out: Dict[str, Any] = {}
    for qid, v in (answers or {}).items():
        q = QUESTIONS.get(qid)
        if q is None or v is None or v == "" or v == []:
            continue
        t = q["type"]
        if t == "text":
            if not isinstance(v, str) or len(v) > 10_000:
                raise ValueError(qid)
            out[qid] = v
        elif t == "choice":
            if v not in q["options"]:
                raise ValueError(qid)
            out[qid] = v
        elif t == "multi":
            if not isinstance(v, list) or any(x not in q["options"] for x in v):
                raise ValueError(qid)
            out[qid] = [o for o in q["options"] if o in set(v)]
        elif t == "date":
            try:
                date.fromisoformat(v)
            except (TypeError, ValueError):
                raise ValueError(qid)
            out[qid] = v
    return out


def missing(answers: Dict[str, Any]) -> List[str]:
    """Required questions without an answer, in template order."""
    out = []
    for s in TEMPLATE:
        for q in s["questions"]:
            need = q["required"] or (q["required_if"] and all(
                answers.get(k) == v for k, v in q["required_if"].items()))
            if need and not _filled(answers.get(q["id"])):
                out.append(q["id"])
    return out


def review_due(answers: Dict[str, Any], approved_at: datetime) -> datetime:
    d = answers.get("review_date")
    if d:
        return datetime.combine(date.fromisoformat(d), time(23, 59, 59), tzinfo=timezone.utc)
    return approved_at + DEFAULT_REVIEW


def summary(a) -> Optional[Dict[str, Any]]:
    if a is None:
        return None
    ans = a.answers or {}
    return {"id": a.id, "version": a.version, "status": a.status, "template_version": a.template_version,
            "residual": ans.get("residual"), "decision": ans.get("decision"),
            "personal_data": ans.get("personal_data"),
            "created_at": a.created_at, "updated_at": a.updated_at, "approved_by": a.approved_by,
            "approved_at": a.approved_at, "review_due": a.review_due}
