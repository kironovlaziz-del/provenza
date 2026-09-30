"""
Unit tests for the EU AI Act risk-tier suggestion engine (pure function).
"""

import pytest

from app.services.risk_classifier import classify


def _refs(result):
    return " | ".join(r["reference"] for r in result.rationale)


class TestTiers:
    def test_no_triggers_is_minimal(self):
        r = classify("general", [])
        assert r.tier == "minimal"

    def test_annex_iii_domain_is_high(self):
        r = classify("employment", [])
        assert r.tier == "high"
        assert "Annex III(4)" in _refs(r)

    @pytest.mark.parametrize("domain", [
        "biometrics", "critical_infrastructure", "education", "employment",
        "essential_services", "law_enforcement", "migration", "justice_democracy",
    ])
    def test_every_annex_iii_area_is_high(self, domain):
        assert classify(domain, []).tier == "high"

    def test_prohibited_practice_is_unacceptable_even_in_general_domain(self):
        r = classify("general", ["social_scoring"])
        assert r.tier == "unacceptable"
        assert "Art. 5(1)(c)" in _refs(r)

    def test_prohibited_beats_high(self):
        assert classify("employment", ["emotion_recognition_workplace_education"]).tier == "unacceptable"

    def test_safety_component_is_high(self):
        r = classify("healthcare", ["safety_component"])
        assert r.tier == "high"
        assert "Art. 6(1)" in _refs(r)

    def test_chatbot_is_limited(self):
        r = classify("customer_service", ["interacts_with_humans"])
        assert r.tier == "limited"
        assert "Art. 50(1)" in _refs(r)


class TestNotes:
    def test_high_plus_transparency_keeps_both(self):
        r = classify("employment", ["interacts_with_humans"])
        assert r.tier == "high"
        assert "Art. 50(1)" in _refs(r)
        assert any("in addition to the high-risk" in n for n in r.notes)

    def test_narrow_procedural_task_mentions_art_6_3_but_stays_high(self):
        r = classify("education", ["narrow_procedural_task"])
        assert r.tier == "high"
        assert any("Art. 6(3) may exempt" in n for n in r.notes)

    def test_profiling_blocks_the_art_6_3_derogation(self):
        r = classify("employment", ["narrow_procedural_task", "profiles_natural_persons"])
        assert r.tier == "high"
        assert any("not available" in n for n in r.notes)

    def test_healthcare_without_safety_flag_hints_at_medical_devices(self):
        assert any("MDR/IVDR" in n for n in classify("healthcare", []).notes)

    def test_always_marked_as_suggestion(self):
        assert any("not legal advice" in n for n in classify("general", []).notes)


class TestValidation:
    def test_unknown_domain_rejected(self):
        with pytest.raises(ValueError):
            classify("astrology", [])

    def test_unknown_flag_rejected(self):
        with pytest.raises(ValueError):
            classify("general", ["mind_reading"])
