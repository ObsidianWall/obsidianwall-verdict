
# tests/unit/test_recommender.py

import pytest
from engine.recommender import (
    classify_resource,
    match_rule_conditions,
    deduplicate_recommendations,
    generate_suggestions,
)


# =====================================================
# classify_resource
# =====================================================

def test_known_azure_vm_classified_as_compute():
    assert classify_resource("azurerm_virtual_machine") == "compute"

def test_known_aws_rds_classified_as_database():
    assert classify_resource("aws_db_instance") == "database"

def test_known_s3_classified_as_storage():
    assert classify_resource("aws_s3_bucket") == "storage"

def test_known_ecs_classified_as_container():
    assert classify_resource("aws_ecs_cluster") == "container"

def test_unknown_resource_returns_unknown():
    assert classify_resource("unknown_resource_type") == "unknown"

def test_empty_string_returns_unknown():
    assert classify_resource("") == "unknown"


# =====================================================
# match_rule_conditions
# =====================================================

def test_matching_conditions_return_true():
    result = match_rule_conditions(
        rule_conditions={"environment": "development"},
        context={"environment": "development"}
    )
    assert result is True


def test_non_matching_conditions_return_false():
    result = match_rule_conditions(
        rule_conditions={"environment": "development"},
        context={"environment": "production"}
    )
    assert result is False


def test_missing_context_key_returns_false():
    result = match_rule_conditions(
        rule_conditions={"environment": "development"},
        context={}
    )
    assert result is False


def test_multiple_conditions_all_must_match():
    result = match_rule_conditions(
        rule_conditions={
            "environment":      "development",
            "workload_profile": "burstable"
        },
        context={
            "environment":      "development",
            "workload_profile": "burstable"
        }
    )
    assert result is True


def test_partial_match_returns_false():
    result = match_rule_conditions(
        rule_conditions={
            "environment":      "development",
            "workload_profile": "burstable"
        },
        context={
            "environment":  "development",
            # workload_profile missing
        }
    )
    assert result is False


def test_malformed_rule_conditions_returns_false():
    result = match_rule_conditions(
        rule_conditions="not a dict",
        context={"environment": "development"}
    )
    assert result is False


# =====================================================
# deduplicate_recommendations
# =====================================================

def test_unique_recommendations_all_preserved():
    recs = [
        {"message": "First recommendation"},
        {"message": "Second recommendation"},
    ]
    result = deduplicate_recommendations(recs)
    assert len(result) == 2


def test_duplicate_messages_deduplicated():
    recs = [
        {"message": "Same message", "type": "a"},
        {"message": "Same message", "type": "b"},
    ]
    result = deduplicate_recommendations(recs)
    assert len(result) == 1
    assert result[0]["type"] == "a"     # first one preserved


def test_ordering_preserved_after_dedup():
    recs = [
        {"message": "Third"},
        {"message": "First"},
        {"message": "Second"},
        {"message": "First"},   # duplicate
    ]
    result = deduplicate_recommendations(recs)
    assert [r["message"] for r in result] == [
        "Third", "First", "Second"
    ]


def test_missing_message_skipped():
    recs = [
        {"type": "no_message"},             # no message key
        {"message": "Valid recommendation"},
    ]
    result = deduplicate_recommendations(recs)
    assert len(result) == 1
    assert result[0]["message"] == "Valid recommendation"


def test_empty_list_returns_empty():
    assert deduplicate_recommendations([]) == []


# =====================================================
# generate_suggestions — boundary validation
# =====================================================

def test_invalid_context_raises():
    with pytest.raises(TypeError, match="context must be a dict"):
        generate_suggestions(
            context="not a dict",
            decision="DENY",
            analyzer_results={}
        )


def test_invalid_decision_raises():
    with pytest.raises(ValueError, match="decision must be"):
        generate_suggestions(
            context={},
            decision="",
            analyzer_results={}
        )


def test_invalid_analyzer_results_raises():
    with pytest.raises(TypeError, match="analyzer_results must be a dict"):
        generate_suggestions(
            context={},
            decision="DENY",
            analyzer_results="not a dict"
        )


def test_deny_always_adds_enforcement_guidance():
    suggestions = generate_suggestions(
        context={"resources": []},
        decision="DENY",
        analyzer_results={}
    )
    enforcement = [
        s for s in suggestions
        if s.get("type") == "enforcement"
    ]
    assert len(enforcement) == 1


def test_allow_does_not_add_enforcement_guidance():
    suggestions = generate_suggestions(
        context={"resources": []},
        decision="ALLOW",
        analyzer_results={}
    )
    enforcement = [
        s for s in suggestions
        if s.get("type") == "enforcement"
    ]
    assert len(enforcement) == 0


def test_suggestions_are_list_of_dicts():
    suggestions = generate_suggestions(
        context={"resources": []},
        decision="ALLOW",
        analyzer_results={}
    )
    assert isinstance(suggestions, list)
    for s in suggestions:
        assert isinstance(s, dict)
