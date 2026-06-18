
# tests/unit/test_base_translator.py
#
# Covers the abstract method NotImplementedError paths in
# context/translators/base_translator.py
# Lines 78, 90, 102, 114 — the raise NotImplementedError
# statements in each abstract method.

import pytest

from context.translators.base_translator import BaseTranslator


# =====================================================
# HELPERS
# =====================================================


def _make_translator_calling_super():
    """
    Create a concrete translator that calls super() on each
    method to trigger the NotImplementedError in the base class.
    """

    class SuperCallingTranslator(BaseTranslator):
        @property
        def plan_format(self) -> str:
            return super().plan_format

        @property
        def supported_extensions(self) -> tuple:
            return super().supported_extensions

        def parse(self, plan_path: str) -> dict:
            return super().parse(plan_path)

    return SuperCallingTranslator()


def _make_minimal_translator():
    """
    Create a properly implemented minimal translator
    for testing _empty_context().
    """

    class MinimalTranslator(BaseTranslator):
        @property
        def plan_format(self) -> str:
            return "test"

        @property
        def supported_extensions(self) -> tuple:
            return (".test",)

        def parse(self, plan_path: str) -> dict:
            return self._empty_context()

    return MinimalTranslator()


# =====================================================
# ABSTRACT METHOD ERROR PATHS
# =====================================================


class TestBaseTranslatorAbstractMethods:

    def test_parse_raises_not_implemented_when_called_via_super(self):
        translator = _make_translator_calling_super()
        with pytest.raises(NotImplementedError, match="must implement parse"):
            translator.parse("test.json")

    def test_plan_format_raises_not_implemented_when_called_via_super(self):
        translator = _make_translator_calling_super()
        with pytest.raises(NotImplementedError, match="must implement plan_format"):
            _ = translator.plan_format

    def test_supported_extensions_raises_not_implemented_when_called_via_super(
        self,
    ):
        translator = _make_translator_calling_super()
        with pytest.raises(
            NotImplementedError, match="must implement supported_extensions"
        ):
            _ = translator.supported_extensions


# =====================================================
# EMPTY CONTEXT
# =====================================================


class TestBaseTranslatorEmptyContext:

    def test_empty_context_returns_all_standard_keys(self):
        translator = _make_minimal_translator()
        context = translator._empty_context()

        expected_keys = {
            "resources",
            "open_ingress_rules",
            "public_storage_buckets",
            "unencrypted_databases",
            "ssl_not_enforced_count",
            "versioning_disabled_count",
            "untagged_resource_count",
            "total_resource_count",
            "compute_instance_count",
            "gpu_instance_count",
            "ai_gpu_workloads",
        }
        assert expected_keys == set(context.keys())

    def test_empty_context_integer_keys_default_to_zero(self):
        translator = _make_minimal_translator()
        context = translator._empty_context()

        integer_keys = [
            "open_ingress_rules",
            "public_storage_buckets",
            "unencrypted_databases",
            "ssl_not_enforced_count",
            "versioning_disabled_count",
            "untagged_resource_count",
            "total_resource_count",
            "compute_instance_count",
            "gpu_instance_count",
            "ai_gpu_workloads",
        ]
        for key in integer_keys:
            assert context[key] == 0, f"{key} should default to 0"

    def test_empty_context_resources_defaults_to_empty_list(self):
        translator = _make_minimal_translator()
        context = translator._empty_context()
        assert context["resources"] == []

    def test_parse_uses_empty_context_as_base(self):
        translator = _make_minimal_translator()
        result = translator.parse("any_path")
        assert result["open_ingress_rules"] == 0
        assert result["resources"] == []