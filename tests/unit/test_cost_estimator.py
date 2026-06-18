
# tests/unit/test_cost_estimator.py
#
# Purpose:
# Unit tests for engine/cost_estimator.py.
# Covers: estimate_cost(), _estimate_resource_cost(),
#         _fetch_azure_vm_price()
# All HTTP calls are mocked — no real network requests.

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from engine.cost_estimator import (
    DEFAULT_FALLBACK_COST,
    HOURS_PER_MONTH,
    estimate_cost,
    _estimate_resource_cost,
    _fetch_azure_vm_price,
)


# =====================================================
# FIXTURES
# =====================================================


def _make_resource(
    resource_type: str,
    name: str = "test_resource",
    values: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal resource dict for testing."""
    return {
        "type":   resource_type,
        "name":   name,
        "values": values or {},
    }


def _make_context(resources: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a minimal context dict for testing."""
    return {"resources": resources}


# =====================================================
# estimate_cost
# =====================================================


class TestEstimateCost:
    """Tests for estimate_cost()."""

    def test_returns_zero_for_empty_resources(self) -> None:
        """Returns 0.0 when context has no resources."""
        result = estimate_cost(context=_make_context([]))
        assert result["estimated_cost"] == 0.0
        assert result["cost_breakdown"] == []

    def test_returns_correct_currency(self) -> None:
        """Returns USD as the currency."""
        result = estimate_cost(context=_make_context([]))
        assert result["currency"] == "USD"

    def test_returns_table_pricing_mode_by_default(self) -> None:
        """Returns 'table' as the pricing mode by default."""
        result = estimate_cost(context=_make_context([]))
        assert result["pricing_mode"] == "table"

    def test_estimates_aws_ec2_instance(self) -> None:
        """Correctly estimates cost for a known AWS EC2 instance type."""
        resource = _make_resource(
            resource_type="aws_instance",
            values={"instance_type": "t2.micro"},
        )
        result = estimate_cost(context=_make_context([resource]))
        assert result["estimated_cost"] == 10.0
        assert result["cost_breakdown"][0]["pricing_source"] == "table"

    def test_estimates_azure_vm_table_mode(self) -> None:
        """Correctly estimates cost for a known Azure VM size."""
        resource = _make_resource(
            resource_type="azurerm_virtual_machine",
            values={"vm_size": "Standard_B2s"},
        )
        result = estimate_cost(context=_make_context([resource]))
        assert result["estimated_cost"] == 25.0

    def test_estimates_fixed_resource_azure_storage(self) -> None:
        """Correctly estimates cost for a fixed-price Azure storage account."""
        resource = _make_resource(resource_type="azurerm_storage_account")
        result = estimate_cost(context=_make_context([resource]))
        assert result["estimated_cost"] == 20.0

    def test_estimates_fixed_resource_aws_s3(self) -> None:
        """Correctly estimates cost for a fixed-price AWS S3 bucket."""
        resource = _make_resource(resource_type="aws_s3_bucket")
        result = estimate_cost(context=_make_context([resource]))
        assert result["estimated_cost"] == 5.0

    def test_sums_multiple_resources(self) -> None:
        """Sums costs across multiple resources."""
        resources = [
            _make_resource("aws_s3_bucket",        "bucket_1"),
            _make_resource("aws_s3_bucket",        "bucket_2"),
            _make_resource("azurerm_storage_account", "storage"),
        ]
        result = estimate_cost(context=_make_context(resources))
        assert result["estimated_cost"] == 5.0 + 5.0 + 20.0

    def test_uses_fallback_for_unknown_resource(self) -> None:
        """Uses fallback cost for unrecognized resource types."""
        resource = _make_resource(resource_type="unknown_provider_resource")
        result = estimate_cost(context=_make_context([resource]))
        assert result["estimated_cost"] == DEFAULT_FALLBACK_COST
        assert result["cost_breakdown"][0]["pricing_source"] == "fallback"

    def test_breakdown_includes_resource_name(self) -> None:
        """Cost breakdown includes the resource name."""
        resource = _make_resource("aws_s3_bucket", name="my_bucket")
        result = estimate_cost(context=_make_context([resource]))
        assert result["cost_breakdown"][0]["resource"] == "my_bucket"

    def test_breakdown_includes_resource_type(self) -> None:
        """Cost breakdown includes the resource type."""
        resource = _make_resource("aws_s3_bucket", name="my_bucket")
        result = estimate_cost(context=_make_context([resource]))
        assert result["cost_breakdown"][0]["type"] == "aws_s3_bucket"


# =====================================================
# _estimate_resource_cost — edge cases
# =====================================================


class TestEstimateResourceCost:
    """Tests for _estimate_resource_cost() edge cases."""

    def test_unknown_aws_instance_type_uses_fallback(self) -> None:
        """Unknown AWS instance type returns fallback cost."""
        cost, source = _estimate_resource_cost(
            resource_type="aws_instance",
            resource_name="my_instance",
            values={"instance_type": "x99.superlarge"},
            pricing_mode="table",
            region="eastus",
        )
        assert cost == DEFAULT_FALLBACK_COST
        assert source == "fallback"

    def test_unknown_azure_vm_size_uses_fallback(self) -> None:
        """Unknown Azure VM size returns fallback cost."""
        cost, source = _estimate_resource_cost(
            resource_type="azurerm_virtual_machine",
            resource_name="my_vm",
            values={"vm_size": "Standard_X99_Unknown"},
            pricing_mode="table",
            region="eastus",
        )
        assert cost == DEFAULT_FALLBACK_COST
        assert source == "fallback"

    def test_default_aws_instance_type_when_missing(self) -> None:
        """Missing instance_type defaults to t2.micro."""
        cost, source = _estimate_resource_cost(
            resource_type="aws_instance",
            resource_name="my_instance",
            values={},
            pricing_mode="table",
            region="eastus",
        )
        assert cost == 10.0
        assert source == "table"

    def test_default_azure_vm_size_when_missing(self) -> None:
        """Missing vm_size defaults to Standard_B1s."""
        cost, source = _estimate_resource_cost(
            resource_type="azurerm_virtual_machine",
            resource_name="my_vm",
            values={},
            pricing_mode="table",
            region="eastus",
        )
        assert cost == 12.0
        assert source == "table"

    def test_all_fixed_resource_types_recognized(self) -> None:
        """All entries in FIXED_RESOURCE_PRICING return table pricing."""
        from engine.cost_estimator import FIXED_RESOURCE_PRICING
        for resource_type in FIXED_RESOURCE_PRICING:
            cost, source = _estimate_resource_cost(
                resource_type=resource_type,
                resource_name="test",
                values={},
                pricing_mode="table",
                region="eastus",
            )
            assert source == "table"
            assert cost == FIXED_RESOURCE_PRICING[resource_type]

    def test_azure_vm_live_mode_success(self) -> None:
        """Azure VM in live mode uses API price when available."""
        with patch(
            "engine.cost_estimator._fetch_azure_vm_price",
            return_value=95.0,
        ):
            cost, source = _estimate_resource_cost(
                resource_type="azurerm_virtual_machine",
                resource_name="my_vm",
                values={"vm_size": "Standard_B2s"},
                pricing_mode="live",
                region="eastus",
            )
        assert cost == 95.0
        assert "azure_api" in source

    def test_azure_vm_live_mode_falls_back_to_table(self) -> None:
        """Azure VM in live mode falls back to table when API unavailable."""
        with patch(
            "engine.cost_estimator._fetch_azure_vm_price",
            return_value=None,
        ):
            cost, source = _estimate_resource_cost(
                resource_type="azurerm_virtual_machine",
                resource_name="my_vm",
                values={"vm_size": "Standard_B2s"},
                pricing_mode="live",
                region="eastus",
            )
        assert cost == 25.0
        assert source == "table"


# =====================================================
# _fetch_azure_vm_price
# =====================================================


class TestFetchAzureVmPrice:
    """Tests for _fetch_azure_vm_price()."""

    def _make_api_response(
        self,
        items: list[dict[str, Any]],
        status_code: int = 200,
    ) -> MagicMock:
        """Build a mock requests.Response."""
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = {"Items": items}
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def test_returns_monthly_cost_on_success(self) -> None:
        """Returns hourly price × 730 when API call succeeds."""
        hourly_price = 0.1
        items = [
            {
                "retailPrice":   hourly_price,
                "currencyCode":  "USD",
                "productName":   "Virtual Machines B Series",
            }
        ]
        mock_response = self._make_api_response(items)

        with patch("requests.get", return_value=mock_response):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        expected = hourly_price * HOURS_PER_MONTH
        assert result == pytest.approx(expected, rel=1e-3)

    def test_returns_none_when_no_items(self) -> None:
        """Returns None when API returns empty Items list."""
        mock_response = self._make_api_response(items=[])

        with patch("requests.get", return_value=mock_response):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        assert result is None

    def test_returns_none_when_price_is_zero(self) -> None:
        """Returns None when API returns a zero retail price."""
        items = [
            {
                "retailPrice":  0,
                "currencyCode": "USD",
                "productName":  "Virtual Machines",
            }
        ]
        mock_response = self._make_api_response(items)

        with patch("requests.get", return_value=mock_response):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        assert result is None

    def test_returns_none_on_request_exception(self) -> None:
        """Returns None when requests.get raises an exception."""
        with patch("requests.get", side_effect=ConnectionError("refused")):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        assert result is None

    def test_returns_none_on_http_error(self) -> None:
        """Returns None when response raises HTTPError."""
        import requests as requests_lib
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = (
            requests_lib.HTTPError("404")
        )

        with patch("requests.get", return_value=mock_response):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        assert result is None

    def test_prefers_linux_over_windows_pricing(self) -> None:
        """Prefers non-Windows items when both are present."""
        items = [
            {
                "retailPrice":  0.5,
                "currencyCode": "USD",
                "productName":  "Virtual Machines Windows",
            },
            {
                "retailPrice":  0.1,
                "currencyCode": "USD",
                "productName":  "Virtual Machines Linux",
            },
        ]
        mock_response = self._make_api_response(items)

        with patch("requests.get", return_value=mock_response):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        # Should use Linux price (0.1), not Windows (0.5)
        assert result == pytest.approx(0.1 * HOURS_PER_MONTH, rel=1e-3)

    def test_uses_windows_when_no_linux_available(self) -> None:
        """Falls back to Windows pricing when no Linux items exist."""
        items = [
            {
                "retailPrice":  0.5,
                "currencyCode": "USD",
                "productName":  "Virtual Machines Windows",
            }
        ]
        mock_response = self._make_api_response(items)

        with patch("requests.get", return_value=mock_response):
            result = _fetch_azure_vm_price("Standard_B2s", "eastus")

        assert result == pytest.approx(0.5 * HOURS_PER_MONTH, rel=1e-3)

    def test_uses_sku_map_for_known_vm_sizes(self) -> None:
        """Uses AZURE_SKU_MAP to translate known VM sizes."""
        captured_urls: list[str] = []

        def capture_url(url: str, **kwargs: Any) -> MagicMock:
            captured_urls.append(url)
            mock_response = self._make_api_response(items=[])
            return mock_response

        with patch("requests.get", side_effect=capture_url):
            _fetch_azure_vm_price("Standard_B2s", "eastus")

        assert len(captured_urls) == 1
        assert "B2s" in captured_urls[0]

    def test_builds_fallback_sku_name_for_unknown_sizes(self) -> None:
        """Builds a SKU name from unknown VM sizes by stripping 'Standard_'."""
        captured_urls: list[str] = []

        def capture_url(url: str, **kwargs: Any) -> MagicMock:
            captured_urls.append(url)
            mock_response = self._make_api_response(items=[])
            return mock_response

        with patch("requests.get", side_effect=capture_url):
            _fetch_azure_vm_price("Standard_Custom_Size", "eastus")

        assert len(captured_urls) == 1
        assert "Custom" in captured_urls[0]