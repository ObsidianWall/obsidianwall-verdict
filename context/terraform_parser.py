# context/terraform_parser.py
import json
from pathlib import Path
from typing import Any

_AZURE_GPU_VM_SIZES: frozenset[str] = frozenset(
    {
        "Standard_NC6",
        "Standard_NC12",
        "Standard_NC24",
        "Standard_NC6s_v3",
        "Standard_NC12s_v3",
        "Standard_NC24s_v3",
        "Standard_ND6s",
        "Standard_ND12s",
        "Standard_ND24s",
        "Standard_NV6",
        "Standard_NV12",
        "Standard_NV24",
    }
)

_AWS_GPU_INSTANCE_PREFIXES: tuple[str, ...] = (
    "p2.",
    "p3.",
    "p4.",
    "p5.",
    "g3.",
    "g4dn.",
    "g5.",
    "inf1.",
    "inf2.",
    "trn1.",
)

_AZURE_COMPUTE_TYPES: frozenset[str] = frozenset(
    {
        "azurerm_virtual_machine",
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
        "azurerm_virtual_machine_scale_set",
    }
)

_AWS_COMPUTE_TYPES: frozenset[str] = frozenset(
    {
        "aws_instance",
        "aws_launch_template",
        "aws_autoscaling_group",
    }
)

_OPEN_INGRESS_SOURCES: frozenset[str] = frozenset(
    {
        "*",
        "Internet",
        "0.0.0.0/0",
        "::/0",
        "Any",
    }
)


def _count_open_ingress_rules(resources: list[dict[str, Any]]) -> int:
    count = 0
    for resource in resources:
        rtype = resource.get("type", "")
        values = resource.get("values", {})
        if rtype == "azurerm_network_security_group":
            for rule in values.get("security_rule", []):
                if (
                    rule.get("direction") == "Inbound"
                    and rule.get("access") == "Allow"
                    and rule.get("source_address_prefix") in _OPEN_INGRESS_SOURCES
                ):
                    count += 1
        if rtype == "azurerm_network_security_rule":
            if (
                values.get("direction") == "Inbound"
                and values.get("access") == "Allow"
                and values.get("source_address_prefix") in _OPEN_INGRESS_SOURCES
            ):
                count += 1
        if rtype == "aws_security_group":
            for rule in values.get("ingress", []):
                if "0.0.0.0/0" in rule.get("cidr_blocks", []):
                    count += 1
    return count


def _count_public_storage(resources: list[dict[str, Any]]) -> int:
    count = 0
    for resource in resources:
        rtype = resource.get("type", "")
        values = resource.get("values", {})
        if rtype == "azurerm_storage_account":
            if values.get("allow_blob_public_access") is True:
                count += 1
        if rtype == "aws_s3_bucket":
            count += 1
        if rtype == "aws_s3_bucket_public_access_block":
            if (
                values.get("block_public_acls") is True
                and values.get("block_public_policy") is True
            ):
                count = max(0, count - 1)
    return count


def _count_unencrypted_databases(resources: list[dict[str, Any]]) -> int:
    count = 0
    for resource in resources:
        rtype = resource.get("type", "")
        values = resource.get("values", {})
        if rtype in ("azurerm_sql_database", "azurerm_mssql_database"):
            if values.get("transparent_data_encryption_enabled") is not True:
                count += 1
        if rtype in ("aws_db_instance", "aws_rds_cluster"):
            if values.get("storage_encrypted") is not True:
                count += 1
    return count


def _count_untagged_resources(resources: list[dict[str, Any]]) -> int:
    return sum(1 for r in resources if not r.get("values", {}).get("tags"))


def _count_compute_instances(resources: list[dict[str, Any]]) -> int:
    return sum(
        1
        for r in resources
        if r.get("type") in _AZURE_COMPUTE_TYPES | _AWS_COMPUTE_TYPES
    )


def _count_gpu_instances(resources: list[dict[str, Any]]) -> int:
    count = 0
    for resource in resources:
        rtype = resource.get("type", "")
        values = resource.get("values", {})
        if rtype in _AZURE_COMPUTE_TYPES:
            if values.get("vm_size", "") in _AZURE_GPU_VM_SIZES:
                count += 1
        if rtype == "aws_instance":
            instance_type = values.get("instance_type", "")
            if any(instance_type.startswith(p) for p in _AWS_GPU_INSTANCE_PREFIXES):
                count += 1
    return count


def parse_terraform_plan(plan_path: str) -> dict[str, Any]:
    path = Path(plan_path)
    if not path.exists():
        raise FileNotFoundError(f"Terraform plan not found: {plan_path}")
    with path.open("r", encoding="utf-8") as f:
        try:
            plan: dict[str, Any] = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in Terraform plan: {plan_path}") from e

    raw_resources: list[dict[str, Any]] = []
    try:
        root = plan.get("planned_values", {}).get("root_module", {})
        raw_resources.extend(root.get("resources", []))
        for child in root.get("child_modules", []):
            raw_resources.extend(child.get("resources", []))
    except (AttributeError, TypeError) as e:
        raise ValueError("Invalid Terraform plan structure") from e

    parsed_resources: list[dict[str, Any]] = []
    for resource in raw_resources:
        rtype = resource.get("type")
        rname = resource.get("name")
        if rtype is None or rname is None:
            continue
        parsed_resources.append(
            {
                "type": rtype,
                "name": rname,
                "values": resource.get("values", {}),
            }
        )

    return {
        "resources": parsed_resources,
        "open_ingress_rules": _count_open_ingress_rules(parsed_resources),
        "public_storage_buckets": _count_public_storage(parsed_resources),
        "unencrypted_databases": _count_unencrypted_databases(parsed_resources),
        "untagged_resource_count": _count_untagged_resources(parsed_resources),
        "total_resource_count": len(parsed_resources),
        "compute_instance_count": _count_compute_instances(parsed_resources),
        "gpu_instance_count": _count_gpu_instances(parsed_resources),
    }


_OPEN_INGRESS_SOURCES = frozenset({"*", "Internet", "0.0.0.0/0", "::/0", "Any"})
_AZURE_COMPUTE_TYPES = frozenset(
    {
        "azurerm_virtual_machine",
        "azurerm_linux_virtual_machine",
        "azurerm_windows_virtual_machine",
    }
)
_AWS_COMPUTE_TYPES = frozenset({"aws_instance", "aws_launch_template"})
_AZURE_GPU_VM_SIZES = frozenset(
    {
        "Standard_NC6",
        "Standard_NC12",
        "Standard_NC6s_v3",
        "Standard_ND6s",
        "Standard_NV6",
    }
)
_AWS_GPU_PREFIXES = ("p2.", "p3.", "p4.", "g3.", "g4dn.", "g5.", "inf1.", "trn1.")


def _count_open_ingress(resources):
    count = 0
    for r in resources:
        t, v = r.get("type", ""), r.get("values", {})
        if t == "azurerm_network_security_group":
            for rule in v.get("security_rule", []):
                if (
                    rule.get("direction") == "Inbound"
                    and rule.get("access") == "Allow"
                    and rule.get("source_address_prefix") in _OPEN_INGRESS_SOURCES
                ):
                    count += 1
        if t == "azurerm_network_security_rule":
            if (
                v.get("direction") == "Inbound"
                and v.get("access") == "Allow"
                and v.get("source_address_prefix") in _OPEN_INGRESS_SOURCES
            ):
                count += 1
        if t == "aws_security_group":
            for rule in v.get("ingress", []):
                if "0.0.0.0/0" in rule.get("cidr_blocks", []):
                    count += 1
    return count


def _count_public_storage(resources):
    count = 0
    for r in resources:
        t, v = r.get("type", ""), r.get("values", {})
        if t == "azurerm_storage_account" and v.get("allow_blob_public_access") is True:
            count += 1
        if t == "aws_s3_bucket":
            count += 1
        if (
            t == "aws_s3_bucket_public_access_block"
            and v.get("block_public_acls") is True
        ):
            count = max(0, count - 1)
    return count


def _count_unencrypted_db(resources):
    count = 0
    for r in resources:
        t, v = r.get("type", ""), r.get("values", {})
        if (
            t in ("azurerm_sql_database", "azurerm_mssql_database")
            and v.get("transparent_data_encryption_enabled") is not True
        ):
            count += 1
        if (
            t in ("aws_db_instance", "aws_rds_cluster")
            and v.get("storage_encrypted") is not True
        ):
            count += 1
    return count


def _count_untagged(resources):
    return sum(1 for r in resources if not r.get("values", {}).get("tags"))


def _count_compute(resources):
    return sum(
        1
        for r in resources
        if r.get("type") in _AZURE_COMPUTE_TYPES | _AWS_COMPUTE_TYPES
    )


def _count_gpu(resources):
    count = 0
    for r in resources:
        t, v = r.get("type", ""), r.get("values", {})
        if t in _AZURE_COMPUTE_TYPES and v.get("vm_size", "") in _AZURE_GPU_VM_SIZES:
            count += 1
        if t == "aws_instance" and any(
            v.get("instance_type", "").startswith(p) for p in _AWS_GPU_PREFIXES
        ):
            count += 1
    return count
