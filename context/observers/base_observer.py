# context/observers/base_observer.py
#
# Purpose:
# Abstract interface for cloud-provider observers — the
# provider-agnostic contract every concrete implementation
# (Azure, later AWS, GCP) must satisfy.
#
# This is the "cloud state" analog to context/translators/
# base_translator.py, which already does the same job for
# static input sources (Terraform plans, CloudFormation
# templates). Same design principle: the rest of the
# pipeline (PolicyOrchestrator, analyzers, condition
# evaluation) never needs to know which cloud provider
# produced the context — it consumes one consistent shape
# regardless of source.
#
# Contract:
# observe() must return a context dict in the SAME shape
# context.context_builder.build_context() produces from a
# Terraform plan — this is what lets policies written
# against plan-file evaluation work UNCHANGED against live
# cloud state. Getting this field mapping wrong is the
# highest-risk failure mode here: it wouldn't crash, it
# would silently evaluate policies against incorrect data,
# which is worse than a loud failure for a governance tool.
#
# Read-only by design:
# Every concrete observer must authenticate with read-only
# credentials only (e.g. Azure "Reader" role). Sentinel
# observes reality — it never has, and never will have,
# write or deploy permission to the resources it inspects.

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CloudObserverError(Exception):
    """
    Raised for any cloud observer failure — authentication,
    API access, or malformed scope. Callers (verdict sentinel
    scan) catch this specifically to produce a clear,
    actionable CLI error rather than an unhandled traceback.
    """


class CloudObserver(ABC):
    """
    Abstract base for all cloud-provider observers.

    A concrete observer's job is narrow and specific: query
    live resource state within a given scope, and translate
    that state into the same context shape a Terraform plan
    produces. It does NOT evaluate policy, does NOT make
    governance decisions, and does NOT write anywhere —
    those remain PolicyOrchestrator's and
    telemetry.governance_store's jobs, unchanged.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """
        Short provider identifier for logging and CLI output —
        e.g. "azure", "aws", "gcp". Used in verdict sentinel
        scan's output to show which provider was observed.
        """

    @property
    def capabilities(self) -> dict[str, bool]:
        """
        Declares which observation categories this provider
        actually supports, so callers can evaluate only the
        policies backed by available evidence instead of
        assuming every provider observes the same things.

        Default implementation returns all False — concrete
        observers override this to declare what they actually
        collect. Deliberately scoped to infrastructure
        observation categories only (not identity/SaaS/HR
        signals — those are a different kind of provider,
        not something this interface should be stretched to
        cover yet).
        """
        return {
            "resource_inventory": False,
            "network_security": False,
            "storage_security": False,
            "database_security": False,
            "compute_sizing": False,
            "secrets_management": False,
        }

    @abstractmethod
    def authenticate(self) -> None:
        """
        Authenticate to the cloud provider using read-only
        credentials. Must raise CloudObserverError with a
        clear, actionable message on failure — e.g. missing
        credentials, insufficient permissions, expired token.

        Never silently proceeds with partial or unauthenticated
        access. If this raises, the caller must not attempt
        observe().
        """

    @abstractmethod
    def observe(self, scope: str) -> dict[str, Any]:
        """
        Query live cloud resource state within the given scope
        (e.g. a resource group name, a subscription ID) and
        return a context dict in the same shape
        context.context_builder.build_context() produces.

        Must raise CloudObserverError on any failure to query
        or interpret cloud state — never return a partial or
        best-guess context silently, since that risks a
        policy evaluating against incomplete data without
        anyone knowing.

        Args:
            scope: provider-specific identifier for what to
                observe (e.g. an Azure resource group name).
                The exact meaning is defined by each concrete
                observer's own documentation.

        Returns:
            A context dict compatible with PolicyOrchestrator.evaluate().
        """