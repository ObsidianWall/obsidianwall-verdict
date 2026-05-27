# engine/explainability/trace_graph.py

# Purpose:
# Build structured governance execution lineage graphs.
#
# Responsibilities:
# - Model evaluation execution as a directed graph
# - Capture nodes: inputs, conditions, analyzers, decision
# - Capture edges: data flow between execution stages
# - Surface consolidated risk summary (pre-computed)
# - Produce replay-ready execution lineage artifacts
# - Foundation for simulation and governance replay
#
# IMPORTANT:
# This module NEVER influences enforcement decisions.
# Trace graphs are structural artifacts only.
# Produced AFTER the deterministic decision is resolved.


from typing import Any

from audit.audit_logger import get_logger

logger = get_logger()


# =====================================================
# NODE TYPES
# =====================================================


class NodeType:
    INPUT = "input"
    CONDITION = "condition"
    ANALYZER = "analyzer"
    DECISION = "decision"
    POLICY = "policy"


# =====================================================
# EDGE TYPES
# =====================================================


class EdgeType:
    PROVIDES = "provides"
    EVALUATES = "evaluates"
    INFORMS = "informs"
    PRODUCES = "produces"
    RESOLVES = "resolves"


# =====================================================
# EXCLUDED INPUT KEYS
#
# These runtime context keys are evaluation metadata,
# not governance inputs. They must not appear as
# input nodes in the trace graph — they did not
# influence the condition evaluation or decision.
# =====================================================

TRACE_GRAPH_EXCLUDED_KEYS: frozenset[str] = frozenset(
    {
        "pricing_mode",  # metadata: how costs were estimated
        "resources",  # structural: raw resource list
        "cost_breakdown",  # structural: per-resource cost detail
    }
)


# =====================================================
# NODE BUILDERS
# =====================================================


def _build_input_nodes(
    runtime_context: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Build graph nodes for runtime context inputs.
    Each scalar context key becomes an input node.
    Metadata keys are excluded — they are not
    governance inputs.
    """

    input_nodes: list[dict[str, Any]] = []

    for key, value in runtime_context.items():
        if key in TRACE_GRAPH_EXCLUDED_KEYS:
            continue

        if isinstance(value, (dict, list)):
            continue

        input_nodes.append(
            {
                "node_id": f"input::{key}",
                "node_type": NodeType.INPUT,
                "label": key,
                "value": value,
            }
        )

    return input_nodes


def _build_condition_nodes(
    trace: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Build graph nodes for each evaluated condition.
    """

    condition_nodes: list[dict[str, Any]] = []

    for trace_item in trace:
        if not isinstance(trace_item, dict):
            continue

        condition_id = trace_item.get("condition_id", "unknown")

        condition_nodes.append(
            {
                "node_id": f"condition::{condition_id}",
                "node_type": NodeType.CONDITION,
                "label": condition_id,
                "expression": trace_item.get("expression", ""),
                "result": trace_item.get("result", False),
                "description": trace_item.get("description", ""),
            }
        )

    return condition_nodes


def _build_analyzer_nodes(
    analyzer_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Build graph nodes for each analyzer execution.
    """

    analyzer_nodes: list[dict[str, Any]] = []

    for analyzer_name, analyzer_data in analyzer_results.items():
        if not isinstance(analyzer_data, dict):
            analyzer_nodes.append(
                {
                    "node_id": f"analyzer::{analyzer_name}",
                    "node_type": NodeType.ANALYZER,
                    "label": analyzer_name,
                    "status": "failed",
                    "risk_score": 0,
                    "finding_count": 0,
                }
            )
            continue

        findings = analyzer_data.get("findings", [])

        analyzer_nodes.append(
            {
                "node_id": f"analyzer::{analyzer_name}",
                "node_type": NodeType.ANALYZER,
                "label": analyzer_name,
                "status": analyzer_data.get("status", "completed"),
                "risk_score": analyzer_data.get("risk_score", 0),
                "finding_count": len(findings),
            }
        )

    return analyzer_nodes


def _build_decision_node(
    evaluation_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Build the terminal decision node.
    """

    return {
        "node_id": "decision::final",
        "node_type": NodeType.DECISION,
        "label": "governance_decision",
        "decision": evaluation_result.get("decision", "UNKNOWN"),
        "conditions_passed": evaluation_result.get("conditions_passed", False),
        "override_required": evaluation_result.get("override_required", False),
        "requires_approval": evaluation_result.get("requires_approval", False),
        "governance_severity": evaluation_result.get("governance_severity", "medium"),
    }


# =====================================================
# EDGE BUILDERS
# =====================================================


def _build_condition_edges(
    trace: list[dict[str, Any]],
    runtime_context: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Build edges from input nodes to condition nodes.
    Infers which inputs each condition expression references.
    Excluded metadata keys are never used as edge sources.
    """

    edges: list[dict[str, Any]] = []

    for trace_item in trace:
        if not isinstance(trace_item, dict):
            continue

        condition_id = trace_item.get("condition_id", "unknown")
        expression = trace_item.get("expression", "")

        for key in runtime_context:
            if key in TRACE_GRAPH_EXCLUDED_KEYS:
                continue

            if isinstance(runtime_context[key], (dict, list)):
                continue

            if key in expression:
                edges.append(
                    {
                        "edge_id": f"input::{key}→condition::{condition_id}",
                        "edge_type": EdgeType.PROVIDES,
                        "source": f"input::{key}",
                        "target": f"condition::{condition_id}",
                        "label": "provides_value",
                    }
                )

    return edges


def _build_decision_edges(
    trace: list[dict[str, Any]],
    analyzer_results: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Build edges from conditions and analyzers
    to the terminal decision node.
    """

    edges: list[dict[str, Any]] = []

    for trace_item in trace:
        if not isinstance(trace_item, dict):
            continue

        condition_id = trace_item.get("condition_id", "unknown")

        edges.append(
            {
                "edge_id": f"condition::{condition_id}→decision::final",
                "edge_type": EdgeType.EVALUATES,
                "source": f"condition::{condition_id}",
                "target": "decision::final",
                "label": "evaluates_to",
                "result": trace_item.get("result", False),
            }
        )

    for analyzer_name in analyzer_results:
        edges.append(
            {
                "edge_id": f"analyzer::{analyzer_name}→decision::final",
                "edge_type": EdgeType.INFORMS,
                "source": f"analyzer::{analyzer_name}",
                "target": "decision::final",
                "label": "informs_decision",
            }
        )

    return edges


# =====================================================
# TRACE GRAPH BUILDER
# =====================================================


def build_trace_graph(
    evaluation_result: dict[str, Any],
    analyzer_results: dict[str, Any],
    runtime_context: dict[str, Any],
    risk_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build the structured governance execution lineage graph.

    The trace graph models the complete evaluation execution
    as a directed graph with typed nodes and edges.

    Graph structure:
        input nodes     → condition nodes   (PROVIDES)
        condition nodes → decision node     (EVALUATES)
        analyzer nodes  → decision node     (INFORMS)

    Metadata keys (pricing_mode, resources, cost_breakdown)
    are excluded from input nodes — they are not governance
    inputs and must not appear in the execution lineage.
    """

    if not isinstance(evaluation_result, dict):
        raise TypeError("evaluation_result must be a dict")

    if not isinstance(analyzer_results, dict):
        raise TypeError("analyzer_results must be a dict")

    if not isinstance(runtime_context, dict):
        raise TypeError("runtime_context must be a dict")

    trace = evaluation_result.get("trace", [])

    # =================================================
    # BUILD NODES
    # =================================================

    input_nodes = _build_input_nodes(runtime_context)
    condition_nodes = _build_condition_nodes(trace)
    analyzer_nodes = _build_analyzer_nodes(analyzer_results)
    decision_node = _build_decision_node(evaluation_result)

    all_nodes = input_nodes + condition_nodes + analyzer_nodes + [decision_node]

    # =================================================
    # BUILD EDGES
    # =================================================

    condition_edges = _build_condition_edges(trace, runtime_context)
    decision_edges = _build_decision_edges(trace, analyzer_results)
    all_edges = condition_edges + decision_edges

    # =================================================
    # EXECUTION SUMMARY
    # =================================================

    execution_summary: dict[str, Any] = {
        "total_nodes": len(all_nodes),
        "total_edges": len(all_edges),
        "input_count": len(input_nodes),
        "condition_count": len(condition_nodes),
        "analyzer_count": len(analyzer_nodes),
        "conditions_passed": evaluation_result.get("conditions_passed", False),
        "final_decision": evaluation_result.get("decision", "UNKNOWN"),
    }

    # =================================================
    # ASSEMBLE GRAPH
    # =================================================

    graph: dict[str, Any] = {
        "nodes": all_nodes,
        "edges": all_edges,
        "risk_summary": risk_summary,
        "execution_summary": execution_summary,
        "replay_ready": True,
        "simulation_ready": False,
    }

    logger.info(
        "trace_graph_built",
        extra={
            "extra": {
                "node_count": len(all_nodes),
                "edge_count": len(all_edges),
                "final_decision": execution_summary["final_decision"],
                "overall_risk_score": (
                    risk_summary.get("overall_risk_score", 0) if risk_summary else 0
                ),
            }
        },
    )

    return graph
