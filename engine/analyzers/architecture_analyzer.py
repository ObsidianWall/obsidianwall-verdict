

# engine/analyzers/architecture_analyzer.py


def analyze_architecture(
    runtime_context: dict
) -> dict:

    findings = []

    resources = runtime_context.get(
        "resources",
        []
    )

    if len(resources) == 1:

        findings.append({

            "type": "single_resource_architecture",

            "severity": "medium",

            "message": (
                "Single-resource deployment detected."
            )
        })

    return {

        "analyzer": "architecture_analyzer",

        "risk_score": 20 if findings else 0,

        "findings": findings,

        "optimization_candidates": []
    }