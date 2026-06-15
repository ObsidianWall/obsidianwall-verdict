# engine/coverage/frameworks/nist_ai_rmf.py

NIST_AI_RMF_CONTROLS = {
    "GOVERN-1.1": {
        "title": "AI Policies and Procedures",
        "description": (
            "Policies, processes, procedures, and practices "
            "across the organization related to the mapping, "
            "measuring, and managing of AI risks are in place."
        ),
        "keywords": [
            "ai_policy", "ai_governance", "ai_approval",
            "ai_authorized", "governance",
        ],
    },
    "GOVERN-1.2": {
        "title": "Accountability for AI Risk",
        "description": (
            "Accountability structures are in place so that "
            "appropriate teams and individuals are empowered, "
            "responsible, and trained for AI risk management."
        ),
        "keywords": [
            "ai_accountability", "ai_owner", "ai_oversight",
            "human_review", "ai_responsible",
        ],
    },
    "GOVERN-4.1": {
        "title": "AI Risk Management",
        "description": (
            "Organizational teams are committed to a culture "
            "that considers and communicates AI risk."
        ),
        "keywords": [
            "ai_risk", "risk_management", "ai_assessment",
        ],
    },
    "GOVERN-5.1": {
        "title": "Governance of AI Deployment",
        "description": (
            "Organizational policies and practices are in "
            "place to address AI risks and benefits arising "
            "from third-party software and data."
        ),
        "keywords": [
            "ai_deployment", "ai_authorized", "ai_workload",
            "ai_governance_required",
        ],
    },
    "MAP-1.1": {
        "title": "AI System Categorization",
        "description": (
            "Context is established for framing risks "
            "related to the AI system."
        ),
        "keywords": [
            "ai_classification", "ai_inventory",
            "ai_workloads", "ai_gpu_workloads",
            "gpu_instance_count",
        ],
    },
    "MAP-2.1": {
        "title": "Impact Assessment",
        "description": (
            "The potential impact of the AI system is "
            "understood and assessed."
        ),
        "keywords": [
            "ai_impact", "impact_assessment", "ai_risk_score",
        ],
    },
    "MAP-5.1": {
        "title": "Likelihood and Impact of AI Harm",
        "description": (
            "Likelihood and magnitude of each identified "
            "impact based on expected use of AI system "
            "are estimated."
        ),
        "keywords": [
            "ai_harm", "ai_likelihood", "ai_magnitude",
        ],
    },
    "MEASURE-1.1": {
        "title": "AI Evaluation Methods",
        "description": (
            "Approaches and metrics for measuring and "
            "monitoring AI risks are selected."
        ),
        "keywords": [
            "ai_evaluation", "ai_benchmark", "ai_metric",
            "ai_monitor",
        ],
    },
    "MEASURE-2.5": {
        "title": "AI System Testing",
        "description": (
            "The AI system is tested to evaluate whether "
            "it meets the intended purpose and objectives."
        ),
        "keywords": [
            "ai_test", "ai_validation", "model_test",
        ],
    },
    "MANAGE-1.1": {
        "title": "AI Risk Treatment",
        "description": (
            "A risk treatment plan for prioritized AI risks "
            "is established and followed."
        ),
        "keywords": [
            "ai_risk_treatment", "ai_mitigation",
            "ai_control", "ai_safeguard",
        ],
    },
    "MANAGE-2.2": {
        "title": "AI Incident Response",
        "description": (
            "Mechanisms are in place and applied to sustain "
            "the value of deployed AI systems and responses "
            "are targeted to the urgency of the situation."
        ),
        "keywords": [
            "ai_incident", "ai_response", "ai_rollback",
            "model_incident",
        ],
    },
    "MANAGE-4.1": {
        "title": "Post-Deployment Monitoring",
        "description": (
            "Post-deployment AI risks and benefits are "
            "evaluated and efforts are informed by feedback."
        ),
        "keywords": [
            "ai_monitor", "post_deployment", "ai_drift",
            "model_drift", "ai_observation",
        ],
    },
}
