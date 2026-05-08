#engine/

#purpose: Containing: 
            # known resource patterns
            # pricing heuristics
            # optimization mappings
            # architecture alternatives



OPTIMIZATION_RULES = {
    "aws_instance:t3.large": {
        "alternative": "t3.medium",
        "savings_percent": 35
    }
}