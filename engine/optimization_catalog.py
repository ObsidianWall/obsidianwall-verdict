

# engine/optimization_catalog.py

# Responsibilities: proprietary heuristics

#purpose: Containing: 
            # known resource patterns
            # pricing heuristics
            # optimization mappings
            # architecture alternatives



OPTIMIZATION_RULES = {
    "aws_instance:t3.large": {
        "alternative": "aws_instance:t3.medium",
        "savings_percent": 35
    },

    "aws_instance:m5.large": {
        "alternative": "aws_instance:t3.large",
        "savings_percent": 28
    },

    "aws_rds_instance:db.m5.large": {
        "alternative": "db.t3.medium",
        "savings_percent": 40
    }
}