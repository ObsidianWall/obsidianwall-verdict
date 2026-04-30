# engine/policy_loader.py

# Purpose: Loads policy definitions from YAML files, returning them as dictionaries for validation and enforcement.


import yaml


def load_policy(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)