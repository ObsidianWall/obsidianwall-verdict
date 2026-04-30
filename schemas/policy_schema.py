# schemas/policy_schema.py
# Purpose: Defines enforceable policy structure (compliance + validation)
# Purpose: Defines the schema for policy validation using Pydantic.
# This schema includes conditions, decisions, actions, and metadata for policies.

# Note: This is a simplified example. In a real-world application, the schema would likely be more complex and include additional fields and validation logic.

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class Condition(BaseModel):
    expression: str
    message: str


class Decision(BaseModel):
    allow: str
    deny: str
    warn: Optional[str] = None


class Action(BaseModel):
    type: str
    message: str


class Metadata(BaseModel):
    severity: str
    category: str


class PolicyModel(BaseModel):
    name: str
    version: str
    inputs: List[str]
    parameters: Dict[str, Any]
    conditions: List[Condition]
    decision: Decision
    actions: List[Action]
    metadata: Metadata