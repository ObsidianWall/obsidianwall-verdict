# schemas/policy_schema.py
# Purpose: Defines enforceable policy structure (compliance + validation)
# Purpose: Defines the schema for policy validation using Pydantic.
# This schema includes conditions, decisions, actions, and metadata for policies.

# Note: This is a simplified example. In a real-world application, the schema would likely be more complex and include additional fields and validation logic.

# schemas/policy_schema.py




from pydantic import BaseModel
from typing import List, Optional


class Metadata(BaseModel):
    name: str
    version: float
    owner: str
    description: Optional[str] = None


class Condition(BaseModel):
    id: str
    expression: str
    description: str


class Action(BaseModel):
    type: str
    message: str
    severity: Optional[str] = "info"


class Decision(BaseModel):
    allow: str
    deny: str
    warn: Optional[str] = None


class Override(BaseModel):
    roles: List[str]


class Budget(BaseModel):
    amount: float
    period: str
    scope: str
    owner: str
    flexibility: str
    override_allowed: bool


class Parameters(BaseModel):
    budget: Budget


class Spec(BaseModel):
    inputs: List[str]
    parameters: Parameters
    conditions: List[Condition]
    decision: Decision
    override: Override
    actions: List[Action]


class Policy(BaseModel):
    apiVersion: str
    kind: str
    metadata: Metadata
    spec: Spec