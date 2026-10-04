from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from app.schemas.attack_execution import AttackExecutionResponse
from app.schemas.gateway_decision import GatewayDecisionResponse


class AIGoatExecutionRequest(BaseModel):
    attack_id: UUID
    conversation_id: str | None = None
    defense_mode: Literal["on", "off"] = "on"


class AIGoatExecutionResponse(BaseModel):
    execution: AttackExecutionResponse
    decision: GatewayDecisionResponse
    # Raw AI Goat payload; None when the Gateway blocked the attack.
    response: dict | None = None