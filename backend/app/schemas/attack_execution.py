from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.schemas.types import GatewayAction


class AttackExecutionBase(BaseModel):
    request: str
    response: str | None = None
    conversation_id: str | None = None
    gateway_action: GatewayAction | None = None
    attack_success: bool = False
    risk_score: float | None = None
    latency_ms: int | None = None


class AttackExecutionCreate(AttackExecutionBase):
    attack_id: UUID


class AttackExecutionResponse(AttackExecutionBase):
    id: UUID
    attack_id: UUID
    executed_at: datetime

    model_config = ConfigDict(from_attributes=True)
